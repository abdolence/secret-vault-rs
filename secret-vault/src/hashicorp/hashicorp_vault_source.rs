use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use jiff::Timestamp;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rsb_derive::Builder;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use serde::Deserialize;
use serde_json::value::RawValue;
use tracing::*;

use crate::errors::*;
use crate::*;

const VAULT_TOKEN_HEADER: &str = "x-vault-token";
const VAULT_NAMESPACE_HEADER: &str = "x-vault-namespace";
/// Vault Agent and Vault Proxy refuse requests without it when `require_request_header` is set.
const VAULT_REQUEST_HEADER: &str = "x-vault-request";

/// Characters a path segment keeps as they are: the RFC 3986 unreserved set.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A Vault token: non-empty visible ASCII, zeroized on drop, shown as `***` by `Debug`.
#[derive(Debug, Clone)]
pub struct HashiCorpVaultToken(SecretValue);

impl TryFrom<SecretValue> for HashiCorpVaultToken {
    type Error = SecretVaultError;

    fn try_from(token: SecretValue) -> Result<Self, Self::Error> {
        let bytes = token.ref_sensitive_value();
        if !bytes.is_empty() && bytes.iter().all(u8::is_ascii_graphic) {
            Ok(Self(token))
        } else {
            Err(SecretVaultInvalidParametersError::create(
                "token",
                "A Vault token must be a non-empty string of visible ASCII characters".into(),
            ))
        }
    }
}

impl HashiCorpVaultToken {
    /// The HTTP stack copies the value into buffers this crate cannot zeroize. Marking it
    /// sensitive keeps it out of the `Debug` output of the request headers.
    fn header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_bytes(self.0.ref_sensitive_value())
            .expect("a token holds visible ASCII only, which is always a valid header value");
        value.set_sensitive(true);
        value
    }
}

/// Options for [`HashiCorpVaultSource`].
#[derive(Debug, Clone, Builder)]
pub struct HashiCorpVaultSourceOptions {
    /// Address of the Vault server, such as `https://vault.example.com:8200`.
    pub address: String,

    /// Token sent with every request. Without one the requests carry no token, which is what a
    /// Vault Agent or Vault Proxy with `use_auto_auth_token` expects.
    pub token: Option<HashiCorpVaultToken>,

    /// Vault Enterprise namespace the mount belongs to.
    pub namespace: Option<String>,

    /// PEM file with CA certificates to trust besides the system ones, for a server whose
    /// certificate comes from a private CA.
    pub ca_certificate: Option<PathBuf>,

    /// Mount path of the KV secrets engine v2 the secrets are read from.
    #[default = "\"secret\".into()"]
    pub mount: String,

    /// Read the KV v2 custom metadata into the secret labels, and the creation time of the
    /// version into `created_at`.
    #[default = "false"]
    pub read_metadata: bool,
}

impl HashiCorpVaultSourceOptions {
    /// Options from the variables the Vault CLI reads: `VAULT_ADDR` (required), `VAULT_TOKEN`,
    /// `VAULT_NAMESPACE` and `VAULT_CACERT`. An empty variable counts as unset.
    pub fn from_env() -> SecretVaultResult<Self> {
        let address = env_var("VAULT_ADDR")?.ok_or_else(|| {
            SecretVaultInvalidParametersError::create(
                "VAULT_ADDR",
                "VAULT_ADDR must be set to the address of the Vault server".into(),
            )
        })?;
        let token = env_var("VAULT_TOKEN")?
            .map(|token| HashiCorpVaultToken::try_from(SecretValue::from(token)))
            .transpose()?;

        Ok(Self::new(address)
            .opt_token(token)
            .opt_namespace(env_var("VAULT_NAMESPACE")?)
            .opt_ca_certificate(env_var("VAULT_CACERT")?.map(PathBuf::from)))
    }
}

/// Reads secrets from the KV secrets engine v2 of a HashiCorp Vault server.
///
/// The secret name is the path of the secret inside the mount, and the secret version is the
/// KV v2 version number, the latest version when it is not set. The secret value is the `data`
/// object of the version: its key/value pairs as the JSON text Vault returns.
pub struct HashiCorpVaultSource {
    http_client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    /// `{address}/v1/{mount}/data/`, the mount percent-encoded.
    data_endpoint: String,
    token: Option<HashiCorpVaultToken>,
    namespace: Option<HeaderValue>,
    mount: String,
    read_metadata: bool,
}

impl HashiCorpVaultSource {
    /// A source with the options from [`HashiCorpVaultSourceOptions::from_env`].
    pub fn new() -> SecretVaultResult<Self> {
        Self::with_options(HashiCorpVaultSourceOptions::from_env()?)
    }

    /// Fails on an invalid address, mount or namespace, or an unreadable CA certificate file.
    /// It sends no request, so a wrong token or an unreachable server fail the first read.
    pub fn with_options(options: HashiCorpVaultSourceOptions) -> SecretVaultResult<Self> {
        let data_endpoint = format!(
            "{}/v1/{}/data/",
            vault_api_base(&options.address)?,
            encoded_vault_path("mount", options.mount.trim_matches('/'))?
        );
        let namespace = options
            .namespace
            .as_deref()
            .map(|namespace| {
                HeaderValue::from_str(namespace).map_err(|_| {
                    SecretVaultInvalidParametersError::create(
                        "namespace",
                        format!("`{namespace}` is not a valid Vault namespace"),
                    )
                })
            })
            .transpose()?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config(options.ca_certificate.as_deref())?)
            .https_or_http()
            .enable_http1()
            .build();

        Ok(Self {
            http_client: Client::builder(TokioExecutor::new()).build(connector),
            data_endpoint,
            token: options.token,
            namespace,
            mount: options.mount,
            read_metadata: options.read_metadata,
        })
    }

    /// `None` when the secret or the version does not exist, or the version is deleted or
    /// destroyed.
    async fn read_secret(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>> {
        let secret_path: &str = secret_ref.key.secret_name.value();
        let kv_version = secret_ref
            .key
            .secret_version
            .as_ref()
            .map(|version| {
                let version: &str = version.value();
                version.parse::<u64>().map_err(|_| {
                    SecretVaultInvalidParametersError::create(
                        "secret_version",
                        format!(
                            "KV v2 version must be a positive integer, got `{version}` for secret `{secret_path}`"
                        ),
                    )
                })
            })
            .transpose()?;

        let mut uri = format!(
            "{}{}",
            self.data_endpoint,
            encoded_vault_path("secret_name", secret_path)?
        );
        if let Some(version) = kv_version {
            uri.push_str(&format!("?version={version}"));
        }
        let uri = Uri::try_from(uri.as_str()).map_err(|e| {
            SecretsSourceError::create(
                "VAULT_REQUEST",
                format!("`{uri}` is not a valid Vault request URI: {e}"),
            )
        })?;

        let mut request = Request::new(Empty::new());
        *request.uri_mut() = uri;
        let headers = request.headers_mut();
        headers.insert(
            HeaderName::from_static(VAULT_REQUEST_HEADER),
            HeaderValue::from_static("true"),
        );
        if let Some(token) = &self.token {
            headers.insert(
                HeaderName::from_static(VAULT_TOKEN_HEADER),
                token.header_value(),
            );
        }
        if let Some(namespace) = &self.namespace {
            headers.insert(
                HeaderName::from_static(VAULT_NAMESPACE_HEADER),
                namespace.clone(),
            );
        }

        trace!(
            mount = %self.mount,
            path = secret_path,
            ?kv_version,
            "Reading HashiCorp Vault secret"
        );
        let response = self.http_client.request(request).await?;
        let status = response.status();
        // The body buffer belongs to the HTTP stack and is freed without being zeroized; the
        // only copy this crate keeps is the `SecretValue`.
        let body = response.into_body().collect().await?.to_bytes();

        if status.is_success() {
            let response = KvReadResponse::try_from(body.as_ref())?;
            return Ok(response.data.data.map(|data| {
                Secret::new(
                    SecretValue::new(data.get().as_bytes().to_vec()),
                    self.metadata(secret_ref, response.data.metadata),
                )
            }));
        }

        // A missing secret or version answers 404 with an empty `errors` list, and a deleted or
        // destroyed version answers 404 with its metadata. A 404 with errors is a request Vault
        // could not route, such as one to a mount that does not exist.
        let errors = match serde_json::from_slice::<VaultErrorResponse>(&body) {
            Ok(response) if status == StatusCode::NOT_FOUND && response.errors.is_empty() => {
                return Ok(None);
            }
            Ok(response) => format!("{:?}", response.errors),
            // The parse error is dropped because serde_json may quote the body in it.
            Err(_) => "the body is not a Vault error response".to_string(),
        };
        Err(SecretsSourceError::create(
            &format!("VAULT_STATUS_{}", status.as_u16()),
            format!(
                "Vault returned {status} for {}/{secret_path}: {errors}",
                self.mount
            ),
        ))
    }

    fn metadata(
        &self,
        secret_ref: &SecretVaultRef,
        version_metadata: KvVersionMetadata,
    ) -> SecretMetadata {
        let mut metadata = SecretMetadata::create_from_ref(secret_ref)
            .with_version(version_metadata.version.to_string().into());

        if self.read_metadata {
            for (name, value) in version_metadata.custom_metadata.into_iter().flatten() {
                metadata.add_label(SecretMetadataLabel::new(name).with_value(value));
            }

            match version_metadata.created_time.parse::<Timestamp>() {
                Ok(created_at) => metadata.created_at = Some(created_at),
                Err(err) => warn!(
                    created_time = %version_metadata.created_time,
                    %err,
                    "Unable to parse the Vault secret version creation time"
                ),
            }
        }

        metadata
    }
}

#[async_trait]
impl SecretsSource for HashiCorpVaultSource {
    fn name(&self) -> String {
        "HashiCorpVault".to_string()
    }

    async fn get_secrets(
        &self,
        references: &[SecretVaultRef],
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        let mut result_map: HashMap<SecretVaultRef, Secret> = HashMap::new();

        for secret_ref in references {
            let secret_path: &str = secret_ref.key.secret_name.value();
            match self.read_secret(secret_ref).await {
                Ok(Some(secret)) => {
                    result_map.insert(secret_ref.clone(), secret);
                }
                Ok(None) if secret_ref.required => {
                    return Err(SecretVaultError::DataNotFoundError(
                        SecretVaultDataNotFoundError::new(
                            SecretVaultErrorPublicGenericDetails::new("SECRET_NOT_FOUND".into()),
                            format!(
                                "Secret is required but not found: {}/{secret_path} (version {:?})",
                                self.mount, secret_ref.key.secret_version
                            ),
                        ),
                    ));
                }
                Ok(None) => {
                    debug!(
                        mount = %self.mount,
                        path = secret_path,
                        version = ?secret_ref.key.secret_version,
                        "Secret or secret version doesn't exist and since it is not required it is skipped"
                    );
                }
                Err(err) => {
                    error!(
                        mount = %self.mount,
                        path = secret_path,
                        version = ?secret_ref.key.secret_version,
                        %err,
                        "Unable to read secret or secret version"
                    );
                    return Err(err);
                }
            }
        }

        Ok(result_map)
    }
}

/// The parts of a KV v2 read response this source uses.
#[derive(Deserialize)]
struct KvReadResponse<'a> {
    #[serde(borrow)]
    data: KvVersion<'a>,
}

#[derive(Deserialize)]
struct KvVersion<'a> {
    /// The key/value pairs as the JSON text Vault sent, so the secret is copied once, into a
    /// `SecretValue`, rather than through an intermediate tree of strings.
    #[serde(borrow)]
    data: Option<&'a RawValue>,
    metadata: KvVersionMetadata,
}

#[derive(Deserialize)]
struct KvVersionMetadata {
    version: u64,
    created_time: String,
    custom_metadata: Option<BTreeMap<String, String>>,
}

impl<'a> TryFrom<&'a [u8]> for KvReadResponse<'a> {
    type Error = SecretVaultError;

    fn try_from(body: &'a [u8]) -> Result<Self, Self::Error> {
        // serde_json quotes the offending value in its messages, and in a read response that
        // value can be the secret itself, so only the category and position are kept.
        serde_json::from_slice(body).map_err(|e| {
            SecretsSourceError::create(
                "VAULT_RESPONSE",
                format!(
                    "Unable to parse the Vault KV v2 read response: {:?} error at line {} column {}",
                    e.classify(),
                    e.line(),
                    e.column()
                ),
            )
        })
    }
}

/// The body of a failed Vault request.
#[derive(Deserialize)]
struct VaultErrorResponse {
    #[serde(default)]
    errors: Vec<String>,
}

/// The value of an environment variable, `None` when it is unset or empty.
fn env_var(name: &str) -> SecretVaultResult<Option<String>> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(SecretVaultInvalidParametersError::create(
            name,
            format!("{name} is not valid Unicode"),
        )),
    }
}

/// `scheme://authority` of a Vault address, followed by its path when Vault is served under a
/// path prefix.
fn vault_api_base(address: &str) -> SecretVaultResult<String> {
    let uri = address.parse::<Uri>().map_err(|e| {
        SecretVaultInvalidParametersError::create(
            "address",
            format!("`{address}` is not a valid Vault address: {e}"),
        )
    })?;
    match (uri.scheme_str(), uri.authority(), uri.query()) {
        (Some(scheme @ ("http" | "https")), Some(authority), None) => Ok(format!(
            "{scheme}://{authority}{}",
            uri.path().trim_end_matches('/')
        )),
        _ => Err(SecretVaultInvalidParametersError::create(
            "address",
            format!("`{address}` is not a valid Vault address: expected http:// or https://, a host and no query"),
        )),
    }
}

/// Percent-encodes each `/`-separated segment of a path inside Vault, so a name can neither add
/// a query nor reach outside the mount.
fn encoded_vault_path(field: &str, path: &str) -> SecretVaultResult<String> {
    path.split('/')
        .map(|segment| match segment {
            "" | "." | ".." => Err(SecretVaultInvalidParametersError::create(
                field,
                format!("`{path}` is not a valid Vault path: its segments must not be empty, `.` or `..`"),
            )),
            segment => Ok(utf8_percent_encode(segment, PATH_SEGMENT).to_string()),
        })
        .collect::<SecretVaultResult<Vec<_>>>()
        .map(|segments| segments.join("/"))
}

/// The system CA certificates plus the ones in `ca_certificate`, with the aws-lc-rs provider
/// the GCP and AWS clients of this crate use. Enabling a second rustls provider in the same build
/// would stop `rustls::ClientConfig::builder()` from finding a default anywhere in the application.
fn tls_config(ca_certificate: Option<&Path>) -> SecretVaultResult<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    let system_certificates = rustls_native_certs::load_native_certs();
    for error in &system_certificates.errors {
        warn!(%error, "Unable to load a system CA certificate");
    }
    roots.add_parsable_certificates(system_certificates.certs);

    if let Some(path) = ca_certificate {
        let certificates = CertificateDer::pem_file_iter(path)
            .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
            .map_err(|e| {
                SecretVaultInvalidParametersError::create(
                    "ca_certificate",
                    format!(
                        "Unable to read PEM certificates from {}: {e}",
                        path.display()
                    ),
                )
            })?;
        let (added, ignored) = roots.add_parsable_certificates(certificates);
        if added == 0 || ignored > 0 {
            return Err(SecretVaultInvalidParametersError::create(
                "ca_certificate",
                format!(
                    "{} must hold CA certificates only: {added} usable, {ignored} not",
                    path.display()
                ),
            ));
        }
    }

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| SecretsSourceError::create("VAULT_TLS", e.to_string()))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_PAYLOAD: &str = "s3cr3t-payload-value";

    #[test]
    fn secret_is_absent_from_read_response_parse_error() {
        // A KV v1 mount returns the secret's own pairs under `data`, so a pair named
        // `metadata` lands where KV v2 keeps the version metadata.
        let body = format!(r#"{{"data":{{"metadata":"{SECRET_PAYLOAD}"}}}}"#);
        let serde_error = serde_json::from_slice::<KvReadResponse>(body.as_bytes())
            .err()
            .expect("a string is not KV v2 version metadata");
        assert!(serde_error.to_string().contains(SECRET_PAYLOAD));

        let Err(error) = KvReadResponse::try_from(body.as_bytes()) else {
            panic!("a string is not KV v2 version metadata");
        };
        assert!(!format!("{error}").contains(SECRET_PAYLOAD));
        assert!(!format!("{error:?}").contains(SECRET_PAYLOAD));
    }

    #[test]
    fn token_is_absent_from_options_debug() {
        let token = HashiCorpVaultToken::try_from(SecretValue::from(SECRET_PAYLOAD)).unwrap();
        let options =
            HashiCorpVaultSourceOptions::new("https://vault.example.com".into()).with_token(token);

        assert!(!format!("{options:?}").contains(SECRET_PAYLOAD));
    }

    #[test]
    fn secret_name_cannot_leave_the_mount() {
        for secret_name in [
            "../sys/health",
            "my-app/../../sys",
            "my-app//db",
            "/my-app",
            "my-app/",
        ] {
            assert!(matches!(
                encoded_vault_path("secret_name", secret_name),
                Err(SecretVaultError::InvalidParametersError(_))
            ));
        }
    }

    #[test]
    fn secret_name_segments_are_percent_encoded() {
        assert_eq!(
            encoded_vault_path("secret_name", "my app/db?version=1#x").unwrap(),
            "my%20app/db%3Fversion%3D1%23x"
        );
    }
}
