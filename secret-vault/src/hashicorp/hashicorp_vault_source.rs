use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http_body_util::{BodyExt, Empty, LengthLimitError, Limited};
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
/// Vault's default `max_request_size`. A KV v2 version cannot be written larger than that, so a
/// longer response is not a secret read and is not buffered.
const MAX_RESPONSE_SIZE: usize = 32 * 1024 * 1024;
/// The longest Vault error text quoted into an error or a log line. A misbehaving proxy may echo
/// the request or other data into `errors`, so only a short prefix of the first one is kept.
const MAX_VAULT_ERROR_CHARS: usize = 256;

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

    /// PEM file with CA certificates to trust besides the roots of the selected TLS root store,
    /// for a server whose certificate comes from a private CA. The file adds to the root store
    /// and does not replace it, unlike `VAULT_CACERT` in the Vault CLI, so a server with a
    /// certificate from any public CA in the root store is trusted as well.
    pub ca_certificate: Option<PathBuf>,

    /// Mount path of the KV secrets engine v2 the secrets are read from.
    #[default = "\"secret\".into()"]
    pub mount: String,

    /// Read the KV v2 custom metadata into the secret labels, and the creation time of the
    /// version into `created_at`.
    #[default = "false"]
    pub read_metadata: bool,

    /// Time limit for one read, from opening the connection to receiving the last byte of the
    /// response. It keeps a server that accepts the connection and never answers from stalling
    /// `refresh` and the auto-refresher.
    #[default = "Duration::from_secs(60)"]
    pub timeout: Duration,
}

impl HashiCorpVaultSourceOptions {
    /// Options from the variables the Vault CLI reads: `VAULT_ADDR` (required), `VAULT_TOKEN`,
    /// `VAULT_NAMESPACE`, `VAULT_CACERT` and `VAULT_CLIENT_TIMEOUT` (whole seconds such as `60`, or
    /// a duration such as `1m30s`). An empty variable counts as unset.
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

        let mut options = Self::new(address)
            .opt_token(token)
            .opt_namespace(env_var("VAULT_NAMESPACE")?)
            .opt_ca_certificate(env_var("VAULT_CACERT")?.map(PathBuf::from));
        if let Some(timeout) = env_var("VAULT_CLIENT_TIMEOUT")? {
            options.timeout = vault_duration("VAULT_CLIENT_TIMEOUT", &timeout)?;
        }
        Ok(options)
    }
}

/// Reads secrets from the KV secrets engine v2 of a HashiCorp Vault server.
///
/// The secret name is the path of the secret inside the mount, and the secret version is the
/// KV v2 version number, the latest version when it is not set. The secret value is the `data`
/// object of the version: its key/value pairs as the JSON text Vault returns.
#[derive(Debug, Clone)]
pub struct HashiCorpVaultSource {
    http_client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
    /// `{address}/v1/{mount}/data/`, the mount percent-encoded.
    data_endpoint: String,
    token: Option<HashiCorpVaultToken>,
    namespace: Option<HeaderValue>,
    mount: String,
    read_metadata: bool,
    timeout: Duration,
}

impl HashiCorpVaultSource {
    /// A source with the options from [`HashiCorpVaultSourceOptions::from_env`].
    pub fn new() -> SecretVaultResult<Self> {
        Self::with_options(HashiCorpVaultSourceOptions::from_env()?)
    }

    /// Fails on an invalid address, mount, namespace or timeout, or an unreadable CA certificate
    /// file. It sends no request, so a wrong token or an unreachable server fail the first read.
    pub fn with_options(options: HashiCorpVaultSourceOptions) -> SecretVaultResult<Self> {
        if options.timeout.is_zero() {
            return Err(SecretVaultInvalidParametersError::create(
                "timeout",
                "The Vault request timeout must be greater than zero".into(),
            ));
        }
        let address = vault_address(&options.address)?;
        if is_plain_http_to_another_host(&address) {
            warn!(
                %address,
                "The Vault address uses plain HTTP to another host, so the token and the secrets cross the network unencrypted"
            );
        }
        let data_endpoint = format!(
            "{}/v1/{}/data/",
            address.to_string().trim_end_matches('/'),
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
            timeout: options.timeout,
        })
    }

    /// `None` when the secret or the version does not exist, or the version is deleted or
    /// destroyed.
    async fn read_secret(&self, secret_ref: &SecretVaultRef) -> SecretVaultResult<Option<Secret>> {
        let secret_path = secret_ref.key.secret_name.value();
        let kv_version = secret_ref
            .key
            .secret_version
            .as_ref()
            .map(|version| {
                let version = version.value();
                version.parse::<NonZeroU64>().map_err(|_| {
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
        let (status, body) = self.send(request).await?;

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
            Ok(response) => response.first_error_prefix(),
            // The parse error is dropped because serde_json may quote the body in it.
            Err(_) => "the body is not a Vault error response".to_string(),
        };
        let code = format!("VAULT_STATUS_{}", status.as_u16());
        let message = format!(
            "Vault returned {status} for {}/{secret_path}: {errors}",
            self.mount
        );
        // A sealed or overloaded server answers 5xx or 429 and may serve the same read later;
        // any other status will not change on a retry.
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            Err(SecretVaultNetworkError::create(&code, message))
        } else {
            Err(SecretsSourceError::create(&code, message))
        }
    }

    /// The status and the whole body of the response, within the timeout.
    async fn send(&self, request: Request<Empty<Bytes>>) -> SecretVaultResult<(StatusCode, Bytes)> {
        let exchange = async {
            let response = self.http_client.request(request).await?;
            let status = response.status();
            // The body buffer belongs to the HTTP stack and is freed without being zeroized;
            // the only copy this crate keeps is the `SecretValue`.
            let body = Limited::new(response.into_body(), MAX_RESPONSE_SIZE)
                .collect()
                .await
                .map_err(|e| {
                    if e.is::<LengthLimitError>() {
                        SecretsSourceError::create(
                            "VAULT_RESPONSE_TOO_LARGE",
                            format!("The Vault response is larger than {MAX_RESPONSE_SIZE} bytes"),
                        )
                    } else {
                        SecretVaultError::NetworkError(SecretVaultNetworkError::with_error_chain(
                            "VAULT_HTTP",
                            "Unable to receive the Vault response",
                            e.as_ref(),
                        ))
                    }
                })?
                .to_bytes();
            Ok((status, body))
        };

        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| {
                SecretVaultNetworkError::create(
                    "VAULT_TIMEOUT",
                    format!("No complete Vault response within {:?}", self.timeout),
                )
            })?
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
            let secret_path = secret_ref.key.secret_name.value();
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

impl VaultErrorResponse {
    /// At most [`MAX_VAULT_ERROR_CHARS`] characters of the first error, quoted.
    fn first_error_prefix(&self) -> String {
        let first_error = self.errors.first().map(String::as_str).unwrap_or_default();
        format!(
            "{:?}",
            first_error
                .chars()
                .take(MAX_VAULT_ERROR_CHARS)
                .collect::<String>()
        )
    }
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

/// A duration the way the Vault CLI reads one: whole seconds (`60`) or a number with units
/// (`30s`, `1m30s`, `500ms`).
fn vault_duration(name: &str, value: &str) -> SecretVaultResult<Duration> {
    let invalid = || {
        SecretVaultInvalidParametersError::create(
            name,
            format!("{name} must be whole seconds or a duration such as `1m30s`, got `{value}`"),
        )
    };
    match value.parse::<u64>() {
        Ok(seconds) => Ok(Duration::from_secs(seconds)),
        Err(_) => value
            .parse::<jiff::SignedDuration>()
            .map_err(|_| invalid())
            .and_then(|duration| Duration::try_from(duration).map_err(|_| invalid())),
    }
}

/// A Vault address: an `http` or `https` URI with a host and no query. Its text without the
/// trailing `/` is the API base, which keeps the path of a Vault served under a path prefix.
fn vault_address(address: &str) -> SecretVaultResult<Uri> {
    let invalid = |reason: String| {
        SecretVaultInvalidParametersError::create(
            "address",
            format!("`{address}` is not a valid Vault address: {reason}"),
        )
    };
    let uri = address.parse::<Uri>().map_err(|e| invalid(e.to_string()))?;
    match (uri.scheme_str(), uri.authority(), uri.query()) {
        (Some("http" | "https"), Some(_), None) => Ok(uri),
        _ => Err(invalid(
            "expected http:// or https://, a host and no query".into(),
        )),
    }
}

/// Whether requests to `address` carry the token and the secrets in plain text off this host:
/// an `http` address whose host is not `localhost` or a loopback IP address.
fn is_plain_http_to_another_host(address: &Uri) -> bool {
    let host = address.host().unwrap_or_default();
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    address.scheme_str() == Some("http") && !is_loopback
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

/// The roots of the selected root store plus the CA certificates in `ca_certificate`, with the
/// selected crypto provider. The provider is passed to this config only and never installed as
/// the process default, which stays the application's choice.
fn tls_config(ca_certificate: Option<&Path>) -> SecretVaultResult<rustls::ClientConfig> {
    let roots = trusted_roots(selected_root_store(), ca_certificate)?;

    #[cfg(feature = "hashicorp-vault-tls-aws-lc-rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "hashicorp-vault-tls-ring")]
    let provider = rustls::crypto::ring::default_provider();

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| SecretsSourceError::create("VAULT_TLS", e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

fn selected_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    #[cfg(feature = "hashicorp-vault-tls-roots")]
    {
        let system_certificates = rustls_native_certs::load_native_certs();
        for error in &system_certificates.errors {
            warn!(%error, "Unable to load a system CA certificate");
        }
        roots.add_parsable_certificates(system_certificates.certs);
    }
    #[cfg(feature = "hashicorp-vault-tls-webpki")]
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// `roots` plus the CA certificates in `ca_certificate`, which add to the roots and never
/// replace them.
fn trusted_roots(
    mut roots: rustls::RootCertStore,
    ca_certificate: Option<&Path>,
) -> SecretVaultResult<rustls::RootCertStore> {
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
    // With system roots on a host that has none installed, such as a distroless image, every
    // request would fail later with an unknown issuer.
    if roots.is_empty() {
        return Err(SecretVaultInvalidParametersError::create(
            "ca_certificate",
            "No CA certificates to trust: the root store has none and no CA certificate file is set"
                .into(),
        ));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const SECRET_PAYLOAD: &str = "s3cr3t-payload-value";
    const DATABASE_SECRET: &str = "my-app/database";

    /// Ends a test whose read would otherwise hang, so a missing timeout fails the test.
    const TEST_GUARD: Duration = Duration::from_secs(5);

    fn local_source(listener: &TcpListener) -> HashiCorpVaultSource {
        let address = format!("http://{}", listener.local_addr().unwrap());
        HashiCorpVaultSource::with_options(
            HashiCorpVaultSourceOptions::new(address).with_timeout(Duration::from_millis(200)),
        )
        .unwrap()
    }

    /// Answers every request on `listener` with `status` and `body`.
    fn answer_with(listener: TcpListener, status: StatusCode, body: String) {
        tokio::spawn(async move {
            loop {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = connection.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                connection.write_all(response.as_bytes()).await.unwrap();
            }
        });
    }

    async fn read_guarded(
        source: &HashiCorpVaultSource,
        secret_ref: SecretVaultRef,
    ) -> SecretVaultResult<HashMap<SecretVaultRef, Secret>> {
        tokio::time::timeout(TEST_GUARD, source.get_secrets(&[secret_ref]))
            .await
            .expect("the read must end before the test guard")
    }

    #[tokio::test]
    async fn unanswered_read_times_out_as_network_error() {
        // The listener is never accepted from: the kernel completes the connection and the
        // request is written, but no response ever comes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = local_source(&listener);

        let result = read_guarded(&source, SecretVaultRef::new(DATABASE_SECRET.into())).await;

        assert!(matches!(result, Err(SecretVaultError::NetworkError(_))));
    }

    #[tokio::test]
    async fn status_decides_whether_error_is_retryable() {
        for (status, retryable) in [
            (StatusCode::SERVICE_UNAVAILABLE, true),
            (StatusCode::TOO_MANY_REQUESTS, true),
            (StatusCode::FORBIDDEN, false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let source = local_source(&listener);
            answer_with(
                listener,
                status,
                r#"{"errors":["Vault is sealed"]}"#.to_string(),
            );

            let result = read_guarded(&source, SecretVaultRef::new(DATABASE_SECRET.into())).await;

            match result {
                Err(SecretVaultError::NetworkError(_)) => assert!(retryable, "{status}"),
                Err(SecretVaultError::SecretsSourceError(_)) => assert!(!retryable, "{status}"),
                other => panic!("{status} gave {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn vault_errors_are_cut_to_first_error_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = local_source(&listener);
        // A proxy echoing the request could fill `errors` with anything; multi-byte characters
        // put the cut inside no character only if it is made on a char boundary.
        let echoed = format!("{}{SECRET_PAYLOAD}", "é".repeat(MAX_VAULT_ERROR_CHARS));
        let body = serde_json::json!({ "errors": [echoed, SECRET_PAYLOAD] }).to_string();
        answer_with(listener, StatusCode::BAD_REQUEST, body);

        let Err(error) = read_guarded(&source, SecretVaultRef::new(DATABASE_SECRET.into())).await
        else {
            panic!("a 400 is an error");
        };

        assert!(matches!(error, SecretVaultError::SecretsSourceError(_)));
        let message = format!("{error}");
        assert!(!message.contains(SECRET_PAYLOAD));
        assert!(!format!("{error:?}").contains(SECRET_PAYLOAD));
        assert!(message.chars().count() < 2 * MAX_VAULT_ERROR_CHARS);
    }

    #[test]
    fn root_store_without_certificates_is_rejected() {
        let Err(SecretVaultError::InvalidParametersError(error)) =
            trusted_roots(rustls::RootCertStore::empty(), None)
        else {
            panic!("a root store without certificates trusts no Vault server");
        };

        assert_eq!(error.public.field, "ca_certificate");
    }

    #[test]
    fn only_plain_http_to_another_host_is_flagged() {
        for (address, flagged) in [
            ("http://vault.example.com:8200", true),
            ("http://10.0.0.5:8200", true),
            ("http://127.0.0.1:8200", false),
            ("http://127.1.2.3:8200", false),
            ("http://[::1]:8200", false),
            ("http://LocalHost:8200", false),
            ("https://vault.example.com:8200", false),
        ] {
            let address = vault_address(address).unwrap();
            assert_eq!(
                is_plain_http_to_another_host(&address),
                flagged,
                "{address}"
            );
        }
    }

    #[tokio::test]
    async fn version_zero_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let source = local_source(&listener);
        let secret_ref =
            SecretVaultRef::new(DATABASE_SECRET.into()).with_secret_version("0".into());

        let result = read_guarded(&source, secret_ref).await;

        assert!(matches!(
            result,
            Err(SecretVaultError::InvalidParametersError(_))
        ));
    }

    #[test]
    fn client_timeout_reads_like_the_vault_cli() {
        for (value, expected) in [
            ("60", Duration::from_secs(60)),
            ("30s", Duration::from_secs(30)),
            ("1m30s", Duration::from_secs(90)),
            ("500ms", Duration::from_millis(500)),
        ] {
            assert_eq!(
                vault_duration("VAULT_CLIENT_TIMEOUT", value).unwrap(),
                expected
            );
        }
        for value in ["-5s", "soon"] {
            assert!(matches!(
                vault_duration("VAULT_CLIENT_TIMEOUT", value),
                Err(SecretVaultError::InvalidParametersError(_))
            ));
        }
    }

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
    fn token_is_absent_from_debug() {
        let token = HashiCorpVaultToken::try_from(SecretValue::from(SECRET_PAYLOAD)).unwrap();
        let options =
            HashiCorpVaultSourceOptions::new("https://vault.example.com".into()).with_token(token);
        let source = HashiCorpVaultSource::with_options(options.clone()).unwrap();

        assert!(!format!("{options:?}").contains(SECRET_PAYLOAD));
        assert!(!format!("{source:?}").contains(SECRET_PAYLOAD));
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
