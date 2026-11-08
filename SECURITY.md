# Security policy

## Reporting a vulnerability

Please follow the general guidelines of the [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).

## Security considerations and risks

### OSS

Open source code is created through voluntary collaboration of software developers.
The original authors license the code so that anyone can see it, modify it and distribute new versions of it.

Manage all OSS with the same procedures and tools that you use for commercial products.
Train your employees on cyber security best practices that help them use and manage software products securely.

Do not rely solely on individuals who read sensitive information, especially in projects like this one.

### Versioning

Do not use broad dependency version ranges. They pull in new versions of a dependency automatically, before you have audited the changes.

### Protect your secrets in GCP/AWS using IAM and service accounts

Do not expose all of your secrets to the apps.
Use IAM and different service accounts to give access only on an as-needed basis.

### Zeroing, protecting memory and encryption do not provide 100% safety

There are still allocations on the protocol layers, a session secret key is available in memory, privileged OS users still have broad access, etc.
Do not consider this a completely safe solution for all possible attacks.
Mitigating some of the attacks is not possible without additional support at the hardware or OS level, such as Intel SGX, which runs code in a hardware-isolated enclave.

## Contacts

Email: [me@abdolence.dev](mailto:me@abdolence.dev)
