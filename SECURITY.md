# Security Policy

## Reporting a Vulnerability

Please follow general guidlines defined here:
https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html

## Security considerations and risks
### OSS
Open source code is created through voluntary collaboration of software developers.
The original authors license the code so that anyone can see it, modify it, and
distribute new versions of it.
You should manage all OSS using the same procedures and tools that you use for
commercial products. As always, train your employees on
cyber security best practices that can help them securely
use and manage software products.
You should not solely rely on individuals, especially on the projects like this
reading sensitive information.

### Versioning
Please don't use broad version dependency management not to include
a new version of dependency automatically without your auditing the changes.

### Auditing source code
This library intentionally doesn't include a lot of source files to make your audit simple.

### Protect your secrets in GCP using IAM and service accounts
Don't expose all of your secrets to the apps. Use IAM and different service accounts to give access only on
as-needed basis.

## Contacts
E-mail: me@abdolence.dev
