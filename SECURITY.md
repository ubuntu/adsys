# Security Policy

## Supported Versions

`ADSys` is released as a Debian package on the Ubuntu archive. We currently
provide security updates for `ADSys` installed on the following Ubuntu LTS
releases:

* Ubuntu 24.04
* Ubuntu 22.04
* Ubuntu 20.04

Please ensure that you are using a supported version to receive updates and
patches.

If you are unsure of your version, please run the following command in a
terminal:

```
adsysctl version
```

## Reporting a Vulnerability

If you discover a security vulnerability within this repository, we encourage
responsible disclosure. Please report any security issues to help us keep
`ADSys` secure for everyone.

### Private Vulnerability Reporting

The most straightforward way to report a security vulnerability is via
[GitHub](https://github.com/ubuntu/adsys/security/advisories/new). For detailed
instructions, please review the
[Privately reporting a security vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
documentation. This method enables you to communicate vulnerabilities directly
and confidentially with the `ADSys` maintainers.

The project's admins will be notified of the issue and will work with you to
determine whether the issue qualifies as a security issue and, if so, in which
component. We will then handle finding a fix, getting a CVE assigned and
coordinating the release of the fix to the various Linux distributions.

The [Ubuntu Security disclosure and embargo policy](https://ubuntu.com/security/disclosure-policy)
contains more information about what you can expect when you contact us, and what we expect from you.

Note, that you can also use
[this Launchpad bug tracker](https://bugs.launchpad.net/ubuntu/+source/adsys/+filebug)
to privately report a security vulnerability.

#### Steps to Report a Vulnerability on GitHub

1. Go to the [Security Advisories Page](https://github.com/ubuntu/adsys/security/advisories) of the `ADSys` repository.
2. Click "Report a Vulnerability."
3. Provide detailed information about the vulnerability, including steps to reproduce, affected versions, and potential impact.

## Security Resources

- [Canonical's Security Site](https://ubuntu.com/security)
- [Ubuntu Security disclosure and embargo policy](https://ubuntu.com/security/disclosure-policy)
- [Ubuntu Security Notices](https://ubuntu.com/security/notices)
- [ADSys Documentation](https://documentation.ubuntu.com/adsys/en/stable/)

If you have any questions regarding security vulnerabilities, please reach out
to the maintainers via the aforementioned channels.
