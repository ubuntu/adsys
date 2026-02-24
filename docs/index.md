---
myst:
  html_meta:
    description: "Official documentation for ADSys - the Active Directory Group Policy client for managing Ubuntu Desktop and Server with Microsoft Active Directory."
---

# ADSys Documentation

ADSys is the Active Directory Group Policy client for Ubuntu.

ADSys enables management of Ubuntu Desktop and Server clients using Microsoft Active Directory. It integrates with services like SSSD or Winbind, which handle user access and authentication, providing extended functionality for managing and controlling Ubuntu clients.

With ADSys, policies can be applied to Ubuntu clients at boot and login, privileges can be granted and revoked, and remote script execution can be automated. ADSys also comes with administrative templates (ADMX and ADML) for all supported versions of Ubuntu.

System administrators can use ADSys to apply familiar skills and tools for managing Windows machines to the management of Ubuntu machines.

```{toctree}
:hidden:
Tutorial <tutorial/getting-started>
how-to/index
reference/index
explanation/index
```

## In this documentation

* **Tutorial**: [Getting started with ADSys](/tutorial/getting-started)
* **Installation and setup**: [Setting up Active Directory](/how-to/set-up-ad) • [Joining AD during Ubuntu Desktop install](/how-to/join-ad-installation) • [Joining AD manually](/how-to/join-ad-manually) • [Setting up ADSys on Ubuntu Desktop](/how-to/set-up-adsys) • [Setting up adwatchd](/how-to/set-up-adwatchd)
* **Client configuration and management**: [Client configuration using Dconf](/explanation/dconf) • [Configuring network shares](/explanation/network-shares) • [Configuring a network proxy](/explanation/proxy) • [Configuring scripts execution](/explanation/scripts) • [Configuring privileges management](/explanation/privileges) • [Configuring AppArmor profiles](/explanation/apparmor)
* **Group policies**: [Using GPOs with ADSys](/how-to/use-gpo) • [Group policies supported by ADSys](/reference/policies/index) • [Security policies managed by SSSD](/explanation/security-policy) • [ADSys architecture](/explanation/adsys-ref-arch) 
* **Certificates**: [Setting up auto-enrollment](/how-to/certificates/setup) • [Configuring auto-enrollment](/how-to/certificates/configure) • [Using a VPN with certificate auto-enrollment](/how-to/certificates/vpn) • [Troubleshooting certificate auto-enrollment](/how-to/certificates/troubleshoot) • [Explanation of certificate auto-enrollment](/explanation/certificates)
* **Command-line tools**: [adsysctl CLI](/reference/adsysctl-cli) • [adsysd CLI](/reference/adsysd-cli) • [adwatchd CLI](/reference/adwatchd-cli)
* **ADSys security**: [Security overview](/explanation/security-overview)
* **ADSys reference**: [Standard and Pro features](/reference/features) • [Release notes](/reference/release-notes) • [Glossary](/reference/glossary)
* **External resources**: [All](ref::external) • [Active Directory](ref::ad-links) • [certmonger](ref::certmonger-links) • [cepces](ref::cepces-links) • [Kerberos](ref::kerberos-links) • [LDAP](ref::ldap-links) • [Samba](ref::samba-links) • [SSSD](ref::sssd-links) 

## How the documentation is organised

This documentation uses the [Diátaxis structure](https://diataxis.fr/).

* [Tutorial](/tutorial/getting-started) takes you through a practical, end-to-end learning experiences.
* [How-to guides](/how-to/index) provide you with the steps necessary for completing specific tasks.
* [References](/reference/index) give you concise and factual information to support your understanding.
* [Explanations](/explanation/index) include topic overviews and additional context on the software.

## Project and community

ADSys is a member of the Ubuntu family. It’s an open source project that warmly welcomes community contributions, suggestions, fixes and constructive feedback.

* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Join us in the Ubuntu Community](https://discourse.ubuntu.com/c/desktop/8)
* [Contribute](https://github.com/ubuntu/adsys/blob/main/CONTRIBUTING.md) or [Report an issue](https://github.com/ubuntu/adsys/issues/new)
* [Thinking about using ADSys for your next project? Get in touch!](https://ubuntu.com/contact-us/form?product=generic-contact-us)
* [Licensed under GPL v3](https://github.com/ubuntu/adsys/blob/main/LICENSE)
