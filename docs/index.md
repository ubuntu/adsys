# ADSys Documentation

ADSys is the Active Directory Group Policy client for Ubuntu.

ADSys enables management of Ubuntu Desktop and Server clients using Microsoft Active Directory. It integrates with services like SSSD or Winbind, which handle user access and authentication, providing extended functionality for managing and controlling Ubuntu clients.

With ADSys, policies can be applied to Ubuntu clients at boot and login, privileges can be granted and revoked, and remote script execution can be automated. Administrative templates (ADMX and ADML) are provided for all supported versions of Ubuntu.

System administrators can use ADSys to apply their skills and tools for managing Windows machines using Microsoft Active Directory to the management of Ubuntu machines.

```{toctree}
:hidden:
tutorial/index
how-to/index
reference/index
explanation/index
```

## In this documentation


````{grid} 1 1 2 2

```{grid-item-card}
### [Tutorials](tutorial/index)

**Learn** to use an ADSys feature:

* [Certificate auto-enrollment with ADSys](/tutorial/certificates-auto-enrollment)

```

```{grid-item-card}
### [How-to guides](how-to/index)

**Follow guides** for specific tasks, like:

* [Joining to AD on Ubuntu Desktop install](/how-to/join-ad-manually)
* [Setting up ADSys on Ubuntu Desktop](./how-to/set-up-adsys.md)
```

````

````{grid} 1 1 2 2

```{grid-item-card}
### [Explanation](explanation/index)

**Understand** topics including:

* [The architecture of ADSys](/explanation/adsys-ref-arch)
* [Client configuration using Dconf](./explanation/dconf)
```

```{grid-item-card}
### [Reference](reference/index)

**Find specific information**, such as:

* [Policies supported by ADSys](/reference/policies/index)
* [The ADSys daemon](/reference/adsysd-cli)

```

````

## Project and community

ADSys is a member of the Ubuntu family. It’s an open source project that warmly welcomes community contributions, suggestions, fixes and constructive feedback.

* [Code of conduct](https://ubuntu.com/community/code-of-conduct)
* [Join us in the Ubuntu Community](https://discourse.ubuntu.com/c/desktop/8)
* [Contribute](https://github.com/ubuntu/adsys/blob/main/CONTRIBUTING.md) or [Report an issue](https://github.com/ubuntu/adsys/issues/new)
* [Thinking about using ADSys for your next project? Get in touch!](https://ubuntu.com/contact-us/form?product=generic-contact-us)
* [Licensed under GPL v3](https://github.com/ubuntu/adsys/blob/main/LICENSE)
