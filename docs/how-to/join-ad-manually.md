# How to manually join Ubuntu clients to an Active Directory domain

ADSys supports manual joining of Ubuntu clients to Active Directory (AD) using different backends.

## Supported backends

ADSys supports two Active Directory backends:

1. [SSSD](https://sssd.io/), or System Security Services Daemon, provides access to centralized identity management systems like Microsoft Active Directory, OpenLDAP, and various other directory servers. This client component retrieves and caches data from remote directory servers, delivering identity, authentication, and authorization services to the host machine.
2. [Winbind](https://wiki.samba.org/index.php/Configuring_Winbindd_on_a_Samba_AD_DC) is a component of the Samba suite that provides integration and authentication services between UNIX or Linux systems and Windows-based networks, allowing the former to appear as members in a Windows Active Directory domain.

Configuring connections with these backends is briefly described below with links to external documentation.

## Join manually using SSSD

Authentication of Ubuntu against the Active Directory server requires configuration of SSSD and Kerberos.
SSSD then retrieves the credentials and the initial security policy of the `Default Domain Policy`.

All these operations are described in detail in the [Introduction to network user authentication with SSSD](https://documentation.ubuntu.com/server/explanation/intro-to/sssd/) and the White Paper [How to integrate Ubuntu Desktop with Active Directory](https://ubuntu.com/engage/microsoft-active-directory).

## Join manually using Winbind

In addition to SSSD, ADSys supports Winbind as a backend. 

The easiest way to join a domain using Winbind is to use the `realmd` utility, as described in the [Samba - Member server in an Active Directory domain](https://documentation.ubuntu.com/server/how-to/samba/member-server-in-an-ad-domain/) guide.

ADSys uses SSSD as the default backend, so Winbind has to be enabled explicitly using the following configuration option in `adsys.yaml`:

```yaml
ad_backend: winbind
```

Winbind also requires additional dependencies to be installed.
They can be installed in Ubuntu by executing the following commands, prior to installing and running ADSys:

```sh
sudo apt update
sudo apt install winbind krb5-user
```
