# How to join an Active Directory domain manually

ADSys supports two Active Directory backends:

1. [SSSD](https://sssd.io/), or System Security Services Daemon, provides access to centralized identity management systems like Microsoft Active Directory, OpenLDAP, and various other directory servers. This client component retrieves and caches data from remote directory servers, delivering identity, authentication, and authorization services to the host machine.
2. [Winbind](https://wiki.samba.org/index.php/Configuring_Winbindd_on_a_Samba_AD_DC) is a component of the Samba suite that provides seamless integration and authentication services between UNIX or Linux systems and Windows-based networks, allowing the former to appear as members in a Windows Active Directory domain.

## Join manually using SSSD

The aim of this documentation is to describe how to operate ADSys. So we won’t do an in depth description of the operations to manually configure a connection to Active Directory from an Ubuntu Client.

Authentication of Ubuntu against the Active Directory server requires to configure SSSD and Kerberos. SSSD will then retrieve the credentials and the initial security policy of the `Default Domain Policy`.

All these operations are described in detail in the [Introduction to network user authentication with SSSD](https://documentation.ubuntu.com/server/explanation/intro-to/sssd/) and the White Paper [How to integrate Ubuntu Desktop with Active Directory](https://ubuntu.com/engage/microsoft-active-directory).

## Join manually using Winbind

In addition to SSSD, ADSys supports Winbind as a backend. The easiest way to join a domain using Winbind is to use the `realmd` utility, as described in the [Samba - Member server in an Active Directory domain](https://documentation.ubuntu.com/server/how-to/samba/member-server-in-an-ad-domain/) guide.

ADSys uses SSSD as a default backend, so Winbind has to be opted into explicitly via the following configuration option in `adsys.yaml`:

```yaml
ad_backend: winbind
```

In addition, Winbind requires additional dependencies to be installed. On Ubuntu-based systems they can be installed by executing the following command, prior to ADSys:

```sh
sudo apt update
sudo apt install winbind krb5-user
```
