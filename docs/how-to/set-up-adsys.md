# How to set up ADSys

ADSys is not currently installed by default on Ubuntu desktop.

This guide shows how it can be installed manually by the local administrator of the machine.

## Requirements

* ADSys is supported on Ubuntu starting from Ubuntu 20.04.2 LTS.
* It is tested with Windows Server 2019.
* Only Active Directory on-premise is supported.

## Installing ADSys

Log in to the Ubuntu machine on first boot.

Update the repositories and install the `adsys` package with the following commands:

```sh
sudo apt update
sudo apt install adsys
```

Reboot the machine to initiate a policy refresh.

## Logging in as a user of the domain

To log in as a user of the domain, click **Not listed?** in the greeter.

Then enter the username followed by the password.

### SSSD

There is no default domain configured in SSSD. 

You have to enter the full user name with one of the forms: `USER@DOMAIN.COM`, `USER@DOMAIN` or `DOMAIN/USER`.

On the first log in, the user's home directory is created.

These setting, including default domain, default path for home directories, and default shell, can be configured in `/etc/sssd/sssd.conf`.

### Winbind

If Winbind is used as a backend, the account can be specified in one of the following forms: `USER@DOMAIN.COM`, `USER@DOMAIN` or `DOMAIN\\USER`.

To create the user's home directory automatically on login, enable the `pam_mkhomedir` module:

```sh
sudo pam-auth-update --enable mkhomedir
```

Settings for Winbind can be configured in `/etc/samba/smb.conf`.
They are documented in the [`smb.conf(5)`](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) man page.

## Kerberos

ADSys relies on the configured AD backend (e.g. SSSD) to export the `KRB5CCNAME` environment variable, which points to a valid Kerberos ticket cache when a domain user performs authentication.

If the backend doesn't export the variable but _does_ initialize a ticket cache in the [default path](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html#default-ccache-name), ADSys can infer the path to the ticket cache and export it as the `KRB5CCNAME` variable during authentication and `adsysctl update` for the current domain user.

To enable this functionality, the following must be added to `/etc/adsys.yaml`:

```yaml
detect_cached_ticket: true
```

ADSys infers the path to the ticket cache using the libkrb5 API.
To avoid unexpected behaviors, like rejecting authentication for non-domain users, no action is taken if the path returned by the libkrb5 API does not exist on disk.
