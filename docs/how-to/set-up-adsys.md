# How to set up ADSys

## Requirements

ADSys is supported on Ubuntu starting from Ubuntu 20.04.2 LTS.

It is tested with Windows Server 2019.

Only Active Directory on-premise is supported.

## Installation

**ADSys** is not currently installed by default on Ubuntu desktop. This must be done manually by the local administrator of the machine.

To do so, log in on first boot, update the repositories and install **ADSys**. On Ubuntu-based systems this can be accomplished with the following commands:

```sh
sudo apt update
sudo apt install adsys
```

Reboot then to allow the machine to do its policy refresh.

## Logging in as a user of the domain

To log in as a user of the domain, press the link **"Not listed?"** in the greeter. Then enter the username followed by the password.

### SSSD

By default, there is no default domain configured in SSSD. You have to enter the full user name with one of the forms: `USER@DOMAIN.COM`, `USER@DOMAIN` or `DOMAIN/USER`.

On the first log in the user's home directory is created.

All of this (default domain, default path for home directories, default shell, etc.) is configurable in `/etc/sssd/sssd.conf`.

### Winbind

If Winbind is used as a backend, the account can be specified in one of the following forms: `USER@DOMAIN.COM`, `USER@DOMAIN` or `DOMAIN\\USER`.

For the home directory to be created automatically on login, the `pam_mkhomedir` module can be enabled:

```sh
sudo pam-auth-update --enable mkhomedir
```

Options such as the home directory path template, shell and others can be tweaked in `/etc/samba/smb.conf` and are documented in the [`smb.conf(5)`](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html) man page.

## Kerberos

ADSys relies on the configured AD backend (e.g. SSSD) to export the `KRB5CCNAME` environment variable pointing to a valid Kerberos ticket cache when a domain user performs authentication.

If for any reason the backend doesn't export the variable but _does_ initialize a ticket cache in the [default path](https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html#default-ccache-name), ADSys can be configured to infer the path to the ticket cache (via the libkrb5 API) and export it as the `KRB5CCNAME` variable during both authentication and runs of `adsysctl update` for the current domain user.

To opt into this functionality, the following must be added to `/etc/adsys.yaml`:
```yaml
detect_cached_ticket: true
```

With this setting active, ADSys attempts to determine and export the path to the ticket cache. To avoid unexpected behaviors like rejecting authentication for non-domain users, no action is taken if the path returned by the libkrb5 API does not exist on disk.
