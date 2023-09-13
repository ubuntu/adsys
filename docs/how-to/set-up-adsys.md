# How to set-up ADSys

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
