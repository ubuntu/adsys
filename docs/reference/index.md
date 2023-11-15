# Technical Reference

This section consolidates technical details on ADSys, including specifications, APIs, and architecture.

On the Linux side, ADSys is composed of a daemon and a command line interface:

* The daemon - `adsysd` - implements the Group Policy protocol. It relies on Kerberos, Samba and LDAP for authentication and policy retrieval.
* The command line interface - `adsysctl` - controls the daemon and reports its status.

A Windows daemon, `adwatchd` can be installed on the domain controller to automatically refresh assets without system administrator interventions.

````{grid} 1 1 2 2
```{grid-item}
## Reference

```{toctree}
:titlesonly:
ADSys Control (adsysctl)<adsysctl>
ADSys Daemon (adsysd)<adsys-daemon>
ADSys Watch Daemon (adwatchd)<adwatchd>
```

```{grid-item}
## Command line

```{toctree}
:titlesonly:
adsysctl<adsysctl-cli>
adsysd<adsysd-cli>
adwatchd<adwatchd-cli>
```

```{grid-item}
## Supported policies

```{toctree}
:titlesonly:
:maxdepth: 2

policies/index
```

````

## Supported releases

**ADSys** is supported on Ubuntu starting from **20.04.2 LTS**, and tested with Windows Server 2019.

Only Active Directory on-premise is supported.

## Recommended readings

* `adsysd help` or `man adsysd`.
* `adsysctl help` or `man adsysctl`.
