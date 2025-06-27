# The adsys daemon

## Policy enforcement

On the client the policies are refreshed in three situations:

* At boot time for the policy of the machine.
* At login time for the policy of the user.
* Periodically by a timer for the machine and the user policy.

### Failed policy refresh and caching

When the client is offline, a user may still need to log in to the machine. 

For this purpose, ADSys uses a cache located in `/var/cache/adsys`.

```{admonition} Types of cache
:class: note

1. A cache for the GPO downloaded from the server in directory `gpo_cache`
2. A cache for the rules as applied by ADSys in directory `policies`
```

The enforcement of the policy will fail when the cache is empty or the client fails to retrieve the policy from the server.

If the enforcement of the policy fails:

* At boot time, ADSys stops the boot process.
* At login time, login is denied.
* During periodic refresh, the policy currently applied on the client remains.

### Policy refresh rate

Periodic refresh of the policies (machine and active users) is handled by the systemd timer unit `adsys-gpo-refresh.timer`.

Here is an example list of timers after running `systemctl list-timers`:


```{terminal}
   :input: systemctl list-timers
   :dir: 
NEXT                         LEFT          LAST                         PASSED             UNIT                           ACTIVATES
Tue 2021-05-18 10:05:49 CEST 11min left    Tue 2021-05-18 09:35:49 CEST 18min ago          adsys-gpo-refresh.timer        adsys-gpo-refresh.service
Tue 2021-05-18 10:31:34 CEST 36min left    Tue 2021-05-18 09:31:09 CEST 23min ago          anacron.timer                  anacron.service
[...]

```

The default refresh rate is **30 minutes**.

Refresh rates are defined with the configuration variables `OnBootSec` and `OnUnitActiveSec`:


```{code-block} ini
:caption: /etc/systemd/system/adsys-gpo-refresh.timer.d/refresh-rate.conf
# Refresh ADSys GPO every two hours
[Timer]
OnBootSec=
OnBootSec=120min
OnUnitActiveSec=
OnUnitActiveSec=120min
```

Any changes to refresh rates are effective after a reload of the daemon.

You can confirm this by running `systemctl list-timers` after a reboot or after
running `systemctl daemon-reload`:

```{terminal}
   :input: sudo systemctl list-timers
   :dir: 
NEXT                         LEFT          LAST                         PASSED             UNIT                           ACTIVATES
Tue 2021-05-18 10:35:45 CEST 16min left    Tue 2021-05-18 10:05:50 CEST 1h43min ago          adsys-gpo-refresh.timer        adsys-gpo-refresh.service
[...]
```

```{note}
The empty `OnBootSec=` and `OnUnitActiveSec=` statements are used to reset the system-wide timer unit time instead of adding new timers. `man systemd.timer` for more information.
```

Administrators can get more details about the timer status:

```{terminal}
   :input: sudo systemctl status adsys-gpo-refresh.timer
   :dir: 
● adsys-gpo-refresh.timer - Refresh ADSys GPO for machine and users
     Loaded: loaded (/lib/systemd/system/adsys-gpo-refresh.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Tue 2021-05-18 08:35:48 CEST; 1h 23min ago
    Trigger: Tue 2021-05-18 10:05:49 CEST; 6min left
   Triggers: ● adsys-gpo-refresh.service

may 18 08:35:48 adclient04 systemd[1]: Started Refresh ADSys GPO for machine and users.
```

<!-- 
TODO: adsysctl service status to get next scheduled refresh
-->

## Socket activation

The ADSys daemon is started on demand by systemd’s socket activation and only runs when it’s required.

It will gracefully shutdown after idling for a short period of time (default: 120 seconds).

## Configuration

`ADSys` doesn’t ship a configuration file by default. 

System-wide or user-specific configuration files can be created to modify the behavior of the daemon and the client:

* System-wide: defined in `/etc/adsys.yaml` and applies to both daemon and client.
* User-specific: defined in `$HOME/adsys.yaml` and applies only to the client for this user.

```{admonition} Other configuration options
:class: tip
The current directory is also searched for an `adsys.yaml` file.

A configuration file path can be passed to the the `adsysd` and `adsysctl` commands using the `--config|-c` flag
This may be especially useful for testing.
```

An example of configuration file is included in the [ADSys
repository](https://github.com/ubuntu/adsys/blob/main/conf.example/adsys.yaml)
and is shown below for reference.

```yaml
# Service and client configuration
verbose: 2
socket: /tmp/adsysd/socket

# Service only configuration
service_timeout: 3600
cache_dir: /tmp/adsysd/cache
run_dir: /tmp/adsysd/run

# Backend selection: sssd (default) or winbind
ad_backend: sssd

# SSSD configuration
sssd:
  config: /etc/sssd.conf
  cache_dir: /var/lib/sss/db

# Winbind configuration
# (if ad_backend is set to winbind)
winbind:
  ad_domain: domain.com
  ad_server: adc.domain.com

# Client only configuration
client_timeout: 60
```

### Configuration common between service and client

* **verbose**
Increase the verbosity of the daemon or client. By default, only warnings and error logs are printed. This value is set between 0 and 3. This has the same effect as the `-v` and `-vv` flags.

* **socket**
Path the Unix socket for communication between clients and daemon. This can be overridden by the `--socket` option. Defaults to `/run/adsysd.sock` (monitored by systemd for socket activation).

### Service only configuration

* **service_timeout**
Time in seconds without any active request before the service exits. This can be overridden by the `--timeout` option. Defaults to 120 seconds.

* **backend**
Backend to use to integrate with Active Directory. It is responsible for providing valid kerberos tickets. Available selection is `sssd` or `winbind`. Default is `sssd`. This can be overridden by the `--backend` option.

* **sss_cache_dir**
The directory that stores Kerberos tickets used by SSSD. By default `/var/lib/sss/db/`.

* **run_dir**
The run directory contains the links to the kerberos tickets for the machine and the active users. This can be overridden by the `--run-dir` option. Defaults to `/run/adsys/`.

#### Backend only options

##### SSSD

* **config**

Path `sssd.conf`. This is the source of selected sss domain (first entry in `domains:`), to find corresponding active directory domain section.

The option `ad_domain` in that section is used for the list of domains list of the host. `ad_server` (optional) is used as the Active directory LDAP server to contact. If it is missing, then the "Active Server" detected by sssd will be used.

Finally `default_domain_suffix` is used too, and falls back to the domain name if missing.

Default lookup path is `/etc/sssd/sssd.conf`. This can be overridden by the `--sssd.config` option.

* **cache_dir**

Path to the sss database to find the HOST kerberos ticket. Default path is `/var/lib/sss/db`. This can be overridden by the `--sssd.cache-dir` option.

##### Winbind

* **ad_domain**

A custom domain can be used to override the C API call that ADSys executes to determine the active domain -- which is returned by the `wbinfo --own-domain` (e.g. `example.com`)

* **ad_server**

A custom domain controller can be used to override the C API call that ADSys executes to determine the AD controller FQDN -- which is returned by `wbinfo --dsgetdcname domain.com` (e.g. `adc.example.com`).

### GPO configuration

* **gpo_list_timeout**

Maximum time in seconds for the GPO list to finish otherwise the GPO list is aborted. This can be overridden by the `--gpo-list-timeout` option. Defaults to 10 seconds. 

### Client only configuration

* **client_timeout**
Maximum time in seconds between two server activities before the client returns and aborts the request. This can be overridden by the `--timeout` option. Defaults to 30 seconds.

## Debugging with logs (cat command)

It is possible to follow the exchanges between all clients and the daemon with the `cat` command. It forwards all logs and message printing from the daemon alone.

Only privileged users have access to this information. As with any other command, the verbosity can be increased with `-v` flags (it’s independent of the daemon or client current verbosity). More flags increases the verbosity further up to 3.

More information is available in the [adsysctl reference](adsysctl.md).

## Authorizations

ADSys uses a privilege mechanism based on polkit to manage authorizations. Many commands require elevated privileges to be executed. If the adsys client is executed with insufficient privileges to execute a command, the user will be prompted to enter its password. If allowed then the command will be executed and denied otherwise.

![Polkit authentication dialog](../images/reference/adsys-daemon/daemon-polkit.png)

This is configurable by the administrator as any service controlled by polkit. For more information `man polkit`.

## Additional notes

There are additional configuration options matching the adsysd command line options. Those are used to define things like dconf, apparmor, polkit, sudo directories. Even though they exist mostly for integration tests purposes, they can be tweaked the same way as other configuration options for the service.

## Further information

Use the shell completion and the `help` subcommands to get more information.
