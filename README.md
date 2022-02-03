# adsys
Active Directory bridging toolset

[![Code quality](https://github.com/ubuntu/adsys/workflows/QA/badge.svg)](https://github.com/ubuntu/adsys/actions?query=workflow%3AQA)
[![Code coverage](https://codecov.io/gh/ubuntu/adsys/branch/master/graph/badge.svg)](https://codecov.io/gh/ubuntu/adsys)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubuntu/adsys.svg)](https://pkg.go.dev/github.com/ubuntu/adsys)
[![Go Report Card](https://goreportcard.com/badge/ubuntu/adsys)](https://goreportcard.com/report/ubuntu/adsys)
[![License](https://img.shields.io/badge/License-GPL3.0-blue.svg)](https://github.com/ubuntu/adsys/blob/master/LICENSE)

## Usage

### User commands

#### adsysctl

AD integration client

##### Synopsis

Active Directory integration bridging toolset command line tool.

```
adsysctl COMMAND [flags]
```

##### Options

```
  -c, --config string   use a specific configuration file
  -h, --help            help for adsysctl
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl applied

Print last applied GPOs for current or given user/machine

##### Synopsis

Alias of "policy applied"

```
adsysctl applied [USER_NAME] [flags]
```

##### Options

```
  -a, --all        show overridden rules in each GPOs.
      --details    show applied rules in addition to GPOs.
  -h, --help       help for applied
      --no-color   don't display colorized version.
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl completion

Generate the autocompletion script for the specified shell

##### Synopsis

Generate the autocompletion script for adsysctl for the specified shell.
See each sub-command's help for details on how to use the generated script.


##### Options

```
  -h, --help   help for completion
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl completion bash

Generate the autocompletion script for bash

##### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(adsysctl completion bash)

To load completions for every new session, execute once:

###### Linux:

	adsysctl completion bash > /etc/bash_completion.d/adsysctl

###### macOS:

	adsysctl completion bash > /usr/local/etc/bash_completion.d/adsysctl

You will need to start a new shell for this setup to take effect.


```
adsysctl completion bash
```

##### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl completion fish

Generate the autocompletion script for fish

##### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	adsysctl completion fish | source

To load completions for every new session, execute once:

	adsysctl completion fish > ~/.config/fish/completions/adsysctl.fish

You will need to start a new shell for this setup to take effect.


```
adsysctl completion fish [flags]
```

##### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl completion powershell

Generate the autocompletion script for powershell

##### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	adsysctl completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
adsysctl completion powershell [flags]
```

##### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl completion zsh

Generate the autocompletion script for zsh

##### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions for every new session, execute once:

###### Linux:

	adsysctl completion zsh > "${fpath[1]}/_adsysctl"

###### macOS:

	adsysctl completion zsh > /usr/local/share/zsh/site-functions/_adsysctl

You will need to start a new shell for this setup to take effect.


```
adsysctl completion zsh [flags]
```

##### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl doc

Documentation

```
adsysctl doc [CHAPTER] [flags]
```

##### Options

```
  -d, --dest string     Write documentation file(s) to this directory.
  -f, --format string   Format type (markdown, raw or html). (default "markdown")
  -h, --help            help for doc
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl policy

Policy management

```
adsysctl policy COMMAND [flags]
```

##### Options

```
  -h, --help   help for policy
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl policy admx

Dump windows policy definitions

```
adsysctl policy admx lts-only|all [flags]
```

##### Options

```
      --distro string   distro for which to retrieve policy definition. (default "Ubuntu")
  -h, --help            help for admx
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl policy applied

Print last applied GPOs for current or given user/machine

```
adsysctl policy applied [USER_NAME] [flags]
```

##### Options

```
  -a, --all        show overridden rules in each GPOs.
      --details    show applied rules in addition to GPOs.
  -h, --help       help for applied
      --no-color   don't display colorized version.
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl policy update

Updates/Create a policy for current user or given user with its kerberos ticket

```
adsysctl policy update [USER_NAME KERBEROS_TICKET_PATH] [flags]
```

##### Options

```
  -a, --all       all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option.
  -h, --help      help for update
  -m, --machine   machine updates the policy of the computer.
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl service

Service management

```
adsysctl service COMMAND [flags]
```

##### Options

```
  -h, --help   help for service
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl service cat

Print service logs

```
adsysctl service cat [flags]
```

##### Options

```
  -h, --help   help for cat
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl service status

Print service status

```
adsysctl service status [flags]
```

##### Options

```
  -h, --help   help for status
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl service stop

Requests to stop the service once all connections are done

```
adsysctl service stop [flags]
```

##### Options

```
  -f, --force   force will shut it down immediately and drop existing connections.
  -h, --help    help for stop
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl update

Updates/Create a policy for current user or given user with its kerberos ticket

##### Synopsis

Alias of "policy update"

```
adsysctl update [USER_NAME KERBEROS_TICKET_PATH] [flags]
```

##### Options

```
  -a, --all       all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option.
  -h, --help      help for update
  -m, --machine   machine updates the policy of the computer.
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl version

Returns version of client and service

```
adsysctl version [flags]
```

##### Options

```
  -h, --help   help for version
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd

AD integration daemon

##### Synopsis

Active Directory integration bridging toolset daemon.

```
adsysd COMMAND [flags]
```

##### Options

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
  -h, --help                              help for adsysd
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd completion

Generate the autocompletion script for the specified shell

##### Synopsis

Generate the autocompletion script for adsysd for the specified shell.
See each sub-command's help for details on how to use the generated script.


##### Options

```
  -h, --help   help for completion
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd completion bash

Generate the autocompletion script for bash

##### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(adsysd completion bash)

To load completions for every new session, execute once:

###### Linux:

	adsysd completion bash > /etc/bash_completion.d/adsysd

###### macOS:

	adsysd completion bash > /usr/local/etc/bash_completion.d/adsysd

You will need to start a new shell for this setup to take effect.


```
adsysd completion bash
```

##### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd completion fish

Generate the autocompletion script for fish

##### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	adsysd completion fish | source

To load completions for every new session, execute once:

	adsysd completion fish > ~/.config/fish/completions/adsysd.fish

You will need to start a new shell for this setup to take effect.


```
adsysd completion fish [flags]
```

##### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd completion powershell

Generate the autocompletion script for powershell

##### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	adsysd completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
adsysd completion powershell [flags]
```

##### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd completion zsh

Generate the autocompletion script for zsh

##### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions for every new session, execute once:

###### Linux:

	adsysd completion zsh > "${fpath[1]}/_adsysd"

###### macOS:

	adsysd completion zsh > /usr/local/share/zsh/site-functions/_adsysd

You will need to start a new shell for this setup to take effect.


```
adsysd completion zsh [flags]
```

##### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd version

Returns version of service and exits

```
adsysd version [flags]
```

##### Options

```
  -h, --help   help for version
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### Hidden commands

Those commands are hidden from help and should primarily be used by the system or for debugging.

#### adsysctl policy debug

Debug various policy infos

```
adsysctl policy debug [flags]
```

##### Options

```
  -h, --help   help for debug
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysctl policy debug gpolist-script

Write GPO list python embeeded script in current directory

```
adsysctl policy debug gpolist-script [flags]
```

##### Options

```
  -h, --help   help for gpolist-script
```

##### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

#### adsysd runscripts

Runs scripts in the given subdirectory

```
adsysd runscripts ORDER_FILE [flags]
```

##### Options

```
      --allow-order-missing   allow ORDER_FILE to be missing once the scripts are ready.
  -h, --help                  help for runscripts
```

##### Options inherited from parent commands

```
      --ad-default-domain-suffix string   AD default domain suffix to use. This overrides parsing sssd.conf.
  -D, --ad-domain string                  AD domain to use. This overrides parsing sssd.conf
  -S, --ad-server string                  URL of the Active Directory server. This overrides parsing sssd.conf.
      --cache-dir string                  directory where ADsys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string                     use a specific configuration file
      --run-dir string                    directory where ADsys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string                     socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int                       time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count                     issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

