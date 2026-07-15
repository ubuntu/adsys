# adsysctl command line

## User commands

### adsysctl

AD integration client

#### Synopsis

Active Directory integration bridging toolset command line tool.

```
adsysctl COMMAND [flags]
```

#### Options

```
  -c, --config string   use a specific configuration file
  -h, --help            help for adsysctl
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl applied

Print last applied GPOs for current or given user/machine

#### Synopsis

Alias of "policy applied"

```
adsysctl applied [USER_NAME] [flags]
```

#### Options

```
  -a, --all        show overridden rules in each GPOs.
      --details    show applied rules in addition to GPOs.
  -h, --help       help for applied
  -m, --machine    show applied rules to the machine.
      --no-color   don't display colorized version.
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate

Certificate management

```
adsysctl certificate COMMAND [flags]
```

#### Options

```
  -h, --help   help for certificate
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate cas

List certificate authorities and templates discovered in AD

```
adsysctl certificate cas [flags]
```

#### Options

```
      --format string   output format: text or json. (default "text")
  -h, --help            help for cas
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate list

List certificates enrolled by adsys

```
adsysctl certificate list [flags]
```

#### Options

```
      --format string   output format: text or json. (default "text")
  -h, --help            help for list
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate remove

Remove enrolled certificate(s) and clean up adsys state

```
adsysctl certificate remove [NICKNAME] [flags]
```

#### Options

```
  -a, --all     remove all enrolled certificates.
  -f, --force   confirm removal of certificate material and adsys state.
  -h, --help    help for remove
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate renew

Force re-enrollment of enrolled certificate(s) now

```
adsysctl certificate renew [NICKNAME] [flags]
```

#### Options

```
  -a, --all    renew all enrolled certificates.
  -h, --help   help for renew
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate status

Show the health of an enrolled certificate

#### Synopsis

Show the health of an enrolled certificate.
The process exit code reflects the certificate health: 0 healthy, 2 missing,
3 expired, 4 due for renewal, 5 key mismatch or unparseable, 1 on error.

```
adsysctl certificate status [NICKNAME] [flags]
```

#### Options

```
      --format string   output format: text or json. (default "text")
  -h, --help            help for status
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate templates

List certificate templates a CA server offers

```
adsysctl certificate templates SERVER [flags]
```

#### Options

```
  -h, --help   help for templates
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl certificate verify

Verify chain, validity and key match of enrolled certificate(s)

```
adsysctl certificate verify [NICKNAME] [flags]
```

#### Options

```
  -h, --help     help for verify
      --online   also perform an online revocation (CRL) check.
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl completion

Generate the autocompletion script for the specified shell

#### Synopsis

Generate the autocompletion script for adsysctl for the specified shell.
See each sub-command's help for details on how to use the generated script.


#### Options

```
  -h, --help   help for completion
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl completion bash

Generate the autocompletion script for bash

#### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(adsysctl completion bash)

To load completions for every new session, execute once:

##### Linux:

	adsysctl completion bash > /etc/bash_completion.d/adsysctl

##### macOS:

	adsysctl completion bash > $(brew --prefix)/etc/bash_completion.d/adsysctl

You will need to start a new shell for this setup to take effect.


```
adsysctl completion bash
```

#### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl completion fish

Generate the autocompletion script for fish

#### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	adsysctl completion fish | source

To load completions for every new session, execute once:

	adsysctl completion fish > ~/.config/fish/completions/adsysctl.fish

You will need to start a new shell for this setup to take effect.


```
adsysctl completion fish [flags]
```

#### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl completion powershell

Generate the autocompletion script for powershell

#### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	adsysctl completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
adsysctl completion powershell [flags]
```

#### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl completion zsh

Generate the autocompletion script for zsh

#### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(adsysctl completion zsh)

To load completions for every new session, execute once:

##### Linux:

	adsysctl completion zsh > "${fpath[1]}/_adsysctl"

##### macOS:

	adsysctl completion zsh > $(brew --prefix)/share/zsh/site-functions/_adsysctl

You will need to start a new shell for this setup to take effect.


```
adsysctl completion zsh [flags]
```

#### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl doc

Documentation

```
adsysctl doc [CHAPTER] [flags]
```

#### Options

```
  -h, --help   help for doc
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy

Policy management

```
adsysctl policy COMMAND [flags]
```

#### Options

```
  -h, --help   help for policy
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy admx

Dump windows policy definitions

```
adsysctl policy admx lts-only|all [flags]
```

#### Options

```
      --distro string   distro for which to retrieve policy definition. (default "Ubuntu")
  -h, --help            help for admx
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy applied

Print last applied GPOs for current or given user/machine

```
adsysctl policy applied [USER_NAME] [flags]
```

#### Options

```
  -a, --all        show overridden rules in each GPOs.
      --details    show applied rules in addition to GPOs.
  -h, --help       help for applied
  -m, --machine    show applied rules to the machine.
      --no-color   don't display colorized version.
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy purge

Purges policies for the current user or a specified one

```
adsysctl policy purge [USER_NAME] [flags]
```

#### Options

```
  -a, --all       all purges the policy of the computer and all the logged in users. -m or USER_NAME cannot be used with this option.
  -h, --help      help for purge
  -m, --machine   machine purges the policy of the computer.
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy update

Updates/Create a policy for current user or given user with its kerberos ticket

```
adsysctl policy update [USER_NAME KERBEROS_TICKET_PATH] [flags]
```

#### Options

```
  -a, --all       all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option.
  -h, --help      help for update
  -m, --machine   machine updates the policy of the computer.
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl service

Service management

```
adsysctl service COMMAND [flags]
```

#### Options

```
  -h, --help   help for service
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl service cat

Print service logs

```
adsysctl service cat [flags]
```

#### Options

```
  -h, --help   help for cat
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl service status

Print service status

```
adsysctl service status [flags]
```

#### Options

```
  -h, --help   help for status
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl service stop

Requests to stop the service once all connections are done

```
adsysctl service stop [flags]
```

#### Options

```
  -f, --force   force will shut it down immediately and drop existing connections.
  -h, --help    help for stop
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl update

Updates/Create a policy for current user or given user with its kerberos ticket

#### Synopsis

Alias of "policy update"

```
adsysctl update [USER_NAME KERBEROS_TICKET_PATH] [flags]
```

#### Options

```
  -a, --all       all updates the policy of the computer and all the logged in users. -m or USER_NAME/TICKET cannot be used with this option.
  -h, --help      help for update
  -m, --machine   machine updates the policy of the computer.
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl version

Returns version of client and service

```
adsysctl version [flags]
```

#### Options

```
  -h, --help   help for version
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

## Hidden commands

Those commands are hidden from help and should primarily be used by the system or for debugging.

### adsysctl policy debug

Debug various policy infos

```
adsysctl policy debug [flags]
```

#### Options

```
  -h, --help   help for debug
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy debug cert-autoenroll-script

Write certificate autoenrollment python embedded script in current directory

```
adsysctl policy debug cert-autoenroll-script [flags]
```

#### Options

```
  -h, --help   help for cert-autoenroll-script
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy debug gpolist-script

Write GPO list python embedded script in current directory

```
adsysctl policy debug gpolist-script [flags]
```

#### Options

```
  -h, --help   help for gpolist-script
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysctl policy debug ticket-path

Print the path of the current (or given) user's Kerberos ticket

#### Synopsis

Infer and print the path of the current user's Kerberos ticket, leveraging the krb5 API.
The command is a no-op if the ticket is not present on disk or the detect_cached_ticket setting is not true.

```
adsysctl policy debug ticket-path [flags]
```

#### Options

```
  -h, --help   help for ticket-path
```

#### Options inherited from parent commands

```
  -c, --config string   use a specific configuration file
  -s, --socket string   socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
  -t, --timeout int     time in seconds before cancelling the client request when the server gives no result. 0 for no timeout. (default 30)
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

