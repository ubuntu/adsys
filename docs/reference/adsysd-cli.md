# adsysd command line

## User commands

### adsysd

AD integration daemon

#### Synopsis

Active Directory integration bridging toolset daemon.

```
adsysd COMMAND [flags]
```

#### Options

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
  -h, --help                    help for adsysd
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd completion

Generate the autocompletion script for the specified shell

#### Synopsis

Generate the autocompletion script for adsysd for the specified shell.
See each sub-command's help for details on how to use the generated script.


#### Options

```
  -h, --help   help for completion
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd completion bash

Generate the autocompletion script for bash

#### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(adsysd completion bash)

To load completions for every new session, execute once:

##### Linux:

	adsysd completion bash > /etc/bash_completion.d/adsysd

##### macOS:

	adsysd completion bash > $(brew --prefix)/etc/bash_completion.d/adsysd

You will need to start a new shell for this setup to take effect.


```
adsysd completion bash
```

#### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd completion fish

Generate the autocompletion script for fish

#### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	adsysd completion fish | source

To load completions for every new session, execute once:

	adsysd completion fish > ~/.config/fish/completions/adsysd.fish

You will need to start a new shell for this setup to take effect.


```
adsysd completion fish [flags]
```

#### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd completion powershell

Generate the autocompletion script for powershell

#### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	adsysd completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
adsysd completion powershell [flags]
```

#### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd completion zsh

Generate the autocompletion script for zsh

#### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(adsysd completion zsh)

To load completions for every new session, execute once:

##### Linux:

	adsysd completion zsh > "${fpath[1]}/_adsysd"

##### macOS:

	adsysd completion zsh > $(brew --prefix)/share/zsh/site-functions/_adsysd

You will need to start a new shell for this setup to take effect.


```
adsysd completion zsh [flags]
```

#### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd version

Returns version of service and exits

```
adsysd version [flags]
```

#### Options

```
  -h, --help   help for version
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

## Hidden commands

Those commands are hidden from help and should primarily be used by the system or for debugging.

### adsysd mount

Mount the locations listed in the specified file for the current user

```
adsysd mount MOUNTS_FILE [flags]
```

#### Options

```
  -h, --help   help for mount
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adsysd runscripts

Runs scripts in the given subdirectory

```
adsysd runscripts ORDER_FILE [flags]
```

#### Options

```
      --allow-order-missing   allow ORDER_FILE to be missing once the scripts are ready.
  -h, --help                  help for runscripts
```

#### Options inherited from parent commands

```
      --ad-backend string       Active Directory authentication backend (default "sssd")
      --cache-dir string        directory where ADSys caches GPOs downloads and policies. (default "/var/cache/adsys")
  -c, --config string           use a specific configuration file
      --run-dir string          directory where ADSys stores transient information erased on reboot. (default "/run/adsys")
  -s, --socket string           socket path to use between daemon and client. Can be overridden by systemd socket activation. (default "/run/adsysd.sock")
      --sssd.cache-dir string   SSSd cache directory (default "/var/lib/sss/db")
      --sssd.config string      SSSd config file path (default "/etc/sssd/sssd.conf")
  -t, --timeout int             time in seconds without activity before the service exists. 0 for no timeout. (default 120)
  -v, --verbose count           issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

