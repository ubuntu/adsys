# adwatchd command line

## User commands

### adwatchd

AD watch daemon

#### Synopsis

Watch directories for changes and bump the relevant GPT.ini versions.

```
adwatchd [COMMAND] [flags]
```

#### Options

```
  -c, --config string   use a specific configuration file
  -h, --help            help for adwatchd
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd completion

Generate the autocompletion script for the specified shell

#### Synopsis

Generate the autocompletion script for adwatchd for the specified shell.
See each sub-command's help for details on how to use the generated script.


#### Options

```
  -h, --help   help for completion
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd completion bash

Generate the autocompletion script for bash

#### Synopsis

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(adwatchd completion bash)

To load completions for every new session, execute once:

##### Linux:

	adwatchd completion bash > /etc/bash_completion.d/adwatchd

##### macOS:

	adwatchd completion bash > $(brew --prefix)/etc/bash_completion.d/adwatchd

You will need to start a new shell for this setup to take effect.


```
adwatchd completion bash
```

#### Options

```
  -h, --help              help for bash
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd completion fish

Generate the autocompletion script for fish

#### Synopsis

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	adwatchd completion fish | source

To load completions for every new session, execute once:

	adwatchd completion fish > ~/.config/fish/completions/adwatchd.fish

You will need to start a new shell for this setup to take effect.


```
adwatchd completion fish [flags]
```

#### Options

```
  -h, --help              help for fish
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd completion powershell

Generate the autocompletion script for powershell

#### Synopsis

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	adwatchd completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.


```
adwatchd completion powershell [flags]
```

#### Options

```
  -h, --help              help for powershell
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd completion zsh

Generate the autocompletion script for zsh

#### Synopsis

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(adwatchd completion zsh)

To load completions for every new session, execute once:

##### Linux:

	adwatchd completion zsh > "${fpath[1]}/_adwatchd"

##### macOS:

	adwatchd completion zsh > $(brew --prefix)/share/zsh/site-functions/_adwatchd

You will need to start a new shell for this setup to take effect.


```
adwatchd completion zsh [flags]
```

#### Options

```
  -h, --help              help for zsh
      --no-descriptions   disable completion descriptions
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd run

Starts the directory watch loop

#### Synopsis

Can run as a service through the service manager or interactively as a standalone application.

The program will monitor the configured directories for changes and bump the appropriate GPT.ini versions anytime a change is detected.
If a GPT.ini file does not exist for a directory, a warning will be issued and the file will be created. If the GPT.ini file is incompatible or malformed, the program will report an error.


```
adwatchd run [flags]
```

#### Options

```
  -c, --config string    use a specific configuration file
  -d, --dirs directory   a directory to check for changes (can be specified multiple times)
  -f, --force            force the program to run even if another instance is already running
  -h, --help             help for run
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service

Manages the adwatchd service

#### Synopsis

The service command allows the user to interact with the adwatchd service. It can manage and query the service status, and also install and uninstall the service.

```
adwatchd service COMMAND [flags]
```

#### Options

```
  -h, --help   help for service
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service install

Installs the service

#### Synopsis

Installs the adwatchd service.

The service will be installed as a Windows service.


```
adwatchd service install [flags]
```

#### Options

```
  -c, --config string   use a specific configuration file
  -h, --help            help for install
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service restart

Restarts the service

#### Synopsis

Restarts the adwatchd service.

```
adwatchd service restart [flags]
```

#### Options

```
  -h, --help   help for restart
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service start

Starts the service

#### Synopsis

Starts the adwatchd service.

```
adwatchd service start [flags]
```

#### Options

```
  -h, --help   help for start
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service status

Returns service status

#### Synopsis

Returns the status of the adwatchd service.

```
adwatchd service status [flags]
```

#### Options

```
  -h, --help   help for status
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service stop

Stops the service

#### Synopsis

Stops the adwatchd service.

```
adwatchd service stop [flags]
```

#### Options

```
  -h, --help   help for stop
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd service uninstall

Uninstalls the service

#### Synopsis

Uninstalls the adwatchd service.

```
adwatchd service uninstall [flags]
```

#### Options

```
  -h, --help   help for uninstall
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

### adwatchd version

Returns version of service and exits

```
adwatchd version [flags]
```

#### Options

```
  -h, --help   help for version
```

#### Options inherited from parent commands

```
  -v, --verbose count   issue INFO (-v), DEBUG (-vv) or DEBUG with caller (-vvv) output
```

## Hidden commands

Those commands are hidden from help and should primarily be used by the system or for debugging.

