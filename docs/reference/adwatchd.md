# Active Directory Watch Daemon

## Monitoring the application

`adwatchd` is configured to log to the Windows Event Log, and can be monitored using the [Event Viewer](https://docs.microsoft.com/en-us/shows/inside/event-viewer). By default, the application will only log events when it starts or stops, but the verbose level can be increased via the configuration file to log more information such as files being watched, or the `GPT.ini` file being updated.

## CLI usage

For more advanced usage, the application can be managed from the command line. If the application was installed via the bespoke installer, a helpful shortcut is available in the Start Menu: `Start Command Prompt with adwatchd`. This will start a Command Prompt window with the `adwatchd` executable in the `PATH`.

There are two commands available:

* The `run` command starts the directory watch loop in foreground mode. This is useful for debugging purposes, as it can be called with the same arguments as the service.
* The `service` provides a set of subcommands to manage the service.

For detailed descriptions and configuration options of `adwatchd`, refer to the [Command line reference](adwatchd-cli.md) section.
