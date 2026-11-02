# Active Directory Watch Daemon

The Active Directory Watch Daemon, or adwatchd, is a Windows application.

It automates the otherwise manual process of incrementing the version stanza of a `GPT.ini` file.

## Monitoring the application

`adwatchd` is configured to log to the Windows Event Log.

It can be monitored using the [Event Viewer](https://docs.microsoft.com/en-us/shows/inside/event-viewer).

By default, the application only logs events when it starts or stops.

The verbosity level can be increased in the configuration file to --- for example --- log more information such as files being watched, or the `GPT.ini` file being updated.

## CLI usage

The application can also be managed from the command line. 

If the application was installed with the bespoke installer, a helpful shortcut is available in the Start Menu: `Start Command Prompt with adwatchd`.

This starts a Command Prompt window with the `adwatchd` executable in the `PATH`.

```{tip}
For detailed descriptions and configuration options of `adwatchd`, refer to the [command line reference](adwatchd-cli.md).
```

There are two commands available:

* The `run` command starts the directory watch loop in foreground mode. This is useful for debugging purposes, as it can be called with the same arguments as the service.
* The `service` provides a set of subcommands to manage the service.

## Additional information

For help setting up `adwatchd`, refer to the [how-to set up adwatchd guide](../how-to/set-up-adwatchd.md).
