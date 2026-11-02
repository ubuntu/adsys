# How to set up the Active Directory Watch Daemon

The Active Directory Watch Daemon or `adwatchd` is a Windows application for automating the otherwise manual process of incrementing the version stanza of a `GPT.ini` file.

The program can be simplified to the following steps:

- Watch a list of user-configured directories and their subdirectories for changes, where only the root directory has a `GPT.ini` file
- When a change is detected, attempt to locate a `GPT.ini` file at the root of the watched directory or create one if absent
- If a `GPT.ini` file is found, increment the version stanza of the file by 1, which ensures that a new version of the assets (including scripts) are available to download during the next client refresh

## Installation

The `adwatchd` application is available as a standalone Windows executable file, distributed as part of the `adsys-windows` Ubuntu package.

It is also packaged as an installer, which is available in the [ADSys GitHub repository](https://github.com/ubuntu/adsys/releases/latest).

### Installing with the Ubuntu package

To source the `adwatchd` executable from the `adsys-windows` package, run the following on Ubuntu:

```sh
sudo apt install adsys-windows
```

This installs the `adwatchd.exe` executable in the following directory on the Ubuntu client:

```text
/usr/share/adsys/windows
```

We recommend that you deploy this executable to a persistent directory on the AD Domain Controller, such as:

```text
%SystemDrive%\Program Files\Ubuntu\adsys\
```

### Installing using the bespoke installer

Download the [latest release](https://github.com/ubuntu/adsys/releases/latest) of the `adwatchd_setup.exe` file --- or a specific version if you prefer.

Run the executable then follow the installation steps.

You can optionally specify a different installation directory for the application.

## Configuring and starting the daemon

We recommend using the interactive configuration tool to install the application, as it provides a level of error handling, accounts for path normalization and handles the creation of the configuration file.

After installation, the configuration file can be edited further as needed.

### Using the interactive configuration tool

Regardless of how the application is installed, the configuration steps are the same:

- Locate and run the `adwatchd.exe` executable to start the interactive configuration tool
- Specify a path for the configuration file, or leave it blank to use the default location (the directory where the executable is located)
- Specify a list of directories to watch, one per line (the program will block installation if any of the directories do not exist)
- Hit the **Install** button to finish the installation, this will:
  - Create the configuration file if it does not exist
  - Install and start the `adwatchd` Windows service

For a better understanding of what directories should be configured for watching, please refer to the [installing scripts on the sysvol](explanation::installing-scripts-on-sysvol) in the explanation page for scripts execution.

```{note}
The interactive configuration tool can only be run if the `adwatchd` service is not already installed on the machine.

Please refer to the `adwatchd` service section of the [CLI reference for `adwatchd`](../reference/adwatchd-cli.md) for instructions on how to manage the service.


```

### Editing the configuration file

The configuration is stored as a YAML file, which can be freely edited after the application has been installed. 

The following keys are configurable:

```yaml
verbose: 0     # 0 = warning, 1 = info, 2 = debug, 3 = debug with caller output
dirs:          # list of directories to watch
  - C:\Windows\SYSVOL\sysvol\testdomain.com\Ubuntu     # traditional path
  - \\testdomain.com\SYSVOL\testdomain.com\Ubuntu      # UNC path
```

### Configuring the service using a pre-filled configuration file

For convenience, the `adwatchd` application can be configured with a pre-filled configuration file.

Open a Command Prompt or PowerShell terminal and run one of the commands below.

**Run interactive configuration tool:**

```bat
C:\path\to\adwatchd.exe -c path\to\config.yaml
```

**Run service installation command:**

```bat
C:\path\to\adwatchd.exe service install -c path\to\config.yaml
```

## Upgrading the service

The upgrade process differs based on the installation method used. If you decide to switch to a different installation method, you need to uninstall the existing service beforehand.

### Upgrading with the Ubuntu package

1. Source the new `adwatchd` executable from the `adsys-windows` Ubuntu package
1. Stop the `adwatchd` service using the Services GUI or the `adwatchd service stop` command
1. (Optional) Remove the existing `adwatchd` service from the system through the `adwatchd service uninstall` command
1. Replace the existing `adwatchd.exe` executable with the new one
1. (Optional) Install the `adwatchd` service through the `adwatchd service install` command
1. Start the `adwatchd` service using the Services GUI or the `adwatchd service start` command

The optional steps are only necessary if you want a complete upgrade of the application, which is not usually needed. Always refer to the changelog for information on the latest version of the application.

### Upgrading with the bespoke installer

1. Source the latest release of the `adwatchd_setup.exe` file
1. Run the installer and follow the prompts

The installer automatically handles the upgrade process.

It will offer to stop the service if it is running prior to the upgrade, and start it again afterwards.
