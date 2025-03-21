# How to set up the Active Directory Watch Daemon

The **Active Directory Watch Daemon** (or `adwatchd`) is a Windows application geared towards automating the manual process of incrementing the version stanza of a `GPT.ini` file.

At its core, the program can be simplified to the following steps:

- watch a list of user-configured directories for changes -- subdirectories are also watched, but only the root directory will have a `GPT.ini` file
- when a change is detected, attempt to locate a `GPT.ini` file at the root of the watched directory, or create one if absent
- if a `GPT.ini` file is found, increment the version stanza of the file by 1, thus signaling clients that a new version of the assets (including scripts) are available to download during the next client refresh

## Installation

The `adwatchd` executable is available as a standalone Windows executable file, distributed as part of the `adsys-windows` Ubuntu package, or packaged as an installer available on the [GitHub repository](https://github.com/ubuntu/adsys/releases/latest).

### Installing via the Ubuntu package

To source the `adwatchd` executable from the `adsys-windows` Ubuntu package, we must run the following (on Ubuntu):

```sh
sudo apt install adsys-windows
```

After a successful installation, the `adwatchd.exe` executable will be available in the `/usr/share/adsys/windows` directory. We suggest you deploy this executable to a persistent directory of your choosing on the AD Domain Controller, such as `%SystemDrive%\Program Files\Ubuntu\adsys\`.

### Installing via the bespoke installer

Download the [latest release](https://github.com/ubuntu/adsys/releases/latest) of the `adwatchd_setup.exe` file (or a specific version if you wish), and run it.

Follow the installation steps, paying attention to the prompts, optionally specifying a different installation directory for the application.

## Configuring and starting the daemon

Regardless of how the application is installed, the configuration steps are the same:

- locate and run the `adwatchd.exe` executable to start the application's interactive configuration tool
- specify a path for the configuration file, or leave it blank to use the default location (the directory where the executable is located)
- specify a list of directories to watch, one per line (the program will block installation if any of the directories do not exist)
- hit the `[ Install ]` button to finish the installation, this will:
  - create the configuration file if it does not exist
  - install and start the `adwatchd` Windows service

For a better understanding on what directories should be configured for watching, please refer to the **Installing scripts on sysvol** section of the [Scripts execution](../explanation/scripts#Installing scripts on sysvol) document.

Note that the interactive configuration tool can only be run if the `adwatchd` service is not already installed on the machine. Please refer to the [CLI usage](#CLI usage) section for instructions on how to finely manage the service.

We recommend making use of the interactive configuration tool to install the application, as it provides a level of error handling, taking care of path normalization and the creation of the configuration file.

The configuration file is stored as a YAML file, and can be freely edited after the application has been installed. The following keys are configurable:

```yaml
verbose: 0     # 0 = warning, 1 = info, 2 = debug, 3 = debug with caller output
dirs:          # list of directories to watch
  - C:\Windows\SYSVOL\sysvol\testdomain.com\Ubuntu     # traditional path
  - \\testdomain.com\SYSVOL\testdomain.com\Ubuntu      # UNC path
```

### Configuring the service using a pre-filled configuration file

For convenience, the `adwatchd` application can be configured with a pre-filled configuration file. Start a Command Prompt or PowerShell window and run one of the following:

```bat
REM Run the interactive configuration tool with a predefined configuration file
REM
REM This will start the interactive configuration tool with pre-filled entries for the
REM config path and directories to watch, leaving the user to press the [ Install ] button
C:\path\to\adwatchd.exe -c path\to\config.yaml

REM Run the service installation command with a predefined configuration file
REM
REM This will install the service with the given configuration file and start it
C:\path\to\adwatchd.exe service install -c path\to\config.yaml
```

## Upgrading

The upgrade process differs based on the installation method used. If you decide to switch to a different installation method, you will need to uninstall the existing service beforehand.

### Upgrading via the Ubuntu package

1. Source the new `adwatchd` executable from the `adsys-windows` Ubuntu package
1. Stop the `adwatchd` service (via the Services GUI or the `adwatchd service stop` command)
1. (Optional) Remove the existing `adwatchd` service from the system (through the `adwatchd service uninstall` command)
1. Replace the existing `adwatchd.exe` executable with the new one
1. (Optional) Install the `adwatchd` service (through the `adwatchd service install` command)
1. Start the `adwatchd` service (via the Services GUI or the `adwatchd service start` command)

The optional steps are only necessary if the intent is to do a complete upgrade of the application and are not usually needed. Always refer to the changelog for information on the latest version of the application.

### Upgrading via the bespoke installer

1. Source the latest release of the `adwatchd_setup.exe` file
1. Run the installer, following the prompts

The installer will automatically take care of the upgrade process, and will offer to stop the service if it is running prior to the upgrade, and start it afterwards.
