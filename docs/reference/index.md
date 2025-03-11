# Reference

Reference information is here provided for:

* The daemon -- `adsysd` -- which implements the Group Policy protocol.
* The command line interface -- `adsysctl` -- which controls the daemon and reports its status.
* The Windows daemon -- `adwatchd` -- can be installed on the domain controller to
automatically refresh assets without system administrator interventions.

## Overview

Technical overview of the daemons and command line interface.

```{toctree}
:titlesonly:
ADSys Daemon (adsysd)<adsys-daemon>
ADSys Control (adsysctl)<adsysctl>
ADSys Watch Daemon (adwatchd)<adwatchd>
```

## Command line interface

Description of commands for achieving specific actions in the terminal.

```{toctree}
:titlesonly:
adsysctl<adsysctl-cli>
adsysd<adsysd-cli>
adwatchd<adwatchd-cli>
```

## Supported policies

A comprehensive reference of policies supported by ADSys.

```{toctree}
:titlesonly:
:maxdepth: 2

policies/index
```

## Glossary

A glossary of technical terms used in the ADSys documentation.
This may be especially useful for Windows sysadmins who are not familiar with
Linux tools and terminology.

```{toctree}
:titlesonly:

glossary
```

