---
myst:
  html_meta:
    description: "Complete reference documentation for ADSys including daemon, CLI tools, supported policies, glossary, features, and release notes."
---

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

Detailed reference for CLI tooling.

```{toctree}
:titlesonly:
cli-index
```

## Supported policies

A comprehensive reference of policies supported by ADSys.

```{toctree}
:titlesonly:
:maxdepth: 2

policies/index
```

## Glossary and resources

A glossary of technical terms used in the ADSys documentation.
This may be especially useful for Windows sysadmins who are not familiar with
Linux tools and terminology.

Links to external resources are also provided, to support troubleshooting of
external tools, including certmonger and SSSD.

```{toctree}
:titlesonly:

glossary
External resources <external-links>
```

## Features

Overview of ADSys' standard features and features enabled with a Pro
subscription, in addition to release notes for ADSys.

```{toctree}
:titlesonly:

features
release-notes
```
