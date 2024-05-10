# adsys

Active Directory GPO support.

[![Code quality](https://github.com/ubuntu/adsys/workflows/QA/badge.svg)](https://github.com/ubuntu/adsys/actions?query=workflow%3AQA)
[![Code coverage](https://codecov.io/gh/ubuntu/adsys/branch/main/graph/badge.svg)](https://codecov.io/gh/ubuntu/adsys)
[![Download XML coverage report](https://img.shields.io/badge/xml%20coverage%20report-download-green)](https://github.com/ubuntu/adsys/releases/download/nightly/Cobertura.xml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ubuntu/adsys.svg)](https://pkg.go.dev/github.com/ubuntu/adsys)
[![Go Report Card](https://goreportcard.com/badge/ubuntu/adsys)](https://goreportcard.com/report/ubuntu/adsys)
[![License](https://img.shields.io/badge/License-GPL3.0-blue.svg)](https://github.com/ubuntu/adsys/blob/main/LICENSE)

## Documentation and Usage

The documentation and the command line reference is available on [Read The Docs](https://canonical-adsys.readthedocs-hosted.com/en/stable/) as well as the [documentation for the current development release](https://canonical-adsys.readthedocs-hosted.com/en/latest/).

## Installing development versions

For every commit on the `main` branch of the `adsys` repository, the GitHub Actions CI builds a development version of the `adwatchd` project. This is *NOT* a stable version of the application and should not be used for production purposes. However, it may prove useful to preview features or bugfixes not yet available as part of a stable release.

To get access to the build artifact you need to be logged in on GitHub. Then, click on any passing run of the [QA workflow](https://github.com/ubuntu/adsys/actions/workflows/qa.yaml) that has the `Windows tests for adwatchd` job, and look for the `adwatchd_setup` file.

## Troubleshooting

If AD authentication works but adsys fails to fetch GPOs (e.g. you see `can't get policies` errors on login), please perform the following steps:

1. Add the following to `/etc/samba/smb.conf`:

```text
log level = 10
```

2. Run `sudo login {user}@{domain}` in a terminal, replacing with your AD credentials

3. Paste the output in the bug report

The `adsysctl` command can also be useful to fetch logs for the daemon and client:

```bash
# You can increase the amount of information that will be displayed by using a more verbose tag (-vv or -vvv).
# Note that this command will start a watcher that will print logs as they are generated, so you will need to perform
# actions (such as trying to login) while the command is running.
adsysctl service cat -v
```

Additionally, you can check the system journal to look at more logs about adsys:
Remember that adsys runs with privileges, so you will need to run the following commands as root.

```bash
# You can use the -b flag to control how many boots the log will show (e.g. -b 0 will show the current boot only)
journalctl -b0 | grep adsys

# You can also get the logs of the individual units:
systemctl list-units | grep adsys # this will show all adsys related systemd units

# The -u flag will show the logs of the specified unit
journalctl -b0 -u adsysd.service # this command will only show the adsysd.service logs of the current boot
```
