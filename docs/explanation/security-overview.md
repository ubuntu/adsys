# ADSys security overview

## Contribution of ADSys to security

ADSys facilitates the remote management of Ubuntu machines using Active
Directory (AD).

By enabling the enforcement of policies on client machines, ADSys can
contribute to the secure maintenance of AD-enrolled Ubuntu machines.

## Operation in air-gapped environments

Once installed, ADSys can be used in an air-gapped environment.

Its functionality does not depend on an internet connection. All that is
required is a local network connection between the AD server and the Ubuntu
client.

The ADSys binary includes both the documentation and the administrative
templates,  which therefore do not need to be fetched online.

For more information on generating documentation and templates, read about
ADSys’ command line utility:

* [The adsysctl command](https://documentation.ubuntu.com/adsys/en/stable/reference/adsysctl/)

## Secure transfer of templates

The admin templates are generated on the Ubuntu client before they are
transferred to the Windows server.

This can be done using the secure copy protocol (`scp`) in a PowerShell
terminal running on the server; for example, the following command copies
template files found in the `templates` directory on the client to the Desktop
of the server:

```text
scp -r user@ubuntu-client/home/ubuntu-client/templates C:\Users\Administrator\Desktop
```

This approach relies on SSH for authentication and encryption, increasing the
security of the file transfer.

## Using ADSys securely

### Security updates

ADSys is released as a Debian package on the Ubuntu archive. We currently
provide security updates for ADSys installed on the following Ubuntu LTS
releases:

* Ubuntu 24.04
* Ubuntu 22.04
* Ubuntu 20.04

Please ensure that you are using a supported version to receive updates and
patches.

If you are unsure of your version, please run the following command in a
terminal:

```text
adsysctl version
```

Always ensure that ADSys and its dependencies are up-to-date with:

```text
sudo apt update && sudo apt upgrade -y
```

### Active Directory

The secure use of ADSys depends greatly on the security of the AD instance with
which it interfaces.

A comprehensive security overview therefore requires consulting security
documentation relating to AD:

* [Best practices for securing Active Directory](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/best-practices-for-securing-active-directory)

### Authentication

For secure enrollment and authentication of clients with AD, ADSys depends on
SSSD or Winbind with Kerberos.

There is an explanation of how ADSys and SSSD work together to manage
authentication and policies in the ADSys documentation:

* [ADSys architecture](https://documentation.ubuntu.com/adsys/en/stable/explanation/adsys-ref-arch/) 

Policies relating to security settings are managed by SSSD, and are described
in the documentation:

* [Security settings that are supported through SSSD](https://documentation.ubuntu.com/adsys/en/stable/explanation/security-policy/) 

For detailed information on logging for use in debugging, review the following guides:

* [Kerberos logging with Active Directory](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-kerberos-event-logging)  
* [Troubleshooting and logging with SSSD](https://sssd.io/troubleshooting/basics.html)  
* [Winbind man pages](https://manpages.ubuntu.com/manpages/man8/winbindd.8.html)

### Risk management

An Ubuntu Pro subscription enables additional features for ADSys, including
privilege management, scripts execution and AppArmor profiles.

These are powerful features but can pose security issues if not managed
responsibly, for example

* Ensure that users are granted administrator privileges only when necessary
and that they are made aware of the associated risks.
* Validate any scripts or binaries to be executed on client machines.
* Develop and test AppArmor profiles before integrating them with ADSys to
ensure that they function as expected.

The ADSys documentation includes detailed explanations of these and other
Pro-specific features:

* [Administrator privilege management](https://documentation.ubuntu.com/adsys/en/stable/explanation/privileges/)  
* [Scripts execution](https://documentation.ubuntu.com/adsys/en/stable/explanation/scripts/)  
* [Managing AppArmor profiles](https://documentation.ubuntu.com/adsys/en/stable/explanation/apparmor/)

### Reporting a vulnerability

Details on the security updates that we provide and the responsible disclosure
of security vulnerabilities for ADSys can be found below:

* [Security policy for ADSys](https://github.com/ubuntu/adsys/blob/main/SECURITY.md)
