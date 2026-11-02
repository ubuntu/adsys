(tutorial::getting-started)=
# Getting started with ADSys

{term}`ADSys` bridges between {term}`Active Directory` (AD) on a centralized Windows server and
Ubuntu {term}`clients` on the same network.

```{admonition} This is a multi-part tutorial
:class: important
In [Part 1](tutorial::active-directory), you will set up an AD environment
on Windows Server.

In [Part 2](tutorial::ubuntu-client), you will configure an Ubuntu client to
integrate with AD.

In [Part 3](tutorial::adsys-integration), you will use ADSys to manage an Ubuntu
machine from AD.
```

To learn how ADSys can be used for {term}`on-premises` management of Ubuntu
machines from AD, you need a {term}`Windows Server` configured for AD, and at
least one Ubuntu client machine configured to join to the AD domain.

```{dropdown} (Optional) Using virtual machines for this tutorial
This tutorial can be followed using virtual machines for both Windows Server
and Ubuntu Desktop, using your preferred virtualization software. While a full
virtualization guide is outside the scope of this tutorial, the general steps
are described below.

## Windows

* Make sure you have 40GB storage available for installation
* Download an image for Windows Server from [Microsoft Evaluation Center](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022)
* Create the VM, selecting {guilabel}`Standard Evaluation (Desktop Experience)` and {guilabel}`Custom: Install Windows only` when prompted
* Agree to make the device available on the network

## Ubuntu

* Check that you have 20GB storage available for installation
* Download an image for Ubuntu Desktop form [Ubuntu releases](https://releases.ubuntu.com/)
* Create the VM and ensure that the Ubuntu VM has internet access
```

(tutorial::active-directory)=
## Part 1. Windows server configuration

If you already have a Windows Server with an AD environment configured, skip to
[Part 2](tutorial::ubuntu-client).

### Prerequisites

* A physical or virtual machine with Windows Server 2019 or 2022
* A {term}`static IP` address configured on Windows Server
* Administrative access to the server

```{tip}
For convenience, we recommend that you set a simple name for the server.
```

### Install Active Directory Domain Services

Before promotion to a {term}`domain controller`, certain features must be
installed on the server.

In Server Manager, go to {menuselection}`Manage --> Add Roles and Features`,
then complete the following steps:

* For **Installation type**, select {guilabel}`Role-based or feature-based
installation`
* In **Server selection**, ensure that your server is selected
* In **Server roles**, check {guilabel}`Active Directory Domain Services` and
add required features
* Continue to **Confirmation** and {guilabel}`Install` the roles, services, and
features on the server

When installation is finished, close the wizard.

### Promote server to domain controller

The server must now be promoted to a domain controller to enable centralized
management of {term}`group policies`, authentication and network resources through AD.

After installing AD domain services, a notification ({octicon}`alert;1em;sd-text-warning`) appears in {term}`Server Manager`.

Click on the notification icon, and select {guilabel}`Promote this server to a
domain controller`, then complete the following steps:

* In **Deployment Configuration**, select {guilabel}`Add a new forest` and
enter a domain name, such as `example.local`
* For **Domain Controller Options**, confirm the selection of {guilabel}`Domain
Name System (DNS) server` and {guilabel}`Global Catalog (GC)`, and enter a
Directory Services Restore Mode (DSRM) password
* Skip the **DNS Options** page, as DNS will be automatically configured
* In **Additional Options** and **Paths**, verify that the default settings are
correct
* Finally, confirm your selections in **Review Options** and after
**Prerequisites Check**, click {guilabel}`Install`

### Configure the NTP server

The {term}`NTP` server must be configured to ensure that the clocks are
synchronized between the domain controller and the Ubuntu client.

Open a {term}`PowerShell` terminal on the server and enable the NTP server:

```{code-block} powershell
:caption: Windows server
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\w32time\TimeProviders\NtpServer" -Name "Enabled" -Value 1
```

Set announce flags to 5, which makes sure that the server is recognized as reliable:

```{code-block} powershell
:caption: Windows server
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\services\W32Time\Config" -Name "AnnounceFlags" -Value 5
```

Restart the time server:

```{code-block} powershell
:caption: Windows server
Restart-Service w32Time
```

Allow the NTP Port (123) on Windows firewall:

```{code-block} powershell
:caption: Windows server
New-NetFirewallRule -Name "NTP Server Port" -DisplayName "NTP Server Port" -Description 'Allow NTP Server Port' -Profile Any -Direction Inbound -Action Allow -Protocol UDP -Program Any -LocalAddress Any -LocalPort 123
```

Later, you will synchronize the clock on the Ubuntu client with the clock on
the domain controller.

(tutorial::ubuntu-client)=
## Part 2. Ubuntu client configuration

In this part of the tutorial, you will configure an Ubuntu machine to join with the AD domain.

If you already have an Ubuntu machine joined to an AD domain, skip to [Part
3](tutorial::adsys-integration).

### Prerequisites

* An Ubuntu Desktop machine with network connectivity to the Windows Server
* Availability of {term}`sudo` privileges on the Ubuntu machine
* The Windows Server's IP address, {term}`FQDN` and domain name

```{note}
In this tutorial, you will use ADSys with Ubuntu Desktop.

ADSys can also be used to manage Ubuntu Server with AD.
```

### Update and install required packages on Ubuntu

Open a terminal and update packages with {term}`apt`, using {term}`sudo` for elevated privileges:

```{code-block} text
:caption: Ubuntu client
sudo apt update && sudo apt upgrade -y
```

Install required packages, including tools for joining to the domain ({term}`realmd`)
and authentication ({term}`SSSD`, {term}`kerberos`):

```{code-block} text
:caption: Ubuntu client
sudo apt install realmd sssd sssd-tools adcli samba-common samba-common-bin krb5-user packagekit-tools -y
```

### Configure DNS

Next, you need to configure your Ubuntu machine to use the Windows Server as its
{term}`DNS server`, which can be done by editing a {term}`netplan` configuration
file:

```{code-block} text
:caption: Ubuntu client
sudo nano /etc/netplan/01-netcfg.yaml
```

Modify the file to include your Windows Server's IP as the DNS server:

```{code-block} yaml
:caption: Ubuntu client
network:
  version: 2
  renderer: networkd
  ethernets:
    enp0s3: # Your network interface name might be different
      dhcp4: no
      addresses:
        - <Ubuntu_Client_IP>/24 # Replace with your Ubuntu client's static IP
      routes:
        - to: default
          via: <Gateway_IP> # Replace with your gateway IP
      nameservers:
        addresses: [<Windows_Server_IP>] # Replace with your Windows Server's IP
        search: [<Domain_Name>] # e.g., example.local
```

Apply the changes:

```{code-block} text
:caption: Ubuntu client
sudo netplan apply
```

Verify DNS resolution:

```{code-block} text
:caption: Ubuntu client
ping <Domain_Name>
ping <Windows_Server_IP>
```

If everything has been configured correctly, they will resolve successfully.

### Set the Windows Server as the NTP server for the Client

Modify `/etc/systemd/timesyncd.conf` to include:

```{code-block} ini
:caption: Ubuntu client
[Time]
NTP=<Windows_Server_FQDN>
RootDistanceMaxSec=15
```

````{tip}
The {term}`FQDN` is the computer name concatenated with the domain name, and can be
found on the server by running the following in PowerShell:

```{code-block} powershell
:caption: Ubuntu client
$env:COMPUTERNAME + "." + $env:USERDNSDOMAIN
```
````

Restart the `timesyncd` service:

```{code-block} text
:caption: Ubuntu client
sudo service systemd-timesyncd restart
```

The clocks of the Windows server and the Ubuntu client are now synced.

### Join Ubuntu to the Active Directory domain

Discover the domain:

```{code-block} text
:caption: Ubuntu client
sudo realm discover <Domain_Name>
```

The command should output information about your domain, for example:

```{terminal}
   :input: realm discover <Domain_Name>
   :user: <ubuntu-user>
   :host: <ubuntu-host>
   :dir: 

example.local
  type: kerberos
  realm-name: EXAMPLE.LOCAL
  domain-name: example.local
  configured: no
  server-software: active-directory
  client-software: sssd
  required-package: sssd-tools
  required-package: sssd
  required-package: libnss-sss
  required-package: libpam-sss
  required-package: adcli
  required-package: samba-common-bin
```

Next, join the Ubuntu client to the domain as the administrator user (default):

```{code-block} text
:caption: Ubuntu client
sudo realm join <Domain_Name>
```

Verify that your Ubuntu machine is part of the AD domain.


```{code-block} text
:caption: Ubuntu client
realm list
```

Log out of the administrator account:

```{code-block} text
:caption: Ubuntu client
exit
```

### Configure SSSD for user authentication

By default, SSSD does not create home directories for domain users,
which requires enabling the `pam_mkhomedir` module:

```{code-block} text
:caption: Ubuntu client
sudo pam-auth-update --enable mkhomedir
```

Restart SSSD after making these changes:

```{code-block} text
:caption: Ubuntu client
sudo systemctl restart sssd
```

```{admonition} ADSys and SSSD
:class: note
You can find an explanation of the relationship between ADSys and SSSD in our
[reference architecture](ref::adsys-arch) documentation.
```

(tutorial::adsys-integration)=
## Part 3. Using ADSys to manage Ubuntu clients with Active Directory

In this part, you will create a test user for your domain, log in to the domain
with that user, and enforce policies on the user's organizational unit using ADSys.

### Prerequisites

* An Ubuntu client that is joined to an AD domain
* SSSD configured for user authentication

### Create a test user on Windows server

In Server Manager on Windows Server:

* Open {menuselection}`Tools --> Active Directory Users and Computers`
* To see a list of users, go to {menuselection}`Domain_Name --> Users`
* From the top menu, select {menuselection}`Action --> New --> User`
* Fill in the details for your new user
* Leave the {guilabel}`user must change password at next logon` checked and
click {guilabel}`Finish`

The user should now appear in the list of users.

### Log in with the test user from the Ubuntu client

Using the test user that you created, log in to the domain:

```{code-block} text
:caption: Ubuntu client
sudo login <AD_User_Login_Name>
```

A successful login should be indicated by a change in the terminal prompt, for example, for example:

```{code-block} text
:caption: Ubuntu client
<test-user>@example.local@<ubuntu-host>:~$
```

Confirm that a home directory has been created for your test user:

```{code-block} text
:caption: Ubuntu client
pwd
```

### Install ADSys on Ubuntu

Now that you have an Ubuntu client joined to AD and a domain user, you can start
applying GPOs using ADSys.

ADSys can be installed directly from the Ubuntu archive by running:

```{code-block} text
:caption: Ubuntu client
sudo apt install adsys
```

### Generate and deploy admin templates

Once adsys is installed, you have access to the [`adsysctl`
tool](ref::adsysctl) command. Generate the {term}`policy templates` on the
Ubuntu client using the command:

```{code-block} text
:caption: Ubuntu client
adsysctl policy admx lts-only
```

To copy the templates from the client, use `scp` in a PowerShell terminal on the server:

```{code-block} powershell
:caption: Windows server
scp -r <Ubuntu_User>@<Ubuntu_Host>/home/<Ubuntu_User>/templates C:\Users\Administrator\Desktop
```

Then move the copied policy files to the following location:

```{code-block} text
:caption: Windows Server
C:\\Windows\SYSVOL\sysvol\example.local\Policies\PolicyDefinitions
```

The directory structure should look like this:

```{code-block} text
:caption: Windows server
.PolicyDefinitions
|_en-US
|__Ubuntu.adml
|_Ubuntu.admx
```

Back in the {term}`Server Manager`, go to {menuselection}`Tools --> Group Policy Management`.
Find your domain and select {menuselection}`Group Policy Objects`.

Add a new policy called `GeneralUbuntuDesktopPolicy`.
Now right click on that policy and click `Edit`.

This opens the Group Policy Management Editor.
You can find Ubuntu policies here in two places:

* {menuselection}`GeneralUbuntuDesktopPolicy --> Computer Configuration --> Policies --> Administrative Templates`
* {menuselection}`GeneralUbuntuDesktopPolicy --> User Configuration --> Policies --> Administrative Templates`

In this tutorial, you will modify a user setting using the second.

### Create an organizational unit for the test user

You can apply GPOs to groups of users using organizational units (OUs).

On the server, go to {menuselection}`Manage --> Active Directory Users and Computers`.
Right click on your domain, choose {menuselection}`New --> Organizational Unit` and call it `MainOffice`.

Next, navigate to {menuselection}`Tools --> Active Directory Users and Computers`.
Find the test user that you created earlier in {menuselection}`Users`.
Right click the user, choose {guilabel}`move` to put them in `MainOffice`.

### Create a GPO for users in an organizational unit

In the Group Policy Management tool, create a new group policy object (GPO)
for the `MainOffice` OU. Call it `DefaultSoftware` then right click it and {guilabel}`edit`.

Navigate to {menuselection}`User Configuration --> Policies --> Administrative
Templates --> Ubuntu  --> Desktop --> Shell --> List of desktop file IDs for
favorite applications`.

Enable the GPO and then enter a list of valid `.desktop` files, like below:

```text
org.gnome.Nautilus.desktop
org.gnome.TextEditor.desktop
```

````{tip}
You can check the files available in the Ubuntu client with:

```text
ls /usr/share/applications
```

````

This sets the software applications that are pinned on the Ubuntu desktop be
default.

## Apply the GPOs with ADSys

If you log out and log back in as the test user on the Ubuntu client, ADSys will
automatically refresh the GPO rules and apply the latest changes.

You can also refresh the GPO rules directly by running the following command on
the Ubuntu client:

```text
adsysctl update
```

## Additional information

You have created an AD environment, joined an Ubuntu client to the domain, and enforced user policies using ADSys.

You can find more detail on topics covered in this tutorial in the rest of the documentation:

* [Joining machine to AD during installation](howto::join-installer)
* [Using GPO with Ubuntu](howto::use-gpo)
* [The `adsysctl` command](ref::adsysctl)
