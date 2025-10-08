(howto::certificates)=
# Certificates auto-enrollment

```{include} ../pro_content_notice.txt
    :start-after: <!-- Include start pro -->
    :end-before: <!-- Include end pro -->
```

Certificate auto-enrollment is a key component of Ubuntu’s Active Directory GPO support. 
This feature enables clients to seamlessly enroll for certificates from Active Directory Certificate Services.

This tutorial is designed to help you develop an understanding of how to efficiently implement and manage certificate auto-enrollment, ensuring your systems remain secure and compliant with organizational policies.

## What you need

- A client machine running Ubuntu 23.04 LTS, Ubuntu 23.10 or Ubuntu 24.04 LTS
- A VPN server that runs in the Azure cloud
- An Ubuntu VM accessible in the VPN

## What you will do

- Configure and update the auto-enrollment policy
- Connect to a VPN server using certificates
- Access resources on the virtual network

## Setup

You will need an installation of ADSys on your client Ubuntu Machine and the client should be joined to an {term}`Active Directory` (AD) domain.
Please refer to our how-to guides on setting up the Ubuntu client machine:

- [Join machine to AD during installation](../how-to/join-ad-installation.md)
- [Join machine to AD manually](../how-to/join-ad-manually.md)
- [Install ADSys](../how-to/set-up-adsys.md)

For the Windows {term}`domain controller`, refer to:

- [Set up AD](../how-to/set-up-ad.md)

## Configure the auto-enrollment policy

First the policy needs to be configured.
This is done through the same entry policy as that which is used to configure Windows clients.

You can find the entry `Certificate Services Client - Auto-Enrollment` in the GPO tree:

`Policies > Windows Settings > Security Settings > Public Key Policies`

Open the entry and set the Configuration Model to `Enabled`.
You should also toggle the option for updating certificates that use certificate templates.

Apply these changes and continue.

## Update policies and query certificates

Now update the policies with ADSys:

```text
sudo adsysctl update -m -v
```

```{note}
This command also typically runs on a fixed schedule and during system reboots.
```

ADSys downloads certificates from the domain controller.
You can query information about the certificates with:

```text
sudo getcert list
```

```{note}
The `getcert list` command is provided by the `certmonger` utility, which is being used to manage the lifecycle of the certificates, ensuring — for example — that they are automatically renewed.
```

The output of the command should look something like this:

```{terminal}
   :input: getcert list
   :dir: 
Number of certificates and requests being tracked: 2
Request ID 'galacticcafe-CA.Machine':
    status: MONITORING
    stuck: no
    key pair storage: type=FILE,location='/var/lib/adsys/private/certs/galacticcafe-CA.Machine.key'
    certificate: type=FILE,location='/var/lib/adsys/certs/galacticcafe-CA.Machine.crt'
    CA: galacticcafe-CA
    issuer: CN=galacticcafe-CA,DC=galacticcafe,DC=com
...
...
Request ID 'galacticcafe-CA.Workstation':
    status: MONITORING
    stuck: no
    key pair storage: type=FILE,location='/var/lib/adsys/private/certs/galacticcafe-CA.Workstation.key'
    certificate: type=FILE,location='/var/lib/adsys/certs/galacticcafe-CA.Workstation.crt'
    CA: galacticcafe-CA
    issuer: CN=galacticcafe-CA,DC=galacticcafe,DC=com
...
...
...

```

From this truncated output, we can see that there are two certificates being monitored:

- `galactic-CA.Machine`
- `galactic-CA.Workstation`

These correspond to certificate templates that are configured on the certificate authority.

The paths to the private key and certificate are included in the `getcert list` output.
Everything should now be in place for the use of corporate services like VPNs and WiFi.

## Connect to VPN server using certificates

To check the VPN configuration run:

```text
cat /etc/ppp/peers/azure-vpn
```

Output:


```{terminal}
   :input: cat /etc/ppp/peers/azure-vpn
   :dir: 
remotename: azure-vpn
linkname: azure-vpn
ipparamname: azure-vpn
...
...
name        keypress.galacticcafe.com
plugin      sstp-pppd-plugin.so
...
...
ca: /var/lib/adsys/certs/galacticcafe-CA.2.crt
cert: /var/lib/adsys/certs/galacticcafe-CA.Machine.crt
key: /var/lib/adsys/private/certs/galacticcafe-CA.Machine.crt
...
...

```

An SSTP VPN is being used for this tutorial, connecting to a gateway in the Azure cloud.
The name specified is the FQDN of the machine that the certificates are generated for.
Confirm that paths to the `ca`, `cert` and private `key` are all specified.

It should then be possible to connect to the VPN:

```text
sudo pon azure-vpn
```

Establishing the connection may take a few seconds.

To check the connection run:

```text
ip a
```

This should output a point-to-point connection:


```{terminal}
   :input: ip a
   :dir: 
...
...
8: ppp0: <POINTTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 pfifo_fast state unknown group default qlen 3
...
...

```

## Accessing resources on a virtual network

The machine should now be connected to a virtual network with access to virtual resources.

For example, if an Ubuntu machine has no public IP but is set up in the same virtual network then it should be accessible:

```text
ping <IPv4-address-of-resource>
```

It should be possible to `ssh` into a machine on the network:

```text
ssh -i ~/.ssh/adsys-integration.pem root@<IPv4-address-of-resource>
```

For example, an instance of Ubuntu 24.04 LTS will give an output that shows it is running on Azure based on the kernel version:

```text
Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.5.0-1004-azure x86_64))
```
