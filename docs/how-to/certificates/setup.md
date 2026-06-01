---
myst:
  html_meta:
    description: "Steps to set up certificate auto-enrollment for ADSys."
---

(howto::certificates-setup)=
# Set up certificate auto-enrollment

```{include} ../../pro_content_notice.txt
    :start-after: <!-- Include start pro -->
    :end-before: <!-- Include end pro -->
```

Certificate auto-enrollment is a key component of Ubuntu’s Active Directory GPO support.
This feature enables clients to seamlessly enroll for certificates from Active Directory Certificate Services.

The certificate policy manager allows clients to enroll for machine certificates from **Active Directory Certificate Services**. The native LDAP method writes certificates and private keys directly to disk; the legacy CEPCES method delegates tracking and refreshes to [`certmonger`](https://www.freeipa.org/page/Certmonger).

Unlike the other ADSys policy managers which are configured in the special Ubuntu section provided by the ADMX files (Administrative Templates), settings for certificate auto-enrollment are configured in the Microsoft GPO tree:

* `Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Certificate Services Client - Auto-Enrollment`

![Certificate GPO tree view](../../images/explanation/certificates/certificate-settings.png)

## Prerequisites

### Active directory

You will need an installation of ADSys on a client Ubuntu Machine and the client should be joined to an {term}`Active Directory` (AD) domain.
Please refer to our how-to guides on setting up the Ubuntu client machine:

- [Join machine to AD during installation](../../how-to/join-ad-installation.md)
- [Join machine to AD manually](../../how-to/join-ad-manually.md)
- [Install ADSys](../../how-to/set-up-adsys.md)

For the Windows {term}`domain controller`, refer to:

- [Set up AD](../../how-to/set-up-ad.md)

### Required packages

The required packages depend on the certificate enrollment method configured in `/etc/adsys.yaml`.

#### LDAP enrollment

No additional client package is required beyond ADSys.

On the Windows side, the `Certification Authority` role is required, and domain controllers must accept LDAP StartTLS with certificates trusted by the Ubuntu client.

#### CEPCES enrollment

The following packages must be installed on the client:

* [`certmonger`](https://www.freeipa.org/page/Certmonger) — daemon that monitors and updates certificates
* `python3-samba` — Samba Python bindings
* `python3-cepces` — CEPCES helper for certmonger

```bash
sudo apt install certmonger python3-samba python3-cepces
```

On the Windows side, the following roles must be installed and configured:

* `Certification Authority`
* `Certificate Enrollment Policy Web Service`
* `Certificate Enrollment Web Service`
