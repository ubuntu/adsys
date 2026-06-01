---
myst:
  html_meta:
    description: "Guidance on troubleshooting certificate auto-enrollment with ADSys."
---

(howto::certificates-troubleshoot)=
# Troubleshoot certificate auto-enrollment

```{include} ../../pro_content_notice.txt
    :start-after: <!-- Include start pro -->
    :end-before: <!-- Include end pro -->
```

Certificate auto-enrollment is a key component of Ubuntu’s Active Directory GPO support.
This feature enables clients to seamlessly enroll for certificates from Active Directory Certificate Services.

## Some dependencies are not available in the client Ubuntu installation

The native LDAP method does not require additional client packages beyond ADSys.
It does require domain controllers to accept LDAP StartTLS with certificates trusted by the Ubuntu client.

The legacy CEPCES method requires `certmonger`, `python3-samba`, and `python3-cepces`.

## Manipulating CEPCES certificates with `getcert`

While not encouraged, certificates enrolled with the CEPCES method can be manipulated with the same tool. This could be helpful for debugging purposes.

```output
# Regenerate a certificate
> getcert rekey -i galacticcafe-CA.Machine
Resubmitting "galacticcafe-CA.Machine" to "galacticcafe-CA".

# Unmonitor a certificate
> getcert stop-tracking -i galacticcafe-CA.Machine
Request "galacticcafe-CA.Machine" removed.

# Remove CA
> getcert remove-ca -c galacticcafe-CA
CA "galacticcafe-CA" removed.
```

For the native LDAP method, ADSys stores certificate state in `/var/lib/adsys/certs/state_*.json`. Manually removing files under `/var/lib/adsys/certs` or `/var/lib/adsys/private/certs` can cause drift between the actual state and the cached state. In this case, remove the state file together with any enrolled certificates and CAs to ensure a clean slate.

## Errors communicating with AD CS

For native LDAP enrollment, check ADSys logs for LDAP, Kerberos, and MS-ICPR errors. For CEPCES enrollment, also check `certmonger` logs (`journalctl -u certmonger`).

## Additional information

While configuring Active Directory Certificate Services is outside the scope of the policy manager documentation, we have found the following resources to be useful:

* [How to setup Microsoft Active Directory Certificate Services](https://www.virtuallyboring.com/setup-microsoft-active-directory-certificate-services-ad-cs/)
* [How to increase your CSR key size on Microsoft IIS without removing the production certificate?](https://leonelson.com/2011/08/15/how-to-increase-your-csr-key-size-on-microsoft-iis-without-removing-the-production-certificate/)

We also provide a comprehensive list of relevant [external resources](../../reference/external-links).
