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
It does require domain controllers to accept LDAP StartTLS. The domain controller's certificate does not need to be pre-installed in the Ubuntu client's trust store: on the first enrollment ADSys trusts the authenticated Kerberos channel to bootstrap trust, installs the discovered CA, and verifies the full certificate chain on subsequent refreshes.

The legacy CEPCES method requires `certmonger`, `python3-samba`, and `python3-cepces`.

## Inspecting and manipulating enrolled certificates

With the native LDAP method, use `adsysctl certificate` (or the `adsysctl cert` alias) to inspect and manage certificates enrolled by ADSys. These certificates are machine-scoped and are not tracked by `certmonger`.

Use `list`, `status`, and `verify` for inspection and diagnosis:

```output
# List certificates enrolled by ADSys
> sudo adsysctl certificate list
Certificate 'galacticcafe-CA.Machine':
  status: healthy
  template: Machine
  CA: galacticcafe-CA (ca01.galacticcafe.com)
  expires: 2024-08-17T18:44:27+03:00 (210 days)
  on disk: yes
  key matches certificate: yes

# Check one certificate; the process exit code reflects its health (for monitoring)
> sudo adsysctl certificate status galacticcafe-CA.Machine

# Validate the certificate chain, validity window, and private key match
> sudo adsysctl certificate verify galacticcafe-CA.Machine
Certificate 'galacticcafe-CA.Machine': PASS
  chain: yes
  validity: yes
  key matches certificate: yes
```

Use `renew` to force re-enrollment before the normal 30-day renewal window, or `remove --force` to cleanly remove enrolled certificates, private keys, root-CA trust symlinks, and ADSys state:

```output
# Force a rekey and renewal now
> sudo adsysctl certificate renew galacticcafe-CA.Machine
Renewing galacticcafe-CA.Machine…
Renewed galacticcafe-CA.Machine

# Remove one enrolled certificate cleanly
> sudo adsysctl certificate remove galacticcafe-CA.Machine --force
Removing certificate galacticcafe-CA.Machine
Removed certificate galacticcafe-CA.Machine
```

```{note}
Lifecycle commands such as `renew` require the machine to be online with a valid Kerberos ticket. If the certificate GPO remains enabled, a later policy refresh re-enrolls removed certificates.
```

With the legacy CEPCES method, certificates are managed by `certmonger`; `adsysctl certificate` makes no changes to them and points administrators to `getcert`. While not encouraged, certificates enrolled with the CEPCES method can be manipulated with the same tool. This could be helpful for debugging purposes.

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

## Errors communicating with AD CS

For native LDAP enrollment, check ADSys logs for LDAP, Kerberos, and MS-ICPR errors. For CEPCES enrollment, also check `certmonger` logs (`journalctl -u certmonger`).

## Additional information

While configuring Active Directory Certificate Services is outside the scope of the policy manager documentation, we have found the following resources to be useful:

* [How to setup Microsoft Active Directory Certificate Services](https://www.virtuallyboring.com/setup-microsoft-active-directory-certificate-services-ad-cs/)
* [How to increase your CSR key size on Microsoft IIS without removing the production certificate?](https://leonelson.com/2011/08/15/how-to-increase-your-csr-key-size-on-microsoft-iis-without-removing-the-production-certificate/)

We also provide a comprehensive list of relevant [external resources](../../reference/external-links).
