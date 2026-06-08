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

The certificate policy manager requires `certmonger` to be installed on the client. The `adsys-certsubmit` helper binary is shipped with ADSys and handles CSR submission to AD CS via the MS-ICPR protocol — no additional packages are required.

## Manipulating certificates with `getcert`

While not encouraged, certificates can be manipulated with the same tool. This could be helpful for debugging purposes.

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

Note that tampering with certificate data outside of ADSys (e.g. manually unmonitoring using `getcert`) will render the enrollment state obsolete as it will cause a drift between the actual state and the "known" cached state. In this case, it's best to remove the state file at `/var/lib/adsys/certs/state_*.json` together with any enrolled certificates and CAs to ensure a clean slate.

## Errors communicating with AD CS

If ADSys successfully applies the policy but `getcert list` does not list the certificates or they are in an unexpected state, check the `certmonger` logs for details (`journalctl -u certmonger`).

## Additional information

While configuring Active Directory Certificate Services is outside the scope of the policy manager documentation, we have found the following resources to be useful:

* [How to setup Microsoft Active Directory Certificate Services](https://www.virtuallyboring.com/setup-microsoft-active-directory-certificate-services-ad-cs/)
* [How to increase your CSR key size on Microsoft IIS without removing the production certificate?](https://leonelson.com/2011/08/15/how-to-increase-your-csr-key-size-on-microsoft-iis-without-removing-the-production-certificate/)

We also provide a comprehensive list of relevant [external resources](../../reference/external-links).
