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

While `certmonger` has been available for a while in Ubuntu, `python3-cepces` is a new package, available starting with Ubuntu 23.10. If unavailable on the client version, it can also be manually installed from the [source repository](https://github.com/openSUSE/cepces). The certificate policy manager only checks for the existence of the `cepces-submit` and `getcert` binaries, not their respective packages, in order to allow some wiggle room for this.

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

Note that tampering with certificate data outside of ADSys (e.g. manually unmonitoring using `getcert`) will render the GPO cache obsolete as it will cause a drift between the actual state and the "known" cached state. In this case, it's best to remove the cache file at `/var/lib/adsys/samba/*.tdb` together with any enrolled certificates and CAs to ensure a clean slate.

## Debugging `auto-enroll` script

While certificate parsing happens in ADSys itself, enrollment is done via an embedded Python helper script. For debugging purposes, it can be dumped to the current directory and made executable by executing the following commands:

```output
> adsysctl policy debug cert-autoenroll-script
> chmod +x ./cert-autoenroll
```

Before executing the script manually, the following environment variables have to be set:

```sh
export PYTHONPATH=/usr/share/adsys/python
export KRB5CCNAME=/var/run/adsys/krb5cc/$(hostname)
```

Then, run the script passing the required arguments (the argument list is also printed in the ADSys debug logs during policy application):

```output
# Un-enroll machine
> ./cert-autoenroll unenroll keypress galacticcafe.com --state_dir /var/lib/adsys --debug
```

## Errors communicating with the CEP/CES servers

If ADSys successfully applies the policy but `getcert list` does not list the certificates or they are in an unexpected state, check the `certmonger` logs for details (`journalctl -u certmonger`). Additionally, debug logging for `cepces` can be enabled by editing the logging configuration at `/etc/cepces/logging.conf`.

The `cepces` configuration itself is batteries-included, meaning it should work out of the box for most setups. All configuration options are documented and configurable at `/etc/cepces/cepces.conf`.

## Additional information

While configuring Active Directory Certificate Services is outside the scope of the policy manager documentation, we have found the following resources to be useful:

* [How to setup Microsoft Active Directory Certificate Services](https://www.virtuallyboring.com/setup-microsoft-active-directory-certificate-services-ad-cs/)
* [How to increase your CSR key size on Microsoft IIS without removing the production certificate?](https://leonelson.com/2011/08/15/how-to-increase-your-csr-key-size-on-microsoft-iis-without-removing-the-production-certificate/)

We also provide a comprehensive list of relevant [external resources](../../reference/external-links).
