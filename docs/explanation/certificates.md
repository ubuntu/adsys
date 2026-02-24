---
myst:
  html_meta:
    description: "Explanation of how certificate auto-enrollment is implemented and applied with ADSys."
---

# Details of certificate auto-enrollment implementation

```{include} ../pro_content_notice.txt
    :start-after: <!-- Include start pro -->
    :end-before: <!-- Include end pro -->
```

## Policy implementation

With the exception of policy parsing, ADSys leverages the Samba implementation of certificate auto-enrollment. As this feature is only available in newer versions of Samba, we have vendored the required Samba files to allow this policy to work on Ubuntu versions that ship an older Samba version. These files are shipped in `/usr/share/adsys/python/vendor_samba`.

To ensure idempotency when applying the policy, we set up a Samba [TDB cache file](https://wiki.samba.org/index.php/TDB) at `/var/lib/adsys/samba/cert_gpo_state_$(hostname).tdb` which contains information pertaining to the enrolled certificate(s).

### Policy application sequence

Here is an overview of what happens during policy application:

* Parse GPO (ADSys)
* Execute Python helper script (ADSys)
* Fetch root CA and policy servers (Samba)
* Start monitoring certificate using `certmonger` and `cepces` (Samba)
