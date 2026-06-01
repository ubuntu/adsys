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

ADSys supports two certificate enrollment methods, selectable via the `certificate_enrollment` configuration key in `/etc/adsys.yaml`:

### LDAP enrollment (recommended for new installations)

The **`ldap`** method is a native Go implementation that:

* Discovers Certificate Authorities and certificate templates from Active Directory via LDAP
* Installs root CA certificates to the system trust store
* Submits CSRs directly to AD CS using the MS-ICPR protocol (DCOM/RPC) via the `adsys-certsubmit` helper binary
* Uses `certmonger` for certificate lifecycle management

This method does not require CEPCES or Python dependencies on the client, and does not require Certificate Enrollment Web Service (CES) or Certificate Enrollment Policy Web Service (CEP) roles on the Windows server — only the Certification Authority role is needed.

### CEPCES enrollment (default for existing installations)

The **`cepces`** method is the legacy implementation that delegates certificate enrollment to an embedded Python script using vendored Samba code and the CEPCES helper. This requires `python3-samba`, `python3-cepces`, and `certmonger` to be installed.

### Configuration

Set the enrollment method in `/etc/adsys.yaml`:

```yaml
certificate_enrollment: ldap    # or "cepces"
```

* **New installations**: The package automatically creates `/etc/adsys.yaml` with `certificate_enrollment: ldap`.
* **Existing installations**: The default is `cepces` for backward compatibility. To switch to the native LDAP enrollment, add the setting above to your configuration file.

To ensure idempotency when applying the policy, enrollment state is persisted as a JSON file at `/var/lib/adsys/certs/state_$(hostname).json`, which contains information pertaining to the enrolled certificate(s).

### Policy application sequence

Here is an overview of what happens during policy application:

* Parse GPO (ADSys)
* Discover CAs and templates from AD via LDAP (ADSys)
* Install root CA certificates to system trust store (ADSys)
* Register CAs and request certificates using `certmonger` with `adsys-certsubmit` helper (ADSys)
