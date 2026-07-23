---
myst:
  html_meta:
    description: "Manage certificates enrolled by ADSys."
---

(howto::certificates-manage)=
# Manage enrolled certificates

```{include} ../../pro_content_notice.txt
    :start-after: <!-- Include start pro -->
    :end-before: <!-- Include end pro -->
```

Use `adsysctl certificate` to inspect and manage certificates enrolled by ADSys with the native LDAP enrollment method. The shorter alias `adsysctl cert` is also available.

These commands are machine-scoped. They operate only on certificates enrolled through the `ldap` method. With the legacy `cepces` method, they make no changes and point administrators to `getcert`, because those certificates are tracked by `certmonger`.

CA certificates and ADSys state are stored under `/var/lib/adsys/certs`. Each issued leaf and private key is an immutable matched generation under `/var/lib/adsys/private/certs/<artifact>/generations`; stable `current/certificate.crt` and `current/private.key` paths resolve through one atomically replaced generation pointer. New state filenames, certificate nicknames, and artifact directories include stable hash suffixes so raw object, CA, hostname, and template names that sanitize alike remain distinct. A legacy nickname remains accepted only when it identifies exactly one enrollment.

```{note}
Lifecycle commands that enroll or re-enroll certificates require the machine to be online with a valid Kerberos ticket.
```

## List enrolled certificates

Use `list` to show every certificate enrolled by ADSys, including template, CA, subject, issuer, serial number, expiry, subject alternative names, enhanced key usage, key size, file paths, trust-store status, last enrollment time, and health state. Use `--format json` for scripting.

```output
> sudo adsysctl certificate list
Certificate 'galacticcafe-CA.Machine.a1b2c3d4e5f6':
  status: healthy
  template: Machine
  CA: galacticcafe-CA (ca01.galacticcafe.com)
  subject: CN=keypress.galacticcafe.com
  issuer: CN=galacticcafe-CA,DC=galacticcafe,DC=com
  serial: 5f7a
  expires: 2024-08-17T18:44:27+03:00 (210 days)
  SANs: keypress.galacticcafe.com
  EKU: id-kp-clientAuth, id-kp-serverAuth
  key: RSA 2048 bits
  key file: /var/lib/adsys/private/certs/galacticcafe-CA.Machine.0123456789abcdef/current/private.key
  certificate: /var/lib/adsys/private/certs/galacticcafe-CA.Machine.0123456789abcdef/current/certificate.crt
  on disk: yes
  key matches certificate: yes
  last enrolled: 2024-01-20T11:22:03+03:00
```

```output
> sudo adsysctl certificate list --format json
[
  {
    "nickname": "galacticcafe-CA.Machine.a1b2c3d4e5f6",
    "template": "Machine",
    "ca": "galacticcafe-CA",
    "ca_hostname": "ca01.galacticcafe.com",
    "subject": "CN=keypress.galacticcafe.com",
    "issuer": "CN=galacticcafe-CA,DC=galacticcafe,DC=com",
    "serial": "5f7a",
    "not_before": "2023-08-18T18:44:27+03:00",
    "not_after": "2024-08-17T18:44:27+03:00",
    "days_until_expiry": 210,
    "sans": ["keypress.galacticcafe.com"],
    "eku": ["id-kp-clientAuth", "id-kp-serverAuth"],
    "key_algo": "RSA",
    "key_size": 2048,
    "key_file": "/var/lib/adsys/private/certs/galacticcafe-CA.Machine.0123456789abcdef/current/private.key",
    "cert_file": "/var/lib/adsys/private/certs/galacticcafe-CA.Machine.0123456789abcdef/current/certificate.crt",
    "root_cert_files": ["/var/lib/adsys/certs/galacticcafe-CA.root.<certificate-id>.crt"],
    "trust_symlinks": ["/usr/local/share/ca-certificates/galacticcafe-CA.root.<certificate-id>.crt"],
    "on_disk": true,
    "key_matches_cert": true,
    "health": "healthy",
    "last_enrolled": "2024-01-20T11:22:03+03:00"
  }
]
```

## Check certificate status

Use `status` to check the health of one certificate or, without a nickname, the overall health of all enrolled certificates. Use `--format json` when integrating with monitoring tools.

```output
> sudo adsysctl certificate status galacticcafe-CA.Machine.a1b2c3d4e5f6
Certificate 'galacticcafe-CA.Machine.a1b2c3d4e5f6':
  status: healthy
  template: Machine
  CA: galacticcafe-CA (ca01.galacticcafe.com)
  subject: CN=keypress.galacticcafe.com
  issuer: CN=galacticcafe-CA,DC=galacticcafe,DC=com
  expires: 2024-08-17T18:44:27+03:00 (210 days)
  key: RSA 2048 bits
  on disk: yes
  key matches certificate: yes
```

The command returns a process exit code suitable for monitoring and scripts:

| Exit code | Meaning |
| --- | --- |
| 0 | healthy |
| 2 | missing |
| 3 | expired |
| 4 | due for renewal |
| 5 | key mismatch or unparseable |
| 6 | not yet valid |
| 1 | error |

## Verify a certificate

Use `verify` to validate the certificate chain, validity window, and private key match. Add `--online` to also perform a best-effort CRL revocation check. The check only trusts a CRL that is signed by the certificate's issuer chain and is inside its validity window; an untrusted, stale, or unreachable CRL makes the revocation state indeterminate rather than clean.

```output
> sudo adsysctl certificate verify galacticcafe-CA.Machine.a1b2c3d4e5f6 --online
Certificate 'galacticcafe-CA.Machine.a1b2c3d4e5f6': PASS
  chain: yes
  validity: yes
  key matches certificate: yes
  revoked: no
```

## Renew a certificate

Use `renew` to force re-enrollment immediately, bypassing the normal renewal window (30 days before expiry, bounded to a third of the certificate lifetime). Renewal generates a fresh private key, so this is also a rekey operation. Use `--all` to renew every enrolled certificate.

If AD CS requires approval, ADSys securely retains the request ID, CSR, and private key and polls that same CA on later policy refreshes or renewals. The currently installed generation remains active until issuance; repeated renewals do not create duplicate requests.

```output
> sudo adsysctl certificate renew galacticcafe-CA.Machine.a1b2c3d4e5f6
Renewing galacticcafe-CA.Machine.a1b2c3d4e5f6…
Renewed galacticcafe-CA.Machine.a1b2c3d4e5f6
```

## Remove a certificate

Use `remove --force` to cleanly delete enrolled certificates, private keys, root-CA trust symlinks, and ADSys state. Use `--all --force` to remove every enrolled certificate.

```output
> sudo adsysctl certificate remove galacticcafe-CA.Machine.a1b2c3d4e5f6 --force
Removing certificate galacticcafe-CA.Machine.a1b2c3d4e5f6
Removing root CA galacticcafe-CA from the trust store
Removed certificate galacticcafe-CA.Machine.a1b2c3d4e5f6
```

```{note}
If the certificate GPO remains enabled, a later policy refresh re-enrolls removed certificates. Disable the GPO first when the removal should be permanent.
```

## Show discovered CAs

Use `cas` to show certificate authorities and templates discovered in Active Directory, including whether each CA is installed in the trust store and whether a certificate is enrolled from each template.

```output
> sudo adsysctl certificate cas
CA 'galacticcafe-CA':
  hostname: ca01.galacticcafe.com
  templates: Machine, Workstation
  installed in trust store: yes
  enrolled: yes
```

## Show templates from a CA server

Use `templates SERVER` to list the certificate templates a CA server offers.

```output
> sudo adsysctl certificate templates ca01.galacticcafe.com
Machine
Workstation
```

## Health states

The health state reports whether ADSys can use and renew an enrolled certificate.

| State | Meaning |
| --- | --- |
| `healthy` | The certificate, private key, and state are valid. |
| `due_renewal` | The certificate is inside its renewal window (30 days before expiry, bounded to a third of its lifetime). |
| `expired` | The certificate is past its validity window. |
| `not_yet_valid` | The certificate's validity window has not started yet. |
| `missing` | The certificate, private key, or state entry is missing. |
| `key_mismatch` | The private key does not match the certificate. |
| `unparseable` | ADSys cannot parse the certificate, key, or state data. |
