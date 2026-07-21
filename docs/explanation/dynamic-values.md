---
myst:
  html_meta:
    description: "Use dynamic value placeholders such as ${USER} and ${HOSTNAME} in Active Directory policies to template per-user and per-machine configuration."
---

(exp::dynamic-values)=
# Dynamic values

Most policy values configured through ADSys can contain *dynamic value placeholders*.
These placeholders are expanded on the client when the policy is applied, against the
user or machine the policy targets. This makes it possible to template a single policy
across many users or machines instead of creating one policy per principal.

For example, a single user mount entry can give every user their own home share:

```text
smb://server/homes/${USER}
```

## Supported variables

| Placeholder | Expands to | Example | User policies | Machine policies |
| --- | --- | --- | --- | --- |
| `${USER}` | Login name without the domain | `bob` | yes | no |
| `${FULL_USER}` | Fully-qualified user name | `bob@example.com` | yes | no |
| `${HOSTNAME}` | Short machine hostname | `workstation01` | yes | yes |
| `${FULL_HOSTNAME}` | Fully-qualified machine name | `workstation01.example.com` | yes | yes |
| `${DOMAIN}` | Active Directory domain | `example.com` | yes | yes |

### Notes on placeholders

- In a user policy, `${DOMAIN}` is the user's domain, which keeps it correct in
  multi-domain forests.
- `${FULL_HOSTNAME}` always uses the machine's domain.
- All placeholder names are matched case-insensitively, so `${user}` and `${USER}` are
  equivalent.

## Syntax

Only the `${VARIABLE}` form (with braces) is recognized. A lone `$` or a bare `$USER`
without braces is left untouched, and percent-encoded characters in URLs (such as `%20`)
are never interpreted as placeholders.

There is currently no way to emit a literal `${...}` string into a value.

## Where placeholders can be used

Dynamic values are expanded for every policy manager (GSettings/dconf, privileges,
scripts, network shares, AppArmor, proxy and certificates). They are expanded only in the
policy value itself: the contents of files referenced by a policy — such as a script body
or an AppArmor profile — are **not** considered.

## Error handling

ADSys is strict about placeholders and will surface a mistake immediately rather than
silently applying a broken value.

Policy application fails, blocking the affected authentication, when:

- An unknown or misspelled placeholder is used. For example: `${USR}`;
- A placeholder is malformed. For example: `${USER` or `${}`;
- A user-only placeholder, such as `${USER}` or `${FULL_USER}`, is used in a machine policy.

## Example uses of dynamic values

- Per-user network share: `smb://server/homes/${USER}`
- Per-machine system mount: `nfs://server/exports/${HOSTNAME}`
- Per-user logon script (relative to `SYSVOL/ubuntu/scripts/`): `${USER}/logon.sh`
