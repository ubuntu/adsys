# Shutdown scripts

Define scripts that are executed on machine power off.
Those scripts are ordered, one by line, and relative to SYSVOL/ubuntu/scripts/ directory.
Scripts from this GPO will be appended to the list of scripts referenced higher in the GPO hierarchy.

Dynamic values: this field supports the placeholders ${USER}, ${FQDN_USER}, ${HOSTNAME}, ${FQDN_HOSTNAME} and ${DOMAIN}, which are expanded on the client when the policy is applied. ${USER} and ${FQDN_USER} are only valid in user policies. Using a user placeholder in a machine policy, or using an unknown placeholder, makes the policy fail to apply.


- Type: scripts
- Key: /shutdown

Note: -
 * Enabled: The scripts in the text entry are executed at shutdown time.
 * Disabled: The scripts will be skipped.
 The set of scripts are per boot, and refreshed only on new boot of the machine.


Supported on Ubuntu 22.04, 24.04, 25.10, 26.04, 26.10.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Computer Scripts -> Shutdown scripts    |
| Registry Key | Software\Policies\Ubuntu\scripts\shutdown         |
| Element type | multiText |
| Class:       | Machine       |
