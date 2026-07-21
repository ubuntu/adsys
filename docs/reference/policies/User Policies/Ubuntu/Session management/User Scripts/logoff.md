# Logoff scripts

Define scripts that are executed when the user exits from last session.
Those scripts are ordered, one by line, and relative to SYSVOL/ubuntu/scripts/ directory.
Scripts from this GPO will be appended to the list of scripts referenced higher in the GPO hierarchy.

Dynamic values: this field supports the placeholders ${USER}, ${FULL_USER}, ${HOSTNAME}, ${FULL_HOSTNAME} and ${DOMAIN}, which are expanded on the client when the policy is applied. ${USER} and ${FULL_USER} are only valid in user policies. Using an unknown placeholder makes the policy fail to apply. For example: ${USER}/logoff.sh


- Type: scripts
- Key: /logoff

Note: -
 * Enabled: The scripts in the text entry are executed at user logoff time.
 * Disabled: The scripts will be skipped.
 The set of scripts are per session, and refreshed only on new session creation.


Supported on Ubuntu 22.04, 24.04, 25.10, 26.04, 26.10.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Session management -> User Scripts -> Logoff scripts    |
| Registry Key | Software\Policies\Ubuntu\scripts\logoff         |
| Element type | multiText |
| Class:       | User       |
