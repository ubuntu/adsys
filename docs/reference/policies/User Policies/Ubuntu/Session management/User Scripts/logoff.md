# Logoff scripts

Define scripts that are executed when the user exits from last session.
Those scripts are ordered, one by line, and relative to SYSVOL/ubuntu/scripts/ directory.
Scripts from this GPO will be appended to the list of scripts referenced higher in the GPO hierarchy.


- Type: scripts
- Key: /logoff

Note: -
 * Enabled: The scripts in the text entry are executed at user logoff time.
 * Disabled: The scripts will be skipped.
 The set of scripts are per session, and refreshed only on new session creation.


Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Session management -> User Scripts -> Logoff scripts    |
| Registry Key | Software\Policies\Ubuntu\scripts\logoff         |
| Element type | multiText |
| Class:       | User       |
