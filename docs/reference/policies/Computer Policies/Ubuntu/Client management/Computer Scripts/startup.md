# Startup scripts

Define scripts that are executed on machine boot, once the GPO is downloaded.
Those scripts are ordered, one by line, and relative to SYSVOL/ubuntu/scripts/ directory.
Scripts from this GPO will be appended to the list of scripts referenced higher in the GPO hierarchy.


- Type: scripts
- Key: /startup

Note: -
 * Enabled: The scripts in the text entry are executed at startup time.
 * Disabled: The scripts will be skipped.
 The set of scripts are per boot, and refreshed only on new boot of the machine.


Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Computer Scripts -> Startup scripts    |
| Registry Key | Software\Policies\Ubuntu\scripts\startup         |
| Element type | multiText |
| Class:       | Machine       |
