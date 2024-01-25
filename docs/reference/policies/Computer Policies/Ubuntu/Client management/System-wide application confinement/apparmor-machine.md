# AppArmor

Define AppArmor profiles to be parsed and loaded on client machines.
These profiles are ordered, one by line, and relative to the SYSVOL/ubuntu/apparmor/ directory.
On the client machine, computer profiles are stored in /etc/apparmor.d/adsys/machine, thus the administrator can reference abstractions and tunables shipped with the client distribution of AppArmor.
Files can be included in each other either using a path relative to the current directory of the profile (include "path/to/profile"), or relying on the include path of AppArmor (include <adsys/machine/path/to/profile>).

Profiles from this GPO will be appended to the list of profiles referenced higher in the GPO hierarchy.


- Type: apparmor
- Key: /apparmor-machine

Note: -
 * Enabled: The profiles in the text entry are applied on the client machine.
 * Disabled: The profiles are removed from the target machine, and any related rules are unloaded.


Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> System-wide application confinement -> AppArmor    |
| Registry Key | Software\Policies\Ubuntu\apparmor\apparmor-machine         |
| Element type | multiText |
| Class:       | Machine       |
