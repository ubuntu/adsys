# AppArmor

Define an AppArmor user profile to be parsed and loaded on client machines.
The profile is specified as a file path relative to the SYSVOL/ubuntu/apparmor/ directory.
On the client machine, user profiles are stored in /etc/apparmor.d/adsys/users/<user-name>, thus the administrator can reference abstractions and tunables shipped with the client distribution of AppArmor.

The profile will ideally contain a mapping between a user and a role. Roles must be configured beforehand in the System-wide application confinement section.
Below is an example of a user profile declaration:

  include <abstractions/authentication>
  include <abstractions/nameservice>

  capability dac_override,
  capability setgid,
  capability setuid,
  /etc/default/su r,
  /etc/environment r,
  @{HOMEDIRS}/.xauth* w,
  /usr/bin/{,b,d,rb}ash Px -> default_user,
  /usr/bin/{c,k,tc}sh Px -> default_user,

The GPO client will wrap this into an apparmor block declaration containing the client username. The default_user role must be declared beforehand in the Machine section. More details and examples can be found in the apparmor section of the adsys documentation.

The configured profile will override any profile referenced higher in the GPO hierarchy.


- Type: apparmor
- Key: /apparmor-users

Note: -
 * Enabled: The profile in the text entry is applied on the client machine.
 * Disabled: The profile is removed from the target machine, and any related rules are unloaded.
 * Not configured: A profile declared higher in the GPO hierarchy will be used if available.


Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Session management -> User application confinement -> AppArmor    |
| Registry Key | Software\Policies\Ubuntu\apparmor\apparmor-users         |
| Element type | text |
| Class:       | User       |
