# Enable power-saver profile when battery is low

Automatically enable the "power-saver" profile using power-profiles-daemon if the battery is low.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/power-saver-profile-on-low-battery
- Default: true

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 22.04, 23.10, 24.04.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Power Management -> Enable power-saver profile when battery is low    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\power-saver-profile-on-low-battery         |
| Element type | boolean |
| Class:       | Machine       |
