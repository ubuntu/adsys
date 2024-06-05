# Sleep timeout computer when on battery

The amount of time in seconds the computer on battery power needs to be inactive before it goes to sleep. A value of 0 means never.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-timeout
- Default for 20.04: 1200
- Default for 22.04: 1200
- Default for 23.10: 900
- Default for 24.04: 900
- Default for 24.10: 900

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Power Management -> Sleep timeout computer when on battery    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\sleep-inactive-battery-timeout         |
| Element type | decimal |
| Class:       | Machine       |
