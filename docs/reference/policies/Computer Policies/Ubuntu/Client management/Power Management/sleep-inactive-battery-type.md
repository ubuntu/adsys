# Whether to hibernate, suspend or do nothing when inactive

The type of sleeping that should be performed when the computer is inactive.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/sleep-inactive-battery-type
- Default: 'suspend'

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.

<span style="font-size: larger;">**Valid values**</span>

* blank
* suspend
* shutdown
* hibernate
* interactive
* nothing
* logout


<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Power Management -> Whether to hibernate, suspend or do nothing when inactive    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\sleep-inactive-battery-type         |
| Element type | dropdownList |
| Class:       | Machine       |
