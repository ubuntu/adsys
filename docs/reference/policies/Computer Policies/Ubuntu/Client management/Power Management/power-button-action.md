# Power button action

The action to take when the system power button is pressed. Virtual machines only honor the 'nothing' action, and will shutdown otherwise. Tablets always suspend, ignoring all the other action options.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/power-button-action
- Default: 'interactive'

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.

<span style="font-size: larger;">**Valid values**</span>

* nothing
* suspend
* hibernate
* interactive


<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Power Management -> Power button action    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\power-button-action         |
| Element type | dropdownList |
| Class:       | Machine       |
