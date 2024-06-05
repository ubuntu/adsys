# Laptop lid close action when on AC

The action to take when the laptop lid is closed and the laptop is on AC power.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/lid-close-ac-action
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
| Location     | Computer Policies -> Ubuntu -> Client management -> Power Management -> Laptop lid close action when on AC    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\lid-close-ac-action         |
| Element type | dropdownList |
| Class:       | Machine       |
