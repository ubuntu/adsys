# Whether to hibernate, suspend or do nothing when inactive

The type of sleeping that should be performed when the computer is inactive.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/sleep-inactive-ac-type
- Default: 'suspend'

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 24.04, 24.10.

<span style="font-size: larger;">**Valid values**</span>

* blank
* suspend
* shutdown
* hibernate
* interactive
* nothing
* logout


<span style="font-size: larger;">**Metadata**</span>

| Element      | Value                          |
| ---          | ---                            |
| Location     | <code>Computer Policies -> Ubuntu -> Client management -> Power Management -> Whether to hibernate, suspend or do nothing when inactive</code>     |
| Registry Key | <code>Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\sleep-inactive-ac-type</code>          |
| Element type | dropdownList               |
| Class:       | Machine                     |
