# Laptop lid, when closed, will suspend even if there is an external monitor plugged in

With no external monitors plugged in, closing a laptop's lid will suspend the machine (as set by the lid-close-battery-action and lid-close-ac-action keys).  By default, however, closing the lid when an external monitor is present will not suspend the machine, so that one can keep working on that monitor (e.g. for docking stations or media viewers).  Set this key to False to keep the default behavior, or to True to suspend the laptop whenever the lid is closed and regardless of external monitors.

- Type: dconf
- Key: /org/gnome/settings-daemon/plugins/power/lid-close-suspend-with-external-monitor
- Default: false

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Power Management -> Laptop lid, when closed, will suspend even if there is an external monitor plugged in    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\settings-daemon\plugins\power\lid-close-suspend-with-external-monitor         |
| Element type | boolean |
| Class:       | Machine       |
