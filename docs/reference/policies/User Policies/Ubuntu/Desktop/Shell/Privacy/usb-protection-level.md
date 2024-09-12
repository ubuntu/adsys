# When USB devices should be rejected

If set to “lockscreen”, only when the lock screen is present new USB devices will be rejected; if set to “always”, all new USB devices will always be rejected.

- Type: dconf
- Key: /org/gnome/desktop/privacy/usb-protection-level
- Default: 'lockscreen'

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 24.04, 24.10.

<span style="font-size: larger;">**Valid values**</span>

* lockscreen
* always


<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Desktop -> Shell -> Privacy -> When USB devices should be rejected    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\desktop\privacy\usb-protection-level         |
| Element type | dropdownList |
| Class:       | User       |
