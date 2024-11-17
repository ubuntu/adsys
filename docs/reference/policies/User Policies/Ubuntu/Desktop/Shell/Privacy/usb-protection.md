# Whether to protect USB devices

If the USBGuard service is present and this setting is enabled, USB devices will be protected as configured in the usb-protection-level setting.

- Type: dconf
- Key: /org/gnome/desktop/privacy/usb-protection
- Default for 20.04: false
- Default for 22.04: true
- Default for 24.04: true
- Default for 24.10: true
- Default for 25.04: true

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 24.04, 24.10, 25.04.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Desktop -> Shell -> Privacy -> Whether to protect USB devices    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\desktop\privacy\usb-protection         |
| Element type | boolean |
| Class:       | User       |
