# Disable print setup

Prevent the user from modifying print settings. For example, this would disable access to all applications’ “Print Setup” dialogs.

- Type: dconf
- Key: /org/gnome/desktop/lockdown/disable-print-setup
- Default: false

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Desktop -> Shell -> LockDown -> Disable print setup    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\desktop\lockdown\disable-print-setup         |
| Element type | boolean |
| Class:       | User       |
