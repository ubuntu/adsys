# Disable saving files to disk

Prevent the user from saving files to disk. For example, this would disable access to all applications’ “Save as” dialogs.

- Type: dconf
- Key: /org/gnome/desktop/lockdown/disable-save-to-disk
- Default: false

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Desktop -> Shell -> LockDown -> Disable saving files to disk    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\desktop\lockdown\disable-save-to-disk         |
| Element type | boolean |
| Class:       | User       |
