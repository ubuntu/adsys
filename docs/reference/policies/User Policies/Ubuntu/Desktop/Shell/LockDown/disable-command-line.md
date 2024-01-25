# Disable command line

Prevent the user from accessing the terminal or specifying a command line to be executed. For example, this would disable access to the panel’s “Run Application” dialog.

- Type: dconf
- Key: /org/gnome/desktop/lockdown/disable-command-line
- Default: false

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Desktop -> Shell -> LockDown -> Disable command line    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\desktop\lockdown\disable-command-line         |
| Element type | boolean |
| Class:       | User       |
