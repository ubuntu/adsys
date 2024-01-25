# Disable user administration

Stop the user from modifying user accounts. By default, we allow adding and removing users, as well as changing other users settings.

- Type: dconf
- Key: /org/gnome/desktop/lockdown/user-administration-disabled
- Default: false

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Desktop -> Shell -> LockDown -> Disable user administration    |
| Registry Key | Software\Policies\Ubuntu\dconf\org\gnome\desktop\lockdown\user-administration-disabled         |
| Element type | boolean |
| Class:       | User       |
