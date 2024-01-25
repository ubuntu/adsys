# Whether or not to allow passwords for login

The login screen can be configured to disallow password authentication, forcing the user to use smartcard or fingerprint authentication.

- Type: dconf
- Key: /org/gnome/login-screen/enable-password-authentication
- Default: true

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Login Screen -> Authentication -> Whether or not to allow passwords for login    |
| Registry Key | Software\Policies\Ubuntu\gdm\dconf\org\gnome\login-screen\enable-password-authentication         |
| Element type | boolean |
| Class:       | Machine       |
