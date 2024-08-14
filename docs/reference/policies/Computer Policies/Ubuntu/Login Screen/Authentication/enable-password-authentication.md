# Whether or not to allow passwords for login

The login screen can be configured to disallow password authentication, forcing the user to use smartcard or fingerprint authentication.

- Type: dconf
- Key: /org/gnome/login-screen/enable-password-authentication
- Default: true

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 24.04, 24.10.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value                          |
| ---          | ---                            |
| Location     | <code>Computer Policies -> Ubuntu -> Login Screen -> Authentication -> Whether or not to allow passwords for login</code>     |
| Registry Key | <code>Software\Policies\Ubuntu\gdm\dconf\org\gnome\login-screen\enable-password-authentication</code>          |
| Element type | boolean               |
| Class:       | Machine                     |
