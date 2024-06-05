# The background-repeat property sets if/how the background image will be repeated.

The background-repeat property sets if/how a background image will be repeated. By default, a background-image is repeated both vertically and horizontally.  It overrides the value defined in the default style sheet.

- Type: dconf
- Key: /com/ubuntu/login-screen/background-repeat
- Default: 'default'

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.

<span style="font-size: larger;">**Valid values**</span>

* default
* repeat
* repeat-x
* repeat-y
* no-repeat
* space
* round


<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Login Screen -> Interface -> how the background image will be repeated.    |
| Registry Key | Software\Policies\Ubuntu\gdm\dconf\com\ubuntu\login-screen\background-repeat         |
| Element type | dropdownList |
| Class:       | Machine       |
