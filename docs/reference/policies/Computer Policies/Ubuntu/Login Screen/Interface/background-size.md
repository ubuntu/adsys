# The background-size property specifies the size of the background image.

The background-size property specifies the size of the background images.  There are three keywords you can use with this property: auto: The background image is displayed in its original size; cover: Resize the background image to cover the entire container, even if it has to stretch the image or cut a little bit off one of the edges; contain: Resize the background image to make sure the image is fully visible.  It overrides the value defined in the default style sheet.

- Type: dconf
- Key: /com/ubuntu/login-screen/background-size
- Default: 'default'

Note: default system value is used for "Not Configured" and enforced if "Disabled".

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.

<span style="font-size: larger;">**Valid values**</span>

* default
* auto
* cover
* contain


<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Login Screen -> Interface -> The background-size property specifies the size of the background image.    |
| Registry Key | Software\Policies\Ubuntu\gdm\dconf\com\ubuntu\login-screen\background-size         |
| Element type | dropdownList |
| Class:       | Machine       |
