# Autoconfiguration URL

Declare system-wide proxy autoconfiguration URL.

Autoconfiguration URLs are always prioritzed over manual proxy settings, meaning that if all proxy options are set, the GPO client will enable automatic proxy configuration for supported backends. An empty value will remove previously set settings of the same type.


- Type: proxy
- Key: /proxy/auto

Note: -
 * Enabled: The setting in the text entry is applied on the client machine.
 * Disabled: The setting is removed from the target machine.
 * Not configured: A setting declared higher in the GPO hierarchy will be used if available.


Supported on Ubuntu 20.04, 22.04, 23.04, 23.10.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> System proxy configuration -> Autoconfiguration URL    |
| Registry Key | Software\Policies\Ubuntu\proxy\proxy\auto         |
| Element type | text |
| Class:       | Machine       |
