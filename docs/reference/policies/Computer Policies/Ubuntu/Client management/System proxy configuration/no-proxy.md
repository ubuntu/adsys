# Ignored hosts

An array of hosts allowed to bypass the proxy settings. The host exclusion setting must be in the form of:

localhost,127.0.0.1,::1

Hosts can be individually wrapped in single (') or double quotes ("), or separated by spaces. An empty value will remove previously set settings of the same type.


- Type: proxy
- Key: /proxy/no-proxy

Note: -
 * Enabled: The setting in the text entry is applied on the client machine.
 * Disabled: The setting is removed from the target machine.
 * Not configured: A setting declared higher in the GPO hierarchy will be used if available.


Supported on Ubuntu 20.04, 22.04, 23.10, 24.04, 24.10.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> System proxy configuration -> Ignored hosts    |
| Registry Key | Software\Policies\Ubuntu\proxy\proxy\no-proxy         |
| Element type | text |
| Class:       | Machine       |
