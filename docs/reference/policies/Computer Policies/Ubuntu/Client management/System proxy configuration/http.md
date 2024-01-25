# HTTP Proxy

Declare system-wide HTTP proxy setting. The value must be in the form of:

  protocol://username:password@host:port

It is not mandatory to escape special characters in the username or password. The GPO client will escape any unescaped special character before applying the proxy settings, and will take care not to double-escape already escaped characters. An empty value will remove previously set settings of the same type.


- Type: proxy
- Key: /proxy/http

Note: -
 * Enabled: The setting in the text entry is applied on the client machine.
 * Disabled: The setting is removed from the target machine.
 * Not configured: A setting declared higher in the GPO hierarchy will be used if available.


Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> System proxy configuration -> HTTP Proxy    |
| Registry Key | Software\Policies\Ubuntu\proxy\proxy\http         |
| Element type | text |
| Class:       | Machine       |
