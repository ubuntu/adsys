# Client administrators

Define users and groups from AD allowed to administer client machines.
One entry per line, prefixed with % for a group. Use the account names as they appear on the client: user@domain and %group@domain when SSSD uses fully qualified names (the default), user and %group when use_fully_qualified_names is set to False in sssd.conf.


- Type: privilege
- Key: /client-admins

Note: -
 * Enabled: This allows defining Active Directory groups and users with administrative privileges in the box entry.
 * Disabled: This disallows any Active Directory group or user to become an administrator of the client even if it is defined in a parent GPO of the hierarchy tree.


An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Privilege Authorization -> Client administrators    |
| Registry Key | Software\Policies\Ubuntu\privilege\client-admins         |
| Element type | multiText |
| Class:       | Machine       |
