# Allow local administrators

This allows or prevents client machine to have local users gaining administrators privilege on the machine.


- Type: privilege
- Key: /allow-local-admins

Note: -
 * Enabled: This leaves the default rules for the “sudo” and “admin” rule intact.
 * Disabled: This denies root privileges to the predefined administrator groups (sudo and admin).


An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | Computer Policies -> Ubuntu -> Client management -> Privilege Authorization -> Allow local administrators    |
| Registry Key | Software\Policies\Ubuntu\privilege\allow-local-admins         |
| Element type |  |
| Class:       | Machine       |
