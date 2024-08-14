# Allow local administrators

This allows or prevents client machine to have local users gaining administrators privilege on the machine.


- Type: privilege
- Key: /allow-local-admins

Note: -
 * Enabled: This leaves the default rules for the “sudo” and “admin” rule intact.
 * Disabled: This denies root privileges to the predefined administrator groups (sudo and admin).


An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value                          |
| ---          | ---                            |
| Location     | <code>Computer Policies -> Ubuntu -> Client management -> Privilege Authorization -> Allow local administrators</code>     |
| Registry Key | <code>Software\Policies\Ubuntu\privilege\allow-local-admins</code>          |
| Element type |                |
| Class:       | Machine                     |
