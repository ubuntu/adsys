# Case of the security policy

Certain group policies are directly managed by **SSSD**. In such instances, **ADSys** is not involved at all. This is applicable to **Security Settings**.

In Windows Group Policy Management Editor,you can locate these keys at `[FOREST.ROOT] > Computer Configuration > Windows Settings > Security Settings`

Below is a table providing a non-comprehensive list of Security Settings defined in Windows, which are not managed by ADSys but receive partial support through SSSD.

| Windows Setting |
| --------------- |
|**Account Policies > Password Policy**|
|Enforce password history|
|Maximum password age|
|Minimum password age|
|Minimum password length|
|Password must meet complexity requirements|
|**Account Policies > Account Lockout Policy**|
|Account lockout duration|
|Account lockout threshold|
|Reset account lockout counter after|
|**Local Policies > User Rights Assignment**|
|Access this computer from the network|
|Allow log on locally|
|Allow log on through Remote Desktop Services|
|Change the system time|
|Change the timezone|
|Deny access to this computer from the network|
|Deny log on as a batch job|
|Deny log on as a service|
|Deny log on locally|
|Deny log on through Remote Desktop Services|
|Log on as a batch job|
|Log on as a service|
|Shutdown the system|
|**Local Policies / Security Options**|
|Administrator account status|
|Shutdown: Allow system to be shut down without having to log on|

Get more information on [SSSD](https://sssd.io/).
