# Admin privileges management

The Admin privilege manager allows to grant or revoke superuser privileges for the default local user, and Active Directory users and groups.

All those settings are globally enforced on the machine and are available at `Computer Configuration > Policies > Administrative Templates > Ubuntu > Client management > Privilege Authorization`.

![Privileges screen in AD](../images/explanation/privileges/privileges-options.png)

## Feature availability

This feature is available only for subscribers of **Ubuntu Pro**.

## Rules precedence

Any settings will override the same settings in less specific GPO.

## What does "administrator" means?

Administrators:

* Can get administrators privileges and ran commands as such with `sudo`.
* Are considered **admin** for all `polkit` actions. If the current user is not an admin and a particular daemon require polkit administrator privilege, a prompt will allow you to choose an existing administrators to authenticate before performing the action.

## Local user

Members of the local sudo group are administrators by default on the machine.

### Not Configured or enabled

This status keep the default for the system: `sudo` group members are considered administrators on the client.

### Disabled

`sudo` group members are not considered administrators on the client.

```{note}
You can grant specific users not necessarily in the `sudo` group administrator privileges with the "Client administrator option".
```

## Active Directory users and groups

Users and groups in the directory can be granted administrator privileges of the local machine with `sudo`.

Several users or groups or a set of both can be assigned.

The form is a list of users and group, one per line, `user@domain` for a user and `%group@domain` for a group.

### Not Configured or disabled

There is no AD user or group configured with admin privileges for the machine.

### Enabled

There is one or several AD user or group configured with admin privileges for the machine via the list under it.

> Note: you can use this list to grant non-default local users matching the name on the client.
