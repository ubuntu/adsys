# User mounts

Define network shares that will be mounted for the client.
If more shares are defined higher the GPO hierarchy, the entries listed here will be appended to the list and duplicates will be removed.

Values should be in the format: 
    <protocol>://<hostname-or-ip>/<shared-dir>
e.g.
    nfs://example_nfs.com/nfs_shared_dir
    smb://example_smb.com/smb_shared_dir
    ftp://ftp_share_server.com

This pattern must be followed, otherwise the policy will not be applied.

By the default, the mounts will be done in anonymous mode. In case of authentication needed, a krb5 tag can be added to the value, e.g.
    `[krb5]`<protocol>://<hostname-or-ip>/<shared-dir>

If the tag is added, the mount will require Kerberos authentication in order to occur.

The supported protocols are the same as the ones supported by gvfs.
They are listed on the man page of gvfs, under the gvfs-backends section: https://manpages.ubuntu.com/manpages/jammy/en/man7/gvfs.7.html
It's up to the user to ensure that the requested protocols are valid and supported and that the shared directories have the correct configuration for the requested connection.


- Type: mount
- Key: /user-mounts

Note: 
 * Enabled: The value(s) referenced in the entry are applied on the client machine.
 * Disabled: The value(s) are removed from the target machine.
 * Not configured: Value(s) declared higher in the GPO hierarchy will be used if available.

Supported on Ubuntu 20.04, 22.04, 23.10, 24.04.

An Ubuntu Pro subscription on the client is required to apply this policy.



<span style="font-size: larger;">**Metadata**</span>

| Element      | Value            |
| ---          | ---              |
| Location     | User Policies -> Ubuntu -> Session management -> User Drive Mapping -> User mounts    |
| Registry Key | Software\Policies\Ubuntu\mount\user-mounts         |
| Element type | multiText |
| Class:       | User       |
