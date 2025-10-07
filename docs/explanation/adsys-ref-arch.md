(ref::adsys-arch)=
# ADSys architecture

Here, we explain ADSys and SSSD, and how they are used in combination for
managing authentication and policies.

## ADSys and SSSD

ADSys is a GPO client. In an AD-managed infrastructure, it can help with the
management and control of Ubuntu clients through the AD controller. It
compliments and depends on SSSD, which is a daemon that handles authentication
and provides authorization to access remote directories, including AD. ADSys
can also be used in combination with Winbind, but here we will focus on SSSD.

SSSD runs on the client Ubuntu machine and enables basic authentication with AD.
When a client machine that is enrolled in the domain attempts to log in, SSSD
sends the user’s information to the AD controller. If the credentials are
valid, they are returned to SSSD. This allows the user to successfully
authenticate.

```{tip}
The diagrams on this page can be zoomed with a scroll-wheel
or panned by clicking and dragging the left mouse button.
```

```{mermaid} ../diagrams/arch-sssd.mmd
:zoom:
:align: center
```

After the user is authenticated, ADSys queries the provider for policies that
are directed to the authenticated user in the AD domain and resolves them,
before applying the policies to the client.

```{mermaid} ../diagrams/arch-adsys.mmd
:zoom:
:align: center
```

## Authentication and policy flow

A detailed visual explanation of the authentication and policy flow with ADSys
and SSSD is shown below:

```{mermaid} ../diagrams/arch-state.mmd
:zoom:
:align: center
```

SSSD manages the enrollment and authentication of clients with AD. If ADSys is
not installed, the control and management of AD clients stops at that point.

If ADSys is installed, it checks whether GPOs on the client are up-to-date. If
not, they are fetched from the domain controller. Once the latest GPOs are
available, they are parsed and applied. The user then authenticates
successfully and the GPOs are applied. If the GPOs are not applied and they are
enforced, then ADSys will not permit the session to continue.

