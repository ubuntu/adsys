# TiCS: disabled # samba mock

import ldb
from samba.dcerpc import security

AUTH_SESSION_INFO_DEFAULT_GROUPS = 1 << 0
AUTH_SESSION_INFO_AUTHENTICATED = 1 << 1
AUTH_SESSION_INFO_SIMPLE_PRIVILEGES = 1 << 2

# Object SID the mock assigns to every account (matches samba.samdb get_entity).
_OBJECT_SID = "S-1-5-21-16178157-162784614-155579044-1103"

# Default well-known SIDs the LSA injects into an authenticated session token.
_DEFAULT_SIDS = ("S-1-1-0", "S-1-5-2", "S-1-5-11")


def system_session():
    return

class Session:
    def __init__(self):
        self.security_token = b""

def user_session(samdb, lp_ctx, dn, session_info_flags):
    ''' Builds the security token AD would compute for the account.

    Mirrors samba.auth.user_session(): the object SID, its full (Global Catalog
    and domain controller) group membership, and the default well-known SIDs.
    Accounts registered in ldb.user_session_failures reproduce the multi-domain
    referral crash where the real user_session() raises and the script must fall
    back to assembling the token from tokenGroups. '''
    if str(dn).lower() in ldb.user_session_failures:
        raise RuntimeError("user_session() failed: NT_STATUS_NOT_SUPPORTED (simulated multi-domain referral)")

    group_sids = ldb.token_groups_for(dn, True) + ldb.token_groups_for(dn, False)
    token = security.token()
    sids = ([security.dom_sid(_OBJECT_SID)]
            + [security.dom_sid(str(s)) for s in group_sids]
            + [security.dom_sid(s) for s in _DEFAULT_SIDS])
    token.sids = sids
    # Real samba keeps num_sids separate from the assigned array; set it so the
    # token is not treated as empty (see samba.dcerpc.security.token mock).
    token.num_sids = len(sids)
    session = Session()
    session.security_token = token
    return session
