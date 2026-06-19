# TiCS: disabled # samba mock

# SDDL aliases for the default well-known SIDs the LSA injects into a token.
# Real descriptors reference them as aliases, so we map them back to verify a
# token assembled from raw SIDs is granted read like AD would compute it.
_SID_ALIASES = {"S-1-1-0": "WD", "S-1-5-2": "NW", "S-1-5-11": "AU"}


def access_check(secdesc, token, flag):
    if secdesc.secdesc == "FAILED":
        raise RuntimeError("access_check() failed requested")

    # Resolve the token to the trustee names used in the descriptor and grant
    # access only if an allow ACE matches, mirroring AD: a token missing the
    # default groups (e.g. World) fails read on a GPO scoped to Everyone.
    trustees = set(str(s) for s in token.sids)
    trustees.update(_SID_ALIASES[s] for s in list(trustees) if s in _SID_ALIASES)
    for ace in secdesc.secdesc.split('(')[1:]:
        access, _, _, _, _, trustee = ace.rstrip(')').split(';')
        if access in ("A", "OA") and trustee in trustees:
            return
    raise RuntimeError("access_check() denied: token grants no read on descriptor")
