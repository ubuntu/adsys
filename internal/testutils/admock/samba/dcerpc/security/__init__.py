# TiCS: disabled # samba mock

descriptor = "SECURITY_DESCRIPTOR"


class dom_sid:
    ''' Minimal stand-in for samba.dcerpc.security.dom_sid. '''
    def __init__(self, sid=""):
        self.sid = sid

    def __str__(self):
        return str(self.sid)


class token:
    ''' Minimal stand-in for samba.dcerpc.security.token.

    Reproduces a real samba quirk that a naive mock would hide: assigning .sids
    stores the SID array but leaves num_sids untouched, and both
    samba.security.access_check() and the .sids getter only ever see the first
    num_sids entries. Callers must set .num_sids explicitly -- exactly as real
    samba requires -- otherwise a token assembled from raw SIDs is silently
    empty and grants no access. '''
    def __init__(self):
        self._sids = []
        self.num_sids = 0

    @property
    def sids(self):
        return self._sids[:self.num_sids]

    @sids.setter
    def sids(self, value):
        # Like real samba: store the array but do not touch num_sids.
        self._sids = list(value)

SECINFO_OWNER = 1<<0
SECINFO_GROUP = 1<<1
SECINFO_DACL = 1<<2

SEC_STD_READ_CONTROL = 1<<0
SEC_ADS_LIST = 1<<1
SEC_ADS_READ_PROP = 1<<2
