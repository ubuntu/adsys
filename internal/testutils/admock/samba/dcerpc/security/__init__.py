# TiCS: disabled # samba mock

descriptor = "SECURITY_DESCRIPTOR"


class dom_sid:
    ''' Minimal stand-in for samba.dcerpc.security.dom_sid. '''
    def __init__(self, sid=""):
        self.sid = sid

    def __str__(self):
        return str(self.sid)


class token:
    ''' Minimal stand-in for samba.dcerpc.security.token. '''
    def __init__(self):
        self.sids = []

SECINFO_OWNER = 1<<0
SECINFO_GROUP = 1<<1
SECINFO_DACL = 1<<2

SEC_STD_READ_CONTROL = 1<<0
SEC_ADS_LIST = 1<<1
SEC_ADS_READ_PROP = 1<<2
