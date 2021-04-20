from samba.dcerpc import security

def ndr_unpack(dom_sid, object_sid):
    if dom_sid == security.descriptor:
        return WrapSecDesc(object_sid)
    return object_sid

class WrapSecDesc:
    def __init__(self, secdesc):
        self.secdesc = secdesc

    def as_sddl(self):
        return self.secdesc
