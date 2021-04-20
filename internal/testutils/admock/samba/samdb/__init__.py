import ldb
from collections import namedtuple
import os
from socket import gethostname


class AccountSearch(dict):
    def __init__(self, dn, objectClass, objectSid):
        self.dn = dn
        dict.__setitem__(self, "objectClass", objectClass)
        dict.__setitem__(self, "objectSid", objectSid)

class GPOSearch(dict):
    def __init__(self, name, displayName, flags, nTSecurityDescriptor, gPCFileSysPath):
        self.dn = name
        dict.__setitem__(self, "name", name)
        dict.__setitem__(self, "displayName", [displayName])
        dict.__setitem__(self, "flags", flags)
        dict.__setitem__(self, "nTSecurityDescriptor", nTSecurityDescriptor)
        dict.__setitem__(self, "gPCFileSysPath", gPCFileSysPath)

class SamDB:
    def __init__(self, url=None, session_info=None, credentials=None, lp=None):
        self.lp = lp
        if url == "ldap://unreachable_url":
            raise Exception("Unreachable ldap url requested")

        krb5ccname = os.getenv("KRB5CCNAME")
        if not krb5ccname:
            raise Exception("$KRB5CCNAME is not set")

        if 'invalid' in krb5ccname:
            raise Exception("Invalid Kerberos Ticket")


    def search(self, expression="", attrs=[], base="", scope=ldb.SCOPE_BASE, controls=""):
        # User/Machine search
        if "samAccountName" in expression:
            accountName = str(expression)[len("(&(|(samAccountName="):].split(")")[0]
            if accountName == "nonexistent":
                return []

            objectClass = b"user"
            if accountName.startswith("hostname") or accountName == gethostname():
                objectClass = b"computer"

            return [AccountSearch(accountName, objectClass, ["S-1-5-21-16178157-162784614-155579044-1103"])]

        # Group search
        elif "objectClass=group" in expression:
            return [{"objectSid": ["SidGroup1"]},{"objectSid": ["SidGroup2"]}]

        # OU search
        elif "gPLink" in attrs:
            ou = ldb.OUs[base.strdn]
            r = {'gPLink': ou.gPLink}
            if hasattr(ou, 'gPOptions'):
                r['gPOptions'] = ou.gPOptions
            return [r]


        # GPO Attribute
        gpo = ldb.GPOs[base]
        if gpo.nTSecurityDescriptor[0] == "MISSING":
            raise "nTSecurityDescriptor not available as requested"
        return [GPOSearch(gpo.name, gpo.display_name, gpo.flags, gpo.nTSecurityDescriptor, gpo.gPCFileSysPath)]


    def get_default_basedn(self):
        return ldb.OUs["/warthogs"]

