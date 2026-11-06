# TiCS: disabled # samba mock

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
        # The Global Catalog uses 3268 for LDAP and 3269 for LDAPS. Remember
        # which view this connection targets so tokenGroups reflect the
        # difference between forest-wide and domain-local memberships.
        self.is_global_catalog = bool(url) and (url.endswith(":3268") or url.endswith(":3269"))
        scheme = ""
        host = ""
        if url and "://" in url:
            scheme, host = url.split("://", 1)

        expected_transport = os.getenv("ADSYS_TESTS_EXPECT_LDAP_TRANSPORT")
        if expected_transport:
            expected_scheme = "ldaps" if expected_transport == "ldaps" else "ldap"
            if scheme != expected_scheme:
                raise Exception("Expected %s URL, got %s" % (expected_scheme, url))
            expected_gc_port = "3269" if expected_transport == "ldaps" else "3268"
            if self.is_global_catalog and not url.endswith(":" + expected_gc_port):
                raise Exception("Expected Global Catalog port %s, got %s" % (expected_gc_port, url))
            if expected_transport == "starttls" and lp.values.get("client ldap sasl wrapping") != "starttls":
                raise Exception("StartTLS was not configured in LoadParm")
            if expected_transport == "ldap" and lp.values:
                raise Exception("Plain LDAP must not set LoadParm options")
            if expected_transport in ("ldaps", "starttls"):
                if not lp.values.get("tls cafile") or not lp.values.get("tls verify peer"):
                    raise Exception("LDAP TLS trust was not configured in LoadParm")
                if "tls crlfile" in lp.values and lp.values.get("tls verify peer") != "as_strict_as_possible":
                    raise Exception("CRL verification did not use strict TLS peer verification")
                if "tls crlfile" not in lp.values and lp.values.get("tls verify peer") != "ca_and_name":
                    raise Exception("TLS without a CRL must use CA-and-name verification")

        if scheme in ("ldap", "ldaps") and host.startswith("NT_STATUS_"):
            raise Exception(1, "ldap/ldb error: %s" % host)

        simulated_status = os.getenv("ADSYS_TESTS_SAMDB_STATUS")
        if self.is_global_catalog:
            simulated_status = os.getenv("ADSYS_TESTS_GC_STATUS", simulated_status)
        if simulated_status:
            raise Exception(1, "ldap/ldb error: %s" % simulated_status)

        krb5ccname = os.getenv("KRB5CCNAME")
        if not krb5ccname:
            raise Exception("$KRB5CCNAME is not set")
        # krb5ccname does not need to start with FILE:
        # the samba bindings knows how to deal with it.
        if krb5ccname.startswith("FILE:"):
            krb5ccname = krb5ccname[5:]
        if not os.path.exists(krb5ccname):
            raise Exception("KRB5CCNAME ticket does not exists")

        with open(krb5ccname, 'r') as f:
            if 'invalid' in f.readline():
                raise Exception("Invalid Kerberos Ticket")


    def search(self, expression="", attrs=[], base="", scope=ldb.SCOPE_BASE, controls=""):
        # User/Machine search
        if "samAccountName" in expression:
            accountName = str(expression)[len("(&(|(samAccountName="):].split(")")[0]
            if accountName == "connectionDropDuringAccountLookup":
                raise Exception(1, "ldap/ldb error: NT_STATUS_CONNECTION_REFUSED")
            # Only the truncated name exists
            if accountName == "nonexistent" or accountName == "hostnameWithTruncatedLongName":
                return []

            objectClass = b"user"
            if accountName.startswith("hostname") or accountName == gethostname():
                objectClass = b"computer"

            return [AccountSearch(accountName, objectClass, ["S-1-5-21-16178157-162784614-155579044-1103"])]

        elif "userPrincipalName" in expression:
            return []

        # Group search
        elif "objectClass=group" in expression:
            return [{"objectSid": ["SidGroup1"]},{"objectSid": ["SidGroup2"]}]

        # Token groups search. The Global Catalog and the domain controller
        # return different memberships (forest-wide universal vs domain-local),
        # so the result depends on which directory this connection targets.
        elif "tokenGroups" in attrs:
            return [{"tokenGroups": ldb.token_groups_for(base, self.is_global_catalog)}]

        # Primary group lookup, used by the tokenGroups fallback to add the
        # primary group (Domain Computers, RID 515) that tokenGroups omits.
        elif "primaryGroupID" in attrs:
            return [{"primaryGroupID": [b"515"]}]

        # OU search
        elif "gPLink" in attrs:
            ou = ldb.OUs[base.strdn]
            if getattr(ou, "transport_error", False):
                raise Exception(1, "ldap/ldb error: NT_STATUS_CONNECTION_DISCONNECTED")
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
        return ldb.OUs["/example"]
