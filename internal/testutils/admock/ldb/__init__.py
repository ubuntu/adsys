
from samba import dsdb

from os import getenv, getuid, path
from pwd import getpwuid
from socket import gethostname

SCOPE_BASE = ""

def binary_encode(s):
    return s

OUs = {}
GPOs = {}
accounts = {}

##############################
# OU=RnD,OU=IT Dept,DC=domain,DC=com

#  /example
#            -- Default Domain Policy    <- UserAtRoot
#  /example/IT
##            -- IT GPO
#  /example/IT/ITDep1                   <- hostname1   <- hostnameWithTru // truncated computer name
#                                                      <- hostnameWithLongName // untruncated computerLongNameme
##            -- ITDep1 GPO
#  /example/IT/ITDep2                   <- hostname2
##            -- ITDep2 User only GPO                                 <- machine flag disabled
#  /example/RnD                         <- RnDUser
##            -- RnD GPO
#  /example/RnD/RnDDep1                 <- RnDUserDep1
##            -- RnDDep1 GPO1
##            -- RnDDep1 GPO2
#  /example/RnD/RnDDep2
##            -- RnDDep2 GPO
##            -- RnDDep2 Forced GPO                                   <- forced GPO
#  /example/RnD/RnDDep2/SubDep2ForcedPolicy     <- RndUserSubDep2ForcedPolicy
##            -- SubDep2ForcedPolicy Forced GPO                       <- forced GPO
#  /example/RnD/RnDDep2/SubDep2BlockInheritance                      <- block inheritance
##            -- SubDep2BlockInheritance GPO
#  /example/RnD/RnDDep2/SubDep2BlockInheritance/SubBlocked   <- RnDUserWithBlockedInheritanceAndForcedPolicies
##            -- SubBlocked GPO
#  /example/RnD/RnDDep3                 <- RnDUserDep3
##            -- RnDDep3 Disabled GPO                                 <- disabled gpo
##            -- RnDDep3 GPO
#  /example/RnD/RnDDep4                 <- RnDUserDep4
##            -- RnDDep4 Security descriptor missing GPO              <- security descriptor missing
#  /example/RnD/RnDDep5                 <- RnDUserDep5
##            -- RnDDep5 security access failed GPO                   <- security failed denied
#  /example/RnD/RnDDep6                 <- RnDUserDep6
##            -- RnDDep6 security access denied GPO                   <- security access denied
#  /example/RnD/RnDDep7                 <- RnDUserDep7
##            -- RnDDep7 machine only GPO                             <- user flag disabled
#  /example/RnD/RnDDep8                 <- RnDUserDep8
##            -- RnDDep8 allow for one user only GPO  <- RnDUserDep8  <- nTSecurityDescriptor allowed for another user that our one
#  /example/RnD/RnDDepBlockInheritance               <-RnDUserWithBlockedInheritance      <- block inheritance
##            -- RnDDepBlockInheritance GPO
#  /example/NoGPO                       <- UserNoGPO
#  /example/NogPOptions                 <- UserNogPOptions
##            -- NogPOptions GPO
#  /example/InvalidGPOLink              <- UserInvalidLink

#  /example/IntegrationTests/
#  /example/IntegrationTests/Dep1                          <-[CURRENT_HOSTNAME]
##            -- {C4F393CA-AD9A-4595-AEBC-3FA6EE484285} "GPO for current machine"
#  /example/IntegrationTests/Dep2                          <- MachineIntegrationTest
##            -- {B8D10A86-0B78-4899-91AF-6F0124ECEB48} "GPO for MachineIntegrationTest"
#  /example/IntegrationTests/UserDep                       <- UserIntegrationTest
##            -- {75545F76-DEC2-4ADA-B7B8-D5209FD48727} "GPO for Integration Test User"
#  /example/IntegrationTests/UserDep/UserDep1              <-[CURRENT_USER]
##            -- {5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242} "GPO1 for current User"
##            -- {073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04} "GPO2 for current User"

##############################

# Only called on user/machine, returns correct account object
def Dn(samdb, dn):
    return accounts[dn.lower()]


# OU themselves
class OU:
    def __init__(self, strdn):
        self.strdn = strdn
        self.gpos=[]

        self.gPLink = [b'']
        if path.basename(strdn) == "InvalidGPOLink":
            self.gPLink = [b'[invalidlink;0]']

        self.gPOptions = b'0'
        if path.basename(strdn) in ("SubDep2BlockInheritance", "RnDDepBlockInheritance"):
            self.gPOptions = [dsdb.GPO_BLOCK_INHERITANCE]
        if path.basename(strdn) == "NogPOptions":
            delattr(self, "gPOptions")
        if path.basename(strdn) == "NoGPOString":
            self.gPLink = [' ']

        OUs[strdn] = self

    def parent(self):
        ppath = path.dirname(self.strdn)
        if ppath == "":
            return None
        return OUs[ppath]

    def addGPO(self, gpo):
        self.gpos.append(gpo)
        gPLink = ""
        for gpo in self.gpos:
            global GPOs
            GPOs[gpo.name] = gpo
            state = 0
            if gpo.disabled:
                state = dsdb.GPLINK_OPT_DISABLE
            if gpo.enforced:
                state = dsdb.GPLINK_OPT_ENFORCE
            gPLink += "[LDAP://%s;%d]" % (gpo.name, state)
        self.gPLink = [gPLink]

    def addAccount(self, accountName):
        Account(accountName, self)


class GPO:
    def __init__(self, name, display_name=None):
        self.name = name.replace(" ", "_")
        self.display_name = name
        if display_name:
            self.display_name = display_name

        self.flags = [b'0']
        if name == "ITDep2 User only GPO":
            self.flags = [str.encode(str(dsdb.GPO_FLAG_MACHINE_DISABLE))]
        elif name == "RnDDep7 machine only GPO":
            self.flags = [str.encode(str(dsdb.GPO_FLAG_USER_DISABLE))]

        self.enforced = False
        if name == "RnDDep2 Forced GPO" or name == "SubDep2ForcedPolicy Forced GPO":
            self.enforced = True
        self.disabled = False
        if name == "RnDDep3 Disabled GPO":
            self.disabled = True

        self.nTSecurityDescriptor = ['O:S-1-5-21-16178157-162784614-155579044-512G:S-1-5-21-16178157-162784614-155579044-512D:PAI(D;;RPLCRC;;;S-1-5-21-16178157-162784614-155579044-1103)(OA;;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;S-1-5-21-16178157-162784614-155579044-1103)(A;;RPWPLCRC;;;S-1-5-21-16178157-162784614-155579044-1102)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-16178157-162784614-155579044-512)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-16178157-162784614-155579044-519)(A;CI;RPLCLORC;;;ED)(A;CI;RPLCLORC;;;AU)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CIIO;RPWPCCDCLCLORCWOWDSDDTSW;;;CO)']

        if name == "RnDDep4 Security descriptor missing GPO":
            self.nTSecurityDescriptor = ["MISSING"]
        if name == "RnDDep5 security access failed GPO":
            self.nTSecurityDescriptor = ["FAILED"]
        if name == "RnDDep6 security access denied GPO":
            self.nTSecurityDescriptor = [self.nTSecurityDescriptor[0].replace("OA", "OD")]
        if name == "RnDDep8 allow for one user only GPO":
            self.nTSecurityDescriptor = [self.nTSecurityDescriptor[0].replace("S-1-5-21-16178157-162784614-155579044-1103", "OtherUserSid")]

        smb_port = getenv("ADSYS_TESTS_SMB_PORT")
        if smb_port:
            smb_port = ":" + smb_port

        smb_domain = getenv("ADSYS_TESTS_MOCK_SMBDOMAIN")
        if not smb_domain:
            smb_domain="EMPTY_SMBDOMAIN"

        self.gPCFileSysPath = ['\\\\localhost%s\\SYSVOL\\%s\\Policies\\%s' % (smb_port, smb_domain, self.name)]


# Can be a User or a Computer
class Account:
    def __init__(self, name, dn):
        self.name = name
        self.parentDn = dn
        accounts[name.lower()] = self

    def parent(self):
        return self.parentDn


def getuserWithoutDomain():
    user = getpwuid(getuid())[0]
    if "@" not in user:
        return user
    return user[:user.index("@")]


# Build Domains
o = OU("/example")
o.addGPO(GPO("{31B2F340-016D-11D2-945F-00C04FB984F9}", display_name="Default Domain Policy"))
o.addAccount("UserAtRoot")

o = OU("/example/IT")
o.addGPO(GPO("IT GPO"))

o = OU("/example/IT/ITDep1")
o.addGPO(GPO("ITDep1 GPO"))
o.addAccount("hostname1")
o.addAccount("hostnameWithTru")
o.addAccount("hostnameWithLongName")

o = OU("/example/IT/ITDep2")
o.addGPO(GPO("ITDep2 User only GPO"))
o.addAccount("hostname2")

o = OU("/example/RnD")
o.addGPO(GPO("RnD GPO"))
o.addAccount("RnDUser")

o = OU("/example/RnD/RnDDep1")
o.addGPO(GPO("RnDDep1 GPO1"))
o.addGPO(GPO("RnDDep1 GPO2"))
o.addAccount("RnDUserDep1")

o = OU("/example/RnD/RnDDep2")
o.addGPO(GPO("RnDDep2 GPO"))
o.addGPO(GPO("RnDDep2 Forced GPO"))

o = OU("/example/RnD/RnDDep2/SubDep2ForcedPolicy")
o.addGPO(GPO("SubDep2ForcedPolicy Forced GPO"))
o.addAccount("RndUserSubDep2ForcedPolicy")

o = OU("/example/RnD/RnDDep2/SubDep2BlockInheritance")
o.addGPO(GPO("SubDep2BlockInheritance GPO"))

o = OU("/example/RnD/RnDDep2/SubDep2BlockInheritance/SubBlocked")
o.addGPO(GPO("SubBlocked GPO"))
o.addAccount("RnDUserWithBlockedInheritanceAndForcedPolicies")

o = OU("/example/RnD/RnDDep3")
o.addGPO(GPO("RnDDep3 Disabled GPO"))
o.addGPO(GPO("RnDDep3 GPO"))
o.addAccount("RnDUserDep3")

o = OU("/example/RnD/RnDDep4")
o.addGPO(GPO("RnDDep4 Security descriptor missing GPO"))
o.addAccount("RnDUserDep4")

o = OU("/example/RnD/RnDDep5")
o.addGPO(GPO("RnDDep5 security access failed GPO"))
o.addAccount("RnDUserDep5")

o = OU("/example/RnD/RnDDep6")
o.addGPO(GPO("RnDDep6 security access denied GPO"))
o.addAccount("RnDUserDep6")

o = OU("/example/RnD/RnDDep7")
o.addGPO(GPO("RnDDep7 machine only GPO"))
o.addAccount("RnDUserDep7")

o = OU("/example/RnD/RnDDep8")
o.addGPO(GPO("RnDDep8 allow for one user only GPO"))
o.addAccount("RnDUserDep8")

o = OU("/example/RnD/RnDDepBlockInheritance")
o.addGPO(GPO("RnDDepBlockInheritance GPO"))
o.addAccount("RnDUserWithBlockedInheritance")

o = OU("/example/NoGPO")
o.addAccount("UserNoGPO")

o = OU("/example/NoGPOString")
o.addAccount("UserNoGPOString")

o = OU("/example/NogPOptions")
o.addGPO(GPO("NogPOptions GPO"))
o.addAccount("UserNogPOptions")

o = OU("/example/InvalidGPOLink")
o.addAccount("UserInvalidLink")

# Integration tests OU and GPO
OU("/example/IntegrationTests")

o = OU("/example/IntegrationTests/Dep1")
o.addGPO(GPO("{C4F393CA-AD9A-4595-AEBC-3FA6EE484285}", display_name="GPO for current machine"))
o.addAccount(gethostname())

o = OU("/example/IntegrationTests/Dep2")
o.addGPO(GPO("{B8D10A86-0B78-4899-91AF-6F0124ECEB48}", display_name="GPO for MachineIntegrationTest"))
o.addAccount("MachineIntegrationTest")

o = OU("/example/IntegrationTests/UserDep")
o.addGPO(GPO("{75545F76-DEC2-4ADA-B7B8-D5209FD48727}", display_name="GPO for Integration Test User"))
o.addAccount("UserIntegrationTest")

o = OU("/example/IntegrationTests/UserDep/Dep1")
o.addGPO(GPO("{5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242}", display_name="GPO1 for current User"))
o.addGPO(GPO("{073AA7FC-5C1A-4A12-9AFC-42EC9C5CAF04}", display_name="GPO2 for current User"))
o.addAccount(getuserWithoutDomain())

# [b'[LDAP://cn={83A5BD5B-1D5D-472D-827F-DE0E6F714300},cn=policies,cn=system,DC=domain,DC=com;0][LDAP://cn={5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242},cn=policies,cn=system,DC=domain,DC=com;0]'

# Message({'dn': Dn('OU=RnD,OU=IT Dept,DC=domain,DC=com'),
# 'gPLink': MessageElement(
#   [b'[LDAP://cn={83A5BD5B-1D5D-472D-827F-DE0E6F714300},cn=policies,cn=system,DC=domain,DC=com;0][LDAP://cn={5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242},cn=policies,cn=system,DC=domain,DC=com;0]']),
# 'gPOptions': MessageElement([b'0'])})


# 'AAAAAA'
# Message({'dn': Dn('OU=RnD,OU=IT Dept,DC=domain,DC=com'), 'gPLink': MessageElement([b'[LDAP://cn={83A5BD5B-1D5D-472D-827F-DE0E6F714300},cn=policies,cn=system,DC=domain,DC=com;0][LDAP://cn={5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242},cn=policies,cn=system,DC=domain,DC=com;0]']), 'gPOptions': MessageElement([b'0'])})
# 'XXXXXX'
# Message({'dn': Dn('cn={83A5BD5B-1D5D-472D-827F-DE0E6F714300},cn=policies,cn=system,DC=domain,DC=com'), 'displayName': MessageElement([b'RnD Policy 2']), 'nTSecurityDescriptor': MessageElement([b'\x01\x00\x04\x9c\x00\x01\x00\x00\x1c\x01\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x04\x00\xec\x00\x08\x00\x00\x00\x05\x02(\x00\x00\x01\x00\x00\x01\x00\x00\x00\x8f\xfd\xac\xed\xb3\xff\xd1\x11\xb4\x1d\x00\xa0\xc9h\xf99\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x00$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00\x00\x02$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00\x00\x02$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x07\x02\x00\x00\x00\x02\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\t\x00\x00\x00\x00\x02\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x02\x14\x00\xff\x00\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\n\x14\x00\xff\x00\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00']), 'name': MessageElement([b'{83A5BD5B-1D5D-472D-827F-DE0E6F714300}']), 'flags': MessageElement([b'0']), 'gPCFileSysPath': MessageElement([b'\\\\domain.com\\SysVol\\domain.com\\Policies\\{83A5BD5B-1D5D-472D-827F-DE0E6F714300}'])})
# 'XXXXXX'
# Message({'dn': Dn('cn={5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242},cn=policies,cn=system,DC=domain,DC=com'), 'displayName': MessageElement([b'RnD Policy']), 'nTSecurityDescriptor': MessageElement([b'\x01\x00\x04\x9c\x00\x01\x00\x00\x1c\x01\x00\x00\x00\x00\x00\x00\x14\x00\x00\x00\x04\x00\xec\x00\x08\x00\x00\x00\x05\x02(\x00\x00\x01\x00\x00\x01\x00\x00\x00\x8f\xfd\xac\xed\xb3\xff\xd1\x11\xb4\x1d\x00\xa0\xc9h\xf99\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x00$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00\x00\x02$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00\x00\x02$\x00\xff\x00\x0f\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x07\x02\x00\x00\x00\x02\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\t\x00\x00\x00\x00\x02\x14\x00\x94\x00\x02\x00\x01\x01\x00\x00\x00\x00\x00\x05\x0b\x00\x00\x00\x00\x02\x14\x00\xff\x00\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x05\x12\x00\x00\x00\x00\n\x14\x00\xff\x00\x0f\x00\x01\x01\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00\x01\x05\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\xed\xdb\xf6\x00f\xe5\xb3\t\xa4\xf2E\t\x00\x02\x00\x00']), 'name': MessageElement([b'{5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242}']), 'flags': MessageElement([b'0']), 'gPCFileSysPath': MessageElement([b'\\\\domain.com\\SysVol\\domain.com\\Policies\\{5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242}'])})


# Message({'dn': Dn('OU=RnD,OU=IT Dept,DC=domain,DC=com'), 'gPLink': MessageElement([b'[LDAP://cn={5EC4DF8F-FF4E-41DE-846B-52AA6FFAF242},cn=policies,cn=system,DC=domain,DC=com;0]']), 'gPOptions': MessageElement([b'0'])})
# Message({'dn': Dn('OU=IT Dept,DC=domain,DC=com'), 'gPLink': MessageElement([b'[LDAP://cn={75545F76-DEC2-4ADA-B7B8-D5209FD48727},cn=policies,cn=system,DC=domain,DC=com;0]'])})
# Message({'dn': Dn('DC=domain,DC=com'), 'gPLink': MessageElement([b'[LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=System,DC=domain,DC=com;0]'])})


# GPO_APPLY_GUID = "edacfd8f-ffb3-11d1-b41d-00a0c968f939"
# secdesc = 'O:S-1-5-21-16178157-162784614-155579044-512G:S-1-5-21-16178157-162784614-155579044-512D:PAI(D;;RPLCRC;;;S-1-5-21-16178157-162784614-155579044-1103)(OA;;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;S-1-5-21-16178157-162784614-155579044-1103)(A;;RPWPLCRC;;;S-1-5-21-16178157-162784614-155579044-1102)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-16178157-162784614-155579044-512)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;S-1-5-21-16178157-162784614-155579044-519)(A;CI;RPLCLORC;;;ED)(A;CI;RPLCLORC;;;AU)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CIIO;RPWPCCDCLCLORCWOWDSDDTSW;;;CO)'
# sids = ["S-1-5-21-16178157-162784614-155579044-1102", "AU"]
