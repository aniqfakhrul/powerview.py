import enum

from impacket.structure import Structure
from powerview.utils.helpers import to_pascal_case

class IntFlag(enum.IntFlag):
    def to_list(self):
        cls = self.__class__
        members, _ = enum._decompose(cls, self._value_)
        return members

    def to_str_list(self):
        return list(map(lambda x: str(x), self.to_list()))

    def __str__(self):
        cls = self.__class__
        if self._name_ is not None:
            return "%s" % (to_pascal_case(self._name_))
        members, _ = enum._decompose(cls, self._value_)
        if len(members) == 1 and members[0]._name_ is None:
            return "%r" % (members[0]._value_)
        else:
            return "%s" % (
                ", ".join(
                    [to_pascal_case(str(m._name_ or m._value_)) for m in members]
                ),
            )

    def __repr__(self):
        return str(self)

class MS_PKI_CERTIFICATE_NAME_FLAG(IntFlag):
    NONE = 0x00000000
    ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    ADD_EMAIL = 0x00000002
    ADD_OBJ_GUID = 0x00000004
    OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME = 0x00000008
    ADD_DIRECTORY_PATH = 0x00000100
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    SUBJECT_REQUIRE_EMAIL = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1
class MS_PKI_ENROLLMENT_FLAG(IntFlag):
    NONE = 0x00000000
    INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    PEND_ALL_REQUESTS = 0x00000002
    PUBLISH_TO_KRA_CONTAINER = 0x00000004
    PUBLISH_TO_DS = 0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    AUTO_ENROLLMENT = 0x00000020
    CT_FLAG_DOMAIN_AUTHENTICATION_NOT_REQUIRED = 0x80
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    USER_INTERACTION_REQUIRED = 0x00000100
    ADD_TEMPLATE_NAME = 0x200
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    ADD_OCSP_NOCHECK = 0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    NOREVOCATIONINFOINISSUEDCERTS = 0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000
    SKIP_AUTO_RENEWAL = 0x00040000
    NO_SECURITY_EXTENSION = 0x00080000


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667
class MS_PKI_PRIVATE_KEY_FLAG(IntFlag):
    REQUIRE_PRIVATE_KEY_ARCHIVAL = 0x00000001
    EXPORTABLE_KEY = 0x00000010
    STRONG_KEY_PROTECTION_REQUIRED = 0x00000020
    REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM = 0x00000040
    REQUIRE_SAME_KEY_RENEWAL = 0x00000080
    USE_LEGACY_PROVIDER = 0x00000100
    ATTEST_NONE = 0x00000000
    ATTEST_REQUIRED = 0x00002000
    ATTEST_PREFERRED = 0x00001000
    ATTESTATION_WITHOUT_POLICY = 0x00004000
    EK_TRUST_ON_USE = 0x00000200
    EK_VALIDATE_CERT = 0x00000400
    EK_VALIDATE_KEY = 0x00000800
    HELLO_LOGON_KEY = 0x00200000


# https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Domain/CertificateAuthority.cs#L23
class MS_PKI_CERTIFICATE_AUTHORITY_FLAG(IntFlag):
    NO_TEMPLATE_SUPPORT = 0x00000001
    SUPPORTS_NT_AUTHENTICATION = 0x00000002
    CA_SUPPORTS_MANUAL_AUTHENTICATION = 0x00000004
    CA_SERVERTYPE_ADVANCED = 0x00000008


# https://www.pkisolutions.com/object-identifiers-oid-in-pki/
OID_TO_STR_MAP = {
    "1.3.6.1.4.1.311.76.6.1": "Windows Update",
    "1.3.6.1.4.1.311.10.3.11": "Key Recovery",
    "1.3.6.1.4.1.311.10.3.25": "Windows Third Party Application Component",
    "1.3.6.1.4.1.311.21.6": "Key Recovery Agent",
    "1.3.6.1.4.1.311.10.3.6": "Windows System Component Verification",
    "1.3.6.1.4.1.311.61.4.1": "Early Launch Antimalware Drive",
    "1.3.6.1.4.1.311.10.3.23": "Windows TCB Component",
    "1.3.6.1.4.1.311.61.1.1": "Kernel Mode Code Signing",
    "1.3.6.1.4.1.311.10.3.26": "Windows Software Extension Verification",
    "2.23.133.8.3": "Attestation Identity Key Certificate",
    "1.3.6.1.4.1.311.76.3.1": "Windows Store",
    "1.3.6.1.4.1.311.10.6.1": "Key Pack Licenses",
    "1.3.6.1.4.1.311.20.2.2": "Smart Card Logon",
    "1.3.6.1.5.2.3.5": "KDC Authentication",
    "1.3.6.1.5.5.7.3.7": "IP security use",
    "1.3.6.1.4.1.311.10.3.8": "Embedded Windows System Component Verification",
    "1.3.6.1.4.1.311.10.3.20": "Windows Kits Component",
    "1.3.6.1.5.5.7.3.6": "IP security tunnel termination",
    "1.3.6.1.4.1.311.10.3.5": "Windows Hardware Driver Verification",
    "1.3.6.1.5.5.8.2.2": "IP security IKE intermediate",
    "1.3.6.1.4.1.311.10.3.39": "Windows Hardware Driver Extended Verification",
    "1.3.6.1.4.1.311.10.6.2": "License Server Verification",
    "1.3.6.1.4.1.311.10.3.5.1": "Windows Hardware Driver Attested Verification",
    "1.3.6.1.4.1.311.76.5.1": "Dynamic Code Generato",
    "1.3.6.1.5.5.7.3.8": "Time Stamping",
    "1.3.6.1.4.1.311.10.3.4.1": "File Recovery",
    "1.3.6.1.4.1.311.2.6.1": "SpcRelaxedPEMarkerCheck",
    "2.23.133.8.1": "Endorsement Key Certificate",
    "1.3.6.1.4.1.311.2.6.2": "SpcEncryptedDigestRetryCount",
    "1.3.6.1.4.1.311.10.3.4": "Encrypting File System",
    "1.3.6.1.5.5.7.3.1": "Server Authentication",
    "1.3.6.1.4.1.311.61.5.1": "HAL Extension",
    "1.3.6.1.5.5.7.3.4": "Secure Email",
    "1.3.6.1.5.5.7.3.5": "IP security end system",
    "1.3.6.1.4.1.311.10.3.9": "Root List Signe",
    "1.3.6.1.4.1.311.10.3.30": "Disallowed List",
    "1.3.6.1.4.1.311.10.3.19": "Revoked List Signe",
    "1.3.6.1.4.1.311.10.3.21": "Windows RT Verification",
    "1.3.6.1.4.1.311.10.3.10": "Qualified Subordination",
    "1.3.6.1.4.1.311.10.3.12": "Document Signing",
    "1.3.6.1.4.1.311.10.3.24": "Protected Process Verification",
    "1.3.6.1.4.1.311.80.1": "Document Encryption",
    "1.3.6.1.4.1.311.10.3.22": "Protected Process Light Verification",
    "1.3.6.1.4.1.311.21.19": "Directory Service Email Replication",
    "1.3.6.1.4.1.311.21.5": "Private Key Archival",
    "1.3.6.1.4.1.311.10.5.1": "Digital Rights",
    "1.3.6.1.4.1.311.10.3.27": "Preview Build Signing",
    "1.3.6.1.4.1.311.20.2.1": "Certificate Request Agent",
    "2.23.133.8.2": "Platform Certificate",
    "1.3.6.1.4.1.311.20.1": "CTL Usage",
    "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    "1.3.6.1.5.5.7.3.3": "Code Signing",
    "1.3.6.1.4.1.311.10.3.1": "Microsoft Trust List Signing",
    "1.3.6.1.4.1.311.10.3.2": "Microsoft Time Stamping",
    "1.3.6.1.4.1.311.76.8.1": "Microsoft Publishe",
    "1.3.6.1.5.5.7.3.2": "Client Authentication",
    "1.3.6.1.5.2.3.4": "PKIINIT Client Authentication",
    "1.3.6.1.4.1.311.10.3.13": "Lifetime Signing",
    "2.5.29.37.0": "Any Purpose",
    "1.3.6.1.4.1.311.64.1.1": "Server Trust",
    "1.3.6.1.4.1.311.10.3.7": "OEM Windows System Component Verification",
}

# https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Domain/CertificateAuthority.cs#L11
class CERTIFICATION_AUTHORITY_RIGHTS(IntFlag):
    MANAGE_CA = 1
    MANAGE_CERTIFICATES = 2
    AUDITOR = 4
    OPERATOR = 8
    READ = 256
    ENROLL = 512

class CERTIFICATE_RIGHTS(IntFlag):
    GENERIC_ALL = 983551
    WRITE_OWNER = 524288
    WRITE_DACL = 262144
    WRITE_PROPERTY = 32

    def to_list(self):
        cls = self.__class__

        if self._value_ == self.GENERIC_ALL:
            return [CERTIFICATE_RIGHTS(self.GENERIC_ALL)]

        members, _ = enum._decompose(cls, self._value_)
        filtered_members = []
        for member in members:
            if str(member) == str(member.value):
                continue
            filtered_members.append(member)
        return filtered_members

# https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=net-5.0
class ACTIVE_DIRECTORY_RIGHTS(IntFlag):
    ACCESS_SYSTEM_SECURITY = 16777216
    SYNCHRONIZE = 1048576
    GENERIC_ALL = 983551
    WRITE_OWNER = 524288
    WRITE_DACL = 262144
    GENERIC_READ = 131220
    GENERIC_WRITE = 131112
    GENERIC_EXECUTE = 131076
    READ_CONTROL = 131072
    DELETE = 65536
    EXTENDED_RIGHT = 256
    LIST_OBJECT = 128
    DELETE_TREE = 64
    WRITE_PROPERTY = 32
    READ_PROPERTY = 16
    SELF = 8
    LIST_CHILDREN = 4
    DELETE_CHILD = 2
    CREATE_CHILD = 1

    def to_list(self):
        cls = self.__class__
        members, _ = enum._decompose(cls, self._value_)
        filtered_members = []
        for member in members:
            found = False
            for n in members:
                if n & member and n != member:
                    found = True

            if not found:
                filtered_members.append(member)
        return members

# GPO
LINK_ENABLED = 0
LINK_DISABLED = 1
ENFORCED = 3

# Universal SIDs
WELL_KNOWN_SIDS = {
    'S-1-0': 'Null Authority',
    'S-1-0-0': 'Nobody',
    'S-1-1': 'World Authority',
    'S-1-1-0': 'Everyone',
    'S-1-2': 'Local Authority',
    'S-1-2-0': 'Local',
    'S-1-2-1': 'Console Logon',
    'S-1-3': 'Creator Authority',
    'S-1-3-0': 'Creator Owner',
    'S-1-3-1': 'Creator Group',
    'S-1-3-2': 'Creator Owner Server',
    'S-1-3-3': 'Creator Group Server',
    'S-1-3-4': 'Owner Rights',
    'S-1-5-80-0': 'All Services',
    'S-1-4': 'Non-unique Authority',
    'S-1-5': 'NT Authority',
    'S-1-5-1': 'Dialup',
    'S-1-5-2': 'Network',
    'S-1-5-3': 'Batch',
    'S-1-5-4': 'Interactive',
    'S-1-5-6': 'Service',
    'S-1-5-7': 'Anonymous',
    'S-1-5-8': 'Proxy',
    'S-1-5-9': 'Enterprise Domain Controllers',
    'S-1-5-10': 'Principal Self',
    'S-1-5-11': 'Authenticated Users',
    'S-1-5-12': 'Restricted Code',
    'S-1-5-13': 'Terminal Server Users',
    'S-1-5-14': 'Remote Interactive Logon',
    'S-1-5-15': 'This Organization',
    'S-1-5-17': 'This Organization',
    'S-1-5-18': 'Local System',
    'S-1-5-19': 'NT Authority',
    'S-1-5-20': 'NT Authority',
    'S-1-5-32-544': 'Administrators',
    'S-1-5-32-545': 'Users',
    'S-1-5-32-546': 'Guests',
    'S-1-5-32-547': 'Power Users',
    'S-1-5-32-548': 'Account Operators',
    'S-1-5-32-549': 'Server Operators',
    'S-1-5-32-550': 'Print Operators',
    'S-1-5-32-551': 'Backup Operators',
    'S-1-5-32-552': 'Replicators',
    'S-1-5-64-10': 'NTLM Authentication',
    'S-1-5-64-14': 'SChannel Authentication',
    'S-1-5-64-21': 'Digest Authority',
    'S-1-5-80': 'NT Service',
    'S-1-5-83-0': 'NT VIRTUAL MACHINE\Virtual Machines',
    'S-1-16-0': 'Untrusted Mandatory Level',
    'S-1-16-4096': 'Low Mandatory Level',
    'S-1-16-8192': 'Medium Mandatory Level',
    'S-1-16-8448': 'Medium Plus Mandatory Level',
    'S-1-16-12288': 'High Mandatory Level',
    'S-1-16-16384': 'System Mandatory Level',
    'S-1-16-20480': 'Protected Process Mandatory Level',
    'S-1-16-28672': 'Secure Process Mandatory Level',
    'S-1-5-32-554': 'BUILTIN\Pre-Windows 2000 Compatible Access',
    'S-1-5-32-555': 'BUILTIN\Remote Desktop Users',
    'S-1-5-32-557': 'BUILTIN\Incoming Forest Trust Builders',
    'S-1-5-32-556': 'BUILTIN\\Network Configuration Operators',
    'S-1-5-32-558': 'BUILTIN\Performance Monitor Users',
    'S-1-5-32-559': 'BUILTIN\Performance Log Users',
    'S-1-5-32-560': 'BUILTIN\Windows Authorization Access Group',
    'S-1-5-32-561': 'BUILTIN\Terminal Server License Servers',
    'S-1-5-32-562': 'BUILTIN\Distributed COM Users',
    'S-1-5-32-569': 'BUILTIN\Cryptographic Operators',
    'S-1-5-32-573': 'BUILTIN\Event Log Readers',
    'S-1-5-32-574': 'BUILTIN\Certificate Service DCOM Access',
    'S-1-5-32-575': 'BUILTIN\RDS Remote Access Servers',
    'S-1-5-32-576': 'BUILTIN\RDS Endpoint Servers',
    'S-1-5-32-577': 'BUILTIN\RDS Management Servers',
    'S-1-5-32-578': 'BUILTIN\Hyper-V Administrators',
    'S-1-5-32-579': 'BUILTIN\Access Control Assistance Operators',
    'S-1-5-32-580': 'BUILTIN\Remote Management Users',
}

# store discovered sids
KNOWN_SIDS = {}

# https://ldapwiki.com/wiki/Common%20Active%20Directory%20Bind%20Errors
LDAP_ERROR_STATUS = {
    "525": "LDAP_NO_SUCH_OBJECT",
    "52e": "ERROR_LOGON_FAILURE",
    "52f": "ERROR_ACCOUNT_RESTRICTION",
    "530": "ERROR_INVALID_LOGON_HOURS",
    "531": "ERROR_INVALID_WORKSTATION",
    "532": "ERROR_PASSWORD_EXPIRED",
    "533": "ERROR_ACCOUNT_DISABLED",
    "568": "ERROR_TOO_MANY_CONTEXT_IDS",
    "701": "ERROR_ACCOUNT_EXPIRED",
    "773": "ERROR_PASSWORD_MUST_CHANGE",
    "775": "ERROR_ACCOUNT_LOCKED_OUT",
    "80090346": "ERROR_ACCOUNT_LOCKED_OUT"
}

# Retrieved from Windows 2022 server via LDAP (CN=Extended-Rights,CN=Configuration,DC=...)
EXTENDED_RIGHTS_MAP = {
    "ab721a52-1e2f-11d0-9819-00aa0040529b": "Domain-Administer-Serve",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "User-Change-Password",
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Send-As",
    "ab721a56-1e2f-11d0-9819-00aa0040529b": "Receive-As",
    "ab721a55-1e2f-11d0-9819-00aa0040529b": "Send-To",
    "c7407360-20bf-11d0-a768-00aa006e0529": "Domain-Password",
    "59ba2f42-79a2-11d0-9020-00c04fc2d3cf": "General-Information",
    "4c164200-20c0-11d0-a768-00aa006e0529": "User-Account-Restrictions",
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Logon",
    "bc0ac240-79a9-11d0-9020-00c04fc2d4cf": "Membership",
    "a1990816-4298-11d1-ade2-00c04fd8d5cd": "Open-Address-Book",
    "77b5b886-944a-11d1-aebd-0000f80367c1": "Personal-Information",
    "e45795b2-9455-11d1-aebd-0000f80367c1": "Email-Information",
    "e45795b3-9455-11d1-aebd-0000f80367c1": "Web-Information",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Synchronize",
    "1131f6ac-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Manage-Topology",
    "e12b56b6-0a95-11d1-adbb-00c04fd8d5cd": "Change-Schema-Maste",
    "d58d5f36-0a98-11d1-adbb-00c04fd8d5cd": "Change-Rid-Maste",
    "fec364e0-0a98-11d1-adbb-00c04fd8d5cd": "Do-Garbage-Collection",
    "0bc1554e-0a99-11d1-adbb-00c04fd8d5cd": "Recalculate-Hierarchy",
    "1abd7cf8-0a99-11d1-adbb-00c04fd8d5cd": "Allocate-Rids",
    "bae50096-4752-11d1-9052-00c04fc2d4cf": "Change-PDC",
    "440820ad-65b4-11d1-a3da-0000f875ae0d": "Add-GUID",
    "014bf69c-7b3b-11d1-85f6-08002be74fab": "Change-Domain-Maste",
    "e48d0154-bcf8-11d1-8702-00c04fb96050": "Public-Information",
    "4b6e08c0-df3c-11d1-9c86-006008764d0e": "msmq-Receive-Dead-Lette",
    "4b6e08c1-df3c-11d1-9c86-006008764d0e": "msmq-Peek-Dead-Lette",
    "4b6e08c2-df3c-11d1-9c86-006008764d0e": "msmq-Receive-computer-Journal",
    "4b6e08c3-df3c-11d1-9c86-006008764d0e": "msmq-Peek-computer-Journal",
    "06bd3200-df3e-11d1-9c86-006008764d0e": "msmq-Receive",
    "06bd3201-df3e-11d1-9c86-006008764d0e": "msmq-Peek",
    "06bd3202-df3e-11d1-9c86-006008764d0e": "msmq-Send",
    "06bd3203-df3e-11d1-9c86-006008764d0e": "msmq-Receive-journal",
    "b4e60130-df3f-11d1-9c86-006008764d0e": "msmq-Open-Connecto",
    "edacfd8f-ffb3-11d1-b41d-00a0c968f939": "Apply-Group-Policy",
    "037088f8-0ae1-11d2-b422-00a0c968f939": "RAS-Information",
    "9923a32a-3607-11d2-b9be-0000f87a36b2": "DS-Install-Replica",
    "cc17b1fb-33d9-11d2-97d4-00c04fd8d5cd": "Change-Infrastructure-Maste",
    "be2bb760-7f46-11d2-b9ad-00c04f79f805": "Update-Schema-Cache",
    "62dd28a8-7f46-11d2-b9ad-00c04f79f805": "Recalculate-Security-Inheritance",
    "69ae6200-7f46-11d2-b9ad-00c04f79f805": "DS-Check-Stale-Phantoms",
    "0e10c968-78fb-11d2-90d4-00c04f79dc55": "Enroll",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Self-Membership",
    "72e39547-7b18-11d1-adef-00c04fd8d5cd": "DNS-Host-Name-Attributes",
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "Validated-SPN",
    "b7b1b3dd-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Planning",
    "9432c620-033c-4db7-8b58-14ef6d0bf477": "Refresh-Group-Cache",
    "91d67418-0135-4acc-8d79-c08e857cfbec": "SAM-Enumerate-Entire-Domain",
    "b7b1b3de-ab09-4242-9e30-9980e5d322f7": "Generate-RSoP-Logging",
    "b8119fd0-04f6-4762-ab7a-4986c76b3f9a": "Domain-Other-Parameters",
    "e2a36dc9-ae17-47c3-b58b-be34c55ba633": "Create-Inbound-Forest-Trust",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "ba33815a-4f93-4c76-87f3-57574bff8109": "Migrate-SID-History",
    "45ec5156-db7e-47bb-b53f-dbeb2d03c40f": "Reanimate-Tombstones",
    "68b1d179-0d15-4d4f-ab71-46152e79a7bc": "Allowed-To-Authenticate",
    "2f16c4a5-b98e-432c-952a-cb388ba33f2e": "DS-Execute-Intentions-Script",
    "f98340fb-7c5b-4cdb-a00b-2ebdfa115a96": "DS-Replication-Monitor-Topology",
    "280f369c-67c7-438e-ae98-1d46f3c6f541": "Update-Password-Not-Required-Bit",
    "ccc2dc7d-a6ad-4a7a-8846-c04e3cc53501": "Unexpire-Password",
    "05c74c5e-4deb-43b4-bd9f-86664c2a7fd5": (
        "Enable-Per-User-Reversibly-Encrypted-Password"
    ),
    "4ecc03fe-ffc0-4947-b630-eb672a8a9dbc": "DS-Query-Self-Quota",
    "91e647de-d96f-4b70-9557-d63ff4f3ccd8": "Private-Information",
    "1131f6ae-9c07-11d1-f79f-00c04fc2dcd2": (
        "Read-Only-Replication-Secret-Synchronization"
    ),
    "ffa6f046-ca4b-4feb-b40d-04dfee722543": "MS-TS-GatewayAccess",
    "5805bc62-bdc9-4428-a5e2-856a0f4c185e": "Terminal-Server-License-Serve",
    "1a60ea8d-58a6-4b20-bcdc-fb71eb8a9ff8": "Reload-SSL-Certificate",
    "89e95b76-444d-4c62-991a-0facbeda640c": (
        "DS-Replication-Get-Changes-In-Filtered-Set"
    ),
    "7726b9d5-a4b4-4288-a6b2-dce952e80a7f": "Run-Protect-Admin-Groups-Task",
    "7c0e2a7c-a419-48e4-a995-10180aad54dd": "Manage-Optional-Features",
    "3e0f7e18-2c7a-4c10-ba82-4d926db99a3e": "DS-Clone-Domain-Controlle",
    "d31a8757-2447-4545-8081-3bb610cacbf2": "Validated-MS-DS-Behavior-Version",
    "80863791-dbe9-4eb8-837e-7f0ab55d9ac7": "Validated-MS-DS-Additional-DNS-Host-Name",
    "a05b8cc2-17bc-4802-a710-e7c15ab866a2": "AutoEnroll",
    "4125c71f-7fac-4ff0-bcb7-f09a41325286": "DS-Set-Owne",
    "88a9933e-e5c8-4f2a-9dd7-2527416b8092": "DS-Bypass-Quota",
    "084c93a2-620d-4879-a836-f0ae47de0e89": "DS-Read-Partition-Secrets",
    "94825a8d-b171-4116-8146-1e34d8f54401": "DS-Write-Partition-Secrets",
    "9b026da6-0d3c-465c-8bee-5199d7165cba": "DS-Validated-Write-Compute",
    "00000000-0000-0000-0000-000000000000": "All-Extended-Rights",
}

EXTENDED_RIGHTS_NAME_MAP = {k: v for v, k in EXTENDED_RIGHTS_MAP.items()}

UAC_DICT = dict([
    (0x00000001, "SCRIPT"),
    (0x00000002, "ACCOUNTDISABLE"),
    (0x00000008, "HOMEDIR_REQUIRED"),
    (0x00000010, "LOCKOUT"),
    (0x00000020, "PASSWD_NOTREQD"),
    (0x00000040, "PASSWD_CANT_CHANGE"),
    (0x00000080, "ENCRYPTED_TEXT_PWD_ALLOWED"),
    (0x00000100, "TEMP_DUPLICATE_ACCOUNT"),
    (0x00000200, "NORMAL_ACCOUNT"),
    (0x00000800, "INTERDOMAIN_TRUST_ACCOUNT"),
    (0x00001000, "WORKSTATION_TRUST_ACCOUNT"),
    (0x00002000, "SERVER_TRUST_ACCOUNT"),
    (0x00010000, "DONT_EXPIRE_PASSWORD"),
    (0x00020000, "MNS_LOGON_ACCOUNT"),
    (0x00040000, "SMARTCARD_REQUIRED"),
    (0x00080000, "TRUSTED_FOR_DELEGATION"),
    (0x00100000, "NOT_DELEGATED"),
    (0x00200000, "USE_DES_KEY_ONLY"),
    (0x00400000, "DONT_REQ_PREAUTH"),
    (0x00800000, "PASSWORD_EXPIRED"),
    (0x01000000, "TRUSTED_TO_AUTH_FOR_DELEGATION"),
    (0x04000000, "PARTIAL_SECRETS_ACCOUNT")
])

SUPPORTED_ENCRYPTION_TYPES = dict([
    (0x00000001, "DES-CBC-CRC"),
    (0x00000002, "DES-CBC-MD5"),
    (0x00000004, "RC4-HMAC"),
    (0x00000008, "AES128"),
    (0x00000010, "AES256")
])

switcher_trustDirection = {
    0: "Disabled",
    1: "Inbound",
    2: "Outbound",
    3: "Bidirectional",
}
switcher_trustType = {
    1: "WINDOWS_NON_ACTIVE_DIRECTORY",
    2: "WINDOWS_ACTIVE_DIRECTORY",
    3: "MIT",
}
switcher_trustAttributes = {
    1 : "NON_TRANSITIVE",
    2 : "UPLEVEL_ONLY",
    4 : "QUARANTINED_DOMAIN",
    8 : "FOREST_TRANSITIVE",
    16 : "CROSS_ORGANIZATION",
    32 : "WITHIN_FOREST",
    64 : "TREAT_AS_EXTERNAL",
    128 : "USES_RC4_ENCRYPTION",
    512 : "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
    2048 : "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION",
    1024 : "PIM_TRUST",
}

PWD_FLAGS = {
    1 : "PASSWORD_COMPLEX",
    2 : "PASSWORD_NO_ANON_CHANGE",
    4 : "PASSWORD_NO_CLEAR_CHANGE",
    8 : "LOCKOUT_ADMINS",
    10 : "PASSWORD_STORE_CLEARTEXT",
    20 : "REFUSE_PASSWORD_CHANGE",

}

class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ("Version", "<H"),
        ("Reserved", "<H"),
        ("Length", "<L"),
        ("CurrentPasswordOffset", "<H"),
        ("PreviousPasswordOffset", "<H"),
        ("QueryPasswordIntervalOffset", "<H"),
        ("UnchangedPasswordIntervalOffset", "<H"),
        ("CurrentPassword", ":"),
        ("PreviousPassword", ":"),
        # ('AlignmentPadding',':'),
        ("QueryPasswordInterval", ":"),
        ("UnchangedPasswordInterval", ":"),
    )

    def __init__(self, data=None):
        Structure.__init__(self, data=data)

    def fromString(self, data):
        Structure.fromString(self, data)

        if self["PreviousPasswordOffset"] == 0:
            endData = self["QueryPasswordIntervalOffset"]
        else:
            endData = self["PreviousPasswordOffset"]

        self["CurrentPassword"] = self.rawData[self["CurrentPasswordOffset"] :][
            : endData - self["CurrentPasswordOffset"]
        ]
        if self["PreviousPasswordOffset"] != 0:
            self["PreviousPassword"] = self.rawData[self["PreviousPasswordOffset"] :][
                : self["QueryPasswordIntervalOffset"] - self["PreviousPasswordOffset"]
            ]

        self["QueryPasswordInterval"] = self.rawData[
            self["QueryPasswordIntervalOffset"] :
        ][
            : self["UnchangedPasswordIntervalOffset"]
            - self["QueryPasswordIntervalOffset"]
        ]
        self["UnchangedPasswordInterval"] = self.rawData[
            self["UnchangedPasswordIntervalOffset"] :
        ]
