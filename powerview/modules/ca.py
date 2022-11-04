#!/usr/bin/env python3
import logging
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from powerview.utils.helpers import (
    is_admin_sid
)
from powerview.utils.constants import (
    ACTIVE_DIRECTORY_RIGHTS,
    CERTIFICATE_RIGHTS,
    CERTIFICATION_AUTHORITY_RIGHTS,
    WELL_KNOWN_SIDS,
    EXTENDED_RIGHTS_NAME_MAP
)

INHERITED_ACE = 0x10

#stolen from https://github.com/ly4k/Certipy
class ActiveDirectorySecurity:
    RIGHTS_TYPE = ACTIVE_DIRECTORY_RIGHTS

    def __init__(
        self,
        security_descriptor: bytes,
    ):
        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(security_descriptor)
        self.sd = sd

        self.owner = format_sid(sd["OwnerSid"].getData())
        self.aces = {}

        aces = sd["Dacl"]["Data"]
        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            if sid not in self.aces:
                self.aces[sid] = {
                    "rights": self.RIGHTS_TYPE(0),
                    "extended_rights": [],
                    "inherited": ace["AceFlags"] & INHERITED_ACE == INHERITED_ACE,
                }

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                self.aces[sid]["rights"] |= self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                if ace["Ace"]["Flags"] == 2:
                    uuid = bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
                elif ace["Ace"]["Flags"] == 1:
                    uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()
                else:
                    continue

                self.aces[sid]["extended_rights"].append(uuid)

class CertifcateSecurity(ActiveDirectorySecurity):
    RIGHTS_TYPE = CERTIFICATE_RIGHTS

class CAEnum:
    def __init__(self, ldap_session, root_dn):
        self.ldap_session = ldap_session
        self.root_dn = root_dn
        self.owner_sid = None
        self.parsed_dacl = {}

    def get_owner_sid(self):
        return self.owner_sid

    def set_owner_sid(self, owner_sid):
        self.owner_sid = owner_sid

    def get_parsed_dacl(self):
        return self.parsed_dacl

    def set_parsed_dacl(self, parsed_dacl):
        self.parsed_dacl = parsed_dacl

    def fetch_root_ca(self, properties=['*']):
        enroll_filter = "(objectclass=certificationAuthority)"
        ca_search_base = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        logging.debug(f'LDAP Base: {ca_search_base}')
        logging.debug(f'LDAP Filter: {enroll_filter}')
        self.ldap_session.search(ca_search_base, enroll_filter,attributes='*')
        return self.ldap_session.entries

    def fetch_enrollment_services(self, properties=['*']):
        enroll_filter = "(objectCategory=pKIEnrollmentService)"
        conf_base = "CN=Configuration,{}".format(self.root_dn)

        self.ldap_session.search(conf_base,enroll_filter,attributes=properties)

        return self.ldap_session.entries

    def get_certificate_templates(self, properties, identity=None):
        ca_search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"

        search_filter = ""
        identity_filter = ""

        if identity:
            identity_filter = f"(|(cn={identity}))"

        search_filter = f"(&(objectclass=pkicertificatetemplate){identity_filter})"

        logging.debug(f"LDAP Filter: {search_filter}")

        self.ldap_session.search(
            ca_search_base,
            search_filter,
            attributes=properties
        )

        return self.ldap_session.entries

    def check_vulnerable_template(self, template):
        vulns = {}

        # ESC1

        # ESC4

        # ESC8
        return vulns

    def parse_dacl(self,template):
        user_can_enroll = False
        enrollment_rights = []
        all_extended_rights = []

        self.parsed_dacl = {}
        sdData = template["nTSecurityDescriptor"].raw_values[0]
        security = CertifcateSecurity(sdData)
        self.owner_sid = security.owner
        aces = security.aces

        for sid, rights in aces.items():
            # TODO: Fix parsing writer owner and shits
            rights_mapping = [
                (CERTIFICATE_RIGHTS.GENERIC_ALL, [], "Full Control Principals"),
                (CERTIFICATE_RIGHTS.WRITE_OWNER, [], "Write Owner Principals"),
                (CERTIFICATE_RIGHTS.WRITE_DACL, [], "Write Dacl Principals"),
                (
                    CERTIFICATE_RIGHTS.WRITE_PROPERTY,
                    [],
                    "Write Property Principals",
                ),
            ]

            _rights = rights["rights"]
            for (right, principal_list, _) in rights_mapping:
                if right in _rights:
                    principal_list.append(sid)

            for _, principal_rights, name in rights_mapping:
                if len(principal_rights) > 0:
                    self.parsed_dacl[name] = principal_rights

            # TODO: Fix Logic here
            if sid in list(WELL_KNOWN_SIDS.keys()):
                continue

            if(EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
               or EXTENDED_RIGHTS_NAME_MAP["Enroll"] in rights["extended_rights"]
               or EXTENDED_RIGHTS_NAME_MAP["AutoEnroll"] in rights["extended_rights"]
               or CERTIFICATE_RIGHTS.GENERIC_ALL in rights["rights"]
               ):
                enrollment_rights.append(sid)

            if (
                EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"] in rights["extended_rights"]
            ):
                all_extended_rights.append(sid)

        self.parsed_dacl['Enrollment Rights'] = enrollment_rights
        self.parsed_dacl['Extended Rights'] = all_extended_rights

        return self.parsed_dacl
