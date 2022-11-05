#!/usr/bin/env python3
import logging
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from powerview.utils.helpers import (
    is_admin_sid,
    filetime_to_str
)
from powerview.utils.constants import (
    ACTIVE_DIRECTORY_RIGHTS,
    CERTIFICATE_RIGHTS,
    CERTIFICATION_AUTHORITY_RIGHTS,
    MS_PKI_CERTIFICATE_NAME_FLAG,
    MS_PKI_ENROLLMENT_FLAG,
    OID_TO_STR_MAP,
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

class PARSE_TEMPLATE:
    def __init__(self, template):
        self.template = template
        self.owner_sid = None
        self.parsed_dacl = {}
        self.certificate_name_flag = None
        self.enrollment_flag = None
        self.extended_key_usage = None
        self.validity_period = None
        self.client_authentication = False
        self.enrollee_supplies_subject = False
        self.any_purpose = False
        self.enrollment_agent = False

    def get_owner_sid(self):
        return self.owner_sid

    def set_owner_sid(self, owner_sid):
        self.owner_sid = owner_sid

    def get_parsed_dacl(self):
        return self.parsed_dacl

    def set_parsed_dacl(self, parsed_dacl):
        self.parsed_dacl = parsed_dacl

    def get_certificate_name_flag(self):
        return self.certificate_name_flag

    def set_certificate_name_flag(self, certificate_name_flag):
        self.certificate_name_flag = certificate_name_flag

    def get_enrollment_flag(self):
        return self.enrollment_flag

    def set_enrollment_flag(self, enrollment_flag):
        self.enrollment_flag = enrollment_flag

    def get_extended_key_usage(self):
        return self.extended_key_usage

    def set_extended_key_usage(self, extended_key_usage):
        self.extended_key_usage = extended_key_usage

    def get_validity_period(self):
        return self.validity_period

    def set_validity_period(self, validity_period):
        self.validity_period = validity_period

    def get_renewal_period(self):
        return self.renewal_period

    def set_renewal_period(self, renewal_period):
        self.renewal_period = renewal_period

    def get_client_authentication(self):
        return self.client_authentication

    def set_client_authentication(self, client_authentication):
        self.client_authentication = client_authentication

    def get_enrollee_supplies_subject(self):
        return self.enrollee_supplies_subject

    def set_enrollee_supplies_subject(self, enrollee_supplies_subject):
        self.enrollee_supplies_subject = enrollee_supplies_subject

    def get_any_purpose(self):
        return self.any_purpose

    def set_any_purpose(self, any_purpose):
        self.any_purpose = any_purpose

    def get_enrollment_agent(self):
        return self.enrollment_agent

    def set_enrollment_agent(self, enrollment_agent):
        self.enrollment_agent = enrollment_agent

    def resolve_flags(self):
        # resolve certificate name flag
        self.set_certificate_name_flag(self.template["msPKI-Certificate-Name-Flag"].raw_values[0])
        if self.certificate_name_flag is not None:
                self.set_certificate_name_flag(MS_PKI_CERTIFICATE_NAME_FLAG(
                    int(self.certificate_name_flag)
                ))
        else:
            self.set_certificate_name_flag(MS_PKI_CERTIFICATE_NAME_FLAG(0))

        # resolve enrollment flag
        self.set_enrollment_flag(self.template["msPKI-Enrollment-Flag"].raw_values[0])
        if self.enrollment_flag is not None:
                self.set_enrollment_flag(MS_PKI_ENROLLMENT_FLAG(int(self.enrollment_flag)))
        else:
            self.set_enrollment_flag(MS_PKI_ENROLLMENT_FLAG(0))

        # resolve pKIExtendedKeyUsage
        eku = self.template["pKIExtendedKeyUsage"].raw_values
        if not isinstance(eku, list):
            if eku is None:
                eku = []
            else:
                eku = [eku]

        eku = list(map(lambda x: x.decode(), eku))
        self.set_extended_key_usage(list(
                map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, eku)
            ))

        self.set_any_purpose((
                "Any Purpose" in self.extended_key_usage or len(self.extended_key_usage) == 0
            ))

        self.set_client_authentication(self.any_purpose or any(
                eku in self.extended_key_usage
                for eku in [
                    "Client Authentication",
                    "Smart Card Logon",
                    "PKINIT Client Authentication",
                ]
            ))

        self.set_enrollment_agent(self.any_purpose or any(
                eku in self.extended_key_usage
                for eku in [
                    "Certificate Request Agent",
                ]
            ))

        self.set_enrollee_supplies_subject(any(
                flag in self.certificate_name_flag
                for flag in [
                    MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
                ]
            ))

        # resolve validity period
        self.set_validity_period(filetime_to_str(self.template["pKIExpirationPeriod"].raw_values[0]))

        # resolve renewal_period
        self.set_renewal_period(filetime_to_str(self.template["pKIOverlapPeriod"].raw_values[0]))

    def check_vulnerable_template(self):
        vulns = {}

        # ESC1
        # TODO: add another user_can_enroll logic
        if (self.get_enrollee_supplies_subject() and self.get_client_authentication()):
            vulns["ESC1"] = "Vulnerable yayyy"

        # ESC4

        # ESC8
        return vulns

    def parse_dacl(self):
        user_can_enroll = False
        enrollment_rights = []
        all_extended_rights = []

        self.parsed_dacl = {}
        sdData = self.template["nTSecurityDescriptor"].raw_values[0]
        security = CertifcateSecurity(sdData)
        self.owner_sid = security.owner
        aces = security.aces

        for sid, rights in aces.items():
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
        object_control_permissions = {}
        # acl
        for sid, rights in security.aces.items():
            rights = rights["rights"]

            for (right, principal_list, _) in rights_mapping:
                if right in rights:
                    principal_list.append(sid)

        for _, rights, name in rights_mapping:
            if len(rights) > 0:
                object_control_permissions[name] = rights

        self.parsed_dacl['Write Owner'] = object_control_permissions['Write Owner Principals']
        self.parsed_dacl['Write Dacl'] = object_control_permissions['Write Dacl Principals']
        self.parsed_dacl['Write Property'] = object_control_permissions['Write Property Principals']
        self.parsed_dacl['Enrollment Rights'] = enrollment_rights
        self.parsed_dacl['Extended Rights'] = all_extended_rights

        return self.parsed_dacl
