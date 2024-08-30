#!/usr/bin/env python3
import logging
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string, string_to_bin
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
import socket

from powerview.utils.helpers import (
    is_admin_sid,
    filetime_to_str,
    get_user_sids,
    host2ip,
    get_random_num,
    get_random_hex,
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

class CertificateSecurity(ActiveDirectorySecurity):
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

    def fetch_enrollment_services(self, properties=['*'], searchbase=None):
        enroll_filter = "(objectCategory=pKIEnrollmentService)"

        if not searchbase:
            searchbase = "CN=Configuration,{}".format(self.root_dn)

        self.ldap_session.search(searchbase,enroll_filter,attributes=properties)

        return self.ldap_session.entries

    def get_certificate_templates(self, properties=None, ca_search_base=None, identity=None):
        if not properties:
            properties = [
                "objectClass",
                "cn",
                "distinguishedName",
                "name",
                "displayName",
                "pKIExpirationPeriod",
                "pKIOverlapPeriod",
                "msPKI-Enrollment-Flag",
                "msPKI-Private-Key-Flag",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Cert-Template-OID",
                "msPKI-RA-Signature",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
                "objectGUID",
            ]
        ca_search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}" if not ca_search_base else ca_search_base
        search_filter = ""
        identity_filter = ""

        if identity:
            identity_filter = f"(|(cn={identity})(displayName={identity}))"

        search_filter = f"(&(objectclass=pkicertificatetemplate){identity_filter})"

        logging.debug(f"LDAP Filter: {search_filter}")

        self.ldap_session.search(
            ca_search_base,
            search_filter,
            attributes=properties,
            controls = security_descriptor_control(sdflags=0x5),
        )

        return self.ldap_session.entries

    # https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L688
    def check_web_enrollment(self, target, nameserver=None, timeout=5, use_ip=False, use_system_ns=True):
        if use_ip:
            target = host2ip(target, nameserver, 3, True, use_system_ns)

        if target is None:
            logging.debug("No target found")
            return False

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            logging.debug("Default timeout is set to 5")
            sock.settimeout(timeout)
            logging.debug("Connecting to %s:80" % target)
            sock.connect((target, 80))
            sock.sendall(
                "\r\n".join(
                    ["HEAD /certsrv/ HTTP/1.1", "Host: %s" % target, "\r\n"]
                ).encode()
            )
            resp = sock.recv(256)
            sock.close()
            head = resp.split(b"\r\n")[0].decode()

            return " 404 " not in head
        except ConnectionRefusedError:
            return False
        except socket.timeout:
            logging.debug("Can't reach %s" % (target))
            return False
        except Exception as e:
            logging.warning(
                "Got error while trying to check for web enrollment: %s" % e
            )
            return False

        return False

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
        self.requires_manager_approval = False
        self.authorized_signatures_required = False
        self.no_security_extension = False
        self.domain_sid = None

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

    def set_requires_manager_approval(self, requires_manager_approval):
        self.requires_manager_approval = requires_manager_approval

    def get_requires_manager_approval(self):
        return self.requires_manager_approval

    def get_authorized_signatures_required(self):
        return self.authorized_signatures_required

    def set_authorized_signatures_required(self, authorized_signatures_required):
        self.authorized_signatures_required = authorized_signatures_required

    def get_no_security_extension(self):
        return self.no_security_extension

    def set_no_security_extension(self, no_security_extension):
        self.no_security_extension = no_security_extension

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

        # resolve authorized signature
        self.set_authorized_signatures_required(self.template["msPKI-RA-Signature"].raw_values[0])
        if self.authorized_signatures_required is not None:
                self.set_authorized_signatures_required(int(self.authorized_signatures_required))
        else:
            self.set_authorized_signatures_required(0)

        # resolve no_security_extension
        self.set_no_security_extension((
                MS_PKI_ENROLLMENT_FLAG.NO_SECURITY_EXTENSION in self.enrollment_flag
            ))

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

        self.set_requires_manager_approval(
                MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in self.enrollment_flag
        )

        # resolve validity period
        self.set_validity_period(filetime_to_str(self.template["pKIExpirationPeriod"].raw_values[0]))

        # resolve renewal_period
        self.set_renewal_period(filetime_to_str(self.template["pKIOverlapPeriod"].raw_values[0]))

    def can_user_enroll_template(self):
        enrollable_sids = []
        user_can_enroll = False
        for sid in self.parsed_dacl["Enrollment Rights"]:
            if sid in get_user_sids(self.domain_sid, sid):
                enrollable_sids.append(sid)
                user_can_enroll = True
        return user_can_enroll, enrollable_sids

    def check_vulnerable_template(self):
        vulns = {}
        user_can_enroll, enrollable_sids = self.can_user_enroll_template()
        if not self.get_requires_manager_approval() and not self.get_authorized_signatures_required():
            # ESC1
            # TODO: add another user_can_enroll logic
            self.parsed_dacl["Enrollment Rights"]
            if (user_can_enroll and self.get_enrollee_supplies_subject() and self.get_client_authentication()):
                vulns["ESC1"] = enrollable_sids[0]

            # ESC2
            if user_can_enroll and self.get_any_purpose():
                vulns["ESC2"] = enrollable_sids[0]

            # ESC3
            if user_can_enroll and self.get_enrollment_agent():
                vulns["ESC3"] = enrollable_sids[0]

            # ESC9
            if user_can_enroll and self.get_no_security_extension():
                vunls["ESC9"] = "Vulnerable yayay"

            # ESC4
            # for s in self.parsed_dacl["Write Owner"]:
            #     rid = int(s.split("-")[-1])
            #     if rid > 1000:
            #         vulns["ESC4"] = f"{rid} have write permission"
            # for s in self.parsed_dacl["Write Dacl"]:
            #     rid = int(s.split("-")[-1])
            #     if rid > 1000:
            #         vulns["ESC4"] = f"{rid} have write permission"
            # for s in self.parsed_dacl["Write Property"]:
            #     rid = int(s.split("-")[-1])
            #     if rid > 1000:
            #         vulns["ESC4"] = f"{rid} have write permission"

        return vulns

    def create_object_ace(self,privguid,sid, mask=983551):
        nace = ldaptypes.ACE()
        nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
        nace['AceFlags'] = 0x02 # inherit to child objects
        acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = mask # Full control
        acedata['ObjectType'] = string_to_bin(privguid)
        acedata['InheritedObjectType'] = b''
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        assert sid == acedata['Sid'].formatCanonical()
        acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        nace['Ace'] = acedata
        return nace
        
    def modify_dacl(self, sid, right_opt):
        permissions = {
                'all': {
                        'rights': [EXTENDED_RIGHTS_NAME_MAP["Enroll"], EXTENDED_RIGHTS_NAME_MAP["AutoEnroll"], EXTENDED_RIGHTS_NAME_MAP["All-Extended-Rights"]],
                        'mask': CERTIFICATE_RIGHTS.GENERIC_ALL,
                    },
                'enroll': {
                        'rights':[EXTENDED_RIGHTS_NAME_MAP["Enroll"], EXTENDED_RIGHTS_NAME_MAP["AutoEnroll"]],
                        'mask': CERTIFICATE_RIGHTS.GENERIC_ALL,
                    },
                'write': {
                        'rights':[EXTENDED_RIGHTS_NAME_MAP["Enroll"], EXTENDED_RIGHTS_NAME_MAP["AutoEnroll"]],
                        'mask':CERTIFICATE_RIGHTS.GENERIC_ALL,
                    }
                }
        sdData = self.template["nTSecurityDescriptor"].raw_values[0]
        security = CertificateSecurity(sdData)
        for guid in permissions.get(right_opt).get('rights'):
            security.sd['Dacl']['Data'].append(self.create_object_ace(guid, sid, mask=permissions.get(right_opt).get('mask')))
        return security.sd.getData() 

    def parse_dacl(self):
        user_can_enroll = False
        enrollment_rights = []
        all_extended_rights = []

        sdData = self.template["nTSecurityDescriptor"].raw_values[0]
        security = CertificateSecurity(sdData)
        self.owner_sid = security.owner
        if not self.domain_sid:
            self.domain_sid = '-'.join(self.owner_sid.split("-")[:-1])
        aces = security.aces

        for sid, rights in aces.items():
            # TODO: Fix Logic here
            # if sid in list(WELL_KNOWN_SIDS.keys()):
            #     continue

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

class UTILS:
    @staticmethod
    def get_template_oid(oid_forest):
        oid_part_1 = get_random_num(10000000,99999999)
        oid_part_2 = get_random_num(10000000,99999999)
        oid_part_3 = get_random_hex(32)
        
        template_oid = f"{oid_forest}.{oid_part_1}.{oid_part_2}"
        templatename = f"{oid_part_2}.{oid_part_3}"

        return template_oid, templatename
        

