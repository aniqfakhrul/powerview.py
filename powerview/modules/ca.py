#!/usr/bin/env python3
import logging
from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string, string_to_bin
from impacket.dcerpc.v5 import rrp
from impacket.smb3 import SessionError
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3 import SUBTREE, BASE, LEVEL
import socket

from powerview.utils.helpers import strip_entry

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

#stolen from https://github.com/ly4k/Certipy
class SecurityDescriptorParser:
    """Base class for parsing security descriptors."""

    RIGHTS_TYPE = None  # Must be defined by subclasses

    def __init__(self, security_descriptor: bytes):
        """
        Initialize a security descriptor parser.

        Args:
            security_descriptor: Binary representation of a security descriptor
        """
        if self.RIGHTS_TYPE is None:
            raise NotImplementedError("Subclasses must define RIGHTS_TYPE")

        # Parse the security descriptor
        self.sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        self.sd.fromString(security_descriptor)

        # Extract owner SID
        self.owner = format_sid(self.sd["OwnerSid"].getData())

        # Dictionary to store access control entries by SID
        self.aces: Dict[str, Dict[str, Any]] = {}

        # Parse the ACEs
        self._parse_aces()

    def _parse_aces(self) -> None:
        """Parse the access control entries from the security descriptor."""
        pass  # To be implemented by subclasses

class CertificateSecurity(ActiveDirectorySecurity):
    RIGHTS_TYPE = CERTIFICATE_RIGHTS

class CASecurity(SecurityDescriptorParser):
    RIGHTS_TYPE = CERTIFICATION_AUTHORITY_RIGHTS
    def _parse_aces(self) -> None:
        """
        Parse the access control entries from the security descriptor.

        CA security descriptors have a simpler structure than AD security descriptors.
        """
        aces = self.sd["Dacl"]["Data"]

        for ace in aces:
            sid = format_sid(ace["Ace"]["Sid"].getData())

            if sid not in self.aces:
                self.aces[sid] = {
                    "rights": self.RIGHTS_TYPE(0),
                    "extended_rights": [],  # CAs don't use extended rights, but keeping for consistency
                    "inherited": bool(ace["AceFlags"] & INHERITED_ACE),
                }

            if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                mask = self.RIGHTS_TYPE(ace["Ace"]["Mask"]["Mask"])
                self.aces[sid]["rights"] |= mask

class CAEnum:
    def __init__(self, powerview, check_all=False):
        self.powerview = powerview
        self.ldap_session = self.powerview.conn.ldap_session
        self.ldap_server = self.powerview.conn.ldap_server
        self.root_dn = self.powerview.root_dn
        self.configuration_dn = self.powerview.configuration_dn
        self.check_all = check_all
        
    def fetch_root_ca(self, properties=['*']):
        enroll_filter = "(objectclass=certificationAuthority)"
        ca_search_base = f"CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        logging.debug(f'LDAP Base: {ca_search_base}')
        logging.debug(f'LDAP Filter: {enroll_filter}')
        
        return self.ldap_session.extend.standard.paged_search(ca_search_base, enroll_filter, attributes=list(properties), paged_size=1000, generator=True)

    def fetch_enrollment_services(self,
            identity=None,
            properties=[
                "cn",
                "name",
                "dNSHostName",
                "cACertificateDN",
                "cACertificate",
                "certificateTemplates",
                "objectGUID",
            ],
            searchbase=None,
            search_scope=SUBTREE,
            no_cache=False,
            no_vuln_check=False,
            raw=False,
            include_sd=False
        ):
        if identity:
            identity_filter = f"(|(cn={identity})(name={identity}))"
        else:
            identity_filter = ""
        enroll_filter = f"(&(objectClass=pKIEnrollmentService){identity_filter})"

        if not searchbase:
            searchbase = f"CN=Enrollment Services,CN=Public Key Services,CN=Services,{self.configuration_dn}"

        if include_sd:
            properties.append("nTSecurityDescriptor")
            controls = security_descriptor_control(sdflags=0x05)
        else:
            controls = None

        logging.debug(f"LDAP Base: {searchbase}")
        logging.debug(f"LDAP Filter: {enroll_filter}")
        entries = self.ldap_session.extend.standard.paged_search(
            searchbase,
            enroll_filter,
            attributes=list(properties),
            paged_size=1000,
            generator=True,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw,
            controls=controls
        )
        if self.check_all:
            for entry in entries:
                # Access Rights + owner
                if not entry["attributes"]["nTSecurityDescriptor"]:
                    continue

                entry_rrp = self.get_rrp_config(computer_name=entry["attributes"]["dNSHostName"], ca=entry["attributes"]["name"])
                aces = entry_rrp["aces"].aces

                # Access Rights + owner
                security = CASecurity(entry["attributes"]["nTSecurityDescriptor"])
                entry["attributes"]["Owner"] = self.powerview.convertfrom_sid(security.owner)
                entry["attributes"]["ManageCa"] = []
                entry["attributes"]["ManageCertificates"] = []
                entry["attributes"]["Enroll"] = []
                entry["attributes"]["Vulnerabilities"] = []
                
                for sid, rights in aces.items():
                    if CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CA in rights["rights"]:
                        entry["attributes"]["ManageCa"].append(self.powerview.convertfrom_sid(sid))
                    if CERTIFICATION_AUTHORITY_RIGHTS.MANAGE_CERTIFICATES in rights["rights"]:
                        entry["attributes"]["ManageCertificates"].append(self.powerview.convertfrom_sid(sid))
                    if CERTIFICATION_AUTHORITY_RIGHTS.ENROLL in rights["rights"]:
                        entry["attributes"]["Enroll"].append(self.powerview.convertfrom_sid(sid))
                
                # Active Policy
                entry["attributes"]["ActivePolicy"] = entry_rrp["active_policy"]

                # Disabled Extensions
                entry["attributes"]["DisabledExtensions"] = entry_rrp["disable_extension_list"]

                # Request Disposition
                entry["attributes"]["RequestDisposition"] = (
                    "Pending" if entry_rrp["request_disposition"] & 0x100 else "Issue"
                )

                # User Specified SAN
                entry["attributes"]["UserSpecifiedSAN"] = (
                    "Enabled" if (entry_rrp["edit_flags"] & 0x00040000) == 0x00040000 else "Disabled"
                )

                # Enforce Encryption Flag
                entry["attributes"]["EnforceEncryptionFlag"] = (
                    "Enabled" if (entry_rrp["interface_flags"] & 0x00000200) == 0x00000200 else "Disabled"
                )

                # Vulnerabilities
                # ESC16
                if ("1.3.6.1.4.1.311.25.2" in entry["attributes"]["DisabledExtensions"]) and (entry["attributes"]["RequestDisposition"] in ["Issue", "Unknown"]):
                    # Check if current user is part of entry["attributes"]["Enroll"]
                    for sid in get_user_sids(self.powerview.get_domain_sid(), self.powerview.current_user_sid, self.ldap_session):
                        if entry["attributes"]["Enroll"][0] in self.powerview.convertfrom_sid(sid):
                            entry["attributes"]["Vulnerabilities"].append("ESC16")  
                
        return entries

    def get_rrp_config(self,
		computer_name,
        ca,
		port=445
	):

        KNOWN_PROTOCOLS = {
            139: {'bindstr': r'ncacn_np:%s[\pipe\winreg]', 'set_host': True},
            445: {'bindstr': r'ncacn_np:%s[\pipe\winreg]', 'set_host': True},
        }

        entries = {}

        stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % computer_name
        computer_name = host2ip(computer_name, self.powerview.conn.nameserver, 3, True, use_system_ns=self.powerview.conn.use_system_ns)
        try:
            dce = self.powerview.conn.connectRPCTransport(host=computer_name, stringBindings=stringBinding)
        except SessionError as e:
            logging.warning(f"[CAEnum] Failed to connect to {computer_name}, retrying...")
            self.get_rrp_config(computer_name, ca)

        if not dce:
            logging.error("[CAEnum] Failed to connect to %s" % (computer_name))
            return False

        for _ in range(3):
            try:
                dce.connect()
                _ = dce.bind(rrp.MSRPC_UUID_RRP)
                break
            except Exception as e:
                logging.error("[CAEnum] Failed to bind to %s" % (computer_name))
                continue

        try:
            # Open Local Machine registry handle
            hklm = rrp.hOpenLocalMachine(dce)
            h_root_key = hklm["phKey"]

            # First retrieve active policy module information
            policy_key_path = (
                f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca}\\"
                "PolicyModules"
            )
            policy_key = rrp.hBaseRegOpenKey(dce, h_root_key, policy_key_path)

            # Get active policy module name
            _, active_policy = rrp.hBaseRegQueryValue(
                dce, policy_key["phkResult"], "Active"
            )

            if not isinstance(active_policy, str):
                logging.warning(f"[CAEnum] Expected a string, got {type(active_policy)!r} for {ca}")
                logging.warning(f"[CAEnum] Falling back to default policy")
                active_policy = "CertificationAuthority_MicrosoftDefault.Policy"

            active_policy = active_policy.strip("\x00")

            # Open policy module configuration
            policy_key_path = (
                f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca}\\"
                f"PolicyModules\\{active_policy}"
            )
            policy_key = rrp.hBaseRegOpenKey(dce, h_root_key, policy_key_path)

            # Retrieve edit flags (controls certificate request behavior)
            _, edit_flags = rrp.hBaseRegQueryValue(
                dce, policy_key["phkResult"], "EditFlags"
            )

            if not isinstance(edit_flags, int):
                logging.warning(f"[CAEnum] Expected an integer, got {type(edit_flags)!r} for {ca}")
                logging.warning(f"[CAEnum] Falling back to default edit flags")
                edit_flags = 0x00000000

            # Retrieve request disposition (auto-enrollment settings    )
            _, request_disposition = rrp.hBaseRegQueryValue(
                dce, policy_key["phkResult"], "RequestDisposition"
            )

            if not isinstance(request_disposition, int):
                logging.warning(f"[CAEnum] Expected an integer, got {type(request_disposition)!r} for {ca}")
                logging.warning(f"[CAEnum] Falling back to default request disposition")
                request_disposition = 0x00000000

            
            # Retrieve disabled extensions
            _, disabled_extensions = rrp.hBaseRegQueryValue(
                dce, policy_key["phkResult"], "DisableExtensionList"
            )

            if not isinstance(disabled_extensions, str):
                logging.warning(f"[CAEnum] Expected a string, got {type(disabled_extensions)!r} for {ca}")
                logging.warning(f"[CAEnum] Falling back to default disabled extensions")
                disabled_extensions = ""

            # Process null-terminated string list into Python list
            disable_extension_list = [
                item for item in disabled_extensions.strip("\x00").split("\x00") if item
            ]

            # Now get general CA configuration settings
            configuration_key_path = (
                f"SYSTEM\\CurrentControlSet\\Services\\CertSvc\\Configuration\\{ca}\\"
            )
            configuration_key = rrp.hBaseRegOpenKey(dce, h_root_key, configuration_key_path)

            # Retrieve interface flags (controls CA interface behavior)
            _, interface_flags = rrp.hBaseRegQueryValue(
                dce, configuration_key["phkResult"], "InterfaceFlags"
            )

            if not isinstance(interface_flags, int):
                logging.warning(f"[CAEnum] Expected an integer, got {type(interface_flags)!r} for {ca}")
                logging.warning(f"[CAEnum] Falling back to default interface flags")
                interface_flags = 0x00000000

            # Retrieve security descriptor (controls access permissions)
            _, security_descriptor = rrp.hBaseRegQueryValue(
                dce, configuration_key["phkResult"], "Security"
            )

            if not isinstance(security_descriptor, bytes):
                logging.warning(f"[CAEnum] Expected bytes, got {type(security_descriptor)!r} for {ca}")
            
            security_descriptor = CASecurity(security_descriptor)

            entries = {
                "active_policy": active_policy,
                "edit_flags": edit_flags,
                "request_disposition": request_disposition,
                "disable_extension_list": disable_extension_list,
                "interface_flags": interface_flags,
                "aces": security_descriptor
            }
        except Exception as e:
            raise ValueError("[CAEnum] %s" % (str(e)))

        dce.disconnect()

        return entries

    def get_certificate_templates(self, properties=None, ca_search_base=None, identity=None, search_scope=SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        if not properties:
            properties=[
                "objectGUID",
                "cn",
                "name",
                "displayName",
                "pKIExpirationPeriod",
                "pKIOverlapPeriod",
                "msPKI-Enrollment-Flag",
                "msPKI-Private-Key-Flag",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Certificate-Policy",
                "msPKI-Minimal-Key-Size",
                "msPKI-RA-Signature",
                "pKIExtendedKeyUsage",
                "nTSecurityDescriptor",
                "objectGUID",
                "whenCreated",
                "whenChanged",
                "msPKI-Template-Schema-Version"
            ]

        if not ca_search_base:
            ca_search_base = f"CN=Certificate Templates,CN=Public Key Services,CN=Services,{self.configuration_dn}"
        
        search_filter = ""
        identity_filter = ""

        if identity:
            identity_filter = f"(|(cn={identity})(displayName={identity}))"

        search_filter = f"(&(objectclass=pKICertificateTemplate){identity_filter})"

        logging.debug(f"LDAP Base: {ca_search_base}")
        logging.debug(f"LDAP Filter: {search_filter}")
        return self.ldap_session.extend.standard.paged_search(
            self.configuration_dn,
            search_filter,
            attributes=properties,
            controls=security_descriptor_control(sdflags=0x05),
            paged_size=1000,
            generator=True,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )

    # https://github.com/ly4k/Certipy/blob/main/certipy/commands/find.py#L688
    def check_web_enrollment(self, target, timeout=5):
        if target is None:
            logging.debug("No target found")
            return [False, False]  # [HTTP, HTTPS]

        results = [False, False]  # [HTTP, HTTPS]
        ports = [80, 443]
        protocols = ["HTTP", "HTTPS"]

        for i, port in enumerate(ports):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                logging.debug(f"Default timeout is set to {timeout}")
                sock.settimeout(timeout)
                logging.debug(f"Connecting to {target}:{port}")
                sock.connect((target, port))
                
                if port == 80:
                    sock.sendall(
                        "\r\n".join(
                            ["HEAD /certsrv/ HTTP/1.1", f"Host: {target}", "\r\n"]
                        ).encode()
                    )
                else:  # HTTPS
                    sock.sendall(
                        "\r\n".join(
                            ["HEAD /certsrv/ HTTP/1.1", f"Host: {target}", "Connection: close", "\r\n"]
                        ).encode()
                    )
                
                resp = sock.recv(256)
                sock.close()
                head = resp.split(b"\r\n")[0].decode()

                results[i] = " 404 " not in head
                logging.debug(f"{protocols[i]} enrollment check result: {results[i]}")
                
            except ConnectionRefusedError:
                logging.debug(f"Connection refused for {protocols[i]} on {target}:{port}")
                continue
            except socket.timeout:
                logging.debug(f"Can't reach {target}:{port} ({protocols[i]})")
                continue
            except Exception as e:
                logging.warning(
                    f"Got error while trying to check for {protocols[i]} enrollment: {e}"
                )
                continue
        
        if results[0] and results[1]:
            return [f"http://{target}/certsrv", f"https://{target}/certsrv"]
        elif results[0]:
            return [f"http://{target}/certsrv"]
        elif results[1]:
            return [f"https://{target}/certsrv"]
        else:
            return results

    def get_issuance_policies(self, properties=None, sdflags=0x5, no_cache=False, no_vuln_check=False, raw=False):
        if not properties:
            properties = [
                "cn",
                "name", 
                "displayName",
                "msDS-OIDToGroupLink",
                "msPKI-Cert-Template-OID",
                "nTSecurityDescriptor",
                "objectGUID"
            ]
        searchbase = f"CN=OID,CN=Public Key Services,CN=Services,{self.configuration_dn}"
        ldap_filter = "(objectclass=msPKI-Enterprise-Oid)"
        entries = []
        return self.ldap_session.extend.standard.paged_search(
            searchbase,
            ldap_filter,
            attributes=list(properties), 
            paged_size=1000,
            generator=True,
            controls=security_descriptor_control(sdflags=sdflags),
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def add_oid(self, template_name, template_oid, displayname=None, flags=0x01):
        oa = {
            'Name': template_name,
            'DisplayName': displayname if displayname else template_name,
            'flags': flags,
            'msPKI-Cert-Template-OID': template_oid,
        }
        oidpath = f"CN={template_oid},CN=OID,CN=Public Key Services,CN=Services,{self.configuration_dn}"
        self.ldap_session.add(oidpath, ['top','msPKI-Enterprise-Oid'], oa)
        if self.ldap_session.result['result'] == 0:
            logging.debug(f"[Add-DomainCATemplate] Added new template OID {oidpath}")
            logging.debug(f"[Add-DomainCATemplate] msPKI-Cert-Template-OID: {template_oid}")
            return True
        else:
            logging.error(f"[Add-DomainCATemplate] Error adding new template OID ({self.ldap_session.result['description']})")
            return False


class PARSE_TEMPLATE:
    def __init__(self, template, current_user_sid=None, linked_group=None, ldap_session=None):
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
        self.current_user_sid = current_user_sid
        self.linked_group = linked_group
        self.ldap_session = ldap_session

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
        self.set_certificate_name_flag(self.template.get("msPKI-Certificate-Name-Flag"))
        if self.certificate_name_flag is not None:
                self.set_certificate_name_flag(MS_PKI_CERTIFICATE_NAME_FLAG(
                    int(self.certificate_name_flag)
                ))
        else:
            self.set_certificate_name_flag(MS_PKI_CERTIFICATE_NAME_FLAG(0))

        # resolve enrollment flag
        self.set_enrollment_flag(self.template.get("msPKI-Enrollment-Flag"))
        if self.enrollment_flag is not None:
            self.set_enrollment_flag(MS_PKI_ENROLLMENT_FLAG(int(self.enrollment_flag)))
        else:
            self.set_enrollment_flag(MS_PKI_ENROLLMENT_FLAG(0))

        # resolve authorized signature
        self.set_authorized_signatures_required(self.template.get("msPKI-RA-Signature"))
        if self.authorized_signatures_required is not None:
                self.set_authorized_signatures_required(int(self.authorized_signatures_required))
        else:
            self.set_authorized_signatures_required(0)

        # resolve no_security_extension
        self.set_no_security_extension((
                MS_PKI_ENROLLMENT_FLAG.NO_SECURITY_EXTENSION in self.enrollment_flag
            ))

        # resolve pKIExtendedKeyUsage
        eku = self.template.get("pKIExtendedKeyUsage")
        if not isinstance(eku, list):
            if eku is None:
                eku = []
            else:
                eku = [eku]

        eku = list(map(lambda x: x.decode() if isinstance(x, bytes) else x, eku))
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
        self.set_validity_period(self.template.get("pKIExpirationPeriod"))

        # resolve renewal_period
        self.set_renewal_period(self.template.get("pKIOverlapPeriod"))

    def can_user_enroll_template(self):
        enrollable_sids = []
        user_can_enroll = False
        for sid in get_user_sids(self.domain_sid, self.current_user_sid, self.ldap_session):
            if sid in self.parsed_dacl["Enrollment Rights"]:
                enrollable_sids.append(sid)
                user_can_enroll = True
        return user_can_enroll, enrollable_sids

    def check_vulnerable_template(self):
        vulns = {}
        user_can_enroll, enrollable_sids = self.can_user_enroll_template()
        if not self.get_requires_manager_approval() and not self.get_authorized_signatures_required():
            # ESC1
            # TODO: add another user_can_enroll logic
            if (user_can_enroll and self.get_enrollee_supplies_subject() and self.get_client_authentication()):
                vulns["ESC1"] = enrollable_sids

            # ESC2
            if user_can_enroll and self.get_any_purpose():
                vulns["ESC2"] = enrollable_sids

            # ESC3
            if user_can_enroll and self.get_enrollment_agent():
                vulns["ESC3"] = enrollable_sids

            # ESC9
            if user_can_enroll and self.get_no_security_extension():
                vulns["ESC9"] = enrollable_sids

            # ESC13
            if user_can_enroll and self.get_client_authentication() and self.template["msPKI-Certificate-Policy"] and self.linked_group:
                vulns["ESC13"] = enrollable_sids

            # ESC15
            if user_can_enroll and self.get_enrollee_supplies_subject() and int(self.template.get("msPKI-Template-Schema-Version")) == 1:
                vulns["ESC15"] = enrollable_sids
        

        # ESC4
        security = CertificateSecurity(self.template.get("nTSecurityDescriptor"))
        owner_sid = security.owner

        if owner_sid in get_user_sids(self.domain_sid, self.current_user_sid, self.ldap_session):
            vulns["ESC4"] = [owner_sid]
        else:
            has_vulnerable_acl = False
            aces = security.aces
            vulnerable_acl_sids = set()
            
            for sid, rights in aces.items():
                if sid not in get_user_sids(self.domain_sid, self.current_user_sid, self.ldap_session):
                    continue

                ad_rights = rights["rights"] 
                ad_extended_rights = rights["extended_rights"]
                
                for right in [CERTIFICATE_RIGHTS.GENERIC_ALL, CERTIFICATE_RIGHTS.WRITE_OWNER, 
                             CERTIFICATE_RIGHTS.WRITE_DACL, CERTIFICATE_RIGHTS.WRITE_PROPERTY]:
                    if right in ad_rights:
                        vulnerable_acl_sids.add(sid)
                        has_vulnerable_acl = True
                
                if (CERTIFICATE_RIGHTS.WRITE_PROPERTY in ad_rights and
                    ('00000000-0000-0000-0000-000000000000' in ad_extended_rights and 
                     ad_rights & ACTIVE_DIRECTORY_RIGHTS.EXTENDED_RIGHT)):
                    vulnerable_acl_sids.add(sid)
                    has_vulnerable_acl = True

            if has_vulnerable_acl:
                vulns["ESC4"] = list(vulnerable_acl_sids)

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
        sdData = self.template.get("nTSecurityDescriptor")
        if not sdData:
            raise Exception(f"No nTSecurityDescriptor found for template {self.template.get('cn')}")
        security = CertificateSecurity(sdData)
        for guid in permissions.get(right_opt).get('rights'):
            security.sd['Dacl']['Data'].append(self.create_object_ace(guid, sid, mask=permissions.get(right_opt).get('mask')))
        return security.sd.getData() 

    def parse_dacl(self):
        user_can_enroll = False
        enrollment_rights = []
        all_extended_rights = []

        sdData = self.template.get("nTSecurityDescriptor")
        if not sdData:
            raise Exception(f"No nTSecurityDescriptor found for template {self.template.get('cn')}")
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
        

