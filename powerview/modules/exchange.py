#!/usr/bin/env python3
import logging
import re
import ldap3
import datetime
from impacket.ldap import ldaptypes
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.protocol.microsoft import security_descriptor_control

from powerview.utils.helpers import (
    strip_entry,
    is_admin_sid,
    format_datetime,
)
from powerview.utils.constants import (
    WELL_KNOWN_SIDS,
    ACTIVE_DIRECTORY_RIGHTS,
    EXTENDED_RIGHTS_NAME_MAP
)

# Exchange-specific constants
EXCHANGE_OBJECT_TYPES = {
    "msExchExchangeServer": "Exchange Server",
    "msExchMailboxDatabase": "Mailbox Database",
    "msExchMailboxServer": "Mailbox Server",
    "msExchActiveSync": "ActiveSync",
    "msExchMailboxUser": "Mailbox User",
    "msExchPublicFolder": "Public Folder"
}

EXCHANGE_ROLES = {
    "Organization Management": "Most powerful Exchange role, equivalent to Domain Admin in Exchange context",
    "Recipient Management": "Can create and modify Exchange recipients",
    "Exchange Trusted Subsystem": "Has extensive Exchange permissions",
    "Public Folder Management": "Can manage public folders",
    "Help Desk": "Can reset passwords and manage mail recipient properties",
    "Discovery Management": "Can perform mailbox searches and exports",
    "Mailbox Import Export": "Can import and export mailbox content"
}

EXCHANGE_EXTENDED_RIGHTS = {
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "Send-As Right",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "Receive-As Right",
    "ab721a54-1e2f-11d0-9819-00aa0040529b": "Open-Mailbox Right",
    "dc50a4f8-6fc8-4b5f-942f-2b103221a85d": "Send-To Right"
}

# Combining Exchange-specific extended rights with common AD extended rights
ALL_EXTENDED_RIGHTS = {**EXTENDED_RIGHTS_NAME_MAP, **EXCHANGE_EXTENDED_RIGHTS}

class ExchangeSecurity:
    """
    Class for parsing and analyzing security descriptors on Exchange objects
    """
    def __init__(self, security_descriptor):
        self.sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        self.sd.fromString(security_descriptor)
        
        self.owner = format_sid(self.sd["OwnerSid"].getData())
        self.owner_name = None
        self.aces = {}
        
        # Process all ACEs in the security descriptor
        if self.sd["Dacl"]:
            aces = self.sd["Dacl"]["Data"]
            for ace in aces:
                sid = format_sid(ace["Ace"]["Sid"].getData())
                
                if sid not in self.aces:
                    self.aces[sid] = {
                        "rights": ACTIVE_DIRECTORY_RIGHTS(0),
                        "extended_rights": [],
                        "inherited": bool(ace["AceFlags"] & 0x10),  # INHERITED_ACE flag
                        "object_type": None
                    }
                
                # Process allowed access ACEs
                if ace["AceType"] == ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE:
                    self.aces[sid]["rights"] |= ACTIVE_DIRECTORY_RIGHTS(ace["Ace"]["Mask"]["Mask"])
                
                # Process object-specific ACEs (like extended rights)
                elif ace["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                    if ace["Ace"]["Flags"] & 0x01:  # OBJECT_TYPE_PRESENT flag
                        uuid = str(ace["Ace"]["ObjectType"]).lower()
                        self.aces[sid]["extended_rights"].append(uuid)
                        self.aces[sid]["object_type"] = uuid
    
    def get_owner_name(self, resolver_func=None):
        """Get the name of the security descriptor owner"""
        if not self.owner_name and resolver_func:
            self.owner_name = resolver_func(self.owner)
        return self.owner_name or self.owner
    
    def get_ace_details(self, resolver_func=None):
        """Get comprehensive details about all ACEs"""
        result = []
        
        for sid, ace_data in self.aces.items():
            principal_name = resolver_func(sid) if resolver_func else sid
            
            # Create a human-readable description of rights
            rights_description = []
            for right_name, right_value in ACTIVE_DIRECTORY_RIGHTS.__members__.items():
                if ace_data["rights"] & right_value:
                    rights_description.append(right_name)
            
            # Create a human-readable description of extended rights
            extended_rights_desc = []
            for right_id in ace_data["extended_rights"]:
                right_name = ALL_EXTENDED_RIGHTS.get(right_id, f"Unknown Right ({right_id})")
                extended_rights_desc.append(right_name)
            
            result.append({
                "Principal": principal_name,
                "SID": sid,
                "Rights": ", ".join(rights_description) if rights_description else "None",
                "ExtendedRights": ", ".join(extended_rights_desc) if extended_rights_desc else "None",
                "Inherited": ace_data["inherited"]
            })
        
        return result
    
    def check_dangerous_permissions(self):
        """Check for permissions that could be abused in Exchange"""
        dangerous = []
        
        for sid, ace_data in self.aces.items():
            # Check for dangerous standard rights
            if ace_data["rights"] & ACTIVE_DIRECTORY_RIGHTS.WRITE_DAC:
                dangerous.append({"SID": sid, "Issue": "WriteDACL permission - Can modify permissions"})
            
            if ace_data["rights"] & ACTIVE_DIRECTORY_RIGHTS.WRITE_OWNER:
                dangerous.append({"SID": sid, "Issue": "WriteOwner permission - Can take ownership"})
            
            if ace_data["rights"] & ACTIVE_DIRECTORY_RIGHTS.GENERIC_ALL:
                dangerous.append({"SID": sid, "Issue": "GenericAll permission - Full control"})
            
            # Check for dangerous extended rights
            for right_id in ace_data["extended_rights"]:
                if right_id in EXCHANGE_EXTENDED_RIGHTS:
                    right_name = EXCHANGE_EXTENDED_RIGHTS[right_id]
                    dangerous.append({"SID": sid, "Issue": f"Exchange right: {right_name}"})
        
        return dangerous


class ExchangeEnum:
    """
    Class for enumerating and analyzing Exchange objects and permissions in Active Directory
    """
    def __init__(self, powerview):
        self.powerview = powerview
        self.ldap_session = self.powerview.conn.ldap_session
        self.ldap_server = self.powerview.conn.ldap_server
        self.root_dn = self.powerview.root_dn
        self.configuration_dn = self.powerview.configuration_dn
    
    def get_exchange_servers(self, properties=None, identity=None, searchbase=None, sd_flag=None, 
                          search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange servers in the domain
        
        Args:
            properties: Properties to retrieve (optional)
            identity: Server name to target (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            List of Exchange servers with their properties
        """
        if not properties:
            properties = [
                "name",
                "cn",
                "objectClass",
                "objectCategory",
                "objectGUID",
                "distinguishedName",
                "whenCreated",
                "whenChanged",
                "serialNumber",
                "serverRole",
                "legacyExchangeDN",
                "networkAddress",
                "msExchServerRole",
                "msExchCurrentServerRoles",
                "msExchVersion",
                "msExchProductID",
                "msExchServerSite",
                "msExchServerFaultZone",
                "msExchInstallPath",
                "msExchDataPath",
                "msExchComponentStates",
                "msExchMinAdminVersion",
                "msExchMailboxRelease",
                "msExchServerInternalTLSCert",
                "nTSecurityDescriptor"
            ]
        
        if not searchbase:
            searchbase = self.configuration_dn

        if sd_flag:
            sd_flag = security_descriptor_control(sdflags=sd_flag)
        
        search_filter = "(&(objectClass=msExchExchangeServer)(adminDisplayName=*))"
        
        if identity:
            search_filter = f"(&{search_filter}(|(name={identity})(dNSHostName={identity})))"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=sd_flag,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def get_exchange_mailboxes(self, properties=None, identity=None, searchbase=None, sd_flag=None, 
                            search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange mailboxes in the domain
        
        Args:
            properties: Properties to retrieve (optional)
            identity: User name to target (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            List of Exchange mailboxes with their properties
        """
        if not properties:
            properties = [
                "name",
                "mail", 
                "proxyAddresses",
                "objectGUID", 
                "objectSid",
                "legacyExchangeDN",
                "homeMDB",
                "msExchHomeServerName",
                "msExchMailboxGuid",
                "msExchMailboxSecurityDescriptor",
                "msExchDelegateListLink",
                "nTSecurityDescriptor",
                "whenCreated",
                "whenChanged"
            ]
        
        if not searchbase:
            searchbase = self.configuration_dn

        if sd_flag:
            sd_flag = security_descriptor_control(sdflags=sd_flag)
        
        # Look for users with Exchange mailboxes
        search_filter = "(&(objectCategory=person)(objectClass=user)(msExchMailboxGuid=*))"
        
        if identity:
            search_filter = f"(&{search_filter}(|(name={identity})(sAMAccountName={identity})(mail={identity})))"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=sd_flag,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def get_exchange_databases(self, properties=None, identity=None, searchbase=None, sd_flag=None, 
                            search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange mailbox databases in the domain
        
        Args:
            properties: Properties to retrieve (optional)
            identity: Database name to target (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            List of Exchange mailbox databases with their properties
        """
        if not properties:
            properties = [
                "objectClass",
                "cn",
                "distinguishedName",
                "displayName",
                "adminDisplayName",
                "objectCategory",
                "name",
                "objectGUID",
                "homeMDBBL",
                "msExchOwningServer",
                "msExchVersion",
                "msExchDatabaseCreated",
                "whenCreated",
                "whenChanged"
            ]
        
        if not searchbase:
            searchbase = self.configuration_dn

        if sd_flag:
            sd_flag = security_descriptor_control(sdflags=sd_flag)
        
        search_filter = "(objectClass=msExchMDB)"
        
        if identity:
            search_filter = f"(&{search_filter}(|(name={identity})(msExchDatabaseName={identity})))"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=sd_flag,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def get_exchange_organization(self, properties=None, searchbase=None, sd_flag=None,
                               search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange organization configuration in the domain
        
        Args:
            properties: Properties to retrieve (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            Exchange organization configuration
        """
        if not properties:
            properties = [
                "name",
                "objectGUID",
                "msExchProductID", 
                "msExchVersion",
                "msExchOrganizationName",
                "whenCreated",
                "whenChanged"
            ]
        
        if not searchbase:
            # Exchange organization containers are in the Configuration naming context
            searchbase = f"CN=Microsoft Exchange,CN=Services,{self.configuration_dn}"

        if sd_flag:
            sd_flag = security_descriptor_control(sdflags=sd_flag)
        
        search_filter = "(objectClass=msExchOrganizationContainer)"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=sd_flag,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def get_exchange_groups(self, properties=None, searchbase=None, sd_flag=None,
                         search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange security groups in the domain
        
        Args:
            properties: Properties to retrieve (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            List of Exchange security groups with their properties
        """
        if not properties:
            properties = [
                "name",
                "objectGUID", 
                "objectSid",
                "member",
                "groupType",
                "msExchGroupDepartRestriction",
                "msExchGroupJoinRestriction",
                "whenCreated",
                "whenChanged"
            ]
        
        if not searchbase:
            searchbase = self.configuration_dn
        
        if sd_flag:
            sd_flag = security_descriptor_control(sdflags=sd_flag)
        
        # This will find Exchange-related security groups
        search_filter = "(&(objectClass=group)(|(name=Exchange*)(name=*Mail*)(name=Organization Management)(name=*recipient*)))"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=sd_flag,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def get_exchange_virtual_directories(self, properties=None, identity=None, searchbase=None, sd_flag=None,
                                      search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange virtual directories in the domain
        
        Args:
            properties: Properties to retrieve (optional)
            identity: Directory name to target (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            List of Exchange virtual directories with their properties
        """
        if not properties:
            properties = [
                "name",
                "objectGUID",
                "msExchInternalHostname",
                "msExchExternalHostname",
                "msExchRequireSSL",
                "msExchUMVirtualDirectory",
                "whenCreated",
                "whenChanged"
            ]
        
        if not searchbase:
            searchbase = self.configuration_dn

        if sd_flag:
            sd_flag = security_descriptor_control(sdflags=sd_flag)
        
        # This will find various Exchange virtual directories (OWA, ECP, etc.)
        search_filter = "(objectClass=msExchVirtualDirectory)"
        
        if identity:
            search_filter = f"(&{search_filter}(name={identity}))"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=sd_flag,
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def get_exchange_ews_virtual_directories(self, properties=None, searchbase=None,
                                         search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
        """
        Find Exchange Web Services (EWS) virtual directories
        
        Args:
            properties: Properties to retrieve (optional)
            searchbase: Search base for the LDAP query (optional)
            search_scope: LDAP search scope (default: SUBTREE)
            no_cache: Whether to use cache (default: False)
            no_vuln_check: Whether to skip vulnerability checks (default: False)
            raw: Whether to return raw LDAP entries (default: False)
        Returns:
            List of EWS virtual directories with their properties
        """
        if not properties:
            properties = [
                "name",
                "objectGUID",
                "msExchInternalHostname",
                "msExchExternalHostname",
                "msExchRequireSSL",
                "whenCreated",
                "whenChanged"
            ]
        
        if not searchbase:
            searchbase = self.configuration_dn
        
        search_filter = "(&(objectClass=msExchVirtualDirectory)(name=EWS*))"
        
        logging.debug(f"[Exchange] LDAP search base: {searchbase}")
        logging.debug(f"[Exchange] LDAP search filter: {search_filter}")
        
        return self.ldap_session.extend.standard.paged_search(
            searchbase, 
            search_filter, 
            attributes=properties, 
            paged_size=1000, 
            generator=True,
            controls=security_descriptor_control(sdflags=0x07),
            search_scope=search_scope,
            no_cache=no_cache,
            no_vuln_check=no_vuln_check,
            raw=raw
        )
    
    def analyze_exchange_permissions(self, objects, resolve_sids=True):
        """
        Analyze security permissions on Exchange objects to identify potential attack vectors
        
        Args:
            objects: List of Exchange LDAP objects to analyze
            resolve_sids: Whether to resolve SIDs to names (default: True)
            
        Returns:
            Dictionary of objects with their permissions and potential security issues
        """
        results = {}
        
        for obj in objects:
            if obj['type'] != 'searchResEntry':
                continue
                
            attrs = obj.get('attributes', {})
            obj_name = attrs.get('name', ['Unknown'])[0] if isinstance(attrs.get('name', []), list) else attrs.get('name', 'Unknown')
            
            # Determine object type
            obj_type = "Unknown"
            for cls, type_name in EXCHANGE_OBJECT_TYPES.items():
                if cls in str(attrs.get('objectClass', [])):
                    obj_type = type_name
                    break
            
            # Skip objects with no security descriptor
            if 'nTSecurityDescriptor' not in attrs:
                continue
            
            # Parse security descriptor
            security = ExchangeSecurity(attrs['nTSecurityDescriptor'])
            
            # Resolver function for SIDs
            def resolve_sid(sid):
                if not resolve_sids:
                    return sid
                
                # First check well-known SIDs
                if sid in WELL_KNOWN_SIDS:
                    return WELL_KNOWN_SIDS[sid]
                
                # Try to resolve via PowerView
                try:
                    return self.powerview.convertfrom_sid(sid)
                except:
                    return sid
            
            # Get all permission details
            permissions = security.get_ace_details(resolve_sid if resolve_sids else None)
            
            # Check for dangerous permissions
            vulnerabilities = security.check_dangerous_permissions()
            if resolve_sids:
                for vuln in vulnerabilities:
                    vuln["Principal"] = resolve_sid(vuln["SID"])
            
            # Store results
            results[obj_name] = {
                "ObjectType": obj_type,
                "Owner": security.get_owner_name(resolve_sid if resolve_sids else None),
                "Permissions": permissions,
                "Vulnerabilities": vulnerabilities,
                "ObjectGUID": attrs.get('objectGUID', 'Unknown')
            }
        
        return results
    
    def check_mailbox_permissions(self, mailboxes, resolve_sids=True):
        """
        Check mailbox permissions for specific scenarios like Send-As, Full Access, etc.
        
        Args:
            mailboxes: List of mailbox LDAP objects to analyze
            resolve_sids: Whether to resolve SIDs to names (default: True)
            
        Returns:
            Dictionary of mailboxes with their special permissions
        """
        results = {}
        
        for mailbox in mailboxes:
            if mailbox['type'] != 'searchResEntry':
                continue
                
            attrs = mailbox.get('attributes', {})
            mailbox_name = attrs.get('name', ['Unknown'])[0] if isinstance(attrs.get('name', []), list) else attrs.get('name', 'Unknown')
            mail = attrs.get('mail', ['Unknown'])[0] if isinstance(attrs.get('mail', []), list) else attrs.get('mail', 'Unknown')
            
            # Skip objects with no security descriptor
            if 'nTSecurityDescriptor' not in attrs:
                continue
            
            # Parse security descriptor
            security = ExchangeSecurity(attrs['nTSecurityDescriptor'])
            
            # Resolver function for SIDs
            def resolve_sid(sid):
                if not resolve_sids:
                    return sid
                
                # First check well-known SIDs
                if sid in WELL_KNOWN_SIDS:
                    return WELL_KNOWN_SIDS[sid]
                
                # Try to resolve via PowerView
                try:
                    return self.powerview.convertfrom_sid(sid)
                except:
                    return sid
            
            # Look for specific permissions
            send_as_rights = []
            full_access_rights = []
            
            for sid, ace_data in security.aces.items():
                principal_name = resolve_sid(sid) if resolve_sids else sid
                
                # Check for Send-As rights
                for right_id in ace_data["extended_rights"]:
                    if right_id == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2":  # Send-As right
                        send_as_rights.append(principal_name)
                
                # Check for Full Access rights (combination of rights)
                if (ace_data["rights"] & ACTIVE_DIRECTORY_RIGHTS.GENERIC_ALL) or \
                   (ace_data["rights"] & ACTIVE_DIRECTORY_RIGHTS.GENERIC_READ and \
                    ace_data["rights"] & ACTIVE_DIRECTORY_RIGHTS.GENERIC_WRITE):
                    full_access_rights.append(principal_name)
            
            # Store results
            results[mailbox_name] = {
                "Email": mail,
                "SendAsRights": list(set(send_as_rights)),  # Remove duplicates
                "FullAccessRights": list(set(full_access_rights)),  # Remove duplicates
                "ObjectGUID": attrs.get('objectGUID', 'Unknown')
            }
        
        return results
    
    def detect_exchange_version(self, exchange_objects):
        """
        Detect Exchange version from Exchange server objects
        
        Args:
            exchange_objects: List of Exchange server LDAP objects
            
        Returns:
            String describing detected Exchange version
        """
        versions = {}
        
        for obj in exchange_objects:
            if obj['type'] != 'searchResEntry':
                continue
                
            attrs = obj.get('attributes', {})
            
            # Check for serialNumber which often contains version info
            if 'serialNumber' in attrs:
                serial = attrs['serialNumber']
                if isinstance(serial, list):
                    serial = serial[0]
                
                if 'Version 15' in serial:
                    if 'CU' in serial:
                        match = re.search(r'Version 15\.(\d+)\.(\d+)\.(\d+)', serial)
                        if match:
                            versions["Exchange 2019/2016"] = serial
                    else:
                        versions["Exchange 2013"] = serial
                elif 'Version 14' in serial:
                    versions["Exchange 2010"] = serial
                elif 'Version 8' in serial:
                    versions["Exchange 2007"] = serial
            
            # Check for msExchProductID
            if 'msExchProductID' in attrs:
                prod_id = attrs['msExchProductID']
                if isinstance(prod_id, list):
                    prod_id = prod_id[0]
                
                # Map product IDs to versions if needed
                logging.debug(f"Exchange Product ID: {prod_id}")
        
        if not versions:
            return "Unknown Exchange version"
        
        # Return the newest version found
        if "Exchange 2019/2016" in versions:
            return versions["Exchange 2019/2016"]
        elif "Exchange 2013" in versions:
            return versions["Exchange 2013"]
        elif "Exchange 2010" in versions:
            return versions["Exchange 2010"]
        elif "Exchange 2007" in versions:
            return versions["Exchange 2007"]
        
        return "Unknown Exchange version" 