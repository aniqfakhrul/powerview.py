"""
MCP Server implementation for PowerView.
"""

import asyncio
import logging
import json
import threading
import sys
from typing import Dict, List, Optional, Any, Tuple, Union, Callable

try:
    from mcp.server.fastmcp import FastMCP, Context
    import mcp.types as types
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False

class MCPServer:
    """
    Model Context Protocol server for PowerView.
    
    This class implements an MCP server that exposes PowerView's functionality
    to AI assistants using the Model Context Protocol.
    """
    
    def __init__(self, powerview, name="PowerView MCP", host="127.0.0.1", port=8080):
        """
        Initialize the MCP server.
        
        Args:
            powerview: PowerView instance to expose via MCP
            name: Name of the MCP server
            host: Host to bind the server to
            port: Port to bind the server to
        """
        if not MCP_AVAILABLE:
            raise ImportError("MCP dependencies not installed. Install with: pip install .[mcp]")
            
        self.powerview = powerview
        self.name = name
        self.host = host
        self.port = port
        self.mcp = FastMCP(self.name)
        self.status = False
        self.server_thread = None
        # self._setup_resources() # Remove or comment out this line
        self._setup_tools()
        self._setup_prompts()

    def set_status(self, status):
        self.status = status

    def get_status(self):
        return self.status

    def _setup_tools(self):
        """Register all PowerView tools with the MCP server."""

        @self.mcp.tool()
        async def get_domain_user(
            identity: str = "*",
            properties: str = "*",
            preauthnotrequired: bool = False,
            passnotrequired: bool = False,
            password_expired: bool = False,
            admincount: bool = False,
            trustedtoauth: bool = False,
            allowdelegation: bool = False,
            disallowdelegation: bool = False,
            rbcd: bool = False,
            unconstrained: bool = False,
            shadowcred: bool = False,
            spn: bool = False,
            enabled: bool = False,
            disabled: bool = False,
            lockout: bool = False,
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get information about domain users with comprehensive filtering options.

            Args:
                identity: Filter by user identity (sAMAccountName, SID, GUID, DN). Defaults to '*' (all users).
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                preauthnotrequired: Filter for users with 'DONT_REQ_PREAUTH' set.
                passnotrequired: Filter for users with 'PASSWORD_NOT_REQUIRED' set.
                password_expired: Filter for users whose password has expired.
                admincount: Filter for users with adminCount=1.
                trustedtoauth: Filter for users/computers trusted for constrained delegation.
                allowdelegation: Filter for accounts allowed to delegate.
                disallowdelegation: Filter for accounts explicitly disallowed from delegation.
                rbcd: Filter for accounts with Resource-Based Constrained Delegation configured.
                unconstrained: Filter for accounts configured for unconstrained delegation.
                shadowcred: Filter for accounts vulnerable to Shadow Credentials attack (msDS-KeyCredentialLink).
                spn: Filter for accounts with a Service Principal Name.
                enabled: Filter for enabled accounts.
                disabled: Filter for disabled accounts.
                lockout: Filter for locked out accounts.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'preauthnotrequired': preauthnotrequired,
                    'passnotrequired': passnotrequired,
                    'password_expired': password_expired,
                    'admincount': admincount,
                    'trustedtoauth': trustedtoauth,
                    'allowdelegation': allowdelegation,
                    'disallowdelegation': disallowdelegation,
                    'rbcd': rbcd,
                    'unconstrained': unconstrained,
                    'shadowcred': shadowcred,
                    'spn': spn,
                    'enabled': enabled,
                    'disabled': disabled,
                    'lockout': lockout,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-DomainUser'
                })
                result = self.powerview.get_domainuser(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No users found matching criteria"})
            except Exception as e:
                logging.error(f"Error in get_domain_user: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_computer(
            identity: str = "*",
            properties: str = "*",
            enabled: bool = False,
            disabled: bool = False,
            unconstrained: bool = False,
            trustedtoauth: bool = False,
            allowdelegation: bool = False,
            disallowdelegation: bool = False,
            rbcd: bool = False,
            shadowcred: bool = False,
            spn: bool = False,
            printers: bool = False,
            ping: bool = False,
            resolveip: bool = False,
            resolvesids: bool = False,
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False,
            laps: bool = False,
            bitlocker: bool = False,
            gmsapassword: bool = False,
            pre2k: bool = False,
            excludedcs: bool = False
        ) -> str:
            """Get information about domain computers with comprehensive filtering options.

            Args:
                identity: Filter by computer identity (sAMAccountName, DNS Hostname, SID, GUID, DN). Defaults to '*'.
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                enabled: Filter for enabled computer accounts.
                disabled: Filter for disabled computer accounts.
                unconstrained: Filter for computers configured for unconstrained delegation.
                trustedtoauth: Filter for computers trusted for constrained delegation.
                allowdelegation: Filter for computers allowed to delegate. (Note: Often used with users)
                disallowdelegation: Filter for computers explicitly disallowed from delegation. (Note: Often used with users)
                rbcd: Filter for computers with Resource-Based Constrained Delegation configured.
                shadowcred: Filter for computers vulnerable to Shadow Credentials attack (msDS-KeyCredentialLink).
                spn: Filter for computers with a Service Principal Name.
                printers: Filter for computers that are print servers (may involve heuristics or specific SPNs).
                ping: Attempt to ping the computer (Note: MCP implementation might not fully support this; relies on underlying library).
                resolveip: Attempt to resolve the IP address for the computer.
                resolvesids: Resolve SIDs found in properties like PrimaryGroupID.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
                laps: Filter for computers potentially managed by LAPS.
                bitlocker: Filter for computers with BitLocker recovery information.
                gmsapassword: Filter for computers associated with GMSA passwords.
                pre2k: Filter for pre-Windows 2000 compatible computers.
                excludedcs: Exclude Domain Controllers from the results.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'enabled': enabled,
                    'disabled': disabled,
                    'unconstrained': unconstrained,
                    'trustedtoauth': trustedtoauth,
                    'allowdelegation': allowdelegation,
                    'disallowdelegation': disallowdelegation,
                    'rbcd': rbcd,
                    'shadowcred': shadowcred,
                    'spn': spn,
                    'printers': printers,
                    'ping': ping, # Pass along, PowerView method needs to handle it
                    'resolveip': resolveip,
                    'resolvesids': resolvesids,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'laps': laps,
                    'bitlocker': bitlocker,
                    'gmsapassword': gmsapassword,
                    'pre2k': pre2k,
                    'excludedcs': excludedcs,
                    'module': 'Get-DomainComputer'
                })
                # Ping might require separate logic if not handled purely by LDAP in get_domaincomputer
                result = self.powerview.get_domaincomputer(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No computers found matching criteria"})
            except Exception as e:
                logging.error(f"Error in get_domain_computer: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_group(
            identity: str = "*",
            properties: str = "*",
            admincount: bool = False,
            ldapfilter: str = "",
            memberidentity: str = "",
            no_cache: bool = False,
            searchbase: str = "",
            raw: bool = False,
            no_vuln_check: bool = False
        ) -> str:
            """Get information about domain groups.

            Args:
                identity: Filter by group identity (sAMAccountName, SID, GUID, DN). Defaults to '*'.
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                admincount: Filter for groups with adminCount=1 (protected groups).
                ldapfilter: Custom LDAP filter string.
                memberidentity: Find groups where this identity (user/group DN or sAMAccountName) is a member.
                no_cache: Bypass the cache and perform a live query.
                searchbase: Specify the search base DN.
                raw: Return raw LDAP entries without formatting.
                no_vuln_check: Disable vulnerability checks.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'admincount': admincount,
                    'ldapfilter': ldapfilter,
                    'memberidentity': memberidentity,
                    'no_cache': no_cache,
                    'searchbase': searchbase if searchbase else None,
                    'raw': raw,
                    'no_vuln_check': no_vuln_check,
                    'module': 'Get-DomainGroup'
                })
                result = self.powerview.get_domaingroup(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No groups found"})
            except Exception as e:
                logging.error(f"Error in get_domain_group: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_group_member(
            identity: str,
            multiple: bool = False,
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """Get members of a domain group.

            Args:
                identity: Identity of the group (sAMAccountName, SID, GUID, DN) to get members from.
                multiple: If specified, handle multiple groups matching the identity (Not typically needed if identity is specific).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries for members without formatting.
                ldapfilter: Custom LDAP filter string to apply to the group search itself.
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'ldapfilter': ldapfilter,
                    'module': 'Get-DomainGroupMember'
                })
                result = self.powerview.get_domaingroupmember(identity=identity, multiple=multiple, args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": f"No members found for group {identity}"})
            except Exception as e:
                logging.error(f"Error in get_domain_group_member: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_controller(
            identity: str = "*",
            properties: str = "*",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False,
            resolvesids: bool = False
        ) -> str:
            """Get information about domain controllers.

            Args:
                identity: Filter by DC identity (hostname, DN). Defaults to '*'.
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
                resolvesids: Resolve SIDs found in properties.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'resolvesids': resolvesids,
                    'module': 'Get-DomainController'
                })
                result = self.powerview.get_domaincontroller(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No domain controllers found"})
            except Exception as e:
                logging.error(f"Error in get_domain_controller: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_trust(
            identity: str = "*",
            properties: str = "*",
            searchbase: str = "",
            ldapfilter: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False,
            sd_flag: str = "" # Note: sd_flag is not in parser, might be internal
        ) -> str:
            """Get information about domain trusts.

            Args:
                identity: Filter by trust identity (target domain name, DN). Defaults to '*'.
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                searchbase: Specify the search base DN (usually the domain root or Configuration NC).
                ldapfilter: Custom LDAP filter string.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
                sd_flag: Security Descriptor flag (internal use, likely not needed via MCP).
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'searchbase': searchbase if searchbase else None,
                    'ldapfilter': ldapfilter,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'sd_flag': sd_flag if sd_flag else None,
                    'module': 'Get-DomainTrust'
                })
                result = self.powerview.get_domaintrust(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No trusts found"})
            except Exception as e:
                logging.error(f"Error in get_domain_trust: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain(
            identity: str = "*",
            properties: str = "*",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get domain information.

            Args:
                identity: Filter by domain identity (name, DN). Defaults to '*' or current domain.
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN (usually the domain root).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-Domain'
                })
                result = self.powerview.get_domain(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No domain information found"})
            except Exception as e:
                logging.error(f"Error in get_domain: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_object_acl(
            identity: str = "*",
            ldapfilter: str = "",
            security_identifier: str = "",
            resolveguids: bool = False,
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get the ACLs for a domain object.

            Args:
                identity: Identity of the object (DN, sAMAccountName, SID, GUID) to get ACLs for. Defaults to '*'.
                ldapfilter: Custom LDAP filter string (applied to the object search if identity is wildcard).
                security_identifier: Filter ACEs to only show those for a specific principal SID.
                resolveguids: Resolve GUIDs in ACEs to friendly names (requires schema access).
                searchbase: Specify the search base DN for the object identity.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'ldapfilter': ldapfilter,
                    'security_identifier': security_identifier,
                    'resolveguids': resolveguids,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-DomainObjectAcl'
                })
                result = self.powerview.get_domainobjectacl(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No ACLs found"})
            except Exception as e:
                logging.error(f"Error in get_domain_object_acl: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_ou(
            identity: str = "",
            properties: str = "",
            resolve_gplink: bool = False,
            gplink: str = "",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get information about organizational units (OUs).

            Args:
                identity: Filter by OU identity (name, DN). Defaults to empty (likely means all OUs).
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                resolve_gplink: Resolve gpLink attribute GUIDs to GPO display names.
                gplink: Filter OUs by a specific GPO GUID linked to them.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'resolve_gplink': resolve_gplink,
                    'gplink': gplink if gplink else None,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-DomainOU'
                })
                result = self.powerview.get_domainou(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No OUs found"})
            except Exception as e:
                logging.error(f"Error in get_domain_ou: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_gpo(
            identity: str = "",
            properties: str = "",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get information about Group Policy Objects (GPOs).

            Args:
                identity: Filter by GPO identity (DisplayName, GUID, DN). Defaults to empty (likely means all GPOs).
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN (usually Configuration NC or domain root).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-DomainGPO'
                })
                result = self.powerview.get_domaingpo(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No GPOs found"})
            except Exception as e:
                logging.error(f"Error in get_domain_gpo: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_dns_zone(
            identity: str = "",
            properties: str = "",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get information about DNS zones.

            Args:
                identity: Filter by DNS zone identity (name, DN). Defaults to empty (likely means all zones).
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN (usually under System container or application partitions).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity, # Also passed separately to func
                    'properties': props, # Also passed separately to func
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'zonename': None,
                    'module': 'Get-DomainDNSZone'
                })
                result = self.powerview.get_domaindnszone(identity=identity, properties=props, args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No DNS zones found"})
            except Exception as e:
                logging.error(f"Error in get_domain_dns_zone: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def invoke_kerberoast(
            identity: str = "",
            ldapfilter: str = "",
            searchbase: str = "",
            opsec: bool = False,
            no_cache: bool = False,
        ) -> str:
            """Perform Kerberoasting against service accounts.

            Args:
                identity: Filter for specific user/computer identities to target.
                ldapfilter: Custom LDAP filter to find target accounts (e.g., filter by group).
                searchbase: Specify the search base DN for target accounts.
                opsec: Perform OpSec-safe Kerberoasting (request TGS for krbtgt).
                no_cache: Bypass LDAP query cache when searching for targets.
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'opsec': opsec,
                    'no_cache': no_cache,
                    # target_domain is internal detail?
                    'module': 'Invoke-Kerberoast'
                })
                result = self.powerview.invoke_kerberoast(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No kerberoastable accounts found"})
            except Exception as e:
                logging.error(f"Error in invoke_kerberoast: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def invoke_asreproast(
            identity: str = "",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
        ) -> str:
            """Perform AS-REP Roasting against accounts with Kerberos pre-authentication disabled.

            Args:
                identity: Filter for specific user identities to target.
                ldapfilter: Custom LDAP filter to find target accounts.
                searchbase: Specify the search base DN for target accounts.
                no_cache: Bypass LDAP query cache when searching for targets.
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'module': 'Invoke-ASREPRoast'
                })
                result = self.powerview.invoke_asreproast(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No AS-REP roastable accounts found"})
            except Exception as e:
                logging.error(f"Error in invoke_asreproast: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_ca(
            identity: str = "",
            properties: str = "",
            check_web_enrollment: bool = False,
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get information about domain certificate authorities.

            Args:
                identity: Filter by CA identity (name, DN). Defaults to empty (all CAs).
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                check_web_enrollment: Check if web enrollment is enabled on the CA.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN (usually Configuration NC).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'check_web_enrollment': check_web_enrollment,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-DomainCA'
                })
                result = self.powerview.get_domainca(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No certificate authorities found"})
            except Exception as e:
                logging.error(f"Error in get_domain_ca: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_ca_template(
            identity: str = "",
            properties: str = "",
            vulnerable: bool = False,
            resolve_sids: bool = False,
            enabled: bool = False,
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """Get information about certificate templates in the domain.

            Args:
                identity: Filter by template identity (DisplayName, Name, OID, DN). Defaults to empty (all templates).
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                vulnerable: Filter for templates potentially vulnerable to abuse (e.g., ESC1, ESC2, etc.).
                resolve_sids: Resolve SIDs in template ACLs/properties to names.
                enabled: Filter for enabled templates.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN (usually Configuration NC).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'vulnerable': vulnerable,
                    'resolve_sids': resolve_sids,
                    'enabled': enabled,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'module': 'Get-DomainCATemplate'
                })
                result = self.powerview.get_domaincatemplate(
                    args=args,
                    properties=props,
                    identity=identity,
                    vulnerable=vulnerable,
                    resolve_sids=resolve_sids,
                    no_cache=no_cache
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No certificate templates found"})
            except Exception as e:
                logging.error(f"Error in get_domain_ca_template: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_object_owner(
            identity: str = "*",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """
            Gets the owner of specified domain objects.

            Args:
                identity: Object identity (name, SID, GUID, DN) to find the owner for. Defaults to '*'.
                searchbase: Specify the search base DN.
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'server': None,
                    'select': None,
                    'where': None,
                    'tableview': '',
                    'sort_by': None,
                    'count': False,
                    'outfile': None,
                    'nowrap': False,
                    'module': 'Get-DomainObjectOwner'
                })
                result = self.powerview.get_domainobjectowner(args=args)
                # Underlying function might return list or single dict/error
                return json.dumps(result, default=str) if result else json.dumps({"info": "No object owner information found matching criteria"})
            except Exception as e:
                logging.error(f"Error in get_domain_object_owner: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_exchange_server(
            identity: str = "*",
            properties: str = "*",
            ldapfilter: str = "",
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """
            Get information about Exchange servers in the domain.

            Args:
                identity: Filter by Exchange server identity (name, DN). Defaults to '*'.
                properties: Comma-separated list of properties to retrieve. Defaults to '*'.
                ldapfilter: Custom LDAP filter string.
                searchbase: Specify the search base DN (usually Configuration NC).
                no_cache: Bypass the cache and perform a live query.
                no_vuln_check: Disable vulnerability checks.
                raw: Return raw LDAP entries without formatting.
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase if searchbase else None,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'server': None,
                    'select': None,
                    'where': None,
                    'tableview': '',
                    'sort_by': None,
                    'count': False,
                    'outfile': None,
                    'module': 'Get-ExchangeServer'
                })
                result = self.powerview.get_exchangeserver(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"info": "No Exchange servers found matching criteria"})
            except Exception as e:
                logging.error(f"Error in get_exchange_server: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_netshare(
            computer: str = "",
            computername: str = ""
        ) -> str:
            """
            Enumerates shares on a specified computer.

            Args:
                computer: Target computer hostname or IP address.
                computername: Alias for computer. Specify only one of computer or computername.
            """
            if not computer and not computername:
                return json.dumps({"error": "Either 'computer' or 'computername' must be specified"})
            if computer and computername:
                return json.dumps({"error": "Specify only one of 'computer' or 'computername'"})

            try:
                args = type('Args', (), {
                    'computer': computer if computer else None,
                    'computername': computername if computername else None,
                    'tableview': '',
                    'count': False,
                    'server': None,
                    'outfile': None,
                    'module': 'Get-NetShare'
                })
                result = self.powerview.get_netshare(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"info": f"No shares found on {computer or computername}"})
            except Exception as e:
                error_msg = str(e)
                if "rpc_s_access_denied" in error_msg.lower():
                    error_msg = f"Access denied to {computer or computername}. Check permissions."
                elif "connection" in error_msg.lower() or "Errno 111" in error_msg:
                     error_msg = f"Could not connect to {computer or computername}. Check network connectivity and RPC/SMB services."
                logging.error(f"Error in get_netshare: {str(e)}")
                return json.dumps({"error": error_msg})

        @self.mcp.tool()
        async def set_domain_user_password(
            identity: str,
            accountpassword: str,
            oldpassword: str | None = None
        ) -> str:
            """
            Sets the password for a specified domain user.

            Args:
                identity: The identity (e.g., sAMAccountName) of the user account.
                accountpassword: The new password to set for the user account.
                oldpassword: The current password (required for non-admin password changes).
            """
            if not identity or not accountpassword:
                 return json.dumps({"success": False, "error": "Identity and AccountPassword are required."})

            try:
                args = type('Args', (), {
                    'identity': identity,
                    'accountpassword': accountpassword,
                    'oldpassword': oldpassword,
                    'server': None,
                    'outfile': None,
                    'module': 'Set-DomainUserPassword'
                })

                result = self.powerview.set_domainuserpassword(
                    identity=identity,
                    accountpassword=accountpassword,
                    oldpassword=oldpassword,
                    args=args
                )

                if result is True:
                    return json.dumps({"success": True, "message": f"Password for '{identity}' set successfully."})
                elif result is False:
                    error_detail = f"Failed to set password for '{identity}'. Check permissions, password complexity/history, or if the old password is required/correct."
                    logging.warning(f"set_domain_user_password returned False for '{identity}'.")
                    return json.dumps({"success": False, "error": error_detail})
                else:
                    error_detail = f"User identity '{identity}' not found or multiple users matched."
                    logging.error(f"set_domain_user_password could not find unique user for '{identity}'.")
                    return json.dumps({"success": False, "error": error_detail})

            except Exception as e:
                logging.error(f"Exception in set_domain_user_password for '{identity}': {str(e)}")
                error_msg = str(e)
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {error_msg}"})

        @self.mcp.tool()
        async def add_domain_user(
            username: str,
            userpass: str,
            basedn: str | None = None
        ) -> str:
            """
            Adds a new domain user.

            Args:
                username: The sAMAccountName for the new user.
                userpass: The password for the new user.
                basedn: The distinguished name of the container/OU to add the user to (default: CN=Users,<domainDN>).
            """
            if not username or not userpass:
                return json.dumps({"success": False, "error": "Username and Userpass are required."})
            try:
                # The underlying function doesn't heavily rely on args for this operation
                args = type('Args', (), {'module': 'Add-DomainUser'})
                result = self.powerview.add_domainuser(
                    username=username,
                    userpass=userpass,
                    basedn=basedn,
                    args=args
                )
                # Assuming the function returns the DN on success or raises an exception on failure
                if result:
                    return json.dumps({"success": True, "message": f"User '{username}' added successfully.", "dn": result})
                else:
                    # It's more likely to raise an exception on failure, but handle False just in case
                    logging.warning(f"add_domain_user returned unexpected value for '{username}'.")
                    return json.dumps({"success": False, "error": f"Failed to add user '{username}'. Check permissions or if user already exists."})
            except Exception as e:
                logging.error(f"Exception in add_domain_user for '{username}': {str(e)}")
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def remove_domain_user(
            identity: str
        ) -> str:
            """
            Removes a domain user.

            Args:
                identity: The identity (e.g., sAMAccountName, DN) of the user to remove.
            """
            if not identity:
                return json.dumps({"success": False, "error": "Identity is required."})
            try:
                # Underlying function doesn't seem to use args here
                result = self.powerview.remove_domainuser(identity=identity)
                if result is True:
                    return json.dumps({"success": True, "message": f"User '{identity}' removed successfully."})
                else: # Assuming False or None indicates failure/not found
                    logging.warning(f"remove_domain_user returned False/None for '{identity}'.")
                    return json.dumps({"success": False, "error": f"Failed to remove user '{identity}'. User might not exist or check permissions."})
            except Exception as e:
                logging.error(f"Exception in remove_domain_user for '{identity}': {str(e)}")
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def add_domain_group_member(
            identity: str,
            members: str
        ) -> str:
            """
            Adds one or more members to a domain group.

            Args:
                identity: The identity (e.g., sAMAccountName, DN) of the group.
                members: One or more member identities (sAMAccountName, DN) to add, separated by commas. Ensure full DNs are used if needed.
            """
            if not identity or not members:
                return json.dumps({"success": False, "error": "Identity (group) and Members are required."})
            try:
                # Pass the members string within a list, assuming underlying function handles list of strings
                # Avoid splitting DNs by comma here.
                if not members.strip(): # Check if members string is empty after stripping
                    return json.dumps({"success": False, "error": "Members string cannot be empty."})
                member_list = [members.strip()] # Pass as a list containing the single (potentially comma-separated) string

                result = self.powerview.add_domaingroupmember(identity=identity, members=member_list, args=None)

                # The function might return True/False or detailed status - adjust based on actual behavior
                # Let's assume True means overall success for now.
                if result is True:
                     return json.dumps({"success": True, "message": f"Attempted to add members {member_list} to group '{identity}'."})
                else:
                     logging.warning(f"add_domaingroupmember might have failed for some members in group '{identity}'.")
                     # Provide a less definitive success message if the return isn't clear
                     return json.dumps({"success": "Partial/Unknown", "message": f"Attempted operation for group '{identity}' with members {member_list}. Check group membership manually."})
            except Exception as e:
                logging.error(f"Exception in add_domaingroupmember for group '{identity}': {str(e)}")
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def remove_domain_group_member(
            identity: str,
            members: str
        ) -> str:
            """
            Removes one or more members from a domain group.

            Args:
                identity: The identity (e.g., sAMAccountName, DN) of the group.
                members: One or more member identities (sAMAccountName, DN) to remove, separated by commas. Ensure full DNs are used if needed.
            """
            if not identity or not members:
                return json.dumps({"success": False, "error": "Identity (group) and Members are required."})
            try:
                # Pass the members string within a list, assuming underlying function handles list of strings
                # Avoid splitting DNs by comma here.
                if not members.strip(): # Check if members string is empty after stripping
                    return json.dumps({"success": False, "error": "Members string cannot be empty."})
                member_list = [members.strip()] # Pass as a list containing the single (potentially comma-separated) string

                result = self.powerview.remove_domaingroupmember(identity=identity, members=member_list, args=None)

                # Similar uncertainty as add_domaingroupmember about return value
                if result is True:
                     return json.dumps({"success": True, "message": f"Attempted to remove members {member_list} from group '{identity}'."})
                else:
                     logging.warning(f"remove_domaingroupmember might have failed for some members in group '{identity}'.")
                     return json.dumps({"success": "Partial/Unknown", "message": f"Attempted operation for group '{identity}' with members {member_list}. Check group membership manually."})
            except Exception as e:
                logging.error(f"Exception in remove_domaingroupmember for group '{identity}': {str(e)}")
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def add_domain_object_acl(
            targetidentity: str,
            principalidentity: str,
            rights: str = "fullcontrol",
            rights_guid: str | None = None,
            ace_type: str = "allowed",
            inheritance: bool = False
        ) -> str:
            """
            Adds an Access Control Entry (ACE) to a domain object's ACL.

            Args:
                targetidentity: Identity of the target object (user, group, computer, etc.). Can be a name (sAMAccountName, UPN) or distinguishedName (DN). If a name resolves to multiple objects, specify the DN instead.
                principalidentity: Identity of the principal (user, group) being granted rights. Can be a name (sAMAccountName, UPN) or distinguishedName (DN). If a name resolves to multiple objects, specify the DN instead.
                rights: The rights to grant. Defaults to 'fullcontrol'. Common examples include 'fullcontrol', 'genericall', 'genericwrite', 'writeowner', 'writedacl', 'writeproperty', 'self', 'rp', 'wp', 'cr', 'lc', 'cc', 'rc', 'lo', 'dt', 'wd', 'wo'. Parser-specific choices: ['immutable', 'resetpassword', 'writemembers', 'dcsync'].
                rights_guid: GUID string for specific extended rights or property sets.
                ace_type: Type of ACE ('allowed' or 'denied'). Defaults to 'allowed'.
                inheritance: Apply inheritance flags (True/False). Defaults to False.
            """
            if not targetidentity or not principalidentity:
                 return json.dumps({"success": False, "error": "TargetIdentity and PrincipalIdentity are required."})
            try:
                # Underlying function doesn't seem to use args here
                result = self.powerview.add_domainobjectacl(
                    targetidentity=targetidentity,
                    principalidentity=principalidentity,
                    rights=rights,
                    rights_guid=rights_guid,
                    ace_type=ace_type,
                    inheritance=inheritance
                )
                # Function likely returns True on success, False/None otherwise
                if result is True:
                    return json.dumps({"success": True, "message": f"Successfully added '{rights}' ACE for '{principalidentity}' on '{targetidentity}'."})
                else:
                    logging.warning(f"add_domain_object_acl returned non-True for target '{targetidentity}'.")
                    return json.dumps({"success": False, "error": f"Failed to add ACE for '{principalidentity}' on '{targetidentity}'. Check inputs and permissions."})
            except Exception as e:
                logging.error(f"Exception in add_domain_object_acl for target '{targetidentity}': {str(e)}")
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def remove_domain_object_acl(
            targetidentity: str,
            principalidentity: str,
            rights: str = "fullcontrol",
            rights_guid: str | None = None,
            ace_type: str = "allowed",
            inheritance: bool = False
        ) -> str:
            """
            Removes an Access Control Entry (ACE) from a domain object's ACL.

            Args:
                targetidentity: Identity of the target object (user, group, computer, etc.).
                principalidentity: Identity of the principal (user, group) whose rights are being removed.
                rights: The rights to remove. Must match the ACE being removed. Defaults to 'fullcontrol'. Common examples are the same as for adding ACEs. Parser-specific choices: ['immutable', 'resetpassword', 'writemembers', 'dcsync'].
                rights_guid: GUID string if removing specific extended rights or property sets.
                ace_type: Type of ACE ('allowed' or 'denied'). Defaults to 'allowed'.
                inheritance: Match inheritance flags (True/False). Defaults to False.
            """
            if not targetidentity or not principalidentity:
                 return json.dumps({"success": False, "error": "TargetIdentity and PrincipalIdentity are required."})
            try:
                # Underlying function doesn't seem to use args here
                result = self.powerview.remove_domainobjectacl(
                    targetidentity=targetidentity,
                    principalidentity=principalidentity,
                    rights=rights,
                    rights_guid=rights_guid,
                    ace_type=ace_type,
                    inheritance=inheritance
                )
                # Function likely returns True on success, False/None otherwise
                if result is True:
                    return json.dumps({"success": True, "message": f"Successfully removed '{rights}' ACE for '{principalidentity}' from '{targetidentity}'."})
                else:
                    logging.warning(f"remove_domain_object_acl returned non-True for target '{targetidentity}'.")
                    return json.dumps({"success": False, "error": f"Failed to remove ACE for '{principalidentity}' from '{targetidentity}'. Check if ACE exists with specified parameters and check permissions."})
            except Exception as e:
                logging.error(f"Exception in remove_domain_object_acl for target '{targetidentity}': {str(e)}")
                return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def set_domain_object_owner(
            targetidentity: str,
            principalidentity: str,
            searchbase: str | None = None
        ) -> str:
            """
            Sets the owner for a specified domain object.

            Args:
                targetidentity: Identity of the target object (user, group, computer, etc.).
                principalidentity: Identity of the principal (user, group) to set as the new owner.
                searchbase: Specify the search base DN for the target object.
            """
            if not targetidentity or not principalidentity:
                 return json.dumps({"success": False, "error": "TargetIdentity and PrincipalIdentity are required."})
            try:
                # Underlying function doesn't seem to use args here
                result = self.powerview.set_domainobjectowner(
                    targetidentity=targetidentity,
                    principalidentity=principalidentity,
                    searchbase=searchbase,
                    args=None # Args not used by underlying function for core logic
                )
                if result is True:
                     return json.dumps({"success": True, "message": f"Successfully set '{principalidentity}' as owner of '{targetidentity}'."})
                else:
                     logging.warning(f"set_domain_object_owner returned non-True for target '{targetidentity}'.")
                     return json.dumps({"success": False, "error": f"Failed to set owner for '{targetidentity}'. Check identities and permissions."})
            except Exception as e:
                 logging.error(f"Exception in set_domain_object_owner for target '{targetidentity}': {str(e)}")
                 return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def set_domain_computer_password(
            identity: str,
            accountpassword: str,
            oldpassword: str | None = None
        ) -> str:
            """
            Sets the password for a specified domain computer account.

            Args:
                identity: The identity (e.g., sAMAccountName) of the computer account.
                accountpassword: The new password to set for the computer account.
                oldpassword: The current password (might be required in some contexts).
            """
            if not identity or not accountpassword:
                return json.dumps({"success": False, "error": "Identity and AccountPassword are required."})
            try:
                 args = type('Args', (), {
                    'identity': identity,
                    'accountpassword': accountpassword,
                    'oldpassword': oldpassword,
                    'server': None,
                    'outfile': None,
                    'module': 'Set-DomainComputerPassword'
                 })
                 result = self.powerview.set_domaincomputerpassword(
                     identity=identity,
                     accountpassword=accountpassword,
                     oldpassword=oldpassword,
                     args=args
                 )
                 if result is True:
                     return json.dumps({"success": True, "message": f"Password for computer '{identity}' set successfully."})
                 else:
                     error_detail = f"Failed to set password for computer '{identity}'. Check permissions or identity."
                     logging.warning(f"set_domain_computer_password returned non-True for '{identity}'.")
                     return json.dumps({"success": False, "error": error_detail})
            except Exception as e:
                 logging.error(f"Exception in set_domain_computer_password for '{identity}': {str(e)}")
                 return json.dumps({"success": False, "error": f"An unexpected exception occurred: {str(e)}"})

        @self.mcp.tool()
        async def get_current_auth_context() -> str:
            """Get the current authenticated user context for the PowerView session."""
            try:
                identity = self.powerview.conn.who_am_i()
                return json.dumps({"identity": identity.split("\\")[1]})
            except Exception as e:
                logging.error(f"Error in get_current_auth_context: {str(e)}")
                return json.dumps({"error": str(e)})

    def _setup_prompts(self):
        """Register all PowerView prompts with the MCP server."""
        
        @self.mcp.prompt()
        async def find_vulnerable_systems(query: str = "") -> str:
            """Create a prompt to find vulnerable systems."""
            return f"""
            Please analyze the Active Directory environment using PowerView 
            and identify potential security vulnerabilities.
            
            Focus areas:
            - Kerberoastable accounts
            - Accounts with SPNs
            - Privilege escalation paths
            - Resource-Based Constrained Delegation (RBCD) issues
            - Shadow Credentials vulnerabilities
            - Unconstrained delegation
            - Other critical security issues
            
            If there's a specific area to focus on: {query}
            """
        
        @self.mcp.prompt()
        async def ad_mapping_prompt(depth: str = "basic") -> str:
            """Create a prompt to map the Active Directory environment."""
            detail_level = {
                "basic": "focus on the high-level structure",
                "detailed": "include detailed information about users, groups, and computers",
                "comprehensive": "perform an exhaustive analysis of all AD objects and their relationships"
            }.get(depth.lower(), "focus on the high-level structure")
            
            return f"""
            Please map the Active Directory environment using PowerView tools.
            
            For this mapping, {detail_level}.
            
            Include the following in your analysis:
            - Domain information and properties
            - Domain controllers
            - Organizational Units (OUs) structure
            - Key security groups and their members
            - User accounts of interest
            - Computer accounts and their properties
            - Trust relationships
            - Group Policy Objects (GPOs)
            
            Provide a structured overview of the environment with notable findings.
            """

        @self.mcp.prompt()
        async def find_attack_path_from_current_context() -> str:
            """Create a prompt to find attack paths from the current user context."""
            current_user = "Unknown"
            try:
                current_user = self.powerview.conn.who_am_i().split("\\")[1]
            except Exception as e:
                 logging.warning(f"Could not get current user for attack path prompt: {e}")

            return f"""
            You are currently authenticated as: {current_user}

            Investigate potential attack paths starting from this user context.
            Focus on actions that {current_user} might be able to perform, such as:

            1.  Check Group Memberships: Does {current_user} belong to any privileged or interesting groups?
                - Use `get_domain_group` with `memberidentity='{current_user}'`
            2.  Find Outgoing ACLs: Does {current_user} have permissions ON other objects (users, groups, computers)?
                - Use `get_domain_object_acl` with `security_identifier='{current_user}'`
                - Pay attention to: GenericAll, GenericWrite, WriteOwner, WriteDACL, WriteProperty (especially on group memberships or userAccountControl), User-Force-Change-Password, AddMembers, etc.
            3.  Check for Owned Objects: Does {current_user} own any objects?
                - Use `get_domain_object_owner` with `identity='{current_user}'` (This might not work directly if identity expects the target object, check tool usage)
                - Alternative: If the above doesn't work, consider querying all objects and filtering for the owner SID corresponding to {current_user} (might be slow).
            4.  Check Delegation Rights:
                - Is {current_user} configured for Unconstrained Delegation? (`get_domain_user` with `identity='{current_user}'` and check `userAccountControl`)
                - Is {current_user} configured for Constrained Delegation (`TRUSTED_TO_AUTH_FOR_DELEGATION`)? (`get_domain_user` with `identity='{current_user}'` and check `msDS-AllowedToDelegateTo`)
                - Is {current_user} allowed to delegate TO other services/computers (Resource-Based Constrained Delegation)? (`get_domain_user` with `identity='{current_user}'` and check `msDS-AllowedToActOnBehalfOfOtherIdentity`)
            5.  Check Local Admin Rights: Can {current_user} access administrative shares (C$, ADMIN$) or perform administrative actions on any computers? (Requires external tooling or specific RPC calls not directly exposed as simple MCP tools here, e.g., trying `get_netshare` on `\\\\TARGET\\C$`).
            6.  Kerberoasting/ASREPRoasting: Can {current_user} request service tickets for accounts with weak passwords or find users vulnerable to ASREPRoasting?
                - Use `invoke_kerberoast`
                - Use `invoke_asreproast`
            7.  Certificate Abuse: Can {current_user} request certificates from templates vulnerable to ESC1/ESC4 etc.?
                - Use `get_domain_ca_template` with `-Vulnerable` flag.

            Prioritize findings based on potential impact (e.g., direct control of admin accounts/groups is higher priority than control of standard users/computers).
            """

    async def _server_started(self):
        """Callback that runs when the server is actually ready to accept connections"""
        self.set_status(True)
        logging.info("MCP server is ready to accept connections")

    def start(self):
        """Start the MCP server."""
        if self.server_thread and self.server_thread.is_alive():
            logging.warning("MCP server is already running")
            return
        
        def run_server():
            import uvicorn
            
            logging.info(f"Starting MCP server on {self.host}:{self.port}")
            try:
                # Create an ASGI application from the MCP server
                app = self.mcp.sse_app()
                
                # Set status before starting server
                self.set_status(True)
                
                # Start the server with uvicorn
                uvicorn.run(
                    app=app,
                    host=self.host,
                    port=self.port,
                    log_level="error",
                    access_log=False
                )
            except Exception as e:
                self.set_status(False)
                logging.error(f"Error starting MCP server: {str(e)}")
                sys.exit(1)

        # Create and start the server thread
        self.server_thread = threading.Thread(target=run_server, daemon=True)
        self.server_thread.start()
        
        import time
        time.sleep(0.2)
        
        logging.debug(f"MCP server thread started, status: {self.get_status()}")

    def stop(self):
        """Stop the MCP server."""
        self.set_status(False)
        logging.info("Stopping MCP server...")
        
        # The MCP server will stop when the main thread exits since we use a daemon thread 