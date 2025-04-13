"""
MCP Server implementation for PowerView.
"""

import asyncio
import logging
import json
import threading
import sys
from typing import Dict, List, Optional, Any, Tuple, Union, Callable

# Import optional MCP dependencies with try/except
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
            """Get information about domain users with comprehensive filtering options."""
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
            """Get information about domain computers with comprehensive filtering options."""
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
            """Get information about domain groups."""
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
            """Get members of a domain group."""
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
            """Get information about domain controllers."""
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
            sd_flag: str = ""
        ) -> str:
            """Get information about domain trusts."""
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
            """Get domain information."""
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
            """Get the ACLs for a domain object."""
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
            """Get information about organizational units (OUs)."""
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
            """Get information about Group Policy Objects (GPOs)."""
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
            """Get information about DNS zones."""
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
            # No raw/no_vuln_check in parser/func for kerberoast?
        ) -> str:
            """Perform Kerberoasting against service accounts."""
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
            # No raw/no_vuln_check in parser/func for asreproast?
        ) -> str:
            """Perform AS-REP Roasting against accounts with Kerberos pre-authentication disabled."""
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
            """Get information about domain certificate authorities."""
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
            """Get information about certificate templates in the domain."""
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
                identity: Object identity (name, SID, GUID, DN) to find the owner for (default: * for all).
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