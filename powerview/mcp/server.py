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
        # Check if MCP is available before initializing
        if not MCP_AVAILABLE:
            raise ImportError("MCP dependencies not installed. Install with: pip install .[mcp]")
            
        self.powerview = powerview
        self.name = name
        self.host = host
        self.port = port
        self.mcp = FastMCP(self.name)
        self.status = False
        self.server_thread = None
        self._setup_resources()
        self._setup_tools()
        self._setup_prompts()

    def set_status(self, status):
        self.status = status

    def get_status(self):
        return self.status

    def _setup_resources(self):
        """Register all PowerView resources with the MCP server."""
        
        @self.mcp.resource("powerview://domain/{domain}")
        async def domain_resource(domain: str) -> str:
            """Get information about a domain."""
            try:
                # Pass args=None to maintain compatibility with any extra parameters
                result = self.powerview.get_domain(properties=[], identity=domain, args=None)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No domain found"})
            except Exception as e:
                logging.error(f"Error retrieving domain info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://users/{identity}")
        async def users_resource(identity: str) -> str:
            """Get information about domain users."""
            try:
                # Creating a mock args object to ensure we handle all flag parameters
                args = type('Args', (), {
                    'identity': identity,
                    'no_cache': False,
                    'no_vuln_check': False
                })
                result = self.powerview.get_domainuser(args=args, properties=[], identity=identity) 
                return json.dumps(result, default=str) if result else json.dumps({"error": "No users found"})
            except Exception as e:
                logging.error(f"Error retrieving user info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://computers/{identity}")
        async def computers_resource(identity: str) -> str:
            """Get information about domain computers."""
            try:
                # Adding resolveip and resolvesids parameters
                result = self.powerview.get_domaincomputer(
                    properties=[], 
                    identity=identity,
                    resolveip=False,  # Default to False
                    resolvesids=False  # Default to False
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No computers found"})
            except Exception as e:
                logging.error(f"Error retrieving computer info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://groups/{identity}")
        async def groups_resource(identity: str) -> str:
            """Get information about domain groups."""
            try:
                # Include no_cache parameter
                result = self.powerview.get_domaingroup(
                    properties=[], 
                    identity=identity,
                    no_cache=False  # Default to False
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No groups found"})
            except Exception as e:
                logging.error(f"Error retrieving group info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://controllers/{identity}")
        async def controllers_resource(identity: str) -> str:
            """Get information about domain controllers."""
            try:
                # Include no_cache parameter 
                result = self.powerview.get_domaincontroller(
                    properties=[], 
                    identity=identity,
                    no_cache=False
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No domain controllers found"})
            except Exception as e:
                logging.error(f"Error retrieving domain controller info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://trusts/{identity}")
        async def trusts_resource(identity: str) -> str:
            """Get information about domain trusts."""
            try:
                # Include searchbase parameter
                result = self.powerview.get_domaintrust(
                    properties=[], 
                    identity=identity,
                    searchbase=None,  # Default to None
                    sd_flag=None      # Include sd_flag parameter
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No trusts found"})
            except Exception as e:
                logging.error(f"Error retrieving trust info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://gpos/{identity}")
        async def gpos_resource(identity: str) -> str:
            """Get information about group policy objects."""
            try:
                # Include no_cache parameter
                result = self.powerview.get_domaingpo(
                    properties=[], 
                    identity=identity,
                    no_cache=False
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No GPOs found"})
            except Exception as e:
                logging.error(f"Error retrieving GPO info: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.resource("powerview://ous/{identity}")
        async def ous_resource(identity: str) -> str:
            """Get information about organizational units."""
            try:
                # Include resolve_gplink parameter
                result = self.powerview.get_domainou(
                    properties=[], 
                    identity=identity,
                    resolve_gplink=False  # Default to False
                )
                return json.dumps(result, default=str) if result else json.dumps({"error": "No OUs found"})
            except Exception as e:
                logging.error(f"Error retrieving OU info: {str(e)}")
                return json.dumps({"error": str(e)})
    
    def _setup_tools(self):
        """Register all PowerView tools with the MCP server."""
        
        @self.mcp.tool()
        async def get_domain_user(
            identity: str = "*", 
            properties: str = "*",
            # Authentication flags
            preauthnotrequired: bool = False,
            passnotrequired: bool = False,
            password_expired: bool = False,
            
            # Admin and privilege flags
            admin_count: bool = False,
            trustedtoauth: bool = False,
            
            # Delegation flags
            allowed_to_delegate: bool = False,
            disallowdelegation: bool = False,
            rbcd: bool = False,
            unconstrained: bool = False,
            
            # Security feature flags
            shadowcred: bool = False,
            spn: bool = False,
            
            # Account status flags
            enabled: bool = False,
            disabled: bool = False,
            locked: bool = False,
            
            # Additional filter
            ldapfilter: str = "",
            
            # Cache options
            no_cache: bool = False
        ) -> str:
            """
            Get information about domain users with comprehensive filtering options.
            
            Args:
                identity: User identity to search for (default: * for all users)
                properties: Comma-separated list of properties to retrieve
                
                # Authentication flags
                preauthnotrequired: Find accounts that don't require Kerberos preauthentication
                passnotrequired: Find accounts where password is not required
                password_expired: Find accounts with expired passwords
                
                # Admin and privilege flags
                admin_count: Find accounts with adminCount=1
                trustedtoauth: Find accounts trusted to authenticate for other principals
                
                # Delegation flags
                allowed_to_delegate: Find accounts that can be delegated (allowdelegation)
                disallowdelegation: Find accounts sensitive and not trusted for delegation
                rbcd: Find accounts configured for resource-based constrained delegation
                unconstrained: Find accounts configured for unconstrained delegation
                
                # Security feature flags
                shadowcred: Find accounts with msDS-KeyCredentialLink attribute set
                spn: Find accounts with Service Principal Names
                
                # Account status flags
                enabled: Find enabled user accounts
                disabled: Find disabled user accounts
                locked: Find locked user accounts (lockout)
                
                # Additional filter
                ldapfilter: Additional LDAP filter to apply
                
                # Cache options
                no_cache: Bypass the cache and perform a live query
            """
            try:
                props = properties.split(",") if properties else []
                
                # Create an args object with the necessary parameters
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    
                    # Authentication flags
                    'preauthnotrequired': preauthnotrequired,
                    'passnotrequired': passnotrequired,
                    'password_expired': password_expired,
                    
                    # Admin and privilege flags
                    'admincount': admin_count,
                    'trustedtoauth': trustedtoauth,
                    
                    # Delegation flags
                    'allowdelegation': allowed_to_delegate,
                    'disallowdelegation': disallowdelegation,
                    'rbcd': rbcd,
                    'unconstrained': unconstrained,
                    
                    # Security feature flags
                    'shadowcred': shadowcred,
                    'spn': spn,
                    
                    # Account status flags
                    'enabled': enabled,
                    'disabled': disabled,
                    'lockout': locked,
                    
                    # Additional filter
                    'ldapfilter': ldapfilter,
                    
                    # Common parameters
                    'searchbase': None,
                    'no_cache': no_cache,
                    'no_vuln_check': False,
                    'raw': False
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
            
            # Status flags
            enabled: bool = False,
            disabled: bool = False,
            
            # Delegation flags
            unconstrained: bool = False,
            trusted_to_auth: bool = False,
            allowed_to_delegate: bool = False,
            disallowdelegation: bool = False,
            
            # Security feature flags
            rbcd: bool = False,
            shadowcred: bool = False,
            spn: bool = False,
            
            # Operating system flags
            printers: bool = False,
            ping: bool = False,
            
            # Resolution options
            resolve_ip: bool = False,
            resolve_sids: bool = False,
            
            # Additional filter
            ldapfilter: str = "",
            
            # Cache options
            no_cache: bool = False
        ) -> str:
            """
            Get information about domain computers with comprehensive filtering options.
            
            Args:
                identity: Computer identity to search for (* for all computers)
                properties: Comma-separated list of properties to retrieve
                
                # Status flags
                enabled: Find enabled computer accounts
                disabled: Find disabled computer accounts
                
                # Delegation flags
                unconstrained: Find computers configured for unconstrained delegation
                trusted_to_auth: Find computers trusted to authenticate for other principals
                allowed_to_delegate: Find computers that can be delegated
                disallowdelegation: Find computers sensitive and not trusted for delegation
                
                # Security feature flags
                rbcd: Find computers configured for resource-based constrained delegation
                shadowcred: Find computers with msDS-KeyCredentialLink attribute set
                spn: Find computers with specific Service Principal Names
                
                # Operating system flags
                printers: Find printer servers
                ping: Ping computers and return only those that respond
                
                # Resolution options
                resolve_ip: Resolve IP addresses for the computers
                resolve_sids: Resolve SIDs to names
                
                # Additional filter
                ldapfilter: Additional LDAP filter to apply
                
                # Cache options
                no_cache: Bypass the cache and perform a live query
            """
            try:
                props = properties.split(",") if properties else []
                
                # Create an args object with the necessary parameters
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    
                    # Status flags
                    'enabled': enabled,
                    'disabled': disabled,
                    
                    # Delegation flags
                    'unconstrained': unconstrained,
                    'trustedtoauth': trusted_to_auth,
                    'allowdelegation': allowed_to_delegate,
                    'disallowdelegation': disallowdelegation,
                    
                    # Security feature flags
                    'rbcd': rbcd,
                    'shadowcred': shadowcred,
                    'spn': spn,
                    
                    # Operating system flags
                    'printers': printers,
                    'ping': ping,
                    
                    # Resolution options
                    'resolveip': resolve_ip,
                    'resolvesids': resolve_sids,
                    
                    # Additional filter
                    'ldapfilter': ldapfilter,
                    
                    # Common parameters
                    'searchbase': None,
                    'no_cache': no_cache,
                    'no_vuln_check': False,
                    'raw': False
                })
                
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
        ) -> str:
            """
            Get information about domain groups.
            
            Args:
                identity: Group identity to search for (default: * for all groups)
                properties: Comma-separated list of properties to retrieve
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'searchbase': None,
                    'ldapfilter': ldapfilter,
                    'no_vuln_check': False,
                    'raw': False,
                    'admincount': False,
                    'enabled': False,
                    'disabled': False,
                    'preauthnotrequired': False,
                    'passnotrequired': False,
                    'password_expired': False,
                    'trustedtoauth': False,
                    'allowdelegation': False,
                    'disallowdelegation': False,
                    'rbcd': False,
                    'unconstrained': False,
                    'shadowcred': False,
                    'spn': False,
                    'lockout': False
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
            raw: bool = False
        ) -> str:
            """
            Get members of a domain group.
            
            Args:
                identity: Group identity to get members for
                multiple: Recursively enumerate multiple groups
                no_cache: Bypass the cache and perform a live query
                no_vuln_check: Bypass vulnerability checks
                raw: Return raw results
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'no_cache': no_cache,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw,
                    'multiple': multiple
                })
                result = self.powerview.get_domaingroupmember(identity=identity, args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": f"No members found for group {identity}"})
            except Exception as e:
                logging.error(f"Error in get_domain_group_member: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.tool()
        async def get_domain_controller(
            identity: str = "*", 
            properties: str = "*",
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Get information about domain controllers.
            
            Args:
                identity: Controller identity to search for (default: * for all DCs)
                properties: Comma-separated list of properties to retrieve
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Optional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'searchbase': None,
                    'ldapfilter': ldapfilter,
                    'no_vuln_check': False,
                    'raw': False
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
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Get information about domain trusts.
            
            Args:
                identity: Trust identity to search for (default: * for all trusts)
                properties: Comma-separated list of properties to retrieve
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'searchbase': searchbase,
                    'ldapfilter': ldapfilter,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw
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
            no_cache: bool = False,
            ldapfilter: str = "",
            searchbase: str = "",
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """
            Get domain information.
            
            Args:
                identity: Domain identity to search for (default: * for all domains)
                properties: Comma-separated list of properties to retrieve
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
                searchbase: Search base to filter by
                no_vuln_check: Bypass vulnerability checks
                raw: Return raw results
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw
                })
                result = self.powerview.get_domain(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No domain information found"})
            except Exception as e:
                logging.error(f"Error in get_domain: {str(e)}")
                return json.dumps({"error": str(e)})

        @self.mcp.tool()
        async def get_domain_object_acl(
            identity: str = "*",
            properties: str = "",
            ldapfilter: str = "",
            security_identifier: str = "",
            resolveguids: bool = False,
            searchbase: str = "",
            no_cache: bool = False,
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """
            Get the ACLs for a domain object.
            
            Args:
                identity: Object identity to get ACLs for
                properties: Comma-separated list of properties to retrieve
                ldapfilter: Additional LDAP filter to apply
                security_identifier: Security identifier to filter by
                resolveguids: Resolve GUIDs to names
                searchbase: Search base to filter by
                no_cache: Bypass the cache and perform a live query
                no_vuln_check: Bypass vulnerability checks
                raw: Return raw results
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'security_identifier': security_identifier,
                    'resolveguids': resolveguids,
                    'searchbase': searchbase,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw
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
            no_cache: bool = False,
            ldapfilter: str = "",
            searchbase: str = "",
            no_vuln_check: bool = False,
            raw: bool = False
        ) -> str:
            """
            Get information about organizational units (OUs).
            
            Args:
                identity: OU identity to search for (default: * for all OUs)
                properties: Comma-separated list of properties to retrieve
                resolve_gplink: Resolve Group Policy links for the OU
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
                searchbase: Search base to filter by
                no_vuln_check: Bypass vulnerability checks
                raw: Return raw results
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'gplink': resolve_gplink,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': searchbase,
                    'no_vuln_check': no_vuln_check,
                    'raw': raw
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
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Get information about Group Policy Objects (GPOs).
            
            Args:
                identity: GPO identity to search for (default: * for all GPOs)
                properties: Comma-separated list of properties to retrieve
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': None,
                    'no_vuln_check': False,
                    'raw': False
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
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Get information about DNS zones.
            
            Args:
                identity: Zone identity to search for (default: * for all zones)
                properties: Comma-separated list of properties to retrieve
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': None,
                    'no_vuln_check': False,
                    'raw': False,
                    'zonename': None  # Add zonename parameter which might be needed
                })
                result = self.powerview.get_domaindnszone(identity=identity, properties=props, args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No DNS zones found"})
            except Exception as e:
                logging.error(f"Error in get_domain_dns_zone: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.tool()
        async def invoke_kerberoast(
            identity: str = "",
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Perform Kerberoasting against service accounts.
            
            Args:
                identity: Target identity to kerberoast (default: * for all service accounts)
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': None,
                    'no_vuln_check': False,
                    'raw': False
                })
                result = self.powerview.invoke_kerberoast(args=args)
                return json.dumps(result, default=str) if result else json.dumps({"error": "No kerberoastable accounts found"})
            except Exception as e:
                logging.error(f"Error in invoke_kerberoast: {str(e)}")
                return json.dumps({"error": str(e)})
        
        @self.mcp.tool()
        async def invoke_asreproast(
            identity: str = "",
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Perform AS-REP Roasting against accounts with Kerberos pre-authentication disabled.
            
            Args:
                identity: Target identity to ASREProast (default: * for all vulnerable accounts)
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                args = type('Args', (), {
                    'identity': identity,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': None,
                    'no_vuln_check': False,
                    'raw': False
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
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Get information about domain certificate authorities.
            
            Args:
                identity: CA identity to search for (default: * for all CAs)
                properties: Comma-separated list of properties to retrieve
                check_web_enrollment: Check if web enrollment is enabled
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'check_web_enrollment': check_web_enrollment,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': None,
                    'no_vuln_check': False,
                    'raw': False
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
            vulnerable: bool = True,
            resolve_sids: bool = True,
            no_cache: bool = False,
            ldapfilter: str = ""
        ) -> str:
            """
            Get information about certificate templates in the domain.
            
            Args:
                identity: Template identity to search for (default: * for all templates)
                properties: Comma-separated list of properties to retrieve
                vulnerable: Only return templates with known vulnerabilities
                resolve_sids: Resolve SIDs to names in ACL entries
                no_cache: Bypass the cache and perform a live query
                ldapfilter: Additional LDAP filter to apply
            """
            try:
                props = properties.split(",") if properties else []
                args = type('Args', (), {
                    'identity': identity,
                    'properties': props,
                    'vulnerable': vulnerable,
                    'resolve_sids': resolve_sids,
                    'no_cache': no_cache,
                    'ldapfilter': ldapfilter,
                    'searchbase': None,
                    'no_vuln_check': False,
                    'raw': False,
                    'enabled': False  # This is checked in the code
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