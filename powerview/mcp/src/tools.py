#!/usr/bin/env python3

import logging
import json
from typing import Any, Optional
import datetime
import os
from powerview.modules.smbclient import SMBClient
from powerview.utils.helpers import is_ipaddress, is_valid_fqdn, host2ip

def _format_mcp_response(
	data: Any = None,
	error: Optional[str] = None,
	success: Optional[bool] = None,
	message: Optional[str] = None,
	status_override: Optional[str] = None
) -> str:
	"""Formats the response payload into a standardized JSON string for MCP."""
	response = {}
	status = "unknown"

	if error:
		status = "error"
		response["error"] = str(error)
	elif success is True:
		status = "success"
		response["message"] = message or "Operation successful."
		if data is not None:
			response["data"] = data
	elif success is False:
		status = "failure"
		response["error"] = message or "Operation failed."
	elif data is not None:
		if isinstance(data, (list, dict)) and not data:
			status = status_override or "not_found"
			response["message"] = message or "No results found matching criteria."
		else:
			status = status_override or "success"
			response["data"] = data
	elif status_override:
		status = status_override
		response["message"] = message or f"Status: {status_override}"
	else:
		status = "no_content"
		response["message"] = message or "Operation completed with no specific content returned."

	response["status"] = status

	try:
		return json.dumps(response, default=str)
	except TypeError as e:
		logging.error(f"Failed to serialize MCP response: {e}. Response data: {response}")
		return json.dumps({"status": "error", "error": f"Internal serialization error: {e}"})

def setup_tools(mcp, powerview_instance):
	"""Register all PowerView tools with the MCP server."""

	@mcp.tool()
	async def login_as(
		username: str,
		password: str | None = None,
		domain: str | None = None,
		lmhash: str | None = None,
		nthash: str | None = None,
		auth_aes_key: str | None = None
	) -> str:
		"""
		Login as a different user from the current context.
		
		Args:
			username: The username to login as.
			password: The password to login with. Mutually exclusive with lmhash and nthash and auth_aes_key.
			domain: The domain to login to. Optional, will use current domain if not provided.
			lmhash: The LM hash to use for the login. Mutually exclusive with password.
			nthash: The NTHash to use for the login. Mutually exclusive with password. If 32 hash length, will be considered as NTHash. Leave blank for lmhash and password.
			auth_aes_key: The AES key to use for the login. Mutually exclusive with password. If longer than 32 characters, will be considered as auth_aes_key. Leave blank for password.
		"""
		try:
			success = powerview_instance.login_as(
				username=username,
				password=password,
				domain=domain,
				lmhash=lmhash,
				nthash=nthash,
				auth_aes_key=auth_aes_key
			)

			if success:
				current_identity = powerview_instance.conn.who_am_i()
				message = f"Successfully logged in as {current_identity}"
				return _format_mcp_response(success=True, message=message)
			else:
				message = f"Failed to login as {username}@{domain or powerview_instance.domain}. Check credentials or permissions."
				logging.warning(message)
				return _format_mcp_response(success=False, message=message)

		except Exception as e:
			logging.error(f"Unexpected exception during login_as for {username}: {str(e)}")
			return _format_mcp_response(error=f"An unexpected error occurred during login: {str(e)}")

	@mcp.tool()
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
			result = powerview_instance.get_domainuser(args=args)
			return _format_mcp_response(data=result, message="No users found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_user: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaincomputer(args=args)
			return _format_mcp_response(data=result, message="No computers found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_computer: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaingroup(args=args)
			return _format_mcp_response(data=result, message="No groups found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_group: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaingroupmember(identity=identity, multiple=multiple, args=args)
			return _format_mcp_response(data=result, message=f"No members found for group '{identity}'")
		except Exception as e:
			logging.error(f"Error in get_domain_group_member: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaincontroller(args=args)
			return _format_mcp_response(data=result, message="No domain controllers found")
		except Exception as e:
			logging.error(f"Error in get_domain_controller: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaintrust(args=args)
			return _format_mcp_response(data=result, message="No trusts found")
		except Exception as e:
			logging.error(f"Error in get_domain_trust: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domain(args=args)
			return _format_mcp_response(data=result, message="No domain information found")
		except Exception as e:
			logging.error(f"Error in get_domain: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def get_domain_object_acl(
		identity: str = "*",
		security_identifier: str = "",
		ldapfilter: str = "",
		resolveguids: bool = False,
		searchbase: str = "",
		no_cache: bool = False,
		no_vuln_check: bool = False,
		raw: bool = False
	) -> str:
		"""Get the ACLs for domain objects. IMPORTANT: When analyzing attack paths, always use `security_identifier` to filter ACLs by a specific identity (like your current user) instead of all ACLs. Not doing so will miss critical attack paths.

		Args:
			identity: Identity of the object (DN, sAMAccountName, SID, GUID) to get ACLs for. Defaults to '*'. Leave blank to get ACLs for all objects.
			security_identifier: CRITICAL FOR ATTACK PATH ANALYSIS - Filter ACEs to only show ACLs that the identity has on the object. Useful to find attack paths for a specific identity like your current user. Can be a SID, username, or DN.
			ldapfilter: Custom LDAP filter string (applied to the object search if identity is wildcard).
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
			result = powerview_instance.get_domainobjectacl(args=args)
			return _format_mcp_response(data=result, message="No ACLs found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_object_acl: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domainou(args=args)
			return _format_mcp_response(data=result, message="No OUs found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_ou: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaingpo(args=args)
			return _format_mcp_response(data=result, message="No GPOs found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_gpo: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def get_domain_gpo_localgroup(
		identity: str = "",
	) -> str:
		"""Get local group membership from GPOs."""
		try:
			args = type('Args', (), {
				'identity': identity,
				'module': 'Get-DomainGPOLocalGroup'
			})
			result = powerview_instance.get_domaingpolocalgroup(args=args)
			return _format_mcp_response(data=result, message="No GPO local group info found")
		except Exception as e:
			logging.error(f"Error in get_domain_gpo_localgroup: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def get_domain_gpo_settings(
		identity: str = "",
		no_cache: bool = False,
		no_vuln_check: bool = False,
		raw: bool = False
	) -> str:
		"""Parse and return GPO settings from SYSVOL.

		Args:
			identity: Filter by GPO identity (DisplayName, GUID, DN). Required, get gpo name with `get_domain_gpo` tool.
			no_cache: Bypass the cache and perform a live query.
			no_vuln_check: Disable vulnerability checks.
			raw: Return raw LDAP entries without formatting.
		"""
		try:
			if not identity:
				return _format_mcp_response(error="Identity is required")

			args = type('Args', (), {
				'identity': identity,
				'no_cache': no_cache,
				'no_vuln_check': no_vuln_check,
				'raw': raw,
				'module': 'Get-DomainGPOSettings'
			})
			result = powerview_instance.get_domaingposettings(args=args)
			return _format_mcp_response(data=result, message="No GPO settings found")
		except Exception as e:
			logging.error(f"Error in get_domain_gpo_settings: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaindnszone(identity=identity, properties=props, args=args)
			return _format_mcp_response(data=result, message="No DNS zones found")
		except Exception as e:
			logging.error(f"Error in get_domain_dns_zone: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.invoke_kerberoast(args=args)
			return _format_mcp_response(data=result, message="No kerberoastable accounts found")
		except Exception as e:
			logging.error(f"Error in invoke_kerberoast: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.invoke_asreproast(args=args)
			return _format_mcp_response(data=result, message="No AS-REP roastable accounts found")
		except Exception as e:
			logging.error(f"Error in invoke_asreproast: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domainca(args=args)
			return _format_mcp_response(data=result, message="No certificate authorities found")
		except Exception as e:
			logging.error(f"Error in get_domain_ca: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domaincatemplate(
				args=args
			)
			return _format_mcp_response(data=result, message="No certificate templates found")
		except Exception as e:
			logging.error(f"Error in get_domain_ca_template: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def get_domain_gmsa(
		identity: str = "",
		ldapfilter: str = "",
		searchbase: str = "",
		no_cache: bool = False,
		no_vuln_check: bool = False,
		raw: bool = False
	) -> str:
		"""Get information about Group Managed Service Accounts (gMSAs).

		Args:
			identity: Filter by gMSA identity (sAMAccountName, SID, DN). Defaults to empty (all gMSAs).
			ldapfilter: Custom LDAP filter string.
			searchbase: Specify the search base DN.
			no_cache: Bypass the cache and perform a live query.
			no_vuln_check: Disable vulnerability checks.
			raw: Return raw LDAP entries without formatting.
		"""
		try:
			args = type('Args', (), {
				'identity': identity,
				'ldapfilter': ldapfilter,
				'searchbase': searchbase if searchbase else None,
				'no_cache': no_cache,
				'no_vuln_check': no_vuln_check,
				'raw': raw,
				'module': 'Get-DomainGMSA'
			})
			result = powerview_instance.get_domaingmsa(
				identity=identity if identity else None,
				args=args,
				no_cache=no_cache,
				no_vuln_check=no_vuln_check,
				raw=raw
			)
			return _format_mcp_response(data=result, message="No Group Managed Service Accounts found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_gmsa: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_domainobjectowner(args=args)
			return _format_mcp_response(data=result, message="No object owner information found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_domain_object_owner: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
			result = powerview_instance.get_exchangeserver(args=args)
			return _format_mcp_response(data=result, message="No Exchange servers found matching criteria")
		except Exception as e:
			logging.error(f"Error in get_exchange_server: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
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
		target_computer = computer or computername
		if not target_computer:
			return _format_mcp_response(success=False, message="Either 'computer' or 'computername' must be specified")
		if computer and computername:
			 return _format_mcp_response(success=False, message="Specify only one of 'computer' or 'computername'")

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
			result = powerview_instance.get_netshare(args=args)
			return _format_mcp_response(data=result, message=f"No shares found on {target_computer}")
		except Exception as e:
			error_msg = str(e)
			if "rpc_s_access_denied" in error_msg.lower():
				error_msg = f"Access denied to {target_computer}. Check permissions."
			elif "connection" in error_msg.lower() or "Errno 111" in error_msg:
				error_msg = f"Could not connect to {target_computer}. Check network connectivity and RPC/SMB services."
			logging.error(f"Error in get_netshare: {str(e)}")
			return _format_mcp_response(error=error_msg)

	@mcp.tool()
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
				return _format_mcp_response(success=False, message="Identity and AccountPassword are required.")

		try:
			args = type('Args', (), {
				'identity': identity,
				'accountpassword': accountpassword,
				'oldpassword': oldpassword,
				'server': None,
				'outfile': None,
				'module': 'Set-DomainUserPassword'
			})

			result = powerview_instance.set_domainuserpassword(
				identity=identity,
				accountpassword=accountpassword,
				oldpassword=oldpassword,
				args=args
			)

			if result is True:
				return _format_mcp_response(success=True, message=f"Password for '{identity}' set successfully.")
			elif result is False:
				error_detail = f"Failed to set password for '{identity}'. Check permissions, password complexity/history, or if the old password is required/correct."
				logging.warning(f"set_domain_user_password returned False for '{identity}'.")
				return _format_mcp_response(success=False, message=error_detail)
			else: # Assumes None means user not found/ambiguous
				error_detail = f"User identity '{identity}' not found or multiple users matched."
				logging.error(f"set_domain_user_password could not find unique user for '{identity}'.")
				return _format_mcp_response(success=False, message=error_detail)

		except Exception as e:
			logging.error(f"Exception in set_domain_user_password for '{identity}': {str(e)}")
			error_msg = str(e)
			return _format_mcp_response(error=f"An unexpected exception occurred: {error_msg}")

	@mcp.tool()
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
			return _format_mcp_response(success=False, message="Username and Userpass are required.")
		try:
			args = type('Args', (), {'module': 'Add-DomainUser'})
			result = powerview_instance.add_domainuser(
				username=username,
				userpass=userpass,
				basedn=basedn,
				args=args
			)
			if result: # Assuming result is DN on success
				return _format_mcp_response(success=True, message=f"User '{username}' added successfully.", data={"dn": result})
			else:
				logging.warning(f"add_domain_user returned unexpected value for '{username}'.")
				return _format_mcp_response(success=False, message=f"Failed to add user '{username}'. Check permissions or if user already exists.")
		except Exception as e:
			logging.error(f"Exception in add_domain_user for '{username}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
	async def remove_domain_user(
		identity: str
	) -> str:
		"""
		Removes a domain user.

		Args:
			identity: The identity (e.g., sAMAccountName, DN) of the user to remove.
		"""
		if not identity:
			return _format_mcp_response(success=False, message="Identity is required.")
		try:
			result = powerview_instance.remove_domainuser(identity=identity)
			if result is True:
				return _format_mcp_response(success=True, message=f"User '{identity}' removed successfully.")
			else:
				msg = f"Failed to remove user '{identity}'. User might not exist or check permissions."
				logging.warning(f"remove_domain_user returned non-True for '{identity}'.")
				return _format_mcp_response(success=False, message=msg)
		except Exception as e:
			logging.error(f"Exception in remove_domain_user for '{identity}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
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
			return _format_mcp_response(success=False, message="Identity (group) and Members are required.")
		try:
			if not members.strip():
				return _format_mcp_response(success=False, message="Members string cannot be empty.")
			# Split comma-separated members into a list
			member_list = [m.strip() for m in members.split(',') if m.strip()]

			result = powerview_instance.add_domaingroupmember(identity=identity, members=member_list, args=None)

			if result is True:
					return _format_mcp_response(success=True, message=f"Attempted to add members {member_list} to group '{identity}'.")
			else:
					msg = f"Operation completed for group '{identity}' with members {member_list}. Some members might not have been added (check permissions, existence)."
					logging.warning(f"add_domaingroupmember returned non-True for group '{identity}'.")
					# Use status_override to indicate potential partial failure
					return _format_mcp_response(success=False, message=msg, status_override="partial_failure")
		except Exception as e:
			logging.error(f"Exception in add_domaingroupmember for group '{identity}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
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
			return _format_mcp_response(success=False, message="Identity (group) and Members are required.")
		try:
			if not members.strip():
				return _format_mcp_response(success=False, message="Members string cannot be empty.")
			# Split comma-separated members into a list
			member_list = [m.strip() for m in members.split(',') if m.strip()]

			result = powerview_instance.remove_domaingroupmember(identity=identity, members=member_list, args=None)

			if result is True:
					return _format_mcp_response(success=True, message=f"Attempted to remove members {member_list} from group '{identity}'.")
			else:
					msg = f"Operation completed for group '{identity}' with members {member_list}. Some members might not have been removed (check permissions, existence)."
					logging.warning(f"remove_domaingroupmember returned non-True for group '{identity}'.")
					return _format_mcp_response(success=False, message=msg, status_override="partial_failure")
		except Exception as e:
			logging.error(f"Exception in remove_domaingroupmember for group '{identity}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
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
				return _format_mcp_response(success=False, message="TargetIdentity and PrincipalIdentity are required.")
		try:
			result = powerview_instance.add_domainobjectacl(
				targetidentity=targetidentity,
				principalidentity=principalidentity,
				rights=rights,
				rights_guid=rights_guid,
				ace_type=ace_type,
				inheritance=inheritance
			)
			if result is True:
				return _format_mcp_response(success=True, message=f"Successfully added '{rights}' ACE for '{principalidentity}' on '{targetidentity}'.")
			else:
				msg = f"Failed to add ACE for '{principalidentity}' on '{targetidentity}'. Check inputs and permissions."
				logging.warning(f"add_domain_object_acl returned non-True for target '{targetidentity}'.")
				return _format_mcp_response(success=False, message=msg)
		except Exception as e:
			logging.error(f"Exception in add_domain_object_acl for target '{targetidentity}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
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
				return _format_mcp_response(success=False, message="TargetIdentity and PrincipalIdentity are required.")
		try:
			result = powerview_instance.remove_domainobjectacl(
				targetidentity=targetidentity,
				principalidentity=principalidentity,
				rights=rights,
				rights_guid=rights_guid,
				ace_type=ace_type,
				inheritance=inheritance
			)
			if result is True:
				return _format_mcp_response(success=True, message=f"Successfully removed '{rights}' ACE for '{principalidentity}' from '{targetidentity}'.")
			else:
				msg = f"Failed to remove ACE for '{principalidentity}' from '{targetidentity}'. Check if ACE exists with specified parameters and check permissions."
				logging.warning(f"remove_domain_object_acl returned non-True for target '{targetidentity}'.")
				return _format_mcp_response(success=False, message=msg)
		except Exception as e:
			logging.error(f"Exception in remove_domain_object_acl for target '{targetidentity}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
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
				return _format_mcp_response(success=False, message="TargetIdentity and PrincipalIdentity are required.")
		try:
			result = powerview_instance.set_domainobjectowner(
				targetidentity=targetidentity,
				principalidentity=principalidentity,
				searchbase=searchbase,
				args=None # Args not used by underlying function for core logic
			)
			if result is True:
					return _format_mcp_response(success=True, message=f"Successfully set '{principalidentity}' as owner of '{targetidentity}'.")
			else:
					msg = f"Failed to set owner for '{targetidentity}'. Check identities and permissions."
					logging.warning(f"set_domain_object_owner returned non-True for target '{targetidentity}'.")
					return _format_mcp_response(success=False, message=msg)
		except Exception as e:
				logging.error(f"Exception in set_domain_object_owner for target '{targetidentity}': {str(e)}")
				return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
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
			return _format_mcp_response(success=False, message="Identity and AccountPassword are required.")
		try:
				args = type('Args', (), {
				'identity': identity,
				'accountpassword': accountpassword,
				'oldpassword': oldpassword,
				'server': None,
				'outfile': None,
				'module': 'Set-DomainComputerPassword'
				})
				result = powerview_instance.set_domaincomputerpassword(
					identity=identity,
					accountpassword=accountpassword,
					oldpassword=oldpassword,
					args=args
				)
				if result is True:
					return _format_mcp_response(success=True, message=f"Password for computer '{identity}' set successfully.")
				else:
					error_detail = f"Failed to set password for computer '{identity}'. Check permissions or identity."
					logging.warning(f"set_domain_computer_password returned non-True for '{identity}'.")
					return _format_mcp_response(success=False, message=error_detail)
		except Exception as e:
				logging.error(f"Exception in set_domain_computer_password for '{identity}': {str(e)}")
				return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
	async def convert_sid_to_name(
		sid: str
	) -> str:
		"""Convert a SID to a name."""
		try:
			result = powerview_instance.convertfrom_sid(sid)
			return _format_mcp_response(data={"name": result})
		except Exception as e:
			logging.error(f"Exception in convert_sid_to_name for '{sid}': {str(e)}")
			return _format_mcp_response(error=f"An unexpected exception occurred: {str(e)}")

	@mcp.tool()
	async def get_current_auth_context() -> str:
		"""Get the current authenticated user context for the PowerView session."""
		try:
			identity = powerview_instance.conn.who_am_i()
			username = identity.split("\\")[-1] if "\\" in identity else identity
			return _format_mcp_response(data={"identity": username})
		except AttributeError:
			logging.error("Error in get_current_auth_context: powerview_instance or connection object not available.")
			return _format_mcp_response(error="Internal server error: Could not access connection details.")
		except Exception as e:
			logging.error(f"Error in get_current_auth_context: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def generate_findings_report(
		custom_findings: str,
		report_title: str = "PowerView Findings Report",
		target_domain: str = "",
		report_format: str = "markdown"
	) -> str:
		"""Generate a custom security findings report based on user-defined findings.
		
		Args:
			custom_findings: JSON string containing custom finding dictionaries with keys like "Title", "Description", "Risk", "Recommendation" etc.
			report_title: Title for the report
			target_domain: Target domain name for the report context
			report_format: Output format (markdown, json, or text)
		"""
		try:
			# Parse the custom findings from JSON string
			findings_list = json.loads(custom_findings)
			if not isinstance(findings_list, list):
				findings_list = [findings_list]  # Convert single dict to list
				
			# Initialize report data
			timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
			
			# Process each custom finding dict and normalize keys
			normalized_findings = []
			for finding in findings_list:
				# Normalize keys (case-insensitive matching)
				normalized = {}
				key_map = {
					"title": ["title", "name", "finding", "issue"],
					"risk": ["risk", "severity", "level", "criticality"],
					"description": ["description", "desc", "details", "info"],
					"affected_entity": ["affected_entity", "affected_objects", "affected", "entity", "entities", "target"],
					"recommendation": ["recommendation", "remediation", "fix", "solution", "mitigation"],
					"notes": ["notes", "comments", "additional", "context"]
				}
				
				# Try to map keys from the input dict to our normalized structure
				for norm_key, possible_keys in key_map.items():
					for pk in possible_keys:
						for k in finding.keys():
							if k.lower() == pk.lower():
								normalized[norm_key] = finding[k]
								break
						if norm_key in normalized:
							break
						
				# Ensure required fields exist with defaults if missing
				if "title" not in normalized:
					normalized["title"] = "Unnamed Finding"
				if "risk" not in normalized:
					normalized["risk"] = "Medium"  # Default risk level
				if "description" not in normalized:
					normalized["description"] = "No description provided."
				if "recommendation" not in normalized:
					normalized["recommendation"] = "No specific recommendation provided."

				# Handle affected_entity field specially (could be string or list or dict)
				if "affected_entity" in normalized:
					if isinstance(normalized["affected_entity"], str):
						normalized["affected_objects"] = [{"name": normalized["affected_entity"]}]
					elif isinstance(normalized["affected_entity"], list):
						if all(isinstance(item, str) for item in normalized["affected_entity"]):
							normalized["affected_objects"] = [{"name": item} for item in normalized["affected_entity"]]
						else:
							normalized["affected_objects"] = normalized["affected_entity"]
					elif isinstance(normalized["affected_entity"], dict):
						normalized["affected_objects"] = [normalized["affected_entity"]]
					normalized["count"] = len(normalized["affected_objects"])
				else:
					normalized["affected_objects"] = []
					normalized["count"] = 0
					
				# Add any extra fields not in our mapping
				for k, v in finding.items():
					if not any(k.lower() == pk.lower() for norm_keys in key_map.values() for pk in norm_keys):
						normalized[k] = v
						
				normalized_findings.append(normalized)
				
			# Format the report
			report = {
				"title": report_title,
				"target_domain": target_domain,
				"timestamp": timestamp,
				"summary": {
					"total_findings": len(normalized_findings),
					"risk_breakdown": {
						"Critical": len([f for f in normalized_findings if f["risk"].lower() == "critical"]),
						"High": len([f for f in normalized_findings if f["risk"].lower() == "high"]),
						"Medium": len([f for f in normalized_findings if f["risk"].lower() == "medium"]),
						"Low": len([f for f in normalized_findings if f["risk"].lower() == "low"])
					}
				},
				"findings": normalized_findings
			}
			
			# Generate report based on requested format
			if report_format.lower() == "json":
				return _format_mcp_response(data=report)
			elif report_format.lower() == "markdown":
				md_report = f"# {report_title}\n\n"
				md_report += f"**Target Domain:** {target_domain}\n"
				md_report += f"**Report Generated:** {timestamp}\n\n"
				
				md_report += "## Summary\n\n"
				md_report += f"**Total Findings:** {report['summary']['total_findings']}\n\n"
				md_report += "**Risk Breakdown:**\n"
				md_report += f"- Critical: {report['summary']['risk_breakdown']['Critical']}\n"
				md_report += f"- High: {report['summary']['risk_breakdown']['High']}\n"
				md_report += f"- Medium: {report['summary']['risk_breakdown']['Medium']}\n"
				md_report += f"- Low: {report['summary']['risk_breakdown']['Low']}\n\n"
				
				if normalized_findings:
					md_report += "## Findings\n\n"
					for i, finding in enumerate(normalized_findings, 1):
						md_report += f"### {i}. {finding['title']} ({finding['risk']})\n\n"
						md_report += f"**Description:** {finding['description']}\n\n"
						
						if finding.get('affected_objects'):
							md_report += f"**Affected Objects:** {finding['count']}\n\n"
							md_report += "**Examples:**\n\n"
							md_report += "```\n"
							for obj in finding['affected_objects'][:5]:  # Limit to 5 examples
								md_report += json.dumps(obj, indent=2) + "\n"
							md_report += "```\n\n"
						
						md_report += f"**Recommendation:** {finding['recommendation']}\n\n"
						
						# Add notes if present
						if 'notes' in finding:
							md_report += f"**Notes:** {finding['notes']}\n\n"
							
						# Add any custom fields
						custom_fields = [k for k in finding.keys() if k not in ["title", "risk", "description", "affected_objects", "count", "recommendation", "notes"]]
						if custom_fields:
							md_report += "**Additional Information:**\n\n"
							for field in custom_fields:
								md_report += f"- **{field}:** {finding[field]}\n"
							md_report += "\n"
						
						md_report += "---\n\n"
				else:
					md_report += "## No Findings\n\n"
					md_report += "No security findings were provided.\n\n"
				
				return _format_mcp_response(data={"report": md_report})
			else:  # text format
				text_report = f"{report_title}\n"
				text_report += f"Target Domain: {target_domain}\n"
				text_report += f"Report Generated: {timestamp}\n\n"
				
				text_report += "SUMMARY:\n"
				text_report += f"Total Findings: {report['summary']['total_findings']}\n\n"
				text_report += "Risk Breakdown:\n"
				text_report += f"Critical: {report['summary']['risk_breakdown']['Critical']}\n"
				text_report += f"High: {report['summary']['risk_breakdown']['High']}\n"
				text_report += f"Medium: {report['summary']['risk_breakdown']['Medium']}\n"
				text_report += f"Low: {report['summary']['risk_breakdown']['Low']}\n\n"
				
				if normalized_findings:
					text_report += "FINDINGS:\n\n"
					for i, finding in enumerate(normalized_findings, 1):
						text_report += f"{i}. {finding['title']} ({finding['risk']})\n\n"
						text_report += f"Description: {finding['description']}\n\n"
						
						if finding.get('affected_objects'):
							text_report += f"Affected Objects: {finding['count']}\n\n"
						
						text_report += f"Recommendation: {finding['recommendation']}\n\n"
						
						# Add notes if present
						if 'notes' in finding:
							text_report += f"Notes: {finding['notes']}\n\n"
						
						text_report += "----------\n\n"
				else:
					text_report += "NO FINDINGS\n\n"
					text_report += "No security findings were provided.\n\n"
				
				return _format_mcp_response(data={"report": text_report})
				
		except Exception as e:
			logging.error(f"Error in generate_custom_findings_report: {str(e)}")
			import traceback
			trace = traceback.format_exc()
			return _format_mcp_response(error=f"Failed to generate report: {str(e)}\n{trace}")

	@mcp.tool()
	async def find_localadminaccess(
		computer: str = None,
		username: str = None,
		password: str = None,
		nthash: str = None,
		lmhash: str = None,
		no_cache: bool = False,
	) -> str:
		"""
		Enumerate computers where the current user has local admin access. Accepts a single computer or checks all domain computers if not specified. When computer is not specified, it will check all domain computers (careful because you might be dealing with thousands of hosts).
		
		Args:
			computer: The computer to check for local admin access. Leave blank to check all domain computers.
			username: The username to use for authentication. Ignore to use current user context.
			password: The password to use for authentication. Ignore to use current user context.
			nthash: The NTHash to use for authentication. Ignore to use current user context.
			lmhash: The LMHash to use for authentication. Ignore to use current user context.
			no_cache: Whether to use cached results.
		"""
		try:
			args = type('Args', (), {
				'computer': computer,
				'username': username,
				'password': password,
				'nthash': nthash,
				'lmhash': lmhash,
				'no_cache': no_cache,
				'module': 'Find-LocalAdminAccess'
			})
			result = powerview_instance.find_localadminaccess(args=args)
			return _format_mcp_response(data=result, message="No local admin access found on any host.")
		except Exception as e:
			logging.error(f"Error in find_localadminaccess: {str(e)}")
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def smb_connect(
		computer: str,
		username: str = "",
		password: str = "",
		nthash: str = "",
		lmhash: str = "",
		domain: str = ""
	) -> str:
		"""
		Establish an SMB connection to target system.
		
		This function establishes a connection to a remote system using SMB protocol, 
		which can be leveraged for file operations, privilege escalation, lateral movement,
		or intelligence gathering. Supports multiple authentication methods including
		NTLM hash pass-the-hash attacks.
		
		Parameters:
			computer: Target hostname or IP address
			username: Optional: Account username (optional if using current context)
			password: Optional: Account password in cleartext
			nthash: Optional: NT hash for pass-the-hash attacks
			lmhash: Optional: LM hash (default: None)
			domain: Optional: Domain name (will use current domain if not specified)
		
		Returns:
			Connection status information
		"""
		try:
			if username and ('/' in username or '\\' in username):
				domain, username = username.replace('/', '\\').split('\\')
			
			if not computer:
				return _format_mcp_response(error="Computer name/IP is required")

			is_fqdn = False
			host = ""

			if not is_ipaddress(computer):
				is_fqdn = True
				if not is_valid_fqdn(computer):
					host = f"{computer}.{powerview_instance.domain}"
				else:
					host = computer
			else:
				host = computer

			if powerview_instance.use_kerberos:
				if is_ipaddress(computer):
					return _format_mcp_response(error="FQDN must be used for kerberos authentication")
			else:
				if is_fqdn:
					host = host2ip(host, powerview_instance.nameserver, 3, True, 
							use_system_ns=powerview_instance.use_system_nameserver)

			if not host:
				return _format_mcp_response(error="Host not found")

			client = powerview_instance.conn.init_smb_session(
				host,
				username=username,
				password=password,
				nthash=nthash,
				lmhash=lmhash,
				domain=domain
			)
			
			if not client:
				return _format_mcp_response(error=f"Failed to connect to {host}")

			if not hasattr(powerview_instance.conn, 'smb_sessions'):
				powerview_instance.conn.smb_sessions = {}
			powerview_instance.conn.smb_sessions[computer.lower()] = client

			return _format_mcp_response(data={"status": "connected", "host": host})
		except Exception as e:
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def smb_shares(
		computer: str
	) -> str:
		"""List available SMB shares on a target system.
		
		Enumerates available SMB shares on a target system, useful for reconnaissance
		and identifying valuable data.
		
		Parameters:
			computer: Target hostname or IP address
		
		Returns:
			List of available SMB shares of the target computer
		"""
		try:
			host = computer.lower()
			
			if not host:
				return _format_mcp_response(error="Computer name/IP is required")
			
			if not hasattr(powerview_instance.conn, 'smb_sessions') or host not in powerview_instance.conn.smb_sessions:
				return _format_mcp_response(error="No active SMB session. Please connect first")

			client = powerview_instance.conn.smb_sessions[host]
			smb_client = SMBClient(client)
			shares = smb_client.shares()

			formatted_shares = []
			for share in shares:
				entry = {
					"Name": share['shi1_netname'][:-1],
					"Remark": share['shi1_remark'][:-1],
					"Address": host
				}
				formatted_shares.append({"attributes": entry})

			return _format_mcp_response(data=formatted_shares)
		except Exception as e:
			return _format_mcp_response(error=str(e))

	@mcp.tool()
	async def smb_ls(
		computer: str,
		share: str,
		path: str = ""
	) -> str:
		"""List contents of a directory on a remote SMB share.
		
		Enumerates files and directories within a specified share path, useful for
		reconnaissance, identifying valuable data, and planning exfiltration.
		Directory traversal is supported to explore the target filesystem.
		
		Parameters:
			computer: Target hostname or IP address
			share: Share name to access (e.g., "C$", "ADMIN$", "NETLOGON")
			path: Directory path within the share to list (default: root of share) (i.e.: "\\Users\\Public\\Desktop")
		
		Returns:
			File listing with metadata (size, timestamps, attributes)
		"""
		try:
			host = computer.lower()
			
			if not host or not share:
				return _format_mcp_response(error="Computer name/IP and share name are required")

			if not hasattr(powerview_instance.conn, 'smb_sessions') or host not in powerview_instance.conn.smb_sessions:
				return _format_mcp_response(error="No active SMB session. Please connect first")
			
			client = powerview_instance.conn.smb_sessions[host]
			smb_client = SMBClient(client)
			
			files = smb_client.ls(share, path)
			logging.debug(f"[SMB LS] Listing {path} on {host} with share {share}")
			
			file_list = []
			for f in files:
				name = f.get_longname()
				if name in ['.', '..']:
					continue
				
				file_info = {
					"name": name,
					"size": f.get_filesize(),
					"is_directory": f.is_directory(),
					"created": str(f.get_ctime()),
					"modified": str(f.get_mtime()),
					"accessed": str(f.get_atime())
				}
				file_list.append(file_info)

			return _format_mcp_response(data=file_list)
		except Exception as e:
			logging.error(f"[SMB LS] Error: {str(e)}")
			return _format_mcp_response(error=str(e))