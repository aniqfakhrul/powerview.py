#!/usr/bin/env python3

import logging

def setup_prompts(mcp):
	"""Register all PowerView prompts with the MCP server."""

	@mcp.prompt()
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

	@mcp.prompt()
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

	@mcp.prompt()
	async def find_attack_path_from_current_context() -> str:
		"""Create a prompt to find attack paths from the current user context.
		   Note: This prompt cannot dynamically fetch the current user anymore. Execute the tool `get_current_auth_context` to get the current user."""
		current_user_placeholder = "[CURRENT_USER_IDENTITY]"

		return f"""
		Please identify the current authentication context (e.g., using `get_current_auth_context` if available, or based on connection info).
		Let's assume the current user is: {current_user_placeholder}

		Investigate potential attack paths starting from this user context.
		Focus on actions that {current_user_placeholder} might be able to perform, such as:

		1.  Check Group Memberships: Does {current_user_placeholder} belong to any privileged or interesting groups?
			- Use `get_domain_group` with `memberidentity=\'{current_user_placeholder}\'`
		2.  Find Outgoing ACLs: Does {current_user_placeholder} have permissions ON other objects (users, groups, computers)?
			- Use `get_domain_user` or `get_domain_computer` to find the SID for {current_user_placeholder}.
			- Use `get_domain_object_acl` with the SID found.
			- Pay attention to: GenericAll, GenericWrite, WriteOwner, WriteDACL, WriteProperty (especially on group memberships or userAccountControl), User-Force-Change-Password, AddMembers, etc.
		3.  Check for Owned Objects: Does {current_user_placeholder} own any objects?
			- Use `get_domain_object_owner` filtering for the SID of {current_user_placeholder}.
		4.  Check Delegation Rights:
			- Is {current_user_placeholder} configured for Unconstrained Delegation? (`get_domain_user` or `get_domain_computer` with `identity=\'{current_user_placeholder}\'` and check `userAccountControl`)
			- Is {current_user_placeholder} configured for Constrained Delegation (`TRUSTED_TO_AUTH_FOR_DELEGATION`)? (`get_domain_user` or `get_domain_computer` with `identity=\'{current_user_placeholder}\'` and check `msDS-AllowedToDelegateTo`)
			- Is {current_user_placeholder} allowed to delegate TO other services/computers (Resource-Based Constrained Delegation)? (`get_domain_user` or `get_domain_computer` with `identity=\'{current_user_placeholder}\'` and check `msDS-AllowedToActOnBehalfOfOtherIdentity`)
		5.  Check Local Admin Rights: Can {current_user_placeholder} access administrative shares (C$, ADMIN$) or perform administrative actions on any computers? (Requires external tooling or specific RPC calls not directly exposed as simple MCP tools here, e.g., trying `get_netshare` on `\\\\\\\\TARGET\\\\C$`).
		6.  Kerberoasting/ASREPRoasting: Can {current_user_placeholder} request service tickets for accounts with weak passwords or find users vulnerable to ASREPRoasting?
			- Use `invoke_kerberoast`
			- Use `invoke_asreproast`
		7.  Certificate Abuse: Can {current_user_placeholder} request certificates from templates vulnerable to ESC1/ESC4 etc.?
			- Use `get_domain_ca_template` with `vulnerable=True`.

		Prioritize findings based on potential impact (e.g., direct control of admin accounts/groups is higher priority than control of standard users/computers).
		"""
