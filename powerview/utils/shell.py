#!/usr/bin/env python3
from powerview.utils.colors import bcolors, Gradient

def get_prompt(powerview, current_target_domain=None, using_cache=False, args=None):
	"""
	Creates a visually enhanced prompt for the PowerView shell.
	
	Args:
		powerview: PowerView instance to extract connection and status information from
		current_target_domain: Optional target domain for cross-domain operations
		using_cache: Indicates if the last results came from cache
		args: Command line arguments for additional context
	Returns:
		A formatted string for the shell prompt
	"""
	try:
		init_proto = powerview.conn.get_proto()
		server_dns = powerview.get_server_dns()
		nameserver = powerview.conn.get_nameserver()
		
		is_admin = False
		if args and not getattr(args, 'no_admin_check', False):
			is_admin = powerview.get_admin_status()
		
		cur_user = powerview.conn.who_am_i()
		if is_admin:
			cur_user = f"{bcolors.WARNING}{cur_user}{bcolors.ENDC}"
		
		mcp_running = False
		web_running = False
		if args:
			if getattr(args, 'mcp', False) and hasattr(powerview, 'mcp_server'):
				mcp_running = powerview.mcp_server.get_status()
			if getattr(args, 'web', False) and hasattr(powerview, 'api_server'):
				web_running = powerview.api_server.get_status()
		
		channel_binding_active = getattr(powerview.conn, 'use_channel_binding', False)
		ldap_signing_active = getattr(powerview.conn, 'use_sign_and_seal', False)
		
	except Exception as e:
		return f"{bcolors.OKGREEN}PV ❯{bcolors.ENDC} "
	
	domain_indicator = ""
	if current_target_domain:
		domain_indicator = f" {bcolors.BOLD}{bcolors.FAIL}[→ {current_target_domain}]{bcolors.ENDC}"
	
	cache_indicator = ""
	if using_cache:
		cache_indicator = f" {bcolors.WARNING}[CACHED]{bcolors.ENDC}"
	
	mcp_indicator = ""
	if mcp_running:
		mcp_text = "[MCP]"
		gradient_colors = Gradient.generate_gradient_colors([138, 43, 226], [0, 191, 255], len(mcp_text))
		colored_text = ""
		for i, char in enumerate(mcp_text):
			r, g, b = gradient_colors[i]
			colored_text += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
		mcp_indicator = f" {bcolors.BOLD}{colored_text}{bcolors.ENDC}"

	web_indicator = ""
	if web_running:
		web_indicator = f" {bcolors.OKBLUE}[WEB]{bcolors.ENDC}"
	
	security_indicators = ""
	if channel_binding_active:
		security_indicators += "📦 "
	if ldap_signing_active:
		security_indicators += "🔒 "
	
	prompt = (f'{bcolors.OKBLUE}╭─{bcolors.ENDC}'
			  f'{security_indicators}'
			  f'{bcolors.WARNING}{bcolors.BOLD}{init_proto}{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}─[{bcolors.ENDC}{bcolors.OKCYAN}{server_dns}{bcolors.ENDC}{bcolors.OKBLUE}]{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}─[{bcolors.ENDC}{cur_user}{bcolors.OKBLUE}]{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}-[NS:{nameserver if nameserver else "<auto>"}]{bcolors.ENDC}'
			  f'{mcp_indicator}'
			  f'{web_indicator}'
			  f'{domain_indicator}'
			  f'{cache_indicator}'
			  f'\n{bcolors.OKBLUE}╰─{bcolors.BOLD}PV{bcolors.ENDC} {bcolors.OKGREEN}❯{bcolors.ENDC} ')
	
	return prompt