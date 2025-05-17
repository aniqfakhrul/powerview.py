#!/usr/bin/env python3
from powerview.utils.colors import bcolors, Gradient
from powerview.utils.terminal import detect_terminal_environment

_env_cache = None

def get_prompt(init_proto, server_dns, cur_user, nameserver, target_domain=None, using_cache=False, mcp_running=False, web_running=False):
	"""
	Creates a visually enhanced prompt for the PowerView shell.
	
	Args:
		init_proto: The protocol being used (LDAP/LDAPS/GC/GC_LDAPS/ADWS)
		server_dns: The DNS name of the server
		cur_user: The current authenticated user
		nameserver: The DNS nameserver being used
		target_domain: Optional target domain for cross-domain operations
		using_cache: Indicates if the last results came from cache
		mcp_running: Indicates if MCP server is running
		web_running: Indicates if web server is running
	Returns:
		A formatted string for the shell prompt
	"""
	global _env_cache
	if _env_cache is None:
		_env_cache = detect_terminal_environment()
	env = _env_cache
	use_unicode = env.get('supports_unicode', False)

	arrow = '→' if use_unicode else '->'
	cached = 'CACHED' if not use_unicode else 'CACHED'
	mcp_text = '[MCP]' if not use_unicode else '[MCP]'
	web_text = '[WEB]' if not use_unicode else '🌐'
	ns_label = 'NS' if not use_unicode else 'NS'
	prompt_arrow = '❯' if use_unicode else '>'
	top_line = '╭─' if use_unicode else '---'
	bottom_line = '╰─' if use_unicode else '---'
	if use_unicode:
		protocol_icon = '🔒' if init_proto == 'LDAPS' or init_proto == 'GC_LDAPS' or init_proto == 'ADWS' else '🔓'
	else:
		protocol_icon = ''

	protocol_indicator = f"{bcolors.WARNING}{bcolors.BOLD}{protocol_icon} {init_proto}{bcolors.ENDC}"
	server_indicator = f" {bcolors.OKBLUE}[{bcolors.ENDC}{bcolors.OKCYAN}{server_dns}{bcolors.ENDC}{bcolors.OKBLUE}]{bcolors.ENDC}"
	user_indicator = f"{bcolors.OKBLUE}-[{bcolors.ENDC}{cur_user}{bcolors.OKBLUE}]{bcolors.ENDC}"
	ns_indicator = f"{bcolors.OKBLUE}-[{ns_label}:{nameserver if nameserver else "<auto>"}]{bcolors.ENDC}"

	domain_indicator = ""
	if target_domain:
		domain_indicator = f" {bcolors.BOLD}{bcolors.FAIL}[{arrow} {target_domain}]{bcolors.ENDC}"
	
	# Add cache indicator if using cached results - enhanced version
	cache_indicator = ""
	if using_cache:
		cache_indicator = f" {bcolors.WARNING}[{cached}]{bcolors.ENDC}"
	
	# Add MCP indicator if server is running
	mcp_indicator = ""
	if mcp_running:
		if use_unicode:
			gradient_colors = Gradient.generate_gradient_colors([138, 43, 226], [0, 191, 255], len(mcp_text))
			colored_text = ""
			for i, char in enumerate(mcp_text):
				r, g, b = gradient_colors[i]
				colored_text += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
			mcp_indicator = f" {bcolors.BOLD}{colored_text}{bcolors.ENDC}"
		else:
			mcp_indicator = f" {bcolors.BOLD}{mcp_text}{bcolors.ENDC}"

	# Add Web indicator if server is running
	web_indicator = ""
	if web_running:
		web_indicator = f" {bcolors.OKBLUE}{web_text}{bcolors.ENDC}"
	
	prompt = (f'{bcolors.OKBLUE}{top_line}{bcolors.ENDC}'
			  f'{protocol_indicator}'
			  f'{server_indicator}'
			  f'{user_indicator}'
			  f'{ns_indicator}'
			  f'{mcp_indicator}'
			  f'{web_indicator}'
			  f'{domain_indicator}'
			  f'{cache_indicator}'
			  f'\n{bcolors.OKBLUE}{bottom_line}{bcolors.BOLD}PV{bcolors.ENDC} {bcolors.OKGREEN}{prompt_arrow}{bcolors.ENDC} ')
	
	return prompt