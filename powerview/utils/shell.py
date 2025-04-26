#!/usr/bin/env python3
from powerview.utils.colors import bcolors, Gradient

def get_prompt(init_proto, server_dns, cur_user, target_domain=None, using_cache=False, mcp_running=False, web_running=False):
	"""
	Creates a visually enhanced prompt for the PowerView shell.
	
	Args:
		init_proto: The protocol being used (LDAP/LDAPS)
		server_dns: The DNS name of the server
		cur_user: The current authenticated user
		target_domain: Optional target domain for cross-domain operations
		using_cache: Indicates if the last results came from cache
		mcp_running: Indicates if MCP server is running
		web_running: Indicates if web server is running
	Returns:
		A formatted string for the shell prompt
	"""
	# Base prompt with improved formatting
	domain_indicator = ""
	if target_domain:
		domain_indicator = f" {bcolors.BOLD}{bcolors.FAIL}[→ {target_domain}]{bcolors.ENDC}"
	
	# Add cache indicator if using cached results - enhanced version
	cache_indicator = ""
	if using_cache:
		cache_indicator = f" {bcolors.WARNING}[CACHED]{bcolors.ENDC}"
	
	# Add MCP indicator if server is running
	mcp_indicator = ""
	if mcp_running:
		mcp_text = "[MCP]"
		gradient_colors = Gradient.generate_gradient_colors([138, 43, 226], [0, 191, 255], len(mcp_text))
		colored_text = ""
		for i, char in enumerate(mcp_text):
			r, g, b = gradient_colors[i]
			colored_text += f"\033[38;2;{r};{g};{b}m{char}\033[0m"
		mcp_indicator = f" {bcolors.BOLD}{colored_text}{bcolors.ENDC}"

	# Add Web indicator if server is running
	web_indicator = ""
	if web_running:
		web_indicator = f" {bcolors.OKBLUE}[WEB]{bcolors.ENDC}"
	
	prompt = (f'{bcolors.OKBLUE}╭─{bcolors.ENDC}'
			  f'{bcolors.WARNING}{bcolors.BOLD}{init_proto}{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}─[{bcolors.ENDC}{bcolors.OKCYAN}{server_dns}{bcolors.ENDC}{bcolors.OKBLUE}]{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}─[{bcolors.ENDC}{cur_user}{bcolors.OKBLUE}]{bcolors.ENDC}'
			  f'{domain_indicator}'
			  f'{cache_indicator}'
			  f'{mcp_indicator}'
			  f'{web_indicator}'
			  f'\n{bcolors.OKBLUE}╰─{bcolors.BOLD}PV{bcolors.ENDC} {bcolors.OKGREEN}❯{bcolors.ENDC} ')
	
	return prompt