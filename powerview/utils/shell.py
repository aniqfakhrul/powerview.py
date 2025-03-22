#!/usr/bin/env python3
from powerview.utils.colors import bcolors, Gradient

def get_prompt(init_proto, server_dns, cur_user, target_domain=None):
	"""
	Creates a visually enhanced prompt for the PowerView shell.
	
	Args:
		init_proto: The protocol being used (LDAP/LDAPS)
		server_dns: The DNS name of the server
		cur_user: The current authenticated user
		target_domain: Optional target domain for cross-domain operations
	
	Returns:
		A formatted string for the shell prompt
	"""
	# Base prompt with improved formatting
	domain_indicator = ""
	if target_domain:
		domain_indicator = f" {bcolors.BOLD}{bcolors.FAIL}[→ {target_domain}]{bcolors.ENDC}"
	
	prompt = (f'{bcolors.OKBLUE}╭─{bcolors.ENDC}'
			  f'{bcolors.WARNING}{bcolors.BOLD}{init_proto}{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}─[{bcolors.ENDC}{bcolors.OKCYAN}{server_dns}{bcolors.ENDC}{bcolors.OKBLUE}]{bcolors.ENDC}'
			  f'{bcolors.OKBLUE}─[{bcolors.ENDC}{cur_user}{bcolors.OKBLUE}]{bcolors.ENDC}'
			  f'{domain_indicator}'
			  f'\n{bcolors.OKBLUE}╰─{bcolors.BOLD}PV{bcolors.ENDC} {bcolors.OKGREEN}❯{bcolors.ENDC} ')
	
	return prompt