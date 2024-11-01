#!/usr/bin/env python3
from powerview.utils.colors import bcolors

def get_prompt(init_proto, server_dns, cur_user):
	return (f'{bcolors.OKBLUE}({bcolors.ENDC}{bcolors.WARNING}{bcolors.BOLD}{init_proto}{bcolors.ENDC}'
			f'{bcolors.OKBLUE})-[{bcolors.ENDC}{server_dns}{bcolors.OKBLUE}]-[{bcolors.ENDC}{cur_user}'
			f'{bcolors.OKBLUE}]{bcolors.ENDC}\n{bcolors.OKBLUE}PV > {bcolors.ENDC}')