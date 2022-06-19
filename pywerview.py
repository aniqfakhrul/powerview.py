#!/usr/bin/env python3
from utils.pywerview import PywerView
from utils.helpers import *
from utils.completer import Completer
from utils.colors import bcolors

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials

import sys
import ldap3
import argparse
import readline
import json

def powerview_arg_parse(cmd):
    parser = argparse.ArgumentParser()
    parser.add_argument('module', action='store')
    parser.add_argument('-identity', action='store',default='*')
    #parser.add_argument('identity', nargs='?', action='store',default='*')
    parser.add_argument('-properties', action='store', default='*')

    #group
    parser.add_argument('-member', '-members', action='store')

    #user
    parser.add_argument('-spn', action='store_true', default=False)

    #computers
    parser.add_argument('-unconstrained', action='store_true', default=False)
    parser.add_argument('-trustedtoauth', action='store_true', default=False)
    parser.add_argument('-preauthnotrequired', action='store_true', default=False)
    
    args = parser.parse_args(cmd)
    return args

def arg_parse():
    parser = argparse.ArgumentParser(description = "Python alternative to SharpSploit's PowerView script")
    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('--use-ldaps', dest='use_ldaps', action='store_true', help='Use LDAPS instead of LDAP')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('-H','--hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth.add_argument('--aes-key', dest="auth_aes_key", action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication \'(128 or 256 bits)\'')
    auth.add_argument("--dc-ip", action='store', metavar='IP address', help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    return args

def main(args):
    domain, username, password, lmhash, nthash = parse_identity(args)
    
    ldap_server, ldap_session = init_ldap_session(args, domain, username, password, lmhash, nthash)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    root_dn = domain_dumper.getRoot()
    fqdn = ".".join(root_dn.replace("DC=","").split(","))

    pywerview = PywerView(ldap_session, root_dn)

    while True:
        comp = Completer()
        # we want to treat '/' as part of a word, so override the delimiters
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)
        cmd = input(f'{bcolors.OKBLUE}PywerView> {bcolors.ENDC}')
        cmd = cmd.lower()
        
        pv_args = powerview_arg_parse(cmd.split())
        properties = pv_args.properties.split(',')

        try:
            if pv_args.module.lower() == 'get-domain':
                entries = pywerview.get_domain(pv_args, properties)
            elif pv_args.module.lower() == 'get-domainuser':
                entries = pywerview.get_domainuser(pv_args, properties)
            elif pv_args.module.lower() == 'get-domaincomputer':
                entries = pywerview.get_domaincomputer(pv_args, properties)
            elif pv_args.module.lower() == 'get-domaingroup':
                entries = pywerview.get_domaingroup(pv_args, properties)
            elif pv_args.module.lower() == 'get-domaincontroller':
                entries = pywerview.get_domaincontroller(pv_args, properties)
            elif pv_args.module.lower() == 'get-domaingpo':
                entries = pywerview.get_domaingpo(pv_args, properties)
            elif pv_args.module.lower() == 'get-domaintrust':
                entries = pywerview.get_domaintrust(pv_args, properties)
            elif pv_args.module.lower() == 'add-domaingroupmember':
                # in development
                print(None)
                #pywerview.add_domaingroupmember(pv_args, identity)
            elif cmd == 'exit':
                sys.exit(1)

            for entry in entries:
                print(f'{entry.entry_to_ldif()}')

        except ldap3.core.exceptions.LDAPBindError as e:
            print(e)
        except ldap3.core.exceptions.LDAPAttributeError as e:
            print(e)

if __name__ == "__main__":
    args = arg_parse()
    main(args)
