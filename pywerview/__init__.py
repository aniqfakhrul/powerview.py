#!/usr/bin/env python3
from pywerview.pywerview import PywerView
from pywerview.utils.helpers import *
from pywerview.utils.native import *
from pywerview.utils.completer import Completer
from pywerview.utils.colors import bcolors

from impacket import version
from impacket.examples import logger
from impacket.examples.utils import parse_credentials

import sys
import ldap3
import argparse
import readline
import logging
import json
import random
import string
import shlex

def powerview_arg_parse(cmd):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='module')
    #parser.add_argument('module', action='store')
    #parser.add_argument('identity', nargs='?', action='store',default='*')

    #domain
    get_domain_parser = subparsers.add_parser('Get-Domain')
    get_domain_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domain_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domain_parser.add_argument('-select', '-Select', action='store', dest='select')

    #domainobject
    get_domainobject_parser = subparsers.add_parser('Get-DomainObject')
    get_domainobject_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainobject_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domainobject_parser.add_argument('-select', '-Select', action='store', dest='select')

    #group
    get_domaingroup_parser = subparsers.add_parser('Get-DomainGroup')
    get_domaingroup_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaingroup_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaingroup_parser.add_argument('-members', '-Members', action='store', dest='members')
    get_domaingroup_parser.add_argument('-select', '-Select', action='store', dest='select')

    #user
    get_domainuser_parser = subparsers.add_parser('Get-DomainUser')
    get_domainuser_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainuser_parser.add_argument('-properties', '-Properties', action='store',default='*', dest='properties')
    get_domainuser_parser.add_argument('-spn', '-SPN', action='store_true', default=False, dest='spn')
    get_domainuser_parser.add_argument('-admincount', '-AdminCount', action='store_true', default=False, dest='admincount')
    get_domainuser_parser.add_argument('-preauthnotrequired', '-PreAuthNotRequired', action='store_true', default=False, dest='preauthnotrequired')
    get_domainuser_parser.add_argument('-trustedtoauth', '-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domainuser_parser.add_argument('-allowdelegation', '-AllowDelegation', action='store_true', default=False, dest='allowdelegation')
    get_domainuser_parser.add_argument('-select', '-Select', action='store', dest='select')

    #computers
    get_domaincomputer_parser = subparsers.add_parser('Get-DomainComputer')
    get_domaincomputer_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaincomputer_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaincomputer_parser.add_argument('-unconstrained', '-Unconstrained', action='store_true', default=False, dest='unconstrained')
    get_domaincomputer_parser.add_argument('-trustedtoauth', '-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domaincomputer_parser.add_argument('-select', '-Select', action='store', dest='select')

    #domain controller
    get_domaincontroller_parser = subparsers.add_parser('Get-DomainController')
    get_domaincontroller_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaincontroller_parser.add_argument('-properties', '-Properties',action='store',default='*', dest='properties')
    get_domaincontroller_parser.add_argument('-select', '-Select',action='store', dest='select')

    #gpo
    get_domaingpo_parser = subparsers.add_parser('Get-DomainGPO')
    get_domaingpo_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaingpo_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaingpo_parser.add_argument('-select', '-Select', action='store', dest='select')

    #trust
    get_domaintrust_parser = subparsers.add_parser('Get-DomainTrust')
    get_domaintrust_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaintrust_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaintrust_parser.add_argument('-select', '-Select', action='store', dest='select')

    # add operations
    add_domaingroupmember_parser = subparsers.add_parser('Add-DomainGroupMember')
    add_domaingroupmember_parser.add_argument('-identity', '-Identity', action='store', const=None, dest='identity')
    add_domaingroupmember_parser.add_argument('-members', '-Members', action='store', const=None, dest='members')

    # add domain computer
    add_domaincomputer_parser = subparsers.add_parser('Add-DomainComputer')
    add_domaincomputer_parser.add_argument('-computername', '-ComputerName', action='store', const=None, dest='computername')
    add_domaincomputer_parser.add_argument('-computerpass', '-ComputerPass', action='store', const=None, dest='computerpass')

    # remove domain computer
    remove_domaincomputer_parser = subparsers.add_parser('Remove-DomainComputer')
    remove_domaincomputer_parser.add_argument('-computername', '-ComputerName',action='store', const=None, dest='computername')

    # set domain object properties
    set_domainobject_parser = subparsers.add_parser('Set-DomainObject')
    set_domainobject_parser.add_argument('-identity', '-Identity',const=None, dest='identity')
    set_domainobject_parser.add_argument('-set', '-Set',const=None, dest='set')
    set_domainobject_parser.add_argument('-clear', '-Clear',action='store', const=None, dest='clear')

    subparsers.add_parser('exit')
    subparsers.add_parser('clear')

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

def main():
    # logger properties
    logging.getLogger().setLevel(logging.INFO)

    args = arg_parse()
    domain, username, password, lmhash, nthash = parse_identity(args)

    ldap_server, ldap_session = init_ldap_session(args, domain, username, password, lmhash, nthash)

    cnf = ldapdomaindump.domainDumpConfig()
    cnf.basepath = None
    domain_dumper = ldapdomaindump.domainDumper(ldap_server, ldap_session, cnf)
    root_dn = domain_dumper.getRoot()
    fqdn = ".".join(root_dn.replace("DC=","").split(","))

    pywerview = PywerView(ldap_session, root_dn, domain_dumper)

    while True:
        comp = Completer()
        # we want to treat '/' as part of a word, so override the delimiters
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(comp.complete)
        cmd = input(f'{bcolors.OKBLUE}PV> {bcolors.ENDC}')

        if cmd:
            # cmd = f'{cmd.lower()}'
            pv_args = powerview_arg_parse(shlex.split(cmd))

            try:
                if pv_args.properties:
                    properties = pv_args.properties.split(',')
                identity = pv_args.identity
            except:
                pass

            try:
                entries = None

                if pv_args.module.casefold() == 'get-domain':
                    entries = pywerview.get_domain(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domainobject':
                    entries = pywerview.get_domainobject(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domainuser':
                    entries = pywerview.get_domainuser(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domaincomputer':
                    entries = pywerview.get_domaincomputer(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domaingroup':
                    entries = pywerview.get_domaingroup(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domaincontroller':
                    entries = pywerview.get_domaincontroller(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domaingpo':
                    entries = pywerview.get_domaingpo(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'get-domaintrust':
                    entries = pywerview.get_domaintrust(pv_args, properties, identity)
                elif pv_args.module.casefold() == 'add-domaingroupmember':
                    if pv_args.identity is not None and pv_args.members is not None:
                        if pywerview.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args):
                            logging.info(f'User {pv_args.members} successfully added to {pv_args.identity}')
                    else:
                        logging.error('-Identity and -Members flags required')
                elif pv_args.module.casefold() == 'set-domainobject':
                    if pv_args.identity is not None and (pv_args.clear or pv_args.set):
                        if pywerview.set_domainobject(pv_args.identity, pv_args):
                            logging.info('Object modified successfully')
                    else:
                        logging.error('-Identity and [-Clear][-Set] flags required')
                elif pv_args.module.casefold() == 'add-domaincomputer':
                    if pv_args.computername is not None:
                        if pv_args.computerpass is None:
                            pv_args.computerpass = ''.join(random.choice(list(string.ascii_letters + string.digits + "!@#$%^&*()")) for _ in range(12))
                        pywerview.add_domaincomputer(username, password, domain, pv_args.computername, pv_args.computerpass, args)
                    else:
                        logging.error(f'-ComputerName and -ComputerPass are required')
                elif pv_args.module.casefold() == 'remove-domaincomputer':
                    if pv_args.computername is not None:
                        pywerview.remove_domaincomputer(username,password,domain,pv_args.computername,args)
                    else:
                        logging.error(f'-ComputerName is required')
                elif pv_args.module.casefold() == 'exit':
                    sys.exit(1)
                elif pv_args.module.casefold() == 'clear':
                    clear_screen()

                if entries:
                    formatter(pv_args, entries)
            except ldap3.core.exceptions.LDAPBindError as e:
                print(e)
            except ldap3.core.exceptions.LDAPAttributeError as e:
                print(e)
