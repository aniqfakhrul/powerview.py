#!/usr/bin/env python3
from pywerview.pywerview import PywerView
from pywerview.utils.helpers import *
from pywerview.utils.native import *
from pywerview.utils.formatter import FORMATTER
from pywerview.utils.completer import Completer, COMMANDS
from pywerview.utils.colors import bcolors
from pywerview.utils.connections import CONNECTION

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
    parser = argparse.ArgumentParser(exit_on_error=False)
    subparsers = parser.add_subparsers(dest='module')

    #domain
    get_domain_parser = subparsers.add_parser('Get-Domain', aliases=['Get-NetDomain'], exit_on_error=False)
    get_domain_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domain_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domain_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domain_parser.add_argument('-where', '-Where', action='store', dest='where')

    #domainobject
    get_domainobject_parser = subparsers.add_parser('Get-DomainObject', aliases=['Get-ADObject'] ,exit_on_error=False)
    get_domainobject_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainobject_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domainobject_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainobject_parser.add_argument('-where', '-Where', action='store', dest='where')

    #domainobjectacl
    get_domainobjectacl_parser = subparsers.add_parser('Get-DomainObjectAcl', aliases=['Get-ObjectAcl'] ,exit_on_error=False)
    get_domainobjectacl_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainobjectacl_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainobjectacl_parser.add_argument('-where', '-Where', action='store', dest='where')

    #group
    get_domaingroup_parser = subparsers.add_parser('Get-DomainGroup', aliases=['Get-NetGroup'], exit_on_error=False)
    get_domaingroup_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaingroup_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaingroup_parser.add_argument('-members', '-Members', action='store', dest='members')
    get_domaingroup_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaingroup_parser.add_argument('-where', '-Where', action='store', dest='where')

    #user
    get_domainuser_parser = subparsers.add_parser('Get-DomainUser', aliases=['Get-NetUser'], exit_on_error=False)
    get_domainuser_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainuser_parser.add_argument('-properties', '-Properties', action='store',default='*', dest='properties')
    get_domainuser_parser.add_argument('-spn', '-SPN', action='store_true', default=False, dest='spn')
    get_domainuser_parser.add_argument('-admincount', '-AdminCount', action='store_true', default=False, dest='admincount')
    get_domainuser_parser.add_argument('-preauthnotrequired', '-PreAuthNotRequired', action='store_true', default=False, dest='preauthnotrequired')
    get_domainuser_parser.add_argument('-trustedtoauth', '-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domainuser_parser.add_argument('-allowdelegation', '-AllowDelegation', action='store_true', default=False, dest='allowdelegation')
    get_domainuser_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainuser_parser.add_argument('-where', '-Where', action='store', dest='where')

    #computers
    get_domaincomputer_parser = subparsers.add_parser('Get-DomainComputer', aliases=['Get-NetComputer'],exit_on_error=False)
    get_domaincomputer_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaincomputer_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaincomputer_parser.add_argument('-unconstrained', '-Unconstrained', action='store_true', default=False, dest='unconstrained')
    get_domaincomputer_parser.add_argument('-trustedtoauth', '-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domaincomputer_parser.add_argument('-laps', '-LAPS', action='store_true', default=False, dest='laps')
    get_domaincomputer_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaincomputer_parser.add_argument('-where', '-Where', action='store', dest='where')

    #domain controller
    get_domaincontroller_parser = subparsers.add_parser('Get-DomainController', aliases=['NetDomainController '], exit_on_error=False)
    get_domaincontroller_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaincontroller_parser.add_argument('-properties', '-Properties',action='store',default='*', dest='properties')
    get_domaincontroller_parser.add_argument('-select', '-Select',action='store', dest='select')
    get_domaincontroller_parser.add_argument('-where', '-Where', action='store', dest='where')

    #gpo
    get_domaingpo_parser = subparsers.add_parser('Get-DomainGPO', aliases=['Get-NetGPO'], exit_on_error=False)
    get_domaingpo_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaingpo_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaingpo_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaingpo_parser.add_argument('-where', '-Where', action='store', dest='where')

    # OU
    get_domainou_parser = subparsers.add_parser('Get-DomainOU', aliases=['Get-NetOU'], exit_on_error=False)
    get_domainou_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainou_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domainou_parser.add_argument('-select', '-Select', action='store', default='*', dest='select')
    get_domainou_parser.add_argument('-gplink', '-GPLink', action='store', const=None, dest='gplink')
    get_domainou_parser.add_argument('-where', '-Where', action='store', dest='where')

    # shares
    get_shares_parser = subparsers.add_parser('Get-Shares', aliases=['Get-NetShares'], exit_on_error=False)
    get_shares_parser.add_argument('-computer','-Computer', action='store', const=None, dest='computer')
    get_shares_parser.add_argument('-computername','-ComputerName', action='store', const=None, dest='computername')

    #trust
    get_domaintrust_parser = subparsers.add_parser('Get-DomainTrust', aliases=['Get-NetTrust'], exit_on_error=False)
    get_domaintrust_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaintrust_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaintrust_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaintrust_parser.add_argument('-where', '-Where', action='store', dest='where')

    # add operations
    add_domaingroupmember_parser = subparsers.add_parser('Add-DomainGroupMember',aliases=['Add-GroupMember'], exit_on_error=False)
    add_domaingroupmember_parser.add_argument('-identity', '-Identity', action='store', const=None, dest='identity')
    add_domaingroupmember_parser.add_argument('-members', '-Members', action='store', const=None, dest='members')

    # add domain object acl
    add_domainobjectacl_parser = subparsers.add_parser('Add-DomainObjectAcl', aliases=['Add-ObjectAcl'], exit_on_error=False)
    add_domainobjectacl_parser.add_argument('-targetidentity','-TargetIdentity', action='store', const=None, dest='targetidentity')
    add_domainobjectacl_parser.add_argument('-principalidentity','-PrincipalIdentity', action='store', const=None, dest='principalidentity')
    add_domainobjectacl_parser.add_argument('-rights','-Rights', action='store', const=None, dest='rights', choices=['all', 'dcsync', 'writemembers'], type = str.lower)

    # remove domain object acl
    remove_domainobjectacl_parser = subparsers.add_parser('Remove-DomainObjectAcl', aliases=['Remove-ObjectAcl'], exit_on_error=False)
    remove_domainobjectacl_parser.add_argument('-targetidentity','-TargetIdentity', action='store', const=None, dest='targetidentity')
    remove_domainobjectacl_parser.add_argument('-principalidentity','-PrincipalIdentity', action='store', const=None, dest='principalidentity')
    remove_domainobjectacl_parser.add_argument('-rights','-Rights', action='store', const=None, dest='rights', choices=['all', 'dcsync', 'writemembers'], type = str.lower)

    # add domain computer
    add_domaincomputer_parser = subparsers.add_parser('Add-DomainComputer', aliases=['Add-ADComputer'], exit_on_error=False)
    add_domaincomputer_parser.add_argument('-computername', '-ComputerName', action='store', const=None, dest='computername')
    add_domaincomputer_parser.add_argument('-computerpass', '-ComputerPass', action='store', const=None, dest='computerpass')

    # remove domain computer
    remove_domaincomputer_parser = subparsers.add_parser('Remove-DomainComputer',
    aliases=['Remove-ADComputer'], exit_on_error=False)
    remove_domaincomputer_parser.add_argument('-computername', '-ComputerName',action='store', const=None, dest='computername')

    # set domain object properties
    set_domainobject_parser = subparsers.add_parser('Set-DomainObject', aliases=['Set-ADObject'], exit_on_error=False)
    set_domainobject_parser.add_argument('-identity', '-Identity',const=None, dest='identity')
    set_domainobject_parser.add_argument('-set', '-Set',const=None, dest='set')
    set_domainobject_parser.add_argument('-clear', '-Clear',action='store', const=None, dest='clear')

    subparsers.add_parser('exit', exit_on_error=False)
    subparsers.add_parser('clear', exit_on_error=False)

    try:
        args = parser.parse_args(cmd)
        return args
    except argparse.ArgumentError as e:
        for i in list(COMMANDS.keys()):
            if cmd[0].casefold() == i.casefold():
                cmd[0] = i
                return parser.parse_args(cmd)

        logging.error(e)
        return None


def arg_parse():
    parser = argparse.ArgumentParser(description = "Python alternative to SharpSploit's PowerView script")
    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('--use-ldaps', dest='use_ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('--debug', dest='debug', action='store_true', help='Enable debug output')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('-H','--hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth.add_argument('--aes-key', dest="auth_aes_key", action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication \'(128 or 256 bits)\'')
    auth.add_argument("--dc-ip", action='store', metavar='IP address', help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    auth.add_argument('--no-pass', action="store_true", help="don't ask for password (useful for -k)")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if args.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        # Print the Library's installation path
        logging.debug(version.getInstallationPath())
    else:
        logging.getLogger().setLevel(logging.INFO)

    return args

def main():
    # logger properties
    logging.getLogger().setLevel(logging.INFO)

    args = arg_parse()
    domain, username, password, lmhash, nthash = parse_identity(args)
    setattr(args,'domain',domain)
    setattr(args,'username',username)
    setattr(args,'password',password)
    setattr(args,'lmhash',lmhash)
    setattr(args,'nthash', nthash)

    try:
        conn = CONNECTION(args)

        pywerview = PywerView(conn, args)

        while True:
            try:
                comp = Completer()
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)
                
                cmd = input(f'{bcolors.OKBLUE}PV> {bcolors.ENDC}')

                if cmd:
                    pv_args = powerview_arg_parse(shlex.split(cmd))
                    if pv_args is not None:
                        try:
                            if pv_args.properties:
                                properties = pv_args.properties.split(',')
                            identity = pv_args.identity
                        except:
                            pass

                        try:
                            entries = None

                            if pv_args.module.casefold() == 'get-domain' or pv_args.module.casefold() == 'get-netdomain':
                                entries = pywerview.get_domain(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobject' or pv_args.module.casefold() == 'get-adobject':
                                entries = pywerview.get_domainobject(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobjectacl' or pv_args.module.casefold() == 'get-objectacl':
                                entries = pywerview.get_domainobjectacl(pv_args)
                            elif pv_args.module.casefold() == 'get-domainuser' or pv_args.module.casefold() == 'get-netuser':
                                entries = pywerview.get_domainuser(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaincomputer' or pv_args.module.casefold() == 'get-netcomputer':
                                entries = pywerview.get_domaincomputer(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingroup' or pv_args.module.casefold() == 'get-netgroup':
                                entries = pywerview.get_domaingroup(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaincontroller' or pv_args.module.casefold() == 'get-netdomaincontroller':
                                entries = pywerview.get_domaincontroller(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingpo' or pv_args.module.casefold() == 'get-netgpo':
                                entries = pywerview.get_domaingpo(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainou' or pv_args.module.casefold() == 'get-netou':
                                entries = pywerview.get_domainou(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaintrust' or pv_args.module.casefold() == 'get-nettrust':
                                entries = pywerview.get_domaintrust(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-shares' or pv_args.module.casefold() == 'get-netshares':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    pywerview.get_shares(pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'add-domainobjectacl' or pv_args.module.casefold() == 'add-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    pywerview.add_domainobjectacl(pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'remove-domainobjectacl' or pv_args.module.casefold() == 'remove-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    pywerview.remove_domainobjectacl(pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'add-domaingroupmember' or pv_args.module.casefold() == 'get-groupmember':
                                if pv_args.identity is not None and pv_args.members is not None:
                                    if pywerview.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args):
                                        logging.info(f'User {pv_args.members} successfully added to {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -Members flags required')
                            elif pv_args.module.casefold() == 'set-domainobject' or pv_args.module.casefold() == 'set-adobject':
                                if pv_args.identity is not None and (pv_args.clear or pv_args.set):
                                    if pywerview.set_domainobject(pv_args.identity, pv_args):
                                        logging.info('Object modified successfully')
                                else:
                                    logging.error('-Identity and [-Clear][-Set] flags required')
                            elif pv_args.module.casefold() == 'add-domaincomputer' or pv_args.module.casefold() == 'add-adcomputer':
                                if pv_args.computername is not None:
                                    if pv_args.computerpass is None:
                                        pv_args.computerpass = ''.join(random.choice(list(string.ascii_letters + string.digits + "!@#$%^&*()")) for _ in range(12))
                                    pywerview.add_domaincomputer(pv_args.computername, pv_args.computerpass)
                                else:
                                    logging.error(f'-ComputerName and -ComputerPass are required')
                            elif pv_args.module.casefold() == 'remove-domaincomputer' or pv_args.module.casefold() == 'remove-adcomputer':
                                if pv_args.computername is not None:
                                    pywerview.remove_domaincomputer(pv_args.computername)
                                else:
                                    logging.error(f'-ComputerName is required')
                            elif pv_args.module.casefold() == 'exit':
                                sys.exit(1)
                            elif pv_args.module.casefold() == 'clear':
                                clear_screen()

                            if entries:
                                formatter = FORMATTER(pv_args)
                                if pv_args.where is not None:
                                    # Alter entries
                                    entries = formatter.alter_entries(entries,pv_args.where)
                                if entries is None:
                                    logging.error(f'Key not available')
                                else:
                                    if pv_args.select is not None:
                                        if pv_args.select.isdecimal():
                                            formatter.print_index(entries)
                                        else:
                                            formatter.print_select(entries)
                                    else:
                                        formatter.print(entries)

                        except ldap3.core.exceptions.LDAPAttributeError as e:
                            print(e)
            except KeyboardInterrupt:
                print()
            except Exception as e:
                logging.error(str(e))
    except ldap3.core.exceptions.LDAPBindError as e:
        print(e)
