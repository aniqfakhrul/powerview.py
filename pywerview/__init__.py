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
    parser.add_argument('-domain', '-Domain', action='store', dest='server')

    #domain
    get_domain_parser = subparsers.add_parser('Get-Domain', aliases=['Get-NetDomain'], exit_on_error=False)
    get_domain_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domain_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domain_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domain_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domain_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domain_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #domainobject
    get_domainobject_parser = subparsers.add_parser('Get-DomainObject', aliases=['Get-ADObject'] ,exit_on_error=False)
    get_domainobject_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainobject_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domainobject_parser.add_argument('-ldapfilter', '-LDAPFilter', action='store', dest='ldapfilter')
    get_domainobject_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domainobject_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainobject_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domainobject_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #domainobjectacl
    get_domainobjectacl_parser = subparsers.add_parser('Get-DomainObjectAcl', aliases=['Get-ObjectAcl'] ,exit_on_error=False)
    get_domainobjectacl_parser.add_argument('-identity', '-Identity', action='store', default='*', dest='identity')
    get_domainobjectacl_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domainobjectacl_parser.add_argument('-securityidentifier', '-SecurityIdentifier', action='store', dest='security_identifier')
    get_domainobjectacl_parser.add_argument('-resolveguids', '-ResolveGUIDs', action='store_true',default=False, dest='resolveguids')
    get_domainobjectacl_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainobjectacl_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domainobjectacl_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #group
    get_domaingroup_parser = subparsers.add_parser('Get-DomainGroup', aliases=['Get-NetGroup'], exit_on_error=False)
    get_domaingroup_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaingroup_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaingroup_parser.add_argument('-ldapfilter', '-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingroup_parser.add_argument('-admincount', '-AdminCount', action='store_true', default=False, dest='admincount')
    get_domaingroup_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domaingroup_parser.add_argument('-members', '-Members', action='store', dest='members')
    get_domaingroup_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaingroup_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domaingroup_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #user
    get_domainuser_parser = subparsers.add_parser('Get-DomainUser', aliases=['Get-NetUser'], exit_on_error=False)
    get_domainuser_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainuser_parser.add_argument('-properties', '-Properties', action='store',default='*', dest='properties')
    get_domainuser_parser.add_argument('-ldapfilter', '-LDAPFilter', action='store', dest='ldapfilter')
    get_domainuser_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domainuser_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainuser_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domainuser_parser.add_argument('-spn', '-SPN', action='store_true', default=False, dest='spn')
    get_domainuser_parser.add_argument('-admincount', '-AdminCount', action='store_true', default=False, dest='admincount')
    get_domainuser_parser.add_argument('-preauthnotrequired', '-PreAuthNotRequired', action='store_true', default=False, dest='preauthnotrequired')
    get_domainuser_parser.add_argument('-trustedtoauth', '-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domainuser_parser.add_argument('-allowdelegation', '-AllowDelegation', action='store_true', default=False, dest='allowdelegation')
    get_domainuser_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #computers
    get_domaincomputer_parser = subparsers.add_parser('Get-DomainComputer', aliases=['Get-NetComputer'],exit_on_error=False)
    get_domaincomputer_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaincomputer_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaincomputer_parser.add_argument('-ldapfilter', '-LDAPFilter', action='store', dest='ldapfilter')
    get_domaincomputer_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domaincomputer_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaincomputer_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domaincomputer_parser.add_argument('-unconstrained', '-Unconstrained', action='store_true', default=False, dest='unconstrained')
    get_domaincomputer_parser.add_argument('-trustedtoauth', '-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domaincomputer_parser.add_argument('-laps', '-LAPS', action='store_true', default=False, dest='laps')
    get_domaincomputer_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #domain controller
    get_domaincontroller_parser = subparsers.add_parser('Get-DomainController', aliases=['NetDomainController '], exit_on_error=False)
    get_domaincontroller_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaincontroller_parser.add_argument('-properties', '-Properties',action='store',default='*', dest='properties')
    get_domaincontroller_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domaincontroller_parser.add_argument('-select', '-Select',action='store', dest='select')
    get_domaincontroller_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domaincontroller_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #gpo
    get_domaingpo_parser = subparsers.add_parser('Get-DomainGPO', aliases=['Get-NetGPO'], exit_on_error=False)
    get_domaingpo_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaingpo_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaingpo_parser.add_argument('-ldapfilter', '-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingpo_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domaingpo_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaingpo_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domaingpo_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    # OU
    get_domainou_parser = subparsers.add_parser('Get-DomainOU', aliases=['Get-NetOU'], exit_on_error=False)
    get_domainou_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domainou_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domainou_parser.add_argument('-ldapfilter', '-LDAPFilter', action='store', dest='ldapfilter')
    get_domainou_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domainou_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainou_parser.add_argument('-gplink', '-GPLink', action='store', dest='gplink')
    get_domainou_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domainou_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    # Find DNS Zone
    get_domaindns_parser = subparsers.add_parser('Get-DomainDNSZone', exit_on_error=False)
    get_domaindns_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaindns_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domaindns_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaindns_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domaindns_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    # Find CAs
    get_domainca_parser = subparsers.add_parser('Get-DomainCA', aliases=['Get-NetCA'], exit_on_error=False)
    get_domainca_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domainca_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domainca_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domainca_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domainca_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    # shares
    get_shares_parser = subparsers.add_parser('Get-Shares', aliases=['Get-NetShares'], exit_on_error=False)
    get_shares_parser.add_argument('-computer','-Computer', action='store', const=None, dest='computer')
    get_shares_parser.add_argument('-computername','-ComputerName', action='store', const=None, dest='computername')
    get_shares_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # invoke kerberoast
    invoke_kerberoast_parser = subparsers.add_parser('Invoke-Kerberoast', exit_on_error=False)
    invoke_kerberoast_parser.add_argument('-identity','-Identity', action='store', dest='identity')
    invoke_kerberoast_parser.add_argument('-ldapfilter','-LDAPFilter', action='store', dest='ldapfilter')
    invoke_kerberoast_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    invoke_kerberoast_parser.add_argument('-select', '-Select', action='store', dest='select')
    invoke_kerberoast_parser.add_argument('-where', '-Where', action='store', dest='where')
    invoke_kerberoast_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    #trust
    get_domaintrust_parser = subparsers.add_parser('Get-DomainTrust', aliases=['Get-NetTrust'], exit_on_error=False)
    get_domaintrust_parser.add_argument('-identity', '-Identity', action='store',default='*', dest='identity')
    get_domaintrust_parser.add_argument('-properties', '-Properties', action='store', default='*', dest='properties')
    get_domaintrust_parser.add_argument('-domain', '-Domain', action='store', dest='server')
    get_domaintrust_parser.add_argument('-select', '-Select', action='store', dest='select')
    get_domaintrust_parser.add_argument('-where', '-Where', action='store', dest='where')
    get_domaintrust_parser.add_argument('-nowrap', '-NoWrap', action='store_true', default=False, dest='nowrap')

    # convert from sid
    convertfrom_sid_parser = subparsers.add_parser('ConvertFrom-SID' ,exit_on_error=False)
    convertfrom_sid_parser.add_argument('-objectsid','-ObjectSID', action='store', dest='objectsid')
    convertfrom_sid_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # add domain group members
    add_domaingroupmember_parser = subparsers.add_parser('Add-DomainGroupMember',aliases=['Add-GroupMember'], exit_on_error=False)
    add_domaingroupmember_parser.add_argument('-identity', '-Identity', action='store', const=None, dest='identity')
    add_domaingroupmember_parser.add_argument('-members', '-Members', action='store', const=None, dest='members')
    add_domaingroupmember_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # remove domain group members
    remove_domaingroupmember_parser = subparsers.add_parser('Remove-DomainGroupMember',aliases=['Remove-GroupMember'], exit_on_error=False)
    remove_domaingroupmember_parser.add_argument('-identity', '-Identity', action='store', const=None, dest='identity')
    remove_domaingroupmember_parser.add_argument('-members', '-Members', action='store', const=None, dest='members')
    remove_domaingroupmember_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # add domain object acl
    add_domainobjectacl_parser = subparsers.add_parser('Add-DomainObjectAcl', aliases=['Add-ObjectAcl'], exit_on_error=False)
    add_domainobjectacl_parser.add_argument('-targetidentity','-TargetIdentity', action='store', const=None, dest='targetidentity')
    add_domainobjectacl_parser.add_argument('-principalidentity','-PrincipalIdentity', action='store', const=None, dest='principalidentity')
    add_domainobjectacl_parser.add_argument('-rights','-Rights', action='store', const=None, dest='rights', choices=['all', 'dcsync', 'writemembers','resetpassword','rbcd','shadowcred'], type = str.lower)
    add_domainobjectacl_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # remove domain object acl
    remove_domainobjectacl_parser = subparsers.add_parser('Remove-DomainObjectAcl', aliases=['Remove-ObjectAcl'], exit_on_error=False)
    remove_domainobjectacl_parser.add_argument('-targetidentity','-TargetIdentity', action='store', const=None, dest='targetidentity')
    remove_domainobjectacl_parser.add_argument('-principalidentity','-PrincipalIdentity', action='store', const=None, dest='principalidentity')
    remove_domainobjectacl_parser.add_argument('-rights','-Rights', action='store', const=None, dest='rights', choices=['all', 'dcsync','writemembers','resetpassword'], type = str.lower)
    remove_domainobjectacl_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # add domain computer
    add_domaincomputer_parser = subparsers.add_parser('Add-DomainComputer', aliases=['Add-ADComputer'], exit_on_error=False)
    add_domaincomputer_parser.add_argument('-computername', '-ComputerName', action='store', const=None, dest='computername')
    add_domaincomputer_parser.add_argument('-computerpass', '-ComputerPass', action='store', const=None, dest='computerpass')
    add_domaincomputer_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # add domain user
    add_domainuser_parser = subparsers.add_parser('Add-DomainUser', aliases=['Add-ADUser'], exit_on_error=False)
    add_domainuser_parser.add_argument('-username', '-UserName', action='store', default=None, const=None, dest='username')
    add_domainuser_parser.add_argument('-userpass', '-UserPass', action='store', default=None, const=None, dest='userpass')
    add_domainuser_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # remove domain user
    remove_domainuser_parser = subparsers.add_parser('Remove-DomainUser', aliases=['Remove-ADUser'], exit_on_error=False)
    remove_domainuser_parser.add_argument('-identity', '-Identity', action='store', dest='identity')
    remove_domainuser_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # remove domain computer
    remove_domaincomputer_parser = subparsers.add_parser('Remove-DomainComputer', aliases=['Remove-ADComputer'], exit_on_error=False)
    remove_domaincomputer_parser.add_argument('-computername', '-ComputerName',action='store', const=None, dest='computername')
    remove_domaincomputer_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # set domain object properties
    set_domainobject_parser = subparsers.add_parser('Set-DomainObject', aliases=['Set-ADObject'], exit_on_error=False)
    set_domainobject_parser.add_argument('-identity', '-Identity', action='store', dest='identity')
    set_domainobject_parser.add_argument('-set', '-Set', dest='set')
    set_domainobject_parser.add_argument('-clear', '-Clear',action='store', dest='clear')
    set_domainobject_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    # set domain object properties
    set_domainuserpassword_parser = subparsers.add_parser('Set-DomainUserPassword', exit_on_error=False)
    set_domainuserpassword_parser.add_argument('-identity', '-Identity', action='store', dest='identity')
    set_domainuserpassword_parser.add_argument('-accountpassword', '-AccountPassword', action='store', dest='accountpassword')
    set_domainuserpassword_parser.add_argument('-domain', '-Domain', action='store', dest='server')

    subparsers.add_parser('exit', exit_on_error=False)
    subparsers.add_parser('clear', exit_on_error=False)

    try:
        args, unknown = parser.parse_known_args(cmd)
        if unknown:
            logging.error(f"Unrecognized argument: {' '.join(unknown)}")
            return None
        return args
    except argparse.ArgumentError as e:
        for i in list(COMMANDS.keys()):
            if cmd[0].casefold() == i.casefold():
                cmd[0] = i
                return parser.parse_args(cmd)

        logging.error(str(e).split("(")[0])
        return None


def arg_parse():
    parser = argparse.ArgumentParser(description = "Python alternative to SharpSploit's PowerView script")
    parser.add_argument('account', action='store', metavar='[domain/]username[:password]', help='Account used to authenticate to DC.')
    parser.add_argument('--use-ldaps', dest='use_ldaps', action='store_true', help='Use LDAPS instead of LDAP')
    parser.add_argument('--debug', dest='debug', action='store_true', help='Enable debug output')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('-H','--hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    auth.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth.add_argument('--no-pass', action="store_true", help="don't ask for password (useful for -k)")
    auth.add_argument('--aes-key', dest="auth_aes_key", action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication \'(128 or 256 bits)\'')
    auth.add_argument("--dc-ip", action='store', metavar='IP address', help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

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
    setattr(args,'init_dc_ip', args.dc_ip)

    try:
        conn = CONNECTION(args)

        pywerview = PywerView(conn, args)
        temp_pywerview = None

        while True:
            try:
                comp = Completer()
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                cmd = input(f'{bcolors.OKBLUE}PV> {bcolors.ENDC}')

                if cmd:
                    pv_args = powerview_arg_parse(shlex.split(cmd))

                    if pv_args:
                        if pv_args.server and pv_args.server != args.domain:
                            foreign_dc_address = get_principal_dc_address(pv_args.server,args.dc_ip)
                            if foreign_dc_address:
                                setattr(args,'dc_ip', foreign_dc_address)
                                conn = CONNECTION(args)
                                temp_pywerview = PywerView(conn, args)
                            else:
                                logging.error(f'Domain {pv_args.server} not found or probably not alive')
                                continue

                        try:
                            entries = None

                            if pv_args.module.casefold() == 'get-domain' or pv_args.module.casefold() == 'get-netdomain':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domain(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domain(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobject' or pv_args.module.casefold() == 'get-adobject':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domainobject(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domainobject(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobjectacl' or pv_args.module.casefold() == 'get-objectacl':
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domainobjectacl(pv_args)
                                else:
                                    entries = pywerview.get_domainobjectacl(pv_args)
                            elif pv_args.module.casefold() == 'get-domainuser' or pv_args.module.casefold() == 'get-netuser':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domainuser(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domainuser(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaincomputer' or pv_args.module.casefold() == 'get-netcomputer':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domaincomputer(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domaincomputer(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingroup' or pv_args.module.casefold() == 'get-netgroup':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domaingroup(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domaingroup(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaincontroller' or pv_args.module.casefold() == 'get-netdomaincontroller':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domaincontroller(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domaincontroller(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingpo' or pv_args.module.casefold() == 'get-netgpo':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domaingpo(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domaingpo(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainou' or pv_args.module.casefold() == 'get-netou':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domainou(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domainou(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaindnszone':
                                properties = pv_args.properties.replace(" ","").split(',')
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domaindnszone(pv_args, properties)
                                else:
                                    entries = pywerview.get_domaindnszone(pv_args, properties)
                            elif pv_args.module.casefold() == 'get-domainca' or pv_args.module.casefold() == 'get-netca':
                                properties = pv_args.properties.replace(" ","").split(',')
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domainca(pv_args, properties)
                                else:
                                    entries = pywerview.get_domainca(pv_args, properties)
                            elif pv_args.module.casefold() == 'get-domaintrust' or pv_args.module.casefold() == 'get-nettrust':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_pywerview:
                                    entries = temp_pywerview.get_domaintrust(pv_args, properties, identity)
                                else:
                                    entries = pywerview.get_domaintrust(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'convertfrom-sid':
                                if pv_args.objectsid:
                                    objectsid = pv_args.objectsid.strip()
                                    if temp_pywerview:
                                        entries = temp_pywerview.convertfrom_sid(objectsid=objectsid)
                                    else:
                                        entries = pywerview.convertfrom_sid(objectsid=objectsid)
                                else:
                                    logging.error("-ObjectSID flag is required")
                            elif pv_args.module.casefold() == 'get-shares' or pv_args.module.casefold() == 'get-netshares':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    pywerview.get_shares(pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'invoke-kerberoast':
                                if temp_pywerview:
                                    entries = temp_pywerview.invoke_kerberoast(pv_args)
                                else:
                                    entries = pywerview.invoke_kerberoast(pv_args)
                            elif pv_args.module.casefold() == 'add-domainobjectacl' or pv_args.module.casefold() == 'add-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_pywerview:
                                        temp_pywerview.add_domainobjectacl(pv_args)
                                    else:
                                        pywerview.add_domainobjectacl(pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'remove-domainobjectacl' or pv_args.module.casefold() == 'remove-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_pywerview:
                                        temp_pywerview.remove_domainobjectacl(pv_args)
                                    else:
                                        pywerview.remove_domainobjectacl(pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'add-domaingroupmember' or pv_args.module.casefold() == 'add-groupmember':
                                if pv_args.identity is not None and pv_args.members is not None:
                                    suceed = False
                                    if temp_pywerview:
                                        succeed = temp_pywerview.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args)
                                    else:
                                        succeed =  pywerview.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args)

                                    if succeed:
                                        logging.info(f'User {pv_args.members} successfully added to {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -Members flags required')
                            elif pv_args.module.casefold() == 'remove-domaingroupmember' or pv_args.module.casefold() == 'remove-groupmember':
                                if pv_args.identity is not None and pv_args.members is not None:
                                    suceed = False
                                    if temp_pywerview:
                                        succeed = temp_pywerview.remove_domaingroupmember(pv_args.identity, pv_args.members, pv_args)
                                    else:
                                        succeed =  pywerview.remove_domaingroupmember(pv_args.identity, pv_args.members, pv_args)

                                    if succeed:
                                        logging.info(f'User {pv_args.members} successfully removed from {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -Members flags required')
                            elif pv_args.module.casefold() == 'set-domainobject' or pv_args.module.casefold() == 'set-adobject':
                                if pv_args.identity and (pv_args.clear or pv_args.set):
                                    succeed = False
                                    if temp_pywerview:
                                        succeed = temp_pywerview.set_domainobject(pv_args.identity, pv_args)
                                    else:
                                        suceed = pywerview.set_domainobject(pv_args.identity, pv_args)

                                    if succeed:
                                        logging.info('Object modified successfully')
                                else:
                                    logging.error('-Identity and [-Clear][-Set] flags required')
                            elif pv_args.module.casefold() == 'set-domainuserpassword':
                                if pv_args.identity and pv_args.accountpassword:
                                    succeed = False
                                    if temp_pywerview:
                                        succeed = temp_pywerview.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, pv_args)
                                    else:
                                        succeed = pywerview.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, pv_args)

                                    if succeed:
                                        logging.info(f'Password changed for {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -AccountPassword flags are required')
                            elif pv_args.module.casefold() == 'add-domaincomputer' or pv_args.module.casefold() == 'add-adcomputer':
                                if pv_args.computername is not None:
                                    if pv_args.computerpass is None:
                                        pv_args.computerpass = ''.join(random.choice(list(string.ascii_letters + string.digits + "!@#$%^&*()")) for _ in range(12))
                                    if temp_pywerview:
                                        temp_pywerview.add_domaincomputer(pv_args.computername, pv_args.computerpass)
                                    else:
                                        pywerview.add_domaincomputer(pv_args.computername, pv_args.computerpass)
                                else:
                                    logging.error(f'-ComputerName and -ComputerPass are required')
                            elif pv_args.module.casefold() == 'add-domainuser' or pv_args.module.casefold() == 'add-aduser':
                                if temp_pywerview:
                                    temp_pywerview.add_domainuser(pv_args.username, pv_args.userpass)
                                else:
                                    pywerview.add_domainuser(pv_args.username, pv_args.userpass)
                            elif pv_args.module.casefold() == 'remove-domainuser' or pv_args.module.casefold() == 'remove-aduser':
                                if pv_args.identity:
                                    if temp_pywerview:
                                        temp_pywerview.remove_domainuser(pv_args.identity)
                                    else:
                                        pywerview.remove_domainuser(pv_args.identity)
                                else:
                                    logging.error(f'-Identity is required')
                            elif pv_args.module.casefold() == 'remove-domaincomputer' or pv_args.module.casefold() == 'remove-adcomputer':
                                if pv_args.computername is not None:
                                    if temp_pywerview:
                                        temp_pywerview.remove_domaincomputer(pv_args.computername)
                                    else:
                                        pywerview.remove_domaincomputer(pv_args.computername)
                                else:
                                    logging.error(f'-ComputerName is required')
                            elif pv_args.module.casefold() == 'exit':
                                sys.exit(0)
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

                            temp_pywerview = None
                            setattr(args,'dc_ip', args.init_dc_ip)
                        except ldap3.core.exceptions.LDAPAttributeError as e:
                            logging.error(str(e))
                        except ldap3.core.exceptions.LDAPSocketSendError as e:
                            logging.error(str(e))
                            sys.exit(0)
            except KeyboardInterrupt:
                print()
            #except Exception as e:
            #    logging.error(str(e))
    except ldap3.core.exceptions.LDAPBindError as e:
        print(e)
