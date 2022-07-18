#!/usr/bin/env python3
from powerview.powerview import PowerView
from powerview.utils.helpers import *
from powerview.utils.native import *
from powerview.utils.formatter import FORMATTER
from powerview.utils.completer import Completer
from powerview.utils.colors import bcolors
from powerview.utils.connections import CONNECTION
from powerview.utils.parsers import powerview_arg_parse, arg_parse

from impacket.examples import logger
from impacket.examples.utils import parse_credentials

import ldap3
import logging
import json
import random
import string
import shlex
from sys import platform
if platform == "linux" or platform == "linux2":
    import gnureadline as readline
else:
    import readline

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

        powerview = PowerView(conn, args)
        temp_powerview = None

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
                            if args.use_kerberos:
                                logging.error("Kerberos authentication doesn't support cross-domain targetting (Coming Soon?)")
                                continue
                            logging.warning(f"Cross-domain targetting might be unstable or slow depending on the network stability")
                            foreign_dc_address = get_principal_dc_address(pv_args.server,args.dc_ip)
                            if foreign_dc_address is not None:
                                setattr(args,'dc_ip', foreign_dc_address)
                                conn = CONNECTION(args)
                                temp_powerview = PowerView(conn, args)
                            else:
                                logging.error(f'Domain {pv_args.server} not found or probably not alive')
                                continue

                        try:
                            entries = None

                            if pv_args.module.casefold() == 'get-domain' or pv_args.module.casefold() == 'get-netdomain':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domain(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domain(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobject' or pv_args.module.casefold() == 'get-adobject':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobject(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainobject(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobjectacl' or pv_args.module.casefold() == 'get-objectacl':
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobjectacl(pv_args)
                                else:
                                    entries = powerview.get_domainobjectacl(pv_args)
                            elif pv_args.module.casefold() == 'get-domainuser' or pv_args.module.casefold() == 'get-netuser':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domainuser(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainuser(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaincomputer' or pv_args.module.casefold() == 'get-netcomputer':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincomputer(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaincomputer(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingroup' or pv_args.module.casefold() == 'get-netgroup':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingroup(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaingroup(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingroupmember' or pv_args.module.casefold() == 'get-netgroupmember':
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingroupmember(pv_args, identity)
                                else:
                                    entries = powerview.get_domaingroupmember(pv_args, identity)
                            elif pv_args.module.casefold() == 'get-domaincontroller' or pv_args.module.casefold() == 'get-netdomaincontroller':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincontroller(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaincontroller(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingpo' or pv_args.module.casefold() == 'get-netgpo':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingpo(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaingpo(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingpolocalgroup' or pv_args.module.casefold() == 'get-gpolocalgroup':
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingpolocalgroup(pv_args, identity)
                                else:
                                    entries = powerview.get_domaingpolocalgroup(pv_args, identity)
                            elif pv_args.module.casefold() == 'get-domainou' or pv_args.module.casefold() == 'get-netou':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domainou(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainou(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaindnszone':
                                properties = pv_args.properties.replace(" ","").split(',')
                                if temp_powerview:
                                    entries = temp_powerview.get_domaindnszone(pv_args, properties)
                                else:
                                    entries = powerview.get_domaindnszone(pv_args, properties)
                            elif pv_args.module.casefold() == 'get-domainca' or pv_args.module.casefold() == 'get-netca':
                                properties = pv_args.properties.replace(" ","").split(',')
                                if temp_powerview:
                                    entries = temp_powerview.get_domainca(pv_args, properties)
                                else:
                                    entries = powerview.get_domainca(pv_args, properties)
                            elif pv_args.module.casefold() == 'get-domaintrust' or pv_args.module.casefold() == 'get-nettrust':
                                properties = pv_args.properties.replace(" ","").split(',')
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaintrust(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaintrust(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'convertfrom-sid':
                                if pv_args.objectsid:
                                    objectsid = pv_args.objectsid.strip()
                                    if temp_powerview:
                                        temp_powerview.convertfrom_sid(objectsid=objectsid, output=True)
                                    else:
                                        powerview.convertfrom_sid(objectsid=objectsid, output=True)
                                else:
                                    logging.error("-ObjectSID flag is required")
                            elif pv_args.module.casefold() == 'get-namedpipes':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    if temp_powerview:
                                        entries = temp_powerview.get_namedpipes(pv_args)
                                    else:
                                        entries = powerview.get_namedpipes(pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-shares' or pv_args.module.casefold() == 'get-netshares':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    if temp_powerview:
                                        temp_powerview.get_shares(pv_args)
                                    else:
                                        powerview.get_shares(pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'find-localadminaccess':
                                if temp_powerview:
                                    entries = temp_powerview.find_localadminaccess(pv_args)
                                else:
                                    entries = powerview.find_localadminaccess(pv_args)
                            elif pv_args.module.casefold() == 'invoke-kerberoast':
                                if temp_powerview:
                                    entries = temp_powerview.invoke_kerberoast(pv_args)
                                else:
                                    entries = powerview.invoke_kerberoast(pv_args)
                            elif pv_args.module.casefold() == 'add-domainobjectacl' or pv_args.module.casefold() == 'add-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_powerview:
                                        temp_powerview.add_domainobjectacl(pv_args)
                                    else:
                                        powerview.add_domainobjectacl(pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'remove-domainobjectacl' or pv_args.module.casefold() == 'remove-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_powerview:
                                        temp_powerview.remove_domainobjectacl(pv_args)
                                    else:
                                        powerview.remove_domainobjectacl(pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'add-domaingroupmember' or pv_args.module.casefold() == 'add-groupmember':
                                if pv_args.identity is not None and pv_args.members is not None:
                                    suceed = False
                                    if temp_powerview:
                                        succeed = temp_powerview.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args)
                                    else:
                                        succeed =  powerview.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args)

                                    if succeed:
                                        logging.info(f'User {pv_args.members} successfully added to {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -Members flags required')
                            elif pv_args.module.casefold() == 'remove-domaingroupmember' or pv_args.module.casefold() == 'remove-groupmember':
                                if pv_args.identity is not None and pv_args.members is not None:
                                    suceed = False
                                    if temp_powerview:
                                        succeed = temp_powerview.remove_domaingroupmember(pv_args.identity, pv_args.members, pv_args)
                                    else:
                                        succeed =  powerview.remove_domaingroupmember(pv_args.identity, pv_args.members, pv_args)

                                    if succeed:
                                        logging.info(f'User {pv_args.members} successfully removed from {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -Members flags required')
                            elif pv_args.module.casefold() == 'set-domainobject' or pv_args.module.casefold() == 'set-adobject':
                                if pv_args.identity and (pv_args.clear or pv_args.set):
                                    succeed = False
                                    if temp_powerview:
                                        succeed = temp_powerview.set_domainobject(pv_args.identity, pv_args)
                                    else:
                                        suceed = powerview.set_domainobject(pv_args.identity, pv_args)

                                    if succeed:
                                        logging.info('Object modified successfully')
                                else:
                                    logging.error('-Identity and [-Clear][-Set] flags required')
                            elif pv_args.module.casefold() == 'set-domainuserpassword':
                                if pv_args.identity and pv_args.accountpassword:
                                    succeed = False
                                    if temp_powerview:
                                        succeed = temp_powerview.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, pv_args)
                                    else:
                                        succeed = powerview.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, pv_args)

                                    if succeed:
                                        logging.info(f'Password changed for {pv_args.identity}')
                                    else:
                                        logging.error(f'Failed password change attempt for {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -AccountPassword flags are required')
                            elif pv_args.module.casefold() == 'add-domaincomputer' or pv_args.module.casefold() == 'add-adcomputer':
                                if pv_args.computername is not None:
                                    if pv_args.computerpass is None:
                                        pv_args.computerpass = ''.join(random.choice(list(string.ascii_letters + string.digits + "!@#$%^&*()")) for _ in range(12))
                                    if temp_powerview:
                                        temp_powerview.add_domaincomputer(pv_args.computername, pv_args.computerpass)
                                    else:
                                        powerview.add_domaincomputer(pv_args.computername, pv_args.computerpass)
                                else:
                                    logging.error(f'-ComputerName and -ComputerPass are required')
                            elif pv_args.module.casefold() == 'add-domainuser' or pv_args.module.casefold() == 'add-aduser':
                                if temp_powerview:
                                    temp_powerview.add_domainuser(pv_args.username, pv_args.userpass)
                                else:
                                    powerview.add_domainuser(pv_args.username, pv_args.userpass)
                            elif pv_args.module.casefold() == 'remove-domainuser' or pv_args.module.casefold() == 'remove-aduser':
                                if pv_args.identity:
                                    if temp_powerview:
                                        temp_powerview.remove_domainuser(pv_args.identity)
                                    else:
                                        powerview.remove_domainuser(pv_args.identity)
                                else:
                                    logging.error(f'-Identity is required')
                            elif pv_args.module.casefold() == 'remove-domaincomputer' or pv_args.module.casefold() == 'remove-adcomputer':
                                if pv_args.computername is not None:
                                    if temp_powerview:
                                        temp_powerview.remove_domaincomputer(pv_args.computername)
                                    else:
                                        powerview.remove_domaincomputer(pv_args.computername)
                                else:
                                    logging.error(f'-ComputerName is required')
                            elif pv_args.module.casefold() == 'exit':
                                sys.exit(0)
                            elif pv_args.module.casefold() == 'clear':
                                clear_screen()

                            if entries:
                                formatter = FORMATTER(pv_args, args.use_kerberos)
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

                            temp_powerview = None
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
