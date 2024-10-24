#!/usr/bin/env python3
from powerview.powerview import PowerView
from powerview.utils.helpers import *
from powerview.utils.native import *
from powerview.utils.formatter import FORMATTER
from powerview.utils.completer import Completer
from powerview.utils.colors import bcolors
from powerview.utils.connections import CONNECTION
from powerview.utils.logging import LOG
from powerview.utils.parsers import powerview_arg_parse, arg_parse

import ldap3
import json
import random
import string
import shlex
from sys import platform
if platform in ["linux","linux2"]:
    import gnureadline as readline
else:
    import readline

def main():
    args = arg_parse()

    domain, username, password, lmhash, nthash, ldap_address = parse_identity(args)

    setattr(args,'domain',domain)
    setattr(args,'username',username)
    setattr(args,'password',password)
    setattr(args,'lmhash',lmhash)
    setattr(args,'nthash', nthash)
    setattr(args, 'ldap_address', ldap_address)

    # setup debugging properties
    log_handler = LOG(ldap_address)

    if args.debug:
        logging = log_handler.setup_logger("DEBUG")
    else:
        logging = log_handler.setup_logger()
    
    try:
        conn = CONNECTION(args)
        init_ldap_address = args.ldap_address
        is_admin = False

        powerview = PowerView(conn, args)
        if not args.no_admin_check:
            is_admin = powerview.get_admin_status()
        server_dns = powerview.get_server_dns()
        init_proto = conn.get_proto()
        server_ip = conn.get_ldap_address()
        temp_powerview = None
        cur_user = conn.who_am_i() if not is_admin else "%s%s%s" % (bcolors.WARNING, conn.who_am_i(), bcolors.ENDC)

        while True:
            try:
                comp = Completer()
                readline.set_completer_delims(' \t\n;')
                readline.parse_and_bind("tab: complete")
                readline.set_completer(comp.complete)

                if args.query:
                    cmd = args.query
                else:
                    cmd = input(f'{bcolors.OKBLUE}({bcolors.ENDC}{bcolors.WARNING}{bcolors.BOLD}{init_proto}{bcolors.ENDC}{bcolors.OKBLUE})-[{bcolors.ENDC}{server_dns}{bcolors.OKBLUE}]-[{bcolors.ENDC}{cur_user}{bcolors.OKBLUE}]{bcolors.ENDC}\n{bcolors.OKBLUE}PV > {bcolors.ENDC}')

                if cmd:
                    try:
                        cmd = shlex.split(cmd)
                    except ValueError as e:
                        logging.error(str(e))
                        continue

                    pv_args = powerview_arg_parse(cmd)

                    if pv_args:
                        if pv_args.server and pv_args.server.casefold() != args.domain.casefold():
                            if args.use_kerberos:
                                ldap_address = pv_args.server
                            elif is_valid_fqdn(pv_args.server):
                                ldap_address = get_principal_dc_address(pv_args.server, args.nameserver, use_system_ns=args.use_system_ns)
                            elif is_ipaddress(pv_args.server):
                                ldap_address = pv_args.server
                            else:
                                logging.error("Invalid server address. It accepts either FQDN or IP address of the target server")
                                continue

                            if not ldap_address:
                                continue

                            conn.set_ldap_address(ldap_address)
                            conn.set_targetDomain(pv_args.server)
                            
                            try:
                                temp_powerview = PowerView(conn, args, target_domain=pv_args.server)
                            except:
                                logging.error(f'Domain {pv_args.server} not found or probably not alive')
                                continue

                        try:
                            entries = None
                            if pv_args.module.casefold() == 'get-domain' or pv_args.module.casefold() == 'get-netdomain':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domain(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domain(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobject' or pv_args.module.casefold() == 'get-adobject':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobject(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainobject(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domainobjectowner' or pv_args.module.casefold() == 'get-objectowner':
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobjectowner(identity=identity, args=pv_args)
                                else:
                                    entries = powerview.get_domainobjectowner(identity=identity, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobjectacl' or pv_args.module.casefold() == 'get-objectacl':
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobjectacl(args=pv_args)
                                else:
                                    entries = powerview.get_domainobjectacl(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainuser' or pv_args.module.casefold() == 'get-netuser':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainuser(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainuser(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-localuser':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                if temp_powerview:
                                    entries = temp_powerview.get_localuser(computer_name=computername, identity=pv_args.identity, properties=properties, args=pv_args)
                                else:
                                    entries = powerview.get_localuser(computer_name=computername, identity=pv_args.identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaincomputer' or pv_args.module.casefold() == 'get-netcomputer':
                                if pv_args.resolveip and not pv_args.identity:
                                    logging.error("-ResolveIP can only be used with -Identity")
                                    continue
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincomputer(pv_args, properties, identity, resolveip=pv_args.resolveip, resolvesids=pv_args.resolvesids)
                                else:
                                    entries = powerview.get_domaincomputer(pv_args, properties, identity, resolveip=pv_args.resolveip, resolvesids=pv_args.resolvesids)
                            elif pv_args.module.casefold() == 'get-domaingroup' or pv_args.module.casefold() == 'get-netgroup':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
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
                            elif pv_args.module.casefold() == 'get-domainforeigngroupmember' or pv_args.module.casefold() == 'find-foreigngroup':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainforeigngroupmember(pv_args)
                                else:
                                    entries = powerview.get_domainforeigngroupmember(pv_args)
                            elif pv_args.module.casefold() == 'get-domainforeignuser' or pv_args.module.casefold() == 'find-foreignuser':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainforeignuser(pv_args)
                                else:
                                    entries = powerview.get_domainforeignuser(pv_args)
                            elif pv_args.module.casefold() == 'get-domaincontroller' or pv_args.module.casefold() == 'get-netdomaincontroller':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincontroller(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaincontroller(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingpo' or pv_args.module.casefold() == 'get-netgpo':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingpo(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaingpo(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingpolocalgroup' or pv_args.module.casefold() == 'get-gpolocalgroup':
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingpolocalgroup(pv_args, identity)
                                else:
                                    entries = powerview.get_domaingpolocalgroup(pv_args, identity)
                            elif pv_args.module.casefold() == 'get-domainou' or pv_args.module.casefold() == 'get-netou':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainou(pv_args, properties, identity, resolve_gplink=pv_args.resolve_gplink)
                                else:
                                    entries = powerview.get_domainou(pv_args, properties, identity, resolve_gplink=pv_args.resolve_gplink)
                            elif pv_args.module.casefold() == 'get-domaindnszone':
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaindnszone(identity, properties, args=pv_args)
                                else:
                                    entries = powerview.get_domaindnszone(identity, properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindnsrecord':
                                zonename = pv_args.zonename.strip() if pv_args.zonename else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaindnsrecord(identity, zonename, properties, args=pv_args)
                                else:
                                    entries = powerview.get_domaindnsrecord(identity, zonename, properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainsccm' or pv_args.module.casefold() == 'get-sccm':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainsccm(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainsccm(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingmsa' or pv_args.module.casefold() == 'get-gmsa':
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingmsa(identity, pv_args)
                                else:
                                    entries = powerview.get_domaingmsa(identity, pv_args)
                            elif pv_args.module.casefold() == 'get-domainrbcd' or pv_args.module.casefold() == 'get-rbcd':
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainrbcd(identity, pv_args)
                                else:
                                    entries = powerview.get_domainrbcd(identity, pv_args)
                            elif pv_args.module.casefold() == 'get-domainca' or pv_args.module.casefold() == 'get-ca':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainca(pv_args, properties)
                                else:
                                    entries = powerview.get_domainca(pv_args, properties)
                            elif pv_args.module.casefold() == 'get-domaincatemplate' or pv_args.module.casefold() == 'get-catemplate':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincatemplate(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaincatemplate(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'remove-domaincatemplate' or pv_args.module.casefold() == 'remove-catemplate':
                                if not pv_args.identity:
                                    logging.error("-Identity flag is required")
                                    continue

                                if temp_powerview:
                                    temp_powerview.remove_domaincatemplate(identity=pv_args.identity, args=pv_args)
                                else:
                                    powerview.remove_domaincatemplate(identity=pv_args.identity, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaincatemplate' or pv_args.module.casefold() == 'add-catemplate':
                                if pv_args.displayname is None:
                                    logging.error("-DisplayName flag is required")
                                    continue

                                displayname = pv_args.displayname
                                name = pv_args.name
                                if temp_powerview:
                                    temp_powerview.add_domaincatemplate(displayname, name, args=pv_args)
                                else:
                                    powerview.add_domaincatemplate(displayname, name, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaincatemplateacl' or pv_args.module.casefold() == 'add-catemplateacl':
                                if pv_args.template is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_powerview:
                                        temp_powerview.add_domaincatemplateacl(pv_args.template, pv_args.principalidentity, args=pv_args)
                                    else:
                                        powerview.add_domaincatemplateacl(pv_args.template, pv_args.principalidentity, args=pv_args)
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity and -Rights flags are required')
                            elif pv_args.module.casefold() == 'get-domaintrust' or pv_args.module.casefold() == 'get-nettrust':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaintrust(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domaintrust(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'convertfrom-uacvalue':
                                if pv_args.value:
                                    value = pv_args.value.strip()
                                    if temp_powerview:
                                        entries = temp_powerview.convertfrom_uacvalue(value=value, output=True)
                                    else:
                                        entries = powerview.convertfrom_uacvalue(value=value, output=True)
                                else:
                                    logging.error("-Value flag is required")
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
                            elif pv_args.module.casefold() == 'get-netshare':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    if temp_powerview:
                                        entries =  temp_powerview.get_netshare(pv_args)
                                    else:
                                        entries = powerview.get_netshare(pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-regloggedon':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_regloggedon(computer_name=computername, args=pv_args)
                                    else:
                                        entries = powerview.get_regloggedon(computer_name=computername, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-netloggedon':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_netloggedon(computer_name=computername, args=pv_args)
                                    else:
                                        entries = powerview.get_netloggedon(computer_name=computername, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-netservice':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_netservice(computer_name=computername, args=pv_args)
                                    else:
                                        entries = powerview.get_netservice(computer_name=computername, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-netsession':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    if temp_powerview:
                                        entries = temp_powerview.get_netsession(pv_args)
                                    else:
                                        entries = powerview.get_netsession(pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'find-localadminaccess':
                                if temp_powerview:
                                    entries = temp_powerview.find_localadminaccess(pv_args)
                                else:
                                    entries = powerview.find_localadminaccess(pv_args)
                            elif pv_args.module.casefold() == 'invoke-kerberoast':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                if temp_powerview:
                                    entries = temp_powerview.invoke_kerberoast(pv_args, properties)
                                else:
                                    entries = powerview.invoke_kerberoast(pv_args, properties)
                            elif pv_args.module.casefold() == 'get-exchangeserver' or pv_args.module.casefold() == 'get-exchange':
                                properties = pv_args.properties.strip(" ").split(',') if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_exchangeserver(identity=identity, properties=properties, args=pv_args)
                                else:
                                    entries = powerview.get_exchangeserver(identity=identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'unlock-adaccount':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.unlock_adaccount(identity=pv_args.identity, args=pv_args)
                                    else:
                                        succeed = powerview.unlock_adaccount(identity=pv_args.identity, args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'add-domaingpo' or pv_args.module.casefold() == 'add-gpo':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.add_domaingpo(identity=pv_args.identity, description=pv_args.description, basedn=pv_args.basedn, args=pv_args)
                                    else:
                                        succeed = powerview.add_domaingpo(identity=pv_args.identity, description=pv_args.description, basedn=pv_args.basedn, args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'add-domainou' or pv_args.module.casefold() == 'add-ou':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        temp_powerview.add_domainou(identity=pv_args.identity, basedn=pv_args.basedn, args=pv_args)
                                    else:
                                        powerview.add_domainou(identity=pv_args.identity, basedn=pv_args.basedn, args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'remove-domainou' or pv_args.module.casefold() == 'remove-ou':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        temp_powerview.remove_domainou(identity=pv_args.identity, args=pv_args)
                                    else:
                                        powerview.remove_domainou(identity=pv_args.identity, args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'add-domainobjectacl' or pv_args.module.casefold() == 'add-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_powerview:
                                        temp_powerview.add_domainobjectacl(
                                            targetidentity=pv_args.targetidentity,
                                            principalidentity=pv_args.principalidentity,
                                            rights=pv_args.rights,
                                            rights_guid=pv_args.rights_guid,
                                            ace_type=pv_args.ace_type,
                                            inheritance=pv_args.inheritance
                                        )
                                    else:
                                        powerview.add_domainobjectacl(
                                            targetidentity=pv_args.targetidentity,
                                            principalidentity=pv_args.principalidentity,
                                            rights=pv_args.rights,
                                            rights_guid=pv_args.rights_guid,
                                            ace_type=pv_args.ace_type,
                                            inheritance=pv_args.inheritance
                                        )
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity flags are required')
                            elif pv_args.module.casefold() == 'remove-domainobjectacl' or pv_args.module.casefold() == 'remove-objectacl':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None and pv_args.rights is not None:
                                    if temp_powerview:
                                        temp_powerview.remove_domainobjectacl(
                                            targetidentity=pv_args.targetidentity,
                                            principalidentity=pv_args.principalidentity,
                                            rights=pv_args.rights,
                                            rights_guid=pv_args.rights_guid,
                                            ace_type=pv_args.ace_type,
                                            inheritance=pv_args.inheritance
                                        )
                                    else:
                                        powerview.remove_domainobjectacl(
                                            targetidentity=pv_args.targetidentity,
                                            principalidentity=pv_args.principalidentity,
                                            rights=pv_args.rights,
                                            rights_guid=pv_args.rights_guid,
                                            ace_type=pv_args.ace_type,
                                            inheritance=pv_args.inheritance
                                        )
                                else:
                                    logging.error('-TargetIdentity , -PrincipalIdentity flags are required')
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
                                if pv_args.identity and (pv_args.clear or pv_args.set or pv_args.append):
                                    if temp_powerview:
                                        succeed = temp_powerview.set_domainobject(pv_args.identity, args=pv_args)
                                    else:
                                        succeed = powerview.set_domainobject(pv_args.identity, args=pv_args)
                                else:
                                    logging.error('-Identity and [-Clear][-Set][-Append] flags required')
                            elif pv_args.module.casefold() == 'set-domainobjectdn' or pv_args.module.casefold() == 'set-adobjectdn':
                                if pv_args.identity and pv_args.destination_dn:
                                    if temp_powerview:
                                        succeed = temp_powerview.set_domainobjectdn(pv_args.identity, destination_dn=pv_args.destination_dn, args=pv_args)
                                    else:
                                        succeed = powerview.set_domainobjectdn(pv_args.identity, destination_dn=pv_args.destination_dn, args=pv_args)
                                else:
                                    logging.error('-Identity and -DestinationDN flags required')
                            elif pv_args.module.casefold() == 'set-domaindnsrecord':
                                if pv_args.recordname is None or pv_args.recordaddress is None:
                                    logging.error("-RecordName and -RecordAddress flags are required")
                                    continue
                                if temp_powerview:
                                    temp_powerview.set_domaindnsrecord(recordname=pv_args.recordname, recordaddress=pv_args.recordaddress, zonename=pv_args.zonename)
                                else:
                                    powerview.set_domaindnsrecord(recordname=pv_args.recordname, recordaddress=pv_args.recordaddress, zonename=pv_args.zonename)
                            elif pv_args.module.casefold() == 'set-domaincatemplate' or pv_args.module.casefold() == 'set-catemplate':
                                if pv_args.identity and (pv_args.clear or pv_args.set or pv_args.append):
                                    if temp_powerview:
                                        temp_powerview.set_domaincatemplate(pv_args.identity, pv_args)
                                    else:
                                        powerview.set_domaincatemplate(pv_args.identity, pv_args)
                                else:
                                    logging.error('-Identity and [-Clear][-Set|-Append] flags required')
                            elif pv_args.module.casefold() == 'set-domainuserpassword':
                                if pv_args.identity and pv_args.accountpassword:
                                    succeed = False
                                    if temp_powerview:
                                        succeed = temp_powerview.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, oldpassword=pv_args.oldpassword, args=pv_args)
                                    else:
                                        succeed = powerview.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, oldpassword=pv_args.oldpassword, args=pv_args)

                                    if succeed:
                                        logging.info(f'Password changed for {pv_args.identity}')
                                    else:
                                        logging.error(f'Failed password change attempt for {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -AccountPassword flags are required')
                            elif pv_args.module.casefold() == 'set-domaincomputerpassword':
                                if pv_args.identity and pv_args.accountpassword:
                                    succeed = False
                                    if temp_powerview:
                                        succeed = temp_powerview.set_domaincomputerpassword(pv_args.identity, pv_args.accountpassword, oldpassword=pv_args.oldpassword, args=pv_args)
                                    else:
                                        succeed = powerview.set_domaincomputerpassword(pv_args.identity, pv_args.accountpassword, oldpassword=pv_args.oldpassword, args=pv_args)

                                    if succeed:
                                        logging.info(f'Password changed for {pv_args.identity}')
                                    else:
                                        logging.error(f'Failed password change attempt for {pv_args.identity}')
                                else:
                                    logging.error('-Identity and -AccountPassword flags are required')
                            elif pv_args.module.casefold() == 'set-domainrbcd' or pv_args.module.casefold() == 'set-rbcd':
                                if pv_args.delegatefrom is not None and pv_args.identity is not None:
                                    if temp_powerview:
                                        temp_powerview.set_domainrbcd(pv_args.identity, pv_args.delegatefrom, args=pv_args)
                                    else:
                                        powerview.set_domainrbcd(pv_args.identity, pv_args.delegatefrom, args=pv_args)
                                else:
                                    logging.error('-Identity and -DelegateFrom flags are required')
                            elif pv_args.module.casefold() == 'set-domainobjectowner' or pv_args.module.casefold() == 'set-objectowner':
                                if pv_args.targetidentity is not None and pv_args.principalidentity is not None:
                                    if temp_powerview:
                                        temp_powerview.set_domainobjectowner(pv_args.targetidentity, pv_args.principalidentity, args=pv_args)
                                    else:
                                        powerview.set_domainobjectowner(pv_args.targetidentity, pv_args.principalidentity, args=pv_args)
                                else:
                                    logging.error('-TargetIdentity and -PrincipalIdentity flags are required')
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
                            elif pv_args.module.casefold() == 'add-domaindnsrecord':
                                if pv_args.recordname is None or pv_args.recordaddress is None:
                                    logging.error("-RecordName and -RecordAddress flags are required")
                                    continue
                                if temp_powerview:
                                    temp_powerview.add_domaindnsrecord(recordname=pv_args.recordname, recordaddress=pv_args.recordaddress, zonename=pv_args.zonename)
                                else:
                                    powerview.add_domaindnsrecord(recordname=pv_args.recordname, recordaddress=pv_args.recordaddress, zonename=pv_args.zonename)
                            elif pv_args.module.casefold() == 'add-domainuser' or pv_args.module.casefold() == 'add-aduser':
                                if temp_powerview:
                                    temp_powerview.add_domainuser(pv_args.username, pv_args.userpass, args=pv_args)
                                else:
                                    powerview.add_domainuser(pv_args.username, pv_args.userpass, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domainobject' or pv_args.module.casefold() == 'remove-adobject':
                                if pv_args.identity:
                                    identity = pv_args.identity.strip()
                                    if temp_powerview:
                                        temp_powerview.remove_domainobject(identity, args=pv_args)
                                    else:
                                        powerview.remove_domainobject(identity, args=pv_args)
                                else:
                                    logging.error("-Identity flag is required")
                            elif pv_args.module.casefold() == 'remove-domainuser' or pv_args.module.casefold() == 'remove-aduser':
                                if pv_args.identity:
                                    if temp_powerview:
                                        temp_powerview.remove_domainuser(pv_args.identity)
                                    else:
                                        powerview.remove_domainuser(pv_args.identity)
                                else:
                                    logging.error("-Identity is required")
                            elif pv_args.module.casefold() == 'remove-domaindnsrecord':
                                if not pv_args.recordname:
                                    logging.error("-RecordName flag is required")
                                    continue
                                if temp_powerview:
                                    temp_powerview.remove_domaindnsrecord(recordname=pv_args.recordname, zonename=pv_args.zonename)
                                else:
                                    powerview.remove_domaindnsrecord(recordname=pv_args.recordname, zonename=pv_args.zonename)
                            elif pv_args.module.casefold() == 'disable-domaindnsrecord':
                                if not pv_args.recordname:
                                    logging.error("-RecordName flag is required")
                                    continue
                                if temp_powerview:
                                    temp_powerview.disable_domaindnsrecord(recordname=pv_args.recordname, zonename=pv_args.zonename)
                                else:
                                    powerview.disable_domaindnsrecord(recordname=pv_args.recordname, zonename=pv_args.zonename)
                            elif pv_args.module.casefold() == 'remove-domaincomputer' or pv_args.module.casefold() == 'remove-adcomputer':
                                if pv_args.computername is not None:
                                    if temp_powerview:
                                        temp_powerview.remove_domaincomputer(pv_args.computername, args=pv_args)
                                    else:
                                        powerview.remove_domaincomputer(pv_args.computername, args=pv_args)
                                else:
                                    logging.error('-ComputerName is required')
                            elif pv_args.module.casefold() == 'add-gplink':
                                if pv_args.guid is not None and pv_args.targetidentity is not None:
                                    if temp_powerview:
                                        powerview.add_gplink(guid=pv_args.guid, targetidentity=pv_args.targetidentity, link_enabled=pv_args.link_enabled, enforced=pv_args.enforced, args=pv_args)
                                    else:
                                        powerview.add_gplink(guid=pv_args.guid, targetidentity=pv_args.targetidentity, link_enabled=pv_args.link_enabled, enforced=pv_args.enforced, args=pv_args)
                                else:
                                    logging.error("-GUID and -TargetIdentity flags are required")
                            elif pv_args.module.casefold() == 'remove-gplink':
                                if pv_args.guid is not None and pv_args.targetidentity is not None:
                                    if temp_powerview:
                                        powerview.remove_gplink(guid=pv_args.guid, targetidentity=pv_args.targetidentity, args=pv_args)
                                    else:
                                        powerview.remove_gplink(guid=pv_args.guid, targetidentity=pv_args.targetidentity, args=pv_args)
                                else:
                                    logging.error("-GUID and -TargetIdentity flags are required")
                            elif pv_args.module.casefold() == 'exit':
                                sys.exit(0)
                            elif pv_args.module.casefold() == 'clear':
                                clear_screen()

                            if entries:
                                if pv_args.outfile:
                                    if os.path.exists(pv_args.outfile):
                                        logging.error("%s exists "%(pv_args.outfile))
                                        continue

                                formatter = FORMATTER(pv_args, args.use_kerberos)
                                if hasattr(pv_args, 'where') and pv_args.where is not None:
                                    entries = formatter.alter_entries(entries,pv_args.where)

                                if hasattr(pv_args, 'sort_by') and pv_args.sort_by is not None:
                                    entries = formatter.sort_entries(entries,pv_args.sort_by)

                                if entries is None:
                                    logging.error(f'Key not available')
                                else:
                                    if hasattr(pv_args, "count") and pv_args.count:
                                        formatter.count(entries)
                                    elif hasattr(pv_args, "tableview") and pv_args.tableview:
                                        formatter.table_view(entries)
                                    elif hasattr(pv_args, "select") and pv_args.select is not None:
                                        if hasattr(pv_args, "select") and pv_args.select.isdecimal():
                                            formatter.print_index(entries)
                                        else:
                                            formatter.print_select(entries)
                                    else:
                                        if isinstance(entries, dict) and entries.get("headers"):
                                            formatter.print_table(entries["rows"], entries["headers"])
                                        else:
                                            formatter.print(entries)

                            temp_powerview = None
                            conn.set_ldap_address(init_ldap_address)
                            conn.set_targetDomain(None)
                        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
                            logging.error(str(e))
                        except ldap3.core.exceptions.LDAPAttributeError as e:
                            logging.error(str(e))
                        except ldap3.core.exceptions.LDAPSocketSendError as e:
                            logging.error(str(e))
                            conn.reset_connection()
                        except ldap3.core.exceptions.LDAPSocketReceiveError as e:
                            logging.error(str(e))
                            conn.reset_connection()
            except KeyboardInterrupt:
                print()
            except EOFError:
                print("Exiting...")
                conn.close()
                sys.exit(0)
            except ldap3.core.exceptions.LDAPSocketSendError as e:
                logging.info("LDAPSocketSendError: Connection dead")
                conn.reset_connection()
            except ldap3.core.exceptions.LDAPSessionTerminatedByServerError as e:
                logging.warning("LDAPSessionTerminatedByServerError: Server connection terminated. Trying to reconnect")
                conn.reset_connection()
                continue
            except ldap3.core.exceptions.LDAPInvalidDnError as e:
                logging.error(f"LDAPInvalidDnError: {str(e)}")
                continue
            except Exception as e:
                if args.stack_trace:
                    raise
                else:
                    logging.error(str(e))

            if args.query:
                conn.close()
                sys.exit(0)

    except ldap3.core.exceptions.LDAPSocketOpenError as e:
        print(str(e))
    except ldap3.core.exceptions.LDAPBindError as e:
        print(str(e))

if __name__ == '__main__':
    main()
