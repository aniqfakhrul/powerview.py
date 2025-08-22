#!/usr/bin/env python3
import sys
try:
    sys.modules.pop('readline', None)
    import gnureadline as readline
    sys.modules['readline'] = readline
except ImportError:
    import readline
    sys.modules['readline'] = readline
from powerview.powerview import PowerView
from powerview.utils.helpers import *
from powerview.utils.native import *
from powerview.utils.formatter import FORMATTER
from powerview.utils.completer import Completer
from powerview.utils.connections import CONNECTION
from powerview.utils.logging import LOG
from powerview.utils.parsers import powerview_arg_parse, arg_parse
from powerview.utils.shell import get_prompt
from powerview.utils.colors import bcolors, Gradient
from powerview.utils.history import get_shell_history

import ldap3
import random
import string
import shlex
import os

def main():
    """
    Main entry point for PowerView tool.
    
    Handles command-line argument parsing, LDAP connection setup,
    and interactive command processing.
    """
    args = arg_parse()

    flat_domain = args.domain.split('.')[0] if '.' in args.domain else args.domain
    flat_domain = sanitize_component(flat_domain.lower())
    username = sanitize_component(args.username.lower())
    ldap_address = sanitize_component(args.ldap_address.lower())

    components = [flat_domain, username, ldap_address]
    folder_name = '-'.join(filter(None, components)) or "default-log"

    log_handler = LOG(folder_name)

    if args.debug:
        logging = log_handler.setup_logger("DEBUG")
    else:
        logging = log_handler.setup_logger()
    
    try:
        conn = CONNECTION(args)
        init_ldap_address = args.ldap_address
        powerview = PowerView(conn, args)
        if powerview.ldap_session and powerview.ldap_session.bound:
            powerview.add_domain_connection(powerview.conn.get_domain())

        comp = Completer()
        comp.setup_completer()

        current_target_domain = None

        using_cache = False

        while True:
            try:
                temp_powerview = None
                if args.query:
                    cmd = args.query
                else:
                    cmd = input(get_prompt(powerview, current_target_domain, using_cache, args))

                if cmd:
                    try:
                        cmd = shlex.split(cmd)
                    except ValueError as e:
                        if args.stack_trace:
                            raise e
                        else:
                            logging.error(str(e))
                            continue

                    pv_args = powerview_arg_parse(cmd)

                    if pv_args:
                        if pv_args.server and pv_args.server.lower() != powerview.domain.lower():
                            try:
                                temp_powerview = powerview.get_domain_powerview(pv_args.server)
                                current_target_domain = pv_args.server
                            except ldap3.core.exceptions.LDAPSocketOpenError as e:
                                logging.error(f'Connection to domain {pv_args.server} failed: {str(e)}')
                                current_target_domain = None
                                continue
                            except ldap3.core.exceptions.LDAPBindError as e:
                                logging.error(f'Authentication to domain {pv_args.server} failed: {str(e)}')
                                current_target_domain = None
                                continue
                            except Exception as e:
                                logging.error(f'Domain {pv_args.server} operation failed: {str(e)}')
                                current_target_domain = None
                                if args.stack_trace:
                                    import traceback
                                    logging.debug(traceback.format_exc())
                                continue
                        else:
                            # No server specified or same as current domain
                            current_target_domain = None
                            temp_powerview = None
                            
                        try:
                            entries = None
                            if pv_args.module.casefold() == 'get-domain':
                                if temp_powerview:
                                    entries = temp_powerview.get_domain(args=pv_args)
                                else:
                                    entries = powerview.get_domain(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobject' or pv_args.module.casefold() == 'get-adobject':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobject(args=pv_args)
                                else:
                                    entries = powerview.get_domainobject(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobjectowner' or pv_args.module.casefold() == 'get-objectowner':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobjectowner(args=pv_args)
                                else:
                                    entries = powerview.get_domainobjectowner(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobjectacl' or pv_args.module.casefold() == 'get-objectacl':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainobjectacl(
                                        args=pv_args
                                    )
                                else:
                                    entries = powerview.get_domainobjectacl(
                                        args=pv_args
                                    )
                            elif pv_args.module.casefold() == 'get-domainuser':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainuser(args=pv_args)
                                else:
                                    entries = powerview.get_domainuser(args=pv_args)
                            elif pv_args.module.casefold() == 'get-localuser':
                                properties = pv_args.properties if pv_args.properties else None
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                if temp_powerview:
                                    entries = temp_powerview.get_localuser(computer_name=computername, identity=pv_args.identity, properties=properties, args=pv_args)
                                else:
                                    entries = powerview.get_localuser(computer_name=computername, identity=pv_args.identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaincomputer':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincomputer(args=pv_args)
                                else:
                                    entries = powerview.get_domaincomputer(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingroup':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingroup(pv_args, properties, identity, no_cache=pv_args.no_cache)
                                else:
                                    entries = powerview.get_domaingroup(pv_args, properties, identity, no_cache=pv_args.no_cache)
                            elif pv_args.module.casefold() == 'get-domaingroupmember':
                                identity = pv_args.identity.strip()
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingroupmember(identity=identity, args=pv_args)
                                else:
                                    entries = powerview.get_domaingroupmember(identity=identity, args=pv_args)
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
                            elif pv_args.module.casefold() == 'get-domaincontroller':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaincontroller(args=pv_args)
                                else:
                                    entries = powerview.get_domaincontroller(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingpo':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingpo(args=pv_args)
                                else:
                                    entries = powerview.get_domaingpo(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingpolocalgroup' or pv_args.module.casefold() == 'get-gpolocalgroup':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingpolocalgroup(args=pv_args)
                                else:
                                    entries = powerview.get_domaingpolocalgroup(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingposettings' or pv_args.module.casefold() == 'get-gposettings':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingposettings(args=pv_args)
                                else:
                                    entries = powerview.get_domaingposettings(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainou':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainou(args=pv_args)
                                else:
                                    entries = powerview.get_domainou(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindnszone':
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                properties = pv_args.properties if pv_args.properties else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaindnszone(identity, properties, args=pv_args)
                                else:
                                    entries = powerview.get_domaindnszone(identity, properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindnsrecord':
                                zonename = pv_args.zonename.strip() if pv_args.zonename else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                properties = pv_args.properties if pv_args.properties else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaindnsrecord(identity, zonename, properties, args=pv_args)
                                else:
                                    entries = powerview.get_domaindnsrecord(identity, zonename, properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainsccm' or pv_args.module.casefold() == 'get-sccm':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domainsccm(pv_args, properties, identity)
                                else:
                                    entries = powerview.get_domainsccm(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingmsa' or pv_args.module.casefold() == 'get-gmsa':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaingmsa(args=pv_args)
                                else:
                                    entries = powerview.get_domaingmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindmsa' or pv_args.module.casefold() == 'get-dmsa':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaindmsa(args=pv_args)
                                else:
                                    entries = powerview.get_domaindmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainrbcd' or pv_args.module.casefold() == 'get-rbcd':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainrbcd(args=pv_args)
                                else:
                                    entries = powerview.get_domainrbcd(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainwds' or pv_args.module.casefold() == 'get-wds':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainwds(args=pv_args)
                                else:
                                    entries = powerview.get_domainwds(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainca' or pv_args.module.casefold() == 'get-ca':
                                if temp_powerview:
                                    entries = temp_powerview.get_domainca(args=pv_args)
                                else:
                                    entries = powerview.get_domainca(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaincatemplate' or pv_args.module.casefold() == 'get-catemplate':
                                properties = pv_args.properties if pv_args.properties else None
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
                            elif pv_args.module.casefold() == 'get-domaintrust':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_domaintrust(args=pv_args)
                                else:
                                    entries = powerview.get_domaintrust(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaintrustkey' or pv_args.module.casefold() == 'get-trustkey':
                                if temp_powerview:
                                    entries = temp_powerview.get_domaintrustkey(args=pv_args)
                                else:
                                    entries = powerview.get_domaintrustkey(args=pv_args)
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
                                        temp_powerview.convertfrom_sid(objectsid=objectsid, output=True, no_cache=pv_args.no_cache)
                                    else:
                                        powerview.convertfrom_sid(objectsid=objectsid, output=True, no_cache=pv_args.no_cache)
                                else:
                                    logging.error("-ObjectSID flag is required")
                            elif pv_args.module.casefold() == 'clear-cache':
                                if temp_powerview:
                                    temp_powerview.clear_cache()
                                else:
                                    powerview.clear_cache()
                                using_cache = False
                            elif pv_args.module.casefold() == 'login-as':
                                if temp_powerview:
                                    powerview.login_as(args=pv_args)
                                else:
                                    powerview.login_as(args=pv_args)
                            elif pv_args.module.casefold() == 'get-namedpipes':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    if temp_powerview:
                                        entries = temp_powerview.get_namedpipes(
                                            pv_args, 
                                            timeout=pv_args.timeout, 
                                            max_threads=pv_args.max_threads
                                        )
                                    else:
                                        entries = powerview.get_namedpipes(
                                            pv_args, 
                                            timeout=pv_args.timeout, 
                                            max_threads=pv_args.max_threads
                                        )
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
                            elif pv_args.module.casefold() == 'get-netcomputerinfo':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_netcomputerinfo(computer_name=computername, args=pv_args)
                                    else:
                                        entries = powerview.get_netcomputerinfo(computer_name=computername, args=pv_args)
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
                                        entries = temp_powerview.get_netservice(
                                            computer_name=computername,
                                            name=pv_args.name,
                                            is_running=pv_args.isrunning,
                                            is_stopped=pv_args.isstopped
                                        )
                                    else:
                                        entries = powerview.get_netservice(
                                            computer_name=computername,
                                            name=pv_args.name,
                                            is_running=pv_args.isrunning,
                                            is_stopped=pv_args.isstopped
                                        )
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'set-netservice':
                                if pv_args.computer is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.set_netservice(
                                            computer_name=pv_args.computer,
                                            service_name=pv_args.service_name,
                                            display_name=pv_args.display_name,
                                            binary_path=pv_args.binary_path,
                                            service_type=pv_args.service_type,
                                            start_type=pv_args.start_type,
                                            delayed_start=pv_args.delayed_start,
                                            error_control=pv_args.error_control,
                                            service_start_name=pv_args.service_start_name,
                                            password=pv_args.password
                                        )
                                    else:
                                        succeed = powerview.set_netservice(
                                            computer_name=pv_args.computer,
                                            service_name=pv_args.service_name,
                                            display_name=pv_args.display_name,
                                            binary_path=pv_args.binary_path,
                                            service_type=pv_args.service_type,
                                            start_type=pv_args.start_type,
                                            delayed_start=pv_args.delayed_start,
                                            error_control=pv_args.error_control,
                                            service_start_name=pv_args.service_start_name,
                                            password=pv_args.password
                                        )
                                else:
                                    logging.error('-Computer is required')
                            elif pv_args.module.casefold() == 'start-netservice':
                                if temp_powerview:
                                    succeed = temp_powerview.start_netservice(computer_name=pv_args.computer, service_name=pv_args.service_name)
                                else:
                                    succeed = powerview.start_netservice(computer_name=pv_args.computer, service_name=pv_args.service_name)
                            elif pv_args.module.casefold() == 'stop-netservice':
                                if temp_powerview:
                                    succeed = temp_powerview.stop_netservice(computer_name=pv_args.computer, service_name=pv_args.service_name)
                                else:
                                    succeed = powerview.stop_netservice(computer_name=pv_args.computer, service_name=pv_args.service_name)
                            elif pv_args.module.casefold() == 'get-netterminalsession' or pv_args.module.casefold() == 'qwinsta':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_netterminalsession(identity=computername, port=445, args=pv_args)
                                    else:
                                        entries = powerview.get_netterminalsession(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'remove-netterminalsession':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        succeed = temp_powerview.remove_netterminalsession(identity=computername, port=445, args=pv_args)
                                    else:
                                        succeed = powerview.remove_netterminalsession(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'stop-computer' or pv_args.module.casefold() == 'shutdown-computer':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        succeed = temp_powerview.stop_computer(identity=computername, port=445, args=pv_args)
                                    else:
                                        succeed = powerview.stop_computer(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'restart-computer' or pv_args.module.casefold() == 'reboot-computer':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        succeed = temp_powerview.restart_computer(identity=computername, port=445, args=pv_args)
                                    else:
                                        succeed = powerview.restart_computer(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-netprocess' or pv_args.module.casefold() == 'tasklist':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_netprocess(identity=computername, port=445, args=pv_args)
                                    else:
                                        entries = powerview.get_netprocess(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'stop-netprocess' or pv_args.module.casefold() == 'taskkill':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        succeed = temp_powerview.stop_netprocess(identity=computername, port=445, args=pv_args)
                                    else:
                                        succeed = powerview.stop_netprocess(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'get-netsession':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        entries = temp_powerview.get_netsession(identity=computername, port=445, args=pv_args)
                                    else:
                                        entries = powerview.get_netsession(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'logoff-session':
                                if pv_args.computer is not None or pv_args.computername is not None:
                                    computername = pv_args.computer if pv_args.computer else pv_args.computername
                                    if temp_powerview:
                                        succeed = temp_powerview.logoff_session(identity=computername, port=445, args=pv_args)
                                    else:
                                        succeed = powerview.logoff_session(identity=computername, port=445, args=pv_args)
                                else:
                                    logging.error('-Computer or -ComputerName is required')
                            elif pv_args.module.casefold() == 'remove-netsession':
                                if pv_args.computer is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.remove_netsession(computer=pv_args.computer, target_session=pv_args.target_session, args=pv_args)
                                    else:
                                        succeed = powerview.remove_netsession(computer=pv_args.computer, target_session=pv_args.target_session, args=pv_args)
                            elif pv_args.module.casefold() == 'find-localadminaccess':
                                if temp_powerview:
                                    entries = temp_powerview.find_localadminaccess(args=pv_args)
                                else:
                                    entries = powerview.find_localadminaccess(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-asreproast':
                                if temp_powerview:
                                    entries = temp_powerview.invoke_asreproast(args=pv_args)
                                else:
                                    entries = powerview.invoke_asreproast(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-kerberoast':
                                if temp_powerview:
                                    entries = temp_powerview.invoke_kerberoast(args=pv_args)
                                else:
                                    entries = powerview.invoke_kerberoast(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-printerbug':
                                if temp_powerview:
                                    entries = temp_powerview.invoke_printerbug(args=pv_args)
                                else:
                                    entries = powerview.invoke_printerbug(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-dfscoerce':
                                if temp_powerview:
                                    entries = temp_powerview.invoke_dfscoerce(args=pv_args)
                                else:
                                    entries = powerview.invoke_dfscoerce(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-messagebox':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                if temp_powerview:
                                    succeed = temp_powerview.invoke_messagebox(identity=computername, args=pv_args)
                                else:
                                    succeed = powerview.invoke_messagebox(identity=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-badsuccessor':
                                if temp_powerview:
                                    entries = temp_powerview.invoke_badsuccessor(args=pv_args)
                                else:
                                    entries = powerview.invoke_badsuccessor(args=pv_args)
                            elif pv_args.module.casefold() == 'get-exchangeserver' or pv_args.module.casefold() == 'get-exchange':
                                if temp_powerview:
                                    entries = temp_powerview.get_exchangeserver(args=pv_args)
                                else:
                                    entries = powerview.get_exchangeserver(args=pv_args)
                            elif pv_args.module.casefold() == 'get-exchangemailbox':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_exchangemailbox(identity=identity, properties=properties, args=pv_args)
                                else:
                                    entries = powerview.get_exchangemailbox(identity=identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-exchangedatabase':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = pv_args.identity.strip() if pv_args.identity else None
                                if temp_powerview:
                                    entries = temp_powerview.get_exchangedatabase(identity=identity, properties=properties, args=pv_args)
                                else:
                                    entries = powerview.get_exchangedatabase(identity=identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'unlock-adaccount':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.unlock_adaccount(args=pv_args)
                                    else:
                                        succeed = powerview.unlock_adaccount(args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'enable-rdp':
                                if temp_powerview:
                                    succeed = temp_powerview.enable_rdp(args=pv_args)
                                else:
                                    succeed = powerview.enable_rdp(args=pv_args)
                            elif pv_args.module.casefold() == 'disable-rdp':
                                if temp_powerview:
                                    succeed = temp_powerview.disable_rdp(args=pv_args)
                                else:
                                    succeed = powerview.disable_rdp(args=pv_args)
                            elif pv_args.module.casefold() == 'enable-adaccount':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.enable_adaccount(args=pv_args)
                                    else:
                                        succeed = powerview.enable_adaccount(args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'disable-adaccount':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        succeed = temp_powerview.disable_adaccount(args=pv_args)
                                    else:
                                        succeed = powerview.disable_adaccount(args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'enable-efsrpc':
                                if temp_powerview:
                                    succeed = temp_powerview.enable_efsrpc(args=pv_args)
                                else:
                                    succeed = powerview.enable_efsrpc(args=pv_args)
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
                            elif pv_args.module.casefold() == 'add-netservice':
                                if temp_powerview:
                                    succeed = temp_powerview.add_netservice(
                                        computer_name=pv_args.computer,
                                        service_name=pv_args.service_name,
                                        display_name=pv_args.display_name,
                                        binary_path=pv_args.binary_path,
                                        service_type=pv_args.service_type,
                                        start_type=pv_args.start_type,
                                        delayed_start=pv_args.delayed_start,
                                        error_control=pv_args.error_control,
                                        service_start_name=pv_args.service_start_name,
                                        password=pv_args.password
                                    )
                                else:
                                    succeed = powerview.add_netservice(
                                        computer_name=pv_args.computer,
                                        service_name=pv_args.service_name,
                                        display_name=pv_args.display_name,
                                        binary_path=pv_args.binary_path,
                                        service_type=pv_args.service_type,
                                        start_type=pv_args.start_type,
                                        delayed_start=pv_args.delayed_start,
                                        error_control=pv_args.error_control,
                                        service_start_name=pv_args.service_start_name,
                                        password=pv_args.password
                                    )
                            elif pv_args.module.casefold() == 'remove-domainou' or pv_args.module.casefold() == 'remove-ou':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        temp_powerview.remove_domainou(identity=pv_args.identity, args=pv_args)
                                    else:
                                        powerview.remove_domainou(identity=pv_args.identity, args=pv_args)
                                else:
                                    logging.error('-Identity flag is required')
                            elif pv_args.module.casefold() == 'remove-netservice':
                                if temp_powerview:
                                    succeed = temp_powerview.remove_netservice(
                                        computer_name=pv_args.computer,
                                        service_name=pv_args.service_name
                                    )
                                else:
                                    succeed = powerview.remove_netservice(
                                        computer_name=pv_args.computer,
                                        service_name=pv_args.service_name
                                    )
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
                                if temp_powerview:
                                    succeed = temp_powerview.set_domainobject(pv_args.identity, args=pv_args)
                                else:
                                    succeed = powerview.set_domainobject(pv_args.identity, args=pv_args)
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
                                        temp_powerview.add_domaincomputer(args=pv_args)
                                    else:
                                        powerview.add_domaincomputer(args=pv_args)
                                else:
                                    logging.error(f'-ComputerName and -ComputerPass are required')
                            elif pv_args.module.casefold() == 'add-domaingmsa' or pv_args.module.casefold() == 'add-gmsa':
                                if temp_powerview:
                                    temp_powerview.add_domaingmsa(args=pv_args)
                                else:
                                    powerview.add_domaingmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaindmsa' or pv_args.module.casefold() == 'add-dmsa':
                                if temp_powerview:
                                    temp_powerview.add_domaindmsa(args=pv_args)
                                else:
                                    powerview.add_domaindmsa(args=pv_args)
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
                            elif pv_args.module.casefold() == 'add-domaingroup' or pv_args.module.casefold() == 'add-adgroup':
                                if pv_args.identity is not None:
                                    if temp_powerview:
                                        temp_powerview.add_domaingroup(pv_args.identity, basedn=pv_args.basedn, args=pv_args)
                                    else:
                                        powerview.add_domaingroup(pv_args.identity, basedn=pv_args.basedn, args=pv_args)
                                else:
                                    logging.error('-Name flag is required')
                            elif pv_args.module.casefold() == 'remove-domainobject' or pv_args.module.casefold() == 'remove-adobject':
                                if pv_args.identity:
                                    identity = pv_args.identity.strip()
                                    if temp_powerview:
                                        temp_powerview.remove_domainobject(identity, args=pv_args)
                                    else:
                                        powerview.remove_domainobject(identity, args=pv_args)
                                else:
                                    logging.error("-Identity flag is required")
                            elif pv_args.module.casefold() == 'remove-domaindmsa' or pv_args.module.casefold() == 'remove-dmsa':
                                if temp_powerview:
                                    temp_powerview.remove_domaindmsa(args=pv_args)
                                else:
                                    powerview.remove_domaindmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domaingmsa' or pv_args.module.casefold() == 'remove-gmsa':
                                if temp_powerview:
                                    temp_powerview.remove_domaingmsa(args=pv_args)
                                else:
                                    powerview.remove_domaingmsa(args=pv_args)
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
                            elif pv_args.module.casefold() == 'restore-domainobject' or pv_args.module.casefold() == 'restore-adobject':
                                if temp_powerview:
                                    temp_powerview.restore_domainobject(args=pv_args)
                                else:
                                    powerview.restore_domainobject(args=pv_args)
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
                            elif pv_args.module.casefold() == 'dump-schema':
                                if temp_powerview:
                                    schema = temp_powerview.conn.get_schema_info(raw=True)
                                else:
                                    schema = powerview.conn.get_schema_info(raw=True)
                                if pv_args.text:
                                    print(schema)
                                else:
                                    if not pv_args.outfile:
                                        pv_args.outfile = f"{powerview.conn.get_domain().lower()}-schema.json"
                                    schema.to_file(os.path.expanduser(pv_args.outfile))
                                    logging.info(f"Schema dumped to {pv_args.outfile}")
                            elif pv_args.module.casefold() == 'dump-serverinfo':
                                if temp_powerview:
                                    server_info = temp_powerview.conn.get_server_info(raw=True)
                                else:
                                    server_info = powerview.conn.get_server_info(raw=True)
                                if pv_args.text:
                                    print(server_info)
                                else:
                                    if not pv_args.outfile:
                                        pv_args.outfile = f"{powerview.conn.get_domain().lower()}-server_info.json"
                                    server_info.to_file(os.path.expanduser(pv_args.outfile))
                                    logging.info(f"Server info dumped to {pv_args.outfile}")
                            elif pv_args.module.casefold() == 'get_pool_stats':
                                if temp_powerview:
                                    stats = temp_powerview.conn.get_pool_stats()
                                else:
                                    stats = powerview.conn.get_pool_stats()
                                
                                FORMATTER.format_pool_stats(stats)
                            elif pv_args.module.casefold() == 'history':
                                hist = get_shell_history(pv_args.last, pv_args.unique)
                                for index, item in list(enumerate(hist,1))[::-1]:
                                    if pv_args.noNumber:
                                        bol = f""
                                    else:
                                        bol = f"[{index}] "
                                    print(f"{bol}{item}")
                            elif pv_args.module.casefold() == 'clear':
                                clear_screen()
                            elif pv_args.module.casefold() == 'whoami':
                                print(powerview.conn.who_am_i())
                            elif pv_args.module.casefold() == 'exit':
                                if args.mcp and hasattr(powerview, 'mcp_server') and powerview.mcp_server.get_status():
                                    powerview.mcp_server.stop()
                                log_handler.save_history()
                                sys.exit(0)

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
                                        if isinstance(pv_args.select, int):
                                            formatter.print_index(entries)
                                        else:
                                            formatter.print_select(entries)
                                    else:
                                        if isinstance(entries, dict) and entries.get("headers"):
                                            formatter.print_table(entries["rows"], entries["headers"])
                                        else:
                                            formatter.print(entries)

                            # After displaying results, check if they came from cache
                            if entries and len(entries) > 0:
                                first_entry = entries[0]
                                using_cache = isinstance(first_entry, dict) and first_entry.get('from_cache', False)

                            temp_powerview = None
                            current_target_domain = None
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
                if args.mcp and hasattr(powerview, 'mcp_server') and powerview.mcp_server.get_status():
                    powerview.mcp_server.stop()
                log_handler.save_history()
                print("Exiting...")
                conn.close()
                sys.exit(0)
            except (ldap3.core.exceptions.LDAPSocketSendError, 
                    ldap3.core.exceptions.LDAPSocketReceiveError) as e:
                logging.info(f"LDAP Socket Error: {str(e)}")
                conn.reset_connection()
                log_handler.save_history()
            except ldap3.core.exceptions.LDAPSessionTerminatedByServerError:
                logging.warning("Server connection terminated. Trying to reconnect")
                conn.reset_connection()
                log_handler.save_history()
            except ldap3.core.exceptions.LDAPInvalidDnError as e:
                logging.error(f"LDAPInvalidDnError: {str(e)}")
                log_handler.save_history()
            except Exception as e:
                if args.stack_trace:
                    log_handler.save_history()
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
    except Exception as e:
        if args.stack_trace:
            log_handler.save_history()
            raise
        else:
            logging.error(str(e))

if __name__ == '__main__':
    main()
