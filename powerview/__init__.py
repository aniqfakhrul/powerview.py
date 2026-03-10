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
from powerview.utils.connections import CONNECTION, ConnectionSetupError
from powerview.lib.adws.error import ADWSError
from powerview.utils.logging import LOG
from powerview.utils.parsers import powerview_arg_parse, arg_parse
from powerview.plugins.registry import PluginRegistry
from powerview.plugins.loader import load_plugins
from powerview.utils.shell import get_prompt
from powerview.utils.colors import bcolors, Gradient
from powerview.utils.history import get_shell_history

import ldap3
import shlex
import os

def normalize_identity_value(value):
    if value is None:
        return None
    if isinstance(value, list):
        items = [item.strip() for item in value if isinstance(item, str) and item.strip()]
        if not items:
            return None
        return items[0] if len(items) == 1 else items
    if isinstance(value, str):
        value = value.strip()
        return value if value else None
    return value

def main():
    """
    Main entry point for PowerView tool.
    
    Handles command-line argument parsing, LDAP connection setup,
    and interactive command processing.
    """
    args = arg_parse()

    flat_domain = args.domain.split('.')[0] if '.' in args.domain else args.domain
    folder_name = sanitize_component(flat_domain.lower()) or "default-log"
    username = sanitize_component(args.username.lower())

    log_handler = LOG(folder_name, username=username)

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

        # Load plugins
        plugin_registry = PluginRegistry()
        load_plugins(plugin_registry, powerview)
        powerview.plugin_registry = plugin_registry

        # Inject plugin commands into completer
        from powerview.utils.completer import COMMANDS
        for cmd_name, cmd_info in plugin_registry.commands.items():
            COMMANDS[cmd_name] = [
                a["name"] if isinstance(a, dict) else a
                for a in cmd_info["args"]
            ]

        # Register plugin commands in argparse
        from powerview.utils.parsers import set_plugin_registry
        set_plugin_registry(plugin_registry)

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
                            
                        pv = temp_powerview if temp_powerview else powerview

                        try:
                            entries = None

                            _before_hooks = pv.plugin_registry.get_before_hooks(pv_args.module) if pv.plugin_registry else []
                            if _before_hooks:
                                for hook in _before_hooks:
                                    try:
                                        modified = hook(pv, pv_args)
                                        if modified is not None:
                                            pv_args = modified
                                    except Exception as e:
                                        logging.error(f"Plugin before hook failed: {e}")
                                        if args.stack_trace:
                                            import traceback
                                            logging.debug(traceback.format_exc())

                            if pv_args.module.casefold() == 'get-domain':
                                entries = pv.get_domain(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobject' or pv_args.module.casefold() == 'get-adobject':
                                entries = pv.get_domainobject(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobjectowner' or pv_args.module.casefold() == 'get-objectowner':
                                entries = pv.get_domainobjectowner(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainobjectacl' or pv_args.module.casefold() == 'get-objectacl':
                                entries = pv.get_domainobjectacl(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainuser':
                                entries = pv.get_domainuser(args=pv_args)
                            elif pv_args.module.casefold() == 'get-localuser':
                                properties = pv_args.properties if pv_args.properties else None
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_localuser(computer_name=computername, identity=pv_args.identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaincomputer':
                                entries = pv.get_domaincomputer(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingroup':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = normalize_identity_value(pv_args.identity)
                                entries = pv.get_domaingroup(pv_args, properties, identity, no_cache=pv_args.no_cache)
                            elif pv_args.module.casefold() == 'get-domaingroupmember':
                                identity = normalize_identity_value(pv_args.identity)
                                entries = pv.get_domaingroupmember(identity=identity, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainforeigngroupmember' or pv_args.module.casefold() == 'find-foreigngroup':
                                entries = pv.get_domainforeigngroupmember(pv_args)
                            elif pv_args.module.casefold() == 'get-domainforeignuser' or pv_args.module.casefold() == 'find-foreignuser':
                                entries = pv.get_domainforeignuser(pv_args)
                            elif pv_args.module.casefold() == 'get-domaincontroller':
                                entries = pv.get_domaincontroller(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingpo':
                                entries = pv.get_domaingpo(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingpolocalgroup' or pv_args.module.casefold() == 'get-gpolocalgroup':
                                entries = pv.get_domaingpolocalgroup(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaingposettings' or pv_args.module.casefold() == 'get-gposettings':
                                entries = pv.get_domaingposettings(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainou':
                                entries = pv.get_domainou(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindnszone':
                                identity = normalize_identity_value(pv_args.identity)
                                properties = pv_args.properties if pv_args.properties else None
                                entries = pv.get_domaindnszone(identity, properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindnsrecord':
                                zonename = pv_args.zonename.strip() if pv_args.zonename else None
                                identity = normalize_identity_value(pv_args.identity)
                                properties = pv_args.properties if pv_args.properties else None
                                entries = pv.get_domaindnsrecord(identity, zonename, properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainsccm' or pv_args.module.casefold() == 'get-sccm':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = normalize_identity_value(pv_args.identity)
                                entries = pv.get_domainsccm(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'get-domaingmsa' or pv_args.module.casefold() == 'get-gmsa':
                                entries = pv.get_domaingmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaindmsa' or pv_args.module.casefold() == 'get-dmsa':
                                entries = pv.get_domaindmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainrbcd' or pv_args.module.casefold() == 'get-rbcd':
                                entries = pv.get_domainrbcd(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainwds' or pv_args.module.casefold() == 'get-wds':
                                entries = pv.get_domainwds(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domainca' or pv_args.module.casefold() == 'get-ca':
                                entries = pv.get_domainca(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaincatemplate' or pv_args.module.casefold() == 'get-catemplate':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = normalize_identity_value(pv_args.identity)
                                entries = pv.get_domaincatemplate(pv_args, properties, identity)
                            elif pv_args.module.casefold() == 'remove-domaincatemplate' or pv_args.module.casefold() == 'remove-catemplate':
                                pv.remove_domaincatemplate(identity=pv_args.identity, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaincatemplate' or pv_args.module.casefold() == 'add-catemplate':
                                pv.add_domaincatemplate(pv_args.displayname, pv_args.name, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaincatemplateacl' or pv_args.module.casefold() == 'add-catemplateacl':
                                pv.add_domaincatemplateacl(pv_args.template, pv_args.principalidentity, args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaintrust':
                                entries = pv.get_domaintrust(args=pv_args)
                            elif pv_args.module.casefold() == 'get-domaintrustkey' or pv_args.module.casefold() == 'get-trustkey':
                                entries = pv.get_domaintrustkey(args=pv_args)
                            elif pv_args.module.casefold() == 'convertfrom-uacvalue':
                                entries = pv.convertfrom_uacvalue(value=pv_args.value.strip(), output=True)
                            elif pv_args.module.casefold() == 'convertfrom-sid':
                                pv.convertfrom_sid(objectsid=pv_args.objectsid.strip(), output=True, no_cache=pv_args.no_cache)
                            elif pv_args.module.casefold() == 'clear-cache':
                                pv.clear_cache()
                                using_cache = False
                            elif pv_args.module.casefold() == 'login-as':
                                powerview.login_as(args=pv_args)
                            elif pv_args.module.casefold() == 'get-namedpipes':
                                entries = pv.get_namedpipes(
                                    pv_args,
                                    timeout=pv_args.timeout,
                                    max_threads=pv_args.max_threads
                                )
                            elif pv_args.module.casefold() == 'get-netshare':
                                entries = pv.get_netshare(pv_args)
                            elif pv_args.module.casefold() == 'get-regloggedon':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_regloggedon(computer_name=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'get-netcomputerinfo':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_netcomputerinfo(computer_name=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'get-netloggedon':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_netloggedon(computer_name=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'get-eventlog':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_eventlog(computer_name=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'get-eventlogchannel':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_eventlogchannel(computer_name=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'get-eventlogpublisher':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_eventlogpublisher(computer_name=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'get-netservice':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_netservice(
                                    computer_name=computername,
                                    name=pv_args.name,
                                    is_running=pv_args.isrunning,
                                    is_stopped=pv_args.isstopped
                                )
                            elif pv_args.module.casefold() == 'set-netservice':
                                succeed = pv.set_netservice(
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
                            elif pv_args.module.casefold() == 'start-netservice':
                                succeed = pv.start_netservice(computer_name=pv_args.computer, service_name=pv_args.service_name)
                            elif pv_args.module.casefold() == 'stop-netservice':
                                succeed = pv.stop_netservice(computer_name=pv_args.computer, service_name=pv_args.service_name)
                            elif pv_args.module.casefold() == 'get-netterminalsession' or pv_args.module.casefold() == 'qwinsta':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_netterminalsession(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-netterminalsession':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                succeed = pv.remove_netterminalsession(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'stop-computer' or pv_args.module.casefold() == 'shutdown-computer':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                succeed = pv.stop_computer(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'restart-computer' or pv_args.module.casefold() == 'reboot-computer':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                succeed = pv.restart_computer(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'get-netprocess' or pv_args.module.casefold() == 'tasklist':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_netprocess(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'stop-netprocess' or pv_args.module.casefold() == 'taskkill':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                succeed = pv.stop_netprocess(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'get-netsession':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                entries = pv.get_netsession(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'logoff-session':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                succeed = pv.logoff_session(identity=computername, port=445, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-netsession':
                                succeed = pv.remove_netsession(computer=pv_args.computer, target_session=pv_args.target_session, args=pv_args)
                            elif pv_args.module.casefold() == 'find-localadminaccess':
                                entries = pv.find_localadminaccess(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-asreproast':
                                entries = pv.invoke_asreproast(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-kerberoast':
                                entries = pv.invoke_kerberoast(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-printerbug':
                                entries = pv.invoke_printerbug(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-dfscoerce':
                                entries = pv.invoke_dfscoerce(args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-messagebox':
                                computername = pv_args.computer if pv_args.computer else pv_args.computername
                                succeed = pv.invoke_messagebox(identity=computername, args=pv_args)
                            elif pv_args.module.casefold() == 'invoke-badsuccessor' or pv_args.module.casefold() == 'invoke-dmsasync':
                                entries = pv.invoke_badsuccessor(args=pv_args)
                            elif pv_args.module.casefold() == 'get-exchangeserver' or pv_args.module.casefold() == 'get-exchange':
                                entries = pv.get_exchangeserver(args=pv_args)
                            elif pv_args.module.casefold() == 'get-exchangemailbox':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = normalize_identity_value(pv_args.identity)
                                entries = pv.get_exchangemailbox(identity=identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'get-exchangedatabase':
                                properties = pv_args.properties if pv_args.properties else None
                                identity = normalize_identity_value(pv_args.identity)
                                entries = pv.get_exchangedatabase(identity=identity, properties=properties, args=pv_args)
                            elif pv_args.module.casefold() == 'unlock-adaccount':
                                succeed = pv.unlock_adaccount(args=pv_args)
                            elif pv_args.module.casefold() == 'enable-rdp':
                                succeed = pv.enable_rdp(args=pv_args)
                            elif pv_args.module.casefold() == 'disable-rdp':
                                succeed = pv.disable_rdp(args=pv_args)
                            elif pv_args.module.casefold() == 'enable-shadowrdp':
                                succeed = pv.enable_shadow_rdp(args=pv_args)
                            elif pv_args.module.casefold() == 'disable-shadowrdp':
                                succeed = pv.disable_shadow_rdp(args=pv_args)
                            elif pv_args.module.casefold() == 'enable-adaccount':
                                succeed = pv.enable_adaccount(args=pv_args)
                            elif pv_args.module.casefold() == 'disable-adaccount':
                                succeed = pv.disable_adaccount(args=pv_args)
                            elif pv_args.module.casefold() == 'enable-efsrpc':
                                succeed = pv.enable_efsrpc(args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaingpo' or pv_args.module.casefold() == 'add-gpo':
                                succeed = pv.add_domaingpo(identity=pv_args.identity, description=pv_args.description, basedn=pv_args.basedn, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domainou' or pv_args.module.casefold() == 'add-ou':
                                pv.add_domainou(identity=pv_args.identity, basedn=pv_args.basedn, args=pv_args)
                            elif pv_args.module.casefold() == 'add-netservice':
                                succeed = pv.add_netservice(
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
                                pv.remove_domainou(identity=pv_args.identity, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-netservice':
                                succeed = pv.remove_netservice(
                                    computer_name=pv_args.computer,
                                    service_name=pv_args.service_name
                                )
                            elif pv_args.module.casefold() == 'add-domainobjectacl' or pv_args.module.casefold() == 'add-objectacl':
                                pv.add_domainobjectacl(
                                    targetidentity=pv_args.targetidentity,
                                    principalidentity=pv_args.principalidentity,
                                    rights=pv_args.rights,
                                    rights_guid=pv_args.rights_guid,
                                    ace_type=pv_args.ace_type,
                                    inheritance=pv_args.inheritance
                                )
                            elif pv_args.module.casefold() == 'remove-domainobjectacl' or pv_args.module.casefold() == 'remove-objectacl':
                                pv.remove_domainobjectacl(
                                    targetidentity=pv_args.targetidentity,
                                    principalidentity=pv_args.principalidentity,
                                    rights=pv_args.rights,
                                    rights_guid=pv_args.rights_guid,
                                    ace_type=pv_args.ace_type,
                                    inheritance=pv_args.inheritance
                                )
                            elif pv_args.module.casefold() == 'add-domaingroupmember' or pv_args.module.casefold() == 'add-groupmember':
                                succeed = pv.add_domaingroupmember(pv_args.identity, pv_args.members, pv_args)
                                if succeed:
                                    logging.info(f'User {pv_args.members} successfully added to {pv_args.identity}')
                            elif pv_args.module.casefold() == 'remove-domaingroupmember' or pv_args.module.casefold() == 'remove-groupmember':
                                succeed = pv.remove_domaingroupmember(pv_args.identity, pv_args.members, pv_args)
                                if succeed:
                                    logging.info(f'User {pv_args.members} successfully removed from {pv_args.identity}')
                            elif pv_args.module.casefold() == 'set-domainobject' or pv_args.module.casefold() == 'set-adobject':
                                succeed = pv.set_domainobject(pv_args.identity, args=pv_args)
                            elif pv_args.module.casefold() == 'set-domainobjectdn' or pv_args.module.casefold() == 'set-adobjectdn':
                                succeed = pv.set_domainobjectdn(pv_args.identity, destination_dn=pv_args.destination_dn, args=pv_args)
                            elif pv_args.module.casefold() == 'set-domaindnsrecord':
                                pv.set_domaindnsrecord(recordname=pv_args.recordname, recordaddress=pv_args.recordaddress, zonename=pv_args.zonename)
                            elif pv_args.module.casefold() == 'set-domaincatemplate' or pv_args.module.casefold() == 'set-catemplate':
                                pv.set_domaincatemplate(pv_args.identity, pv_args)
                            elif pv_args.module.casefold() == 'set-domainuserpassword':
                                succeed = pv.set_domainuserpassword(pv_args.identity, pv_args.accountpassword, oldpassword=pv_args.oldpassword, args=pv_args)
                            elif pv_args.module.casefold() == 'set-domaincomputerpassword':
                                succeed = pv.set_domaincomputerpassword(pv_args.identity, pv_args.accountpassword, oldpassword=pv_args.oldpassword, args=pv_args)
                            elif pv_args.module.casefold() == 'set-domainrbcd' or pv_args.module.casefold() == 'set-rbcd':
                                pv.set_domainrbcd(pv_args.identity, pv_args.delegatefrom, args=pv_args)
                            elif pv_args.module.casefold() == 'set-shadowcredential' or pv_args.module.casefold() == 'set-shadowcred':
                                if pv_args.remove and not pv_args.deviceid:
                                    logging.error('-DeviceId flag is required when using -Remove')
                                else:
                                    entries = pv.set_shadowcredential(args=pv_args)
                            elif pv_args.module.casefold() == 'get-shadowcredential' or pv_args.module.casefold() == 'get-shadowcred':
                                entries = pv.get_shadowcredential(args=pv_args)
                            elif pv_args.module.casefold() == 'remove-shadowcredential' or pv_args.module.casefold() == 'remove-shadowcred':
                                entries = pv.remove_shadowcredential(args=pv_args)
                            elif pv_args.module.casefold() == 'set-domainobjectowner' or pv_args.module.casefold() == 'set-objectowner':
                                pv.set_domainobjectowner(pv_args.targetidentity, pv_args.principalidentity, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaincomputer' or pv_args.module.casefold() == 'add-adcomputer':
                                pv.add_domaincomputer(args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaingmsa' or pv_args.module.casefold() == 'add-gmsa':
                                pv.add_domaingmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaindmsa' or pv_args.module.casefold() == 'add-dmsa':
                                pv.add_domaindmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaindnsrecord':
                                pv.add_domaindnsrecord(args=pv_args)
                            elif pv_args.module.casefold() == 'add-domainuser' or pv_args.module.casefold() == 'add-aduser':
                                pv.add_domainuser(pv_args.username, pv_args.password, args=pv_args)
                            elif pv_args.module.casefold() == 'add-domaingroup' or pv_args.module.casefold() == 'add-adgroup':
                                pv.add_domaingroup(pv_args.identity, basedn=pv_args.basedn, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domainobject' or pv_args.module.casefold() == 'remove-adobject':
                                identity = normalize_identity_value(pv_args.identity)
                                pv.remove_domainobject(identity, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domaindmsa' or pv_args.module.casefold() == 'remove-dmsa':
                                pv.remove_domaindmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domaingmsa' or pv_args.module.casefold() == 'remove-gmsa':
                                pv.remove_domaingmsa(args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domainuser' or pv_args.module.casefold() == 'remove-aduser':
                                pv.remove_domainuser(pv_args.identity)
                            elif pv_args.module.casefold() == 'remove-domaindnsrecord':
                                pv.remove_domaindnsrecord(args=pv_args)
                            elif pv_args.module.casefold() == 'disable-domaindnsrecord':
                                pv.disable_domaindnsrecord(recordname=pv_args.recordname, zonename=pv_args.zonename)
                            elif pv_args.module.casefold() == 'restore-domainobject' or pv_args.module.casefold() == 'restore-adobject':
                                pv.restore_domainobject(args=pv_args)
                            elif pv_args.module.casefold() == 'remove-domaincomputer' or pv_args.module.casefold() == 'remove-adcomputer':
                                pv.remove_domaincomputer(pv_args.computername, args=pv_args)
                            elif pv_args.module.casefold() == 'add-gplink':
                                pv.add_gplink(guid=pv_args.guid, targetidentity=pv_args.targetidentity, link_enabled=pv_args.link_enabled, enforced=pv_args.enforced, args=pv_args)
                            elif pv_args.module.casefold() == 'remove-gplink':
                                pv.remove_gplink(guid=pv_args.guid, targetidentity=pv_args.targetidentity, args=pv_args)
                            elif pv_args.module.casefold() == 'dump-schema':
                                schema = pv.conn.get_schema_info(raw=True)
                                if pv_args.text:
                                    print(schema)
                                else:
                                    if not pv_args.outfile:
                                        pv_args.outfile = f"{powerview.conn.get_domain().lower()}-schema.json"
                                    schema.to_file(os.path.expanduser(pv_args.outfile))
                                    logging.info(f"Schema dumped to {pv_args.outfile}")
                            elif pv_args.module.casefold() == 'dump-serverinfo':
                                server_info = pv.conn.get_server_info(raw=True)
                                if pv_args.text:
                                    print(server_info)
                                else:
                                    if not pv_args.outfile:
                                        pv_args.outfile = f"{powerview.conn.get_domain().lower()}-server_info.json"
                                    server_info.to_file(os.path.expanduser(pv_args.outfile))
                                    logging.info(f"Server info dumped to {pv_args.outfile}")
                            elif pv_args.module.casefold() == 'get_pool_stats':
                                stats = pv.conn.get_pool_stats()
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
                            elif pv_args.module.casefold() == 'get-plugin' and pv.plugin_registry:
                                plugins = pv.plugin_registry.list_plugins()
                                if not plugins:
                                    print("No plugins loaded")
                                else:
                                    headers = ["Name", "Author", "Type", "Status", "Description", "Commands", "Hooks"]
                                    rows = []
                                    for p in plugins:
                                        status = f"{bcolors.OKGREEN}enabled{bcolors.ENDC}" if p["enabled"] else f"{bcolors.FAIL}disabled{bcolors.ENDC}"
                                        tag = f"{bcolors.WARNING}builtin{bcolors.ENDC}" if p.get("builtin") else "user"
                                        cmds = ", ".join(p["commands"]) if p["commands"] else ""
                                        hooks = []
                                        if p["before_hooks"]:
                                            hooks.append(f"before: {', '.join(set(p['before_hooks']))}")
                                        if p["after_hooks"]:
                                            hooks.append(f"after: {', '.join(set(p['after_hooks']))}")
                                        rows.append([p["name"], p.get("author", ""), tag, status, p.get("description", ""), cmds, "; ".join(hooks)])
                                    FORMATTER(pv_args).print_table(rows, headers)
                            elif pv_args.module.casefold() == 'enable-plugin' and pv.plugin_registry:
                                name = getattr(pv_args, 'name', None)
                                if not name:
                                    logging.error("Usage: Enable-Plugin -Name <plugin_name>")
                                elif not pv.plugin_registry.enable_plugin(name):
                                    logging.error(f"Plugin '{name}' not found")
                            elif pv_args.module.casefold() == 'disable-plugin' and pv.plugin_registry:
                                name = getattr(pv_args, 'name', None)
                                if not name:
                                    logging.error("Usage: Disable-Plugin -Name <plugin_name>")
                                elif not pv.plugin_registry.disable_plugin(name):
                                    logging.error(f"Plugin '{name}' not found")
                            elif pv.plugin_registry and pv.plugin_registry.find_command(pv_args.module)[1]:
                                try:
                                    entries = pv.execute(pv_args)
                                except Exception as e:
                                    logging.error(f"Plugin command '{pv_args.module}' failed: {e}")
                                    if args.stack_trace:
                                        import traceback
                                        logging.debug(traceback.format_exc())

                            if pv.plugin_registry and entries is not None:
                                for hook in pv.plugin_registry.get_after_hooks(pv_args.module):
                                    try:
                                        modified = hook(pv, pv_args, entries)
                                        if modified is not None:
                                            entries = modified
                                    except Exception as e:
                                        logging.error(f"Plugin after hook failed: {e}")
                                        if args.stack_trace:
                                            import traceback
                                            logging.debug(traceback.format_exc())

                            if entries:
                                if pv_args.outfile:
                                    if os.path.exists(pv_args.outfile):
                                        logging.error("%s exists "%(pv_args.outfile))
                                        continue

                                formatter = FORMATTER(pv_args)
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

                            if isinstance(entries, list) and entries:
                                first_entry = entries[0]
                                using_cache = isinstance(first_entry, dict) and first_entry.get('from_cache', False)
                            else:
                                using_cache = False

                            temp_powerview = None
                            current_target_domain = None
                            conn.set_ldap_address(init_ldap_address)
                            conn.set_targetDomain(None)
                        except ldap3.core.exceptions.LDAPInvalidFilterError as e:
                            logging.error(str(e))
                        except ldap3.core.exceptions.LDAPAttributeError as e:
                            logging.error(str(e))
                        except ADWSError as e:
                            logging.error(f"[ADWS] {str(e)}")
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
