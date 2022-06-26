#!/usr/bin/env python3
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

from pywerview.modules.ldapattack import LDAPAttack
from pywerview.modules.addcomputer import ADDCOMPUTER
from pywerview.utils.helpers import *

import ldap3
import logging
import re

class PywerView:

    def __init__(self, conn, args):
        self.conn = conn
        self.args = args
        self.username = args.username
        self.password = args.password
        self.domain = args.domain
        self.lmhash = args.lmhash
        self.nthash = args.nthash
        self.dc_ip = args.dc_ip

        self.ldap_server, self.ldap_session = self.conn.init_ldap_session()

        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)
        self.root_dn = self.domain_dumper.getRoot()
        self.fqdn = ".".join(self.root_dn.replace("DC=","").split(","))

    def get_domainuser(self, args=None, properties=['cn','name','sAMAccountName','distinguishedName','mail','description','lastLogoff','lastLogon','memberof','objectSid','userPrincipalName'], identity='*'):
        if args:
            if args.preauthnotrequired:
                ldap_filter = f'(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(sAMAccountName={identity}))'
            elif args.admincount:
                ldap_filter = f'(&(samAccountType=805306368)(admincount=1)(sAMAccountName={identity}))'
            elif args.allowdelegation:
                ldap_filter = f'(&(samAccountType=805306368)!(userAccountControl:1.2.840.113556.1.4.803:=1048574)(sAMAccountName={identity}))'
            elif args.trustedtoauth:
                ldap_filter = f'(&(samAccountType=805306368)(|(samAccountName={identity}))(msds-allowedtodelegateto=*))'
            elif args.spn:
                ldap_filter = f'(&(samAccountType=805306368)(servicePrincipalName=*)(sAMAccountName={identity}))'
            else:
                ldap_filter = f'(&(samAccountType=805306368)(sAMAccountName={identity}))'
        else:
            ldap_filter = f'(&(samAccountType=805306368)(sAMAccountName={identity}))'

        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaincontroller(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domainobject(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(&(|(|(samAccountName={identity})(name={identity})(displayname={identity}))))'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries
    
    def get_domaincomputer(self, args=None, properties='*', identity='*'):
        if args:
            if args.unconstrained:
                ldap_filter = f'(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)(name={identity}))'
            elif args.trustedtoauth:
                ldap_filter = f'(&(samAccountType=805306369)(|(name={identity}))(msds-allowedtodelegateto=*))'
            elif args.laps:
                ldap_filter = f'(&(objectCategory=computer)(ms-MCS-AdmPwd=*)(sAMAccountName={identity}))'
            else:
                ldap_filter = f'(&(samAccountType=805306369)(name={identity}))'
        else:
            ldap_filter = f'(&(samAccountType=805306369)(name={identity}))'

        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaingroup(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(&(objectCategory=group)(|(|(samAccountName={identity})(name={identity}))))'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaingpo(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(&(objectCategory=groupPolicyContainer)(cn={identity}))'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domainou(self, args=None, properties='*', identity='*'):
        if args.gplink is None:
            ldap_filter = f'(&(objectCategory=organizationalUnit)(|(name={identity})))'
        else:
            print("masuk bawah")
            ldap_filter = f'(&(objectCategory=organizationalUnit)(|(name={identity}))(gplink={args.gplink}))'
        
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries
    
    def get_domaintrust(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(objectClass=trustedDomain)'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domain(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(objectClass=domain)'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def add_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties='distinguishedName')
        user_entry = self.get_domainobject(identity=members,properties='distinguishedName')
        targetobject = group_entry[0]
        userobject = user_entry[0]
        succeeded = self.ldap_session.modify(targetobject.entry_dn,{'member': [(ldap3.MODIFY_ADD, [userobject.entry_dn])]})
        if not succeeded:
            print(self.ldap_session.result['message'])
        return succeeded

    def add_domainobjectacl(self, args):
        c = NTLMRelayxConfig()
        c.addcomputer = 'idk lol'
        c.target = self.dc_ip

        setattr(args, "delete", False)

        entries = self.get_domainobject(identity=args.principalidentity)
        if len(entries) == 0:
            logging.error('Target object not found in domain')
            return
        
        identity_dn = entries[0].entry_dn
        logging.info(f'Found target dn {identity_dn}')
        
        logging.info(f'Adding {args.rights} privilege to {args.targetidentity}')
        la = LDAPAttack(c, self.ldap_session, f'{self.domain}/{args.principalidentity}', args)
        la.aclAttack(identity_dn, self.domain_dumper)

    def remove_domainobjectacl(self, args):
        c = NTLMRelayxConfig()
        c.addcomputer = 'idk lol'
        c.target = self.dc_ip
        
        setattr(args, "delete", True)

        entries = self.get_domainobject(identity=args.principalidentity)
        if len(entries) == 0:
            logging.error('Target object not found in domain')
            return
        
        identity_dn = entries[0].entry_dn
        logging.info(f'Found target dn {identity_dn}')
        
        logging.info(f'Adding {args.rights} privilege to {args.targetidentity}')
        la = LDAPAttack(c, self.ldap_session, f'{self.domain}/{args.principalidentity}', args)
        la.aclAttack(identity_dn, self.domain_dumper)
        

    def remove_domaincomputer(self,computer_name):
        if computer_name[-1] != '$':
            computer_name += '$'

        dcinfo = get_dc_host(self.ldap_session, self.domain_dumper, self.args)
        if len(dcinfo)== 0:
            logging.error("Cannot get domain info")
            exit()
        c_key = 0
        dcs = list(dcinfo.keys())
        if len(dcs) > 1:
            logging.info('We have more than one target, Pls choices the hostname of the -dc-ip you input.')
            cnt = 0
            for name in dcs:
                logging.info(f"{cnt}: {name}")
                cnt += 1
            while True:
                try:
                    c_key = int(input(">>> Your choice: "))
                    if c_key in range(len(dcs)):
                        break
                except Exception:
                    pass
        dc_host = dcs[c_key].lower()

        setattr(self.args, "dc_host", dc_host)
        setattr(self.args, "delete", True)

        if self.args.use_ldaps:
            setattr(self.args, "method", "LDAPS")
        else:
            setattr(self.args, "method", "SAMR")

        # Creating Machine Account
        addmachineaccount = ADDCOMPUTER(
            self.args.username,
            self.args.password,
            self.args.domain,
            self.args,
            computer_name)
        addmachineaccount.run()

        if len(self.get_domainobject(identity=computer_name)) == 0:
            return True
        else:
            return False


    def add_domaincomputer(self, computer_name, computer_pass):
        if computer_name[-1] != '$':
            computer_name += '$'

        dcinfo = get_dc_host(self.ldap_session, self.domain_dumper, self.args)
        if len(dcinfo)== 0:
            logging.error("Cannot get domain info")
            exit()
        c_key = 0
        dcs = list(dcinfo.keys())
        if len(dcs) > 1:
            logging.info('We have more than one target, Pls choices the hostname of the -dc-ip you input.')
            cnt = 0
            for name in dcs:
                logging.info(f"{cnt}: {name}")
                cnt += 1
            while True:
                try:
                    c_key = int(input(">>> Your choice: "))
                    if c_key in range(len(dcs)):
                        break
                except Exception:
                    pass
        dc_host = dcs[c_key].lower()

        setattr(self.args, "dc_host", dc_host)
        setattr(self.args, "delete", False)

        if self.args.use_ldaps:
            setattr(self.args, "method", "LDAPS")
        else:
            setattr(self.args, "method", "SAMR")
            

        # Creating Machine Account
        addmachineaccount = ADDCOMPUTER(
            self.username,
            self.password,
            self.domain,
            self.args,
            computer_name,
            computer_pass)
        addmachineaccount.run()


        if self.get_domainobject(identity=computer_name)[0].entry_dn:
            return True
        else:
            return False

    def set_domainobject(self,identity, args=None):
        targetobject = self.get_domainobject(identity=identity)
        if len(targetobject) > 1:
            logging.error('More than one object found')
            return False

        if args.clear:
            logging.info('Printing object before clearing')
            logging.info(f'Found target object {targetobject[0].entry_dn}')
            succeeded = self.ldap_session.modify(targetobject[0].entry_dn, {args.clear: [(ldap3.MODIFY_REPLACE,[])]})
        elif args.set:
            attrs = self.parse_object(args.set)
            logging.info('Printing object before modifying')
            logging.info(f'Found target object {targetobject[0].entry_dn}')
            succeeded = self.ldap_session.modify(targetobject[0].entry_dn, {attrs['attr']:[(ldap3.MODIFY_REPLACE,[attrs['val']])]})

        if not succeeded:
            logging.error(self.ldap_session.result['message'])

        return succeeded

    def get_shares(self, args):
        if args.computer:
            if is_ipaddress(args.computer):
                host = args.computer
            else:
                host = resolve_domain(args.computer, self.dc_ip)
        elif args.computername:
            if is_ipaddress(args.computername):
                host = args.computername
            else:
                host = resolve_domain(args.computername, self.dc_ip)
        else:
            logging.error(f'-Computer or -ComputerName is required')
            return

        if not host:
            return
        
        client = self.conn.init_smb_session(host)
        
        if not client:
            return

        shares = client.listShares()
        share_infos = []
       
        print(f'{"Name".ljust(15)}{"Remark".ljust(25)}ComputerName')
        print(f'{"----".ljust(15)}{"-------".ljust(25)}------------')
        for i in range(len(shares)):
            share_name = shares[i]['shi1_netname'][:-1]
            share_remark = shares[i]['shi1_remark'][:-1]
            share_info = {'name': share_name, 'remark': share_remark}
            share_infos.append(share_info)

            print(f'{share_info["name"].ljust(15)}{share_info["remark"].ljust(25)}{args.computer if args.computer else args.computername}')
        print()

    def parse_object(self,obj):
        attrs = dict()
        regex = r'\{(.*?)\}'
        res = re.search(regex,obj)
        dd = res.group(1).replace("'","").replace('"','').split("=")
        attrs['attr'] = dd[0]
        attrs['val'] = dd[1]
        return attrs
