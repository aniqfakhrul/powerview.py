#!/usr/bin/env python3
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.ldap import ldaptypes

from pywerview.modules.ldapattack import LDAPAttack, ACLEnum, ADUser, switcher_sid
from pywerview.modules.ca import CAEnum
from pywerview.modules.addcomputer import ADDCOMPUTER
from pywerview.modules.kerberoast import GetUserSPNs
from pywerview.utils.helpers import *
from pywerview.utils.connections import CONNECTION
from pywerview.utils.colors import bcolors

import chardet
from io import BytesIO
import ldap3
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword, removeMembersFromGroups
import logging
import re

class PywerView:

    def __init__(self, conn, args, target_server=None):
        self.conn = conn
        self.args = args
        self.username = args.username
        self.password = args.password
        self.domain = args.domain
        self.lmhash = args.lmhash
        self.nthash = args.nthash
        self.use_ldaps = args.use_ldaps
        self.dc_ip = args.dc_ip
        self.use_kerberos = args.use_kerberos

        self.ldap_server, self.ldap_session = self.conn.init_ldap_session()
        if not self.ldap_session.tls_started and not self.ldap_session.server.ssl:
            self.use_ldaps = False

        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)
        self.root_dn = self.domain_dumper.getRoot()
        self.fqdn = ".".join(self.root_dn.replace("DC=","").split(","))

    def get_domainuser(self, args=None, properties=['cn','name','sAMAccountName','distinguishedName','mail','description','lastLogoff','lastLogon','memberof','objectSid','userPrincipalName'], identity='*'):
        ldap_filter = ""
        identity_filter = f"(|(sAMAccountName={identity})(distinguishedName={identity}))"

        if args:
            if args.preauthnotrequired:
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            if args.passnotrequired:
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=32)'
            if args.admincount:
                ldap_filter += f'(admincount=1)'
            if args.allowdelegation:
                ldap_filter += f'!(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            if args.trustedtoauth:
                ldap_filter += f'(msds-allowedtodelegateto=*)'
            if args.spn:
                ldap_filter += f'(servicePrincipalName=*)'
            if args.ldapfilter:
                logging.debug(f'[Get-DomainUser] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f'{args.ldapfilter}'

        # previous ldap filter, need to changed to filter based on objectClass instead because i couldn't get the trust account
        #ldap_filter = f'(&(samAccountType=805306368){identity_filter}{ldap_filter})'
        ldap_filter = f'(&(objectCategory=person)(objectClass=user){identity_filter}{ldap_filter})'

        logging.debug(f'LDAP search filter: {ldap_filter}')

        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaincontroller(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domainobject(self, args=None, properties='*', identity='*'):
        identity_filter = f"(|(samAccountName={identity})(name={identity})(displayname={identity})(objectSid={identity})(distinguishedName={identity})(dnshostname={identity}))"
        ldap_filter = f"(|{identity_filter})"
        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-DomainObject] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldap_filter}"
        ldap_fiter = f"(&{ldap_filter})"
        logging.debug(f'LDAP search filter: {ldap_filter}')
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domainou(self, args=None, properties='*', identity='*'):
        ldap_filter = ""
        if args:
            if args.gplink:
                ldap_filter += f"(gplink=*{args.gplink}*)"
            if args.ldapfilter:
                logging.debug(f'[Get-DomainOU] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        ldap_filter = f'(&(objectCategory=organizationalUnit)(|(name={identity})){ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domainobjectacl(self, args=None):
        #enumerate available guids
        guids_dict = {}
        self.ldap_session.search(f"CN=Extended-Rights,CN=Configuration,{self.root_dn}", "(rightsGuid=*)",attributes=['displayName','rightsGuid'])
        for entry in self.ldap_session.entries:
            guids_dict[entry['rightsGuid'].values[0]] = entry['displayName'].values[0]
        #self.ldap_session.search(f"CN=Schema,CN=Configuration,{self.root_dn}", "(schemaIdGuid=*)",attributes=['name','schemaIdGuid'])
        #for entry in self.ldap_session.entries:
        #    guids_dict[entry['schemaIdGuid'].values[0]] = entry['name'].values[0]
        setattr(args,"guids_map_dict",guids_dict)

        if args.security_identifier:
            principalsid_entry = self.get_domainobject(identity=args.security_identifier,properties=['objectSid'])
            if not principalsid_entry:
                logging.error(f'Principal {args.security_identifier} not found in domain')
                return
            elif len(principalsid_entry) > 1:
                logging.error(f'[SecurityIdentifier] Multiple identities found. Use exact match')
                return
            args.security_identifier = principalsid_entry[0]['objectSid'].values[0]

        identity = args.identity
        if identity != "*":
            identity_entries = self.get_domainobject(identity=identity,properties=['objectSid','distinguishedName'])
            if len(identity_entries) == 0:
                logging.error(f'Identity {args.identity} not found in domain')
                return
            elif len(identity_entries) > 1:
                logging.error(f'[Identity] Multiple identities found. Use exact match')
                return
            logging.debug(f'Target identity found in domain {identity_entries[0]["distinguishedName"].values[0]}')
            identity = identity_entries[0]['distinguishedName'].values[0]
        else:
            logging.info('Recursing all domain objects. This might take a while')

        self.ldap_session.search(self.root_dn, f'(distinguishedName={identity})', attributes=['nTSecurityDescriptor','sAMAccountName','distinguishedName','objectSid'], controls=security_descriptor_control(sdflags=0x04))
        entries = self.ldap_session.entries

        if not entries:
            logging.error(f'Identity not found in domain')
            return

        enum = ACLEnum(entries, self.ldap_session, self.root_dn, args)
        entries_dacl = enum.read_dacl()
        return entries_dacl

    def get_domaincomputer(self, args=None, properties='*', identity='*'):
        ldap_filter = ""
        identity_filter = f"(|(name={identity})(sAMAccountName={identity})(dnsHostName={identity}))"

        if args:
            if args.unconstrained:
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            if args.trustedtoauth:
                ldap_filter += f'(msds-allowedtodelegateto=*)'
            if args.laps:
                ldap_filter += f'(ms-MCS-AdmPwd=*)'
            if args.ldapfilter:
                logging.debug(f'[Get-DomainComputer] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        # also need to change this to filter from objectClass instead
        #ldap_filter = f'(&(samAccountType=805306369){identity_filter}{ldap_filter})'
        ldap_filter = f'(&(objectClass=computer){identity_filter}{ldap_filter})'

        logging.debug(f'LDAP search filter: {ldap_filter}')

        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaingroup(self, args=None, properties='*', identity='*'):
        ldap_filter = ""
        identity_filter = f"(|(|(samAccountName={identity})(name={identity})(distinguishedName={identity})))"
        if args:
            if args.admincount:
                ldap_filter += f"(admincount=1)"
            if args.ldapfilter:
                ldap_filter += f"{args.ldapfilter}"
                logging.debug(f'[Get-DomainGroup] Using additional LDAP filter: {args.ldapfilter}')
            if args.memberidentity:
                entries = self.get_domainobject(identity=args.memberidentity)
                if len(entries) == 0:
                    logging.info("Member identity not found")
                    return
                memberidentity_dn = entries[0]['distinguishedName'].values[0]
                ldap_filter += f"(member={memberidentity_dn})"
                logging.debug(f'[Get-DomainGroup] Filter is based on member property {ldap_filter}')

        ldap_filter = f'(&(objectCategory=group){identity_filter}{ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaingroupmember(self, args=None, identity='*'):
        # get the identity group information
        entries = self.get_domaingroup(identity=identity)
        if len(entries) == 0:
            logging.info("No group found")
            return
        elif len(entries) > 1:
            logging.info("Multiple group found. Probably try searching with distinguishedName")
            return

        group_identity_sam = entries[0]['sAMAccountName'].values[0]
        group_identity_dn = entries[0]['distinguishedName'].values[0]

        ldap_filter = f"(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={group_identity_dn}))"
        self.ldap_session.search(self.root_dn, ldap_filter, attributes='*')

        # create a new entry structure
        new_entries = []
        for entry in self.ldap_session.entries:
            attr = {}
            member_infos = {}
            member_infos['GroupDomainName'] = group_identity_sam
            member_infos['GroupDistinguishedName'] = group_identity_dn
            member_infos['MemberDomain'] = entry['userPrincipalName'].values[0].split("@")[-1]
            member_infos['MemberName'] = entry['sAMAccountName'].values[0]
            member_infos['MemberDistinguishedName'] = entry['distinguishedName'].values[0]
            member_infos['MemberSID'] = entry['objectSid'].values[0]

            attr['attributes'] = member_infos
            new_entries.append(attr.copy())

        return new_entries

    def get_domaingpo(self, args=None, properties='*', identity='*'):
        ldap_filter = ""
        identity_filter = f"(cn={identity})"
        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-DomainGPO] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        ldap_filter = f'(&(objectCategory=groupPolicyContainer){identity_filter}{ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaingpolocalgroup(self, args=None, identity='*'):
        new_entries = []
        entries = self.get_domaingpo(identity=identity)
        if len(entries) == 0:
            logging.error("No GPO object found")
            return
        for entry in entries:
            new_dict = {}
            try:
                gpcfilesyspath = f"{entry['gPCFileSysPath'].values[0]}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
                if self.use_kerberos:
                    conn = self.conn.init_smb_session(self.kdcHost)
                else:
                    conn = self.conn.init_smb_session(self.dc_ip)
                share = 'sysvol'
                filepath = ''.join(gpcfilesyspath.lower().split(share)[1:])

                fh = BytesIO()
                try:
                    conn.getFile(share, filepath, fh.write)
                except:
                    pass
                output = fh.getvalue()
                encoding = chardet.detect(output)["encoding"]
                error_msg = "[-] Output cannot be correctly decoded, are you sure the text is readable ?"
                if encoding:
                    data_content = output.decode(encoding)
                    found, infobject = parse_inicontent(filecontent=data_content)
                    if found:
                        #for i in infobject: # i = dict
                        #    new_dict['attributes'] = {'GPODisplayName': entry['displayName'].values[0],'GroupSID':i['sid'],'GroupMemberOf': i['memberof'], 'GroupMembers': i['memberof']}

                        if len(infobject) == 2:
                            new_dict['attributes'] = {'GPODisplayName': entry['displayName'].values[0], 'GPOName': entry['name'].values[0], 'GPOPath': entry['gPCFileSysPath'].values[0], 'GroupName': self.convertfrom_sid(infobject[0]['sids']),'GroupSID':infobject[0]['sids'],'GroupMemberOf': f"{infobject[0]['memberof']}" if infobject[0]['memberof'] else "{}", 'GroupMembers': f"{infobject[1]['members']}" if infobject[1]['members'] else "{}"}
                            new_entries.append(new_dict.copy())
                        else:
                            for i in range(0,len(infobject),2):
                                new_dict['attributes'] = {'GPODisplayName': entry['displayName'].values[0], 'GPOName': entry['name'].values[0], 'GPOPath': entry['gPCFileSysPath'].values[0], 'GroupName':self.convertfrom_sid(infobject[0]['sids']) ,'GroupSID':infobject[i]['sids'],'GroupMemberOf': f"{infobject[i]['memberof']}" if infobject[i]['memberof'] else "{}", 'GroupMembers': f"{infobject[i+1]['members']}" if infobject[i+1]['members'] else "{}"}
                                new_entries.append(new_dict.copy())
                    fh.close()
                else:
                    fh.close()
                    continue

            except ldap3.core.exceptions.LDAPKeyError as e:
                pass
        return new_entries

    def get_domaintrust(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(objectClass=trustedDomain)'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        switcher_trustDirection = {
            0: "Disabled",
            1: "Inbound",
            2: "Outbound",
            3: "Bidirectional",
        }
        switcher_trusttype = {
            1: "WINDOWS_NON_ACTIVE_DIRECTORY",
            2: "WINDOWS_ACTIVE_DIRECTORY",
            3: "MIT",
        }
        switcher_trustAttributes = {
            1 : "NON_TRANSITIVE",
            2 : "UPLEVEL_ONLY",
            4 : "QUARANTINED_DOMAIN",
            8 : "FOREST_TRANSITIVE",
            16 : "CROSS_ORGANIZATION",
            32 : "WITHIN_FOREST",
            64 : "TREAT_AS_EXTERNAL",
            128 : "USES_RC4_ENCRYPTION",
            512 : "CROSS_ORGANIZATION_NO_TGT_DELEGATION",
            2048 : "CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION",
            1024 : "PIM_TRUST",

        }
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        new_entries = []
        for entry in self.ldap_session.entries:
            try:
                for index in range(len(entry['trustDirection'].values)):
                    entry['trustDirection'].values[index] = switcher_trustDirection.get(entry['trustDirection'].values[index])
            except:
                pass
            try:
                for index in range(len(entry['trustType'].values)):
                    entry['trustType'].values[index] = switcher_trusttype.get(entry['trustType'].values[index])
            except:
                pass
            try:
                for index in range(len(entry['trustAttributes'].values)):
                    entry['trustAttributes'].values[index] = switcher_trustAttributes.get(entry['trustAttributes'].values[index])
            except:
                pass
        return self.ldap_session.entries

    def convertfrom_sid(self, objectsid, args=None, output=False):
        ldap_filter = f"(|(|(objectSid={objectsid})))"
        logging.debug(f"LDAP search filter: {ldap_filter}")
        domain_name = self.get_domain()[0]['name'].values[0].upper()
        identity = switcher_sid.get(objectsid)
        if identity:
            identity = f"{domain_name}\\{identity}"
        else:
            self.ldap_session.search(self.root_dn,ldap_filter,attributes=['sAMAccountName','name'])
            if len(self.ldap_session.entries) != 0:
                try:
                    identity = f"{domain_name}\\{self.ldap_session.entries[0]['sAMAccountName'].values[0]}"
                except IndexError:
                    identity = f"{domain_name}\\{self.ldap_session.entries[0]['name'].value}"
            else:
                logging.info("No objects found")
                return
        if output:
            print(identity)
        return identity

    def get_domain(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(objectClass=domain)'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries

    def get_domaindnszone(self, args=None, properties='*'):
        ldap_filter = "(objectClass=dnsZone)"
        search_base = f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}"
        self.ldap_session.search(search_base, ldap_filter, attributes=properties)
        return self.ldap_session.entries

    def get_domainca(self, args=None, properties='*'):
        ca_fetch = CAEnum(self.ldap_session, self.root_dn)
        entries = ca_fetch.fetch_enrollment_services(properties)
        return entries

    def add_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties='distinguishedName')
        user_entry = self.get_domainobject(identity=members,properties='distinguishedName')
        if len(group_entry) == 0:
            logging.error(f'Group {identity} not found in domain')
            return
        if len(user_entry) == 0:
            logging.error(f'User {members} not found in domain')
            return
        targetobject = group_entry[0]
        userobject = user_entry[0]
        succeeded = self.ldap_session.modify(targetobject.entry_dn,{'member': [(ldap3.MODIFY_ADD, [userobject.entry_dn])]})
        if not succeeded:
            print(self.ldap_session.result['message'])
        return succeeded

    def remove_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties='distinguishedName')
        user_entry = self.get_domainobject(identity=members,properties='distinguishedName')
        if len(group_entry) == 0:
            logging.error(f'Group {identity} not found in domain')
            return
        if len(user_entry) == 0:
            logging.error(f'User {members} not found in domain')
            return
        targetobject = group_entry[0]
        userobject = user_entry[0]
        succeeded = self.ldap_session.modify(targetobject.entry_dn,{'member': [(ldap3.MODIFY_DELETE, [userobject.entry_dn])]})
        if not succeeded:
            print(self.ldap_session.result['message'])
        return succeeded

    def remove_domainuser(self, identity):
        if not identity:
            logging.error('Identity is required')
            return
        entries = self.get_domainuser(identity=identity)
        if len(entries) == 0:
            logging.error('Identity not found in domain')
            return
        identity_dn = entries[0].entry_dn
        au = ADUser(self.ldap_session, self.root_dn)
        au.removeUser(identity_dn)

    def add_domainuser(self, username, userpass):
        parent_dn_entries = self.get_domainobject(identity="Users")
        if len(parent_dn_entries) == 0:
            logging.error('Users parent DN not found in domain')
            return
        au = ADUser(self.ldap_session, self.root_dn, parent = parent_dn_entries[0].entry_dn)
        if au.addUser(username, userpass):
            return True
        else:
            return False

    def add_domainobjectacl(self, args):
        c = NTLMRelayxConfig()
        c.addcomputer = 'idk lol'
        c.target = self.dc_ip

        setattr(args, "delete", False)

        if '\\' not in args.principalidentity or '/' not in args.principalidentity:
            username = f'{self.domain}/{args.principalidentity}'
        else:
            username = args.principalidentity

        principal_entries = self.get_domainobject(identity=args.principalidentity, properties=['objectSid'])
        if len(principal_entries) == 0:
            logging.error('Principal Identity object not found in domain')
            return
        principalidentity_dn = principal_entries[0].entry_dn
        principalidentity_sid = principal_entries[0]['objectSid'].values[0]
        setattr(args,'principalidentity_dn', principalidentity_dn)
        setattr(args,'principalidentity_sid', principalidentity_sid)
        logging.info(f'Found principal identity dn {principalidentity_dn}')

        target_entries = self.get_domainobject(identity=args.targetidentity, properties=['objectSid'])
        if len(target_entries) == 0:
            logging.error('Target Identity object not found in domain')
            return
        targetidentity_dn = target_entries[0].entry_dn
        targetidentity_sid = target_entries[0]['objectSid'].values[0]
        setattr(args,'targetidentity_dn', targetidentity_dn)
        setattr(args,'targetidentity_sid', targetidentity_sid)
        logging.info(f'Found target identity dn {targetidentity_dn}')

        logging.info(f'Adding {args.rights} privilege to {args.targetidentity}')
        la = LDAPAttack(config=c, LDAPClient=self.ldap_session, username=username, root_dn=self.root_dn, args=args)
        if args.rights in ['all','dcsync','writemembers','resetpassword']:
            la.aclAttack()
        elif args.rights in ['rbcd']:
            la.delegateAttack()
        elif args.rights in ['shadowcred']:
            la.shadowCredentialsAttack()

    def remove_domainobjectacl(self, args):
        c = NTLMRelayxConfig()
        c.addcomputer = 'idk lol'
        c.target = self.dc_ip

        setattr(args, "delete", True)

        if '\\' not in args.principalidentity or '/' not in args.principalidentity:
            username = f'{self.domain}/{args.principalidentity}'
        else:
            username = args.principalidentity

        principal_entries = self.get_domainobject(identity=args.principalidentity)
        if len(principal_entries) == 0:
            logging.error('Principal Identity object not found in domain')
            return
        principalidentity_dn = principal_entries[0].entry_dn
        principalidentity_sid = principal_entries[0]['ObjectSid'].values[0]
        setattr(args,'principalidentity_dn', principalidentity_dn)
        setattr(args,'principalidentity_sid', principalidentity_sid)
        logging.info(f'Found principal identity dn {principalidentity_dn}')

        target_entries = self.get_domainobject(identity=args.targetidentity)
        if len(target_entries) == 0:
            logging.error('Target Identity object not found in domain')
            return
        targetidentity_dn = target_entries[0].entry_dn
        targetidentity_sid = target_entries[0]['ObjectSid'].values[0]
        setattr(args,'targetidentity_dn', targetidentity_dn)
        setattr(args,'targetidentity_sid', targetidentity_sid)
        logging.info(f'Found target identity dn {targetidentity_dn}')
        entries = self.get_domainobject(identity=args.principalidentity)
        if len(entries) == 0:
            logging.error('Target object not found in domain')
            return

        logging.info(f'Restoring {args.rights} privilege on {args.targetidentity}')
        la = LDAPAttack(config=c, LDAPClient=self.ldap_session, username=username, root_dn=self.root_dn, args=args)
        la.aclAttack()

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

        if self.use_ldaps:
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

    def get_namedpipes(self, args=None):
        host = ""
        if args.computer:
            if is_ipaddress(args.computer):
                host = args.computer
            else:
                host = host2ip(args.computer, self.dc_ip, 3, True)
        elif args.computername:
            if is_ipaddress(args.computername):
                host = args.computername
            else:
                host = host2ip(args.computername, self.dc_ip, 3, True)
        else:
            logging.error(f'Host is required')
            return

        if not host:
            logging.error('Host not found')
            return

        available_pipes = []
        binding_params = {
            'lsarpc': {
                'stringBinding': r'ncacn_np:%s[\PIPE\lsarpc]' % host,
                'protocol': 'MS-EFSRPC',
                'description': 'Encrypting File System Remote (EFSRPC) Protocol',
            },
            'efsr': {
                'stringBinding': r'ncacn_np:%s[\PIPE\efsrpc]' % host,
                'protocol': 'MS-EFSR',
                'description': 'Encrypting File System Remote (EFSRPC) Protocol',
            },
            'samr': {
                'stringBinding': r'ncacn_np:%s[\PIPE\samr]' % host,
                'protocol': 'MS-SAMR',
                'description': 'Security Account Manager (SAM)',
            },
            'lsass': {
                'stringBinding': r'ncacn_np:%s[\PIPE\lsass]' % host,
                'protocol': 'N/A',
                'description': 'N/A',
            },
            'netlogon': {
                'stringBinding': r'ncacn_np:%s[\PIPE\netlogon]' % host,
                'protocol': 'MS-NRPC',
                'description': 'Netlogon Remote Protocol',
            },
            'spoolss': {
                'stringBinding': r'ncacn_np:%s[\PIPE\spoolss]' % host,
                'protocol': 'MS-RPRN',
                'description': 'Print System Remote Protocol',
            },
            'DAV RPC SERVICE': {
                'stringBinding': r'ncacn_np:%s[\PIPE\DAV RPC SERVICE]' % host,
                'protocol': 'WebClient',
                'description': 'WebDAV WebClient Service',
            },
            'netdfs': {
                'stringBinding': r'ncacn_np:%s[\PIPE\netdfs]' % host,
                'protocol': 'MS-DFSNM',
                'description': 'Distributed File System (DFS)',
            },
            'atsvc': {
                'stringBinding': r'ncacn_np:%s[\PIPE\atsvc]' % host,
                'protocol': 'ATSvc',
                'description': 'Microsoft AT-Scheduler Service',
            },
        }
        #self.rpc_conn = CONNECTION(self.args)
        if args.name:
            if args.name in list(binding_params.keys()):
                pipe = args.name
                if self.conn.connectRPCTransport(host, binding_params[pipe]['stringBinding'], auth=False):
                    #logging.info(f"Found named pipe: {args.name}")
                    pipe_attr = {'attributes': {'Name': pipe, 'Protocol':binding_params[pipe]['protocol'],'Description':binding_params[pipe]['description'],'Authenticated':f'{bcolors.WARNING}No{bcolors.ENDC}'}}
                    available_pipes.append(pipe_attr)
                elif self.conn.connectRPCTransport(host, binding_params[pipe]['stringBinding']):
                    pipe_attr = {'attributes': {'Name': pipe, 'Protocol':binding_params[pipe]['protocol'],'Description':binding_params[pipe]['description'],'Authenticated':f'{bcolors.OKGREEN}Yes{bcolors.ENDC}'}}
                    available_pipes.append(pipe_attr)
            else:
                logging.error(f"Invalid pipe name")
                return
        else:
            pipes = [ 'netdfs','netlogon', 'lsarpc', 'samr', 'browser', 'spoolss', 'atsvc', 'DAV RPC SERVICE', 'epmapper', 'eventlog', 'InitShutdown', 'keysvc', 'lsass', 'LSM_API_service', 'ntsvcs', 'plugplay', 'protected_storage', 'router', 'SapiServerPipeS-1-5-5-0-70123', 'scerpc', 'srvsvc', 'tapsrv', 'trkwks', 'W32TIME_ALT', 'wkssvc','PIPE_EVENTROOT\CIMV2SCM EVENT PROVIDER', 'db2remotecmd']
            for pipe in binding_params.keys():
                # TODO: Return entries
                pipe_attr = {}
                if self.conn.connectRPCTransport(host, binding_params[pipe]['stringBinding'], auth=False):
                    # logging.info(f"Found named pipe: {pipe}")
                    pipe_attr['attributes'] = {'Name':pipe, 'Protocol': binding_params[pipe]['protocol'], 'Description':binding_params[pipe]['description'], 'Authenticated': f'{bcolors.WARNING}No{bcolors.ENDC}'}
                    available_pipes.append(pipe_attr.copy())
                elif self.conn.connectRPCTransport(host, binding_params[pipe]['stringBinding']):
                    pipe_attr = {'attributes': {'Name': pipe, 'Protocol':binding_params[pipe]['protocol'],'Description':binding_params[pipe]['description'],'Authenticated':f'{bcolors.OKGREEN}Yes{bcolors.ENDC}'}}
                    available_pipes.append(pipe_attr.copy())
        return available_pipes

    def set_domainuserpassword(self, identity, accountpassword, args=None):
        entries = self.get_domainuser(identity=identity, properties=['distinguishedName','sAMAccountName'])
        if len(entries) == 0:
            logging.error(f'No principal object found in domain')
            return
        elif len(entries) > 1:
            logging.error(f'Multiple principal objects found in domain. Use specific identifier')
            return
        logging.info(f'Principal {entries[0].entry_dn} found in domain')
        if self.use_ldaps:
            succeed = modifyPassword.ad_modify_password(self.ldap_session, entries[0].entry_dn, accountpassword, old_password=None)
            if succeed:
                logging.info(f'Password has been successfully changed for user {entries[0]["sAMAccountName"].values[0]}')
                return True
            else:
                logging.error(f'Failed to change password for {entries[0]["sAMAccountName"].values[0]}')
                return False
        else:
            try:
                #self.samr_conn = CONNECTION(self.args)
                #dce = self.samr_conn.init_samr_session()
                dce = self.conn.init_samr_session()
                if not dce:
                    logging.error('Error binding with SAMR')
                    return

                server_handle = samr.hSamrConnect(dce, self.dc_ip + '\x00')['ServerHandle']
                domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.domain)['DomainId']
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domainSID)['DomainHandle']
                userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (entries[0]['sAMAccountName'].values[0],))['RelativeIds']['Element'][0]
                opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

                req = samr.SamrSetInformationUser2()
                req['UserHandle'] = opened_user['UserHandle']
                req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
                req['Buffer'] = samr.SAMPR_USER_INFO_BUFFER()
                req['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
                req['Buffer']['Internal5']['UserPassword'] = cryptPassword(b'SystemLibraryDTC', accountpassword)
                req['Buffer']['Internal5']['PasswordExpired'] = 0

                resp = dce.request(req)
                return True
            except:
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
            if not attrs:
                logging.error("Parsing -Set value failed")
                return
            logging.info('Printing object before modifying')
            logging.info(f'Found target object {targetobject[0].entry_dn}')
            succeeded = self.ldap_session.modify(targetobject[0].entry_dn, {attrs['attr']:[(ldap3.MODIFY_REPLACE,[attrs['val']])]})

        if not succeeded:
            logging.error(self.ldap_session.result['message'])
        else:
            logging.info('Success! modified attribute for target object')

        return succeeded

    def invoke_kerberoast(self, args):
        # look for users with SPN set
        ldap_filter = ""
        ldap_filter = f"(servicePrincipalName=*)(UserAccountControl:1.2.840.113556.1.4.803:=512)(!(UserAccountControl:1.2.840.113556.1.4.803:=2))(!(objectCategory=computer))"
        if args.identity:
            ldap_filter = f"(sAMAccountName={identity})"
        ldap_filter = f"(&{ldap_filter})"
        logging.debug(f'[Invoke-Kerberoast] LDAP Filter string: {ldap_filter}')
        self.ldap_session.search(self.root_dn, ldap_filter, attributes=['servicePrincipalName', 'sAMAccountName','pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'])
        entries = self.ldap_session.entries
        # request TGS for each accounts
        target_domain = self.domain
        if args.server:
            target_domain = args.server
        userspn = GetUserSPNs(self.username, self.password, self.domain, target_domain, self.args, identity=args.identity)
        entries_out = userspn.run(entries)

        # properly formatted for output
        return entries_out

    def find_localadminaccess(self, args):
        host_entries = []
        hosts = {}

        if is_ipaddress(args.computer) or is_ipaddress(args.computername) and self.use_kerberos:
            logging.error('FQDN must be used for kerberos authentication')
            return

        if args.computer:
            if is_ipaddress(args.computer):
                hosts['address'] = args.computer
            else:
                hosts['address'] = host2ip(args.computer, self.dc_ip, 3, True)
                hosts['hostname'] = args.computer
            host_entries.append(hosts)
        elif args.computername:
            if is_ipaddress(args.computername):
                hosts['address'] = args.computername
            else:
                hosts['address'] = host2ip(args.computername, self.dc_ip, 3, True)
                hosts['hostname'] = args.computername
            host_entries.append(hosts)
        else:
            entries = self.get_domaincomputer(properties=['dnsHostName'])

            for entry in entries:
                try:
                    hosts['address'] = host2ip(entry['dnsHostName'].values[0], self.dc_ip, 3, True)
                    hosts['hostname'] = entry['dnsHostname'].values[0]
                    host_entries.append(hosts.copy())
                except IndexError:
                    pass

        local_admin_pcs = []
        for ent in host_entries:
            pc_attr = {}

            if self.use_kerberos:
                smbconn = self.conn.init_smb_session(ent['hostname'])
            else:
                smbconn = self.conn.init_smb_session(ent['address'])

            try:
                smbconn.connectTree("C$")
                pc_attr['attributes'] = {'Name': ent['address'], 'Hostname': ent['hostname']}
                local_admin_pcs.append(pc_attr.copy())
            except:
                pass

        return local_admin_pcs

    def get_shares(self, args):
        if is_ipaddress(args.computer) or is_ipaddress(args.computername) and self.use_kerberos:
            logging.error('FQDN must be used for kerberos authentication')
            return

        if self.use_kerberos:
            host = args.computer if args.computer else args.computername
        else:
            if args.computer:
                if is_ipaddress(args.computer):
                    host = args.computer
                else:
                    host = host2ip(args.computer, self.dc_ip, 3, True)
            elif args.computername:
                if is_ipaddress(args.computername):
                    host = args.computername
                else:
                    host = host2ip(args.computername, self.dc_ip, 3, True)
            else:
                logging.error(f'Host is required')
                return

        if not host:
            return

        if self.use_kerberos:
            client = self.conn.init_smb_session(host)
        else:
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

            print(f'{share_info["name"].ljust(15)}{share_info["remark"].ljust(25)}{host}')
        print()

    def parse_object(self,obj):
        if '{' not in obj and '}' not in obj:
            logging.error('Error format retrieve, (e.g. {dnsHostName=temppc.contoso.local})')
            return None
        attrs = dict()
        try:
            regex = r'\{(.*?)\}'
        except:
            raise Exception('Error regex parsing')
        res = re.search(regex,obj)
        dd = res.group(1).replace("'","").replace('"','').split("=")
        attrs['attr'] = dd[0].strip()
        attrs['val'] = dd[1].strip()
        return attrs
