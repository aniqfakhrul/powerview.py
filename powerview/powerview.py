#!/usr/bin/env python3
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.ldap import ldaptypes
from impacket.dcerpc.v5 import srvs
from impacket.dcerpc.v5.ndr import NULL

from powerview.modules.ca import CAEnum, PARSE_TEMPLATE, UTILS
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
import re

class PowerView:
    def __init__(self, conn, args, target_server=None, target_domain=None):
        self.conn = conn
        self.args = args
        self.username = args.username
        self.password = args.password

        if target_domain:
            self.domain = target_domain
        else:
            self.domain = args.domain.lower()

        self.lmhash = args.lmhash
        self.nthash = args.nthash
        self.use_ldaps = args.use_ldaps
        self.nameserver = args.nameserver
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
        self.flatName = self.ldap_server.info.other["ldapServiceName"][0].split("@")[-1].split(".")[0]

    def get_domainuser(self, args=None, properties=[], identity=None, searchbase=None):
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
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn 

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

        logging.debug(f'[Get-DomainUser] LDAP search filter: {ldap_filter}')

        # in case need more then 1000 entries
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
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
        searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

        ldap_filter = f'(userAccountControl:1.2.840.113556.1.4.803:=8192)'
        logging.debug(f'[Get-DomainController] LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
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

    def get_domainobject(self, args=None, properties=['*'], identity='*', identity_filter=None, searchbase=None, sd_flag=None):
        if sd_flag:
            # Set SD flags to only query for DACL and Owner
            controls = security_descriptor_control(sdflags=sd_flag)
        else:
            controls = None

        ldap_filter = ""
        if not identity_filter:
            identity_filter = f"(|(samAccountName={identity})(name={identity})(displayname={identity})(objectSid={identity})(distinguishedName={identity})(dnshostname={identity}))"

        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

        logging.debug(f"[Get-DomainObject] Using search base: {searchbase}")

        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-DomainObject] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        ldap_fiter = f"(&{ldap_filter})"
        ldap_filter = f'(&{identity_filter}{ldap_filter})'
        logging.debug(f'[Get-DomainObject] LDAP search filter: {ldap_filter}')

        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True, controls=controls)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries

    def get_domainobjectowner(self, identity=None, searchbase=None, args=None):
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
        
        if not identity:
            identity = '*'
            logging.info("[Get-DomainObjectOwner] Recursing all domain objects. This might take a while")

        objects = self.get_domainobject(identity=identity, properties=[
            'cn',
            'nTSecurityDescriptor',
            'sAMAccountname',
            'ObjectSID',
            'distinguishedName',
        ], searchbase=searchbase, sd_flag=0x01)

        if len(objects) == 0:
            logging.error("[Get-DomainObjectOwner] Identity not found in domain")
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
        logging.debug(f'[Get-DomainOU] LDAP search filter: {ldap_filter}')
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

    def get_domainobjectacl(self, searchbase=None, args=None):
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

        #enumerate available guids
        guids_dict = {}
        self.ldap_session.search(f"CN=Extended-Rights,CN=Configuration,{self.root_dn}", "(rightsGuid=*)",attributes=['displayName','rightsGuid'])
        for entry in self.ldap_session.entries:
            guids_dict[entry['rightsGuid'].value] = entry['displayName'].value
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
            identity_entries = self.get_domainobject(identity=identity,properties=['objectSid','distinguishedName'], searchbase=searchbase)
            if len(identity_entries) == 0:
                logging.error(f'[Get-DomainObjectAcl] Identity {args.identity} not found. Try to use DN')
                return
            elif len(identity_entries) > 1:
                logging.error(f'[Get-DomainObjectAcl] Multiple identities found. Use exact match')
                return
            logging.debug(f'[Get-DomainObjectAcl] Target identity found in domain {"".join(identity_entries[0]["attributes"]["distinguishedName"])}')
            identity = "".join(identity_entries[0]['attributes']['distinguishedName'])
        else:
            logging.info('[Get-DomainObjectAcl] Recursing all domain objects. This might take a while')

        logging.debug(f"[Get-DomainObjectAcl] Searching for identity %s" % (identity))
        self.ldap_session.search(searchbase, f'(distinguishedName={identity})', attributes=['nTSecurityDescriptor','sAMAccountName','distinguishedName','objectSid'], controls=security_descriptor_control(sdflags=0x04))
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
        searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

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
                ldap_filter += f'(ms-Mcs-AdmPwd=*)'
                properties += ['ms-MCS-AdmPwd','ms-Mcs-AdmPwdExpirationTime']
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
        logging.debug(f'[Get-DomainComputer] LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
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
                ip = host2ip(_entries['attributes']['dnsHostName'], self.nameserver, 3, True)
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
        logging.debug(f'[Get-DomainGroup] LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(self.root_dn,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries

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
        searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

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
        logging.debug(f'[Get-DomainGroup] LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries

    def get_domainforeigngroupmember(self, args=None):
        group_members = self.get_domaingroupmember(multiple=True)
        cur_domain_sid = self.get_domain()[0]['attributes']['objectSid']

        if not group_members:
            logging.info("[Get-DomainForeignGroupMember] No group members found")
            return
        
        new_entries = []
        for member in group_members:
            member_sid = member['attributes']['MemberSID']
            if cur_domain_sid not in member_sid:
                new_entries.append(member)

        return new_entries

    def get_domainforeignuser(self, args=None):
        domain_users = self.get_domainuser()

        entries = []
        for user in domain_users:
            user_san = user['attributes']['sAMAccountName']
            user_memberof = user['attributes']['memberOf']
            if isinstance(user_memberof, str):
                user_memberof = [user_memberof]

            for group in user_memberof:
                group_domain = dn2domain(group)
                group_root_dn = dn2rootdn(group)
                if group_domain.casefold() != self.domain.casefold():
                    _, ldap_session = self.conn.init_ldap_session(ldap_address=group_domain)
                    ldap_filter = f"(&(objectCategory=group)(distinguishedName={group}))"
                    succeed = ldap_session.search(group_root_dn, ldap_filter, attributes='*')
                    if not succeed:
                        logging.error("[Get-DomainForeignUser] Failed ldap query")
                    if ldap_session.entries:
                        ent = ldap_session.entries[0]
                    entries.append(
                            {'attributes':{
                                    'UserDomain': dn2domain(user['attributes']['distinguishedName']),
                                    'UserName': user_san,
                                    'UserDistinguishedName': user['attributes']['distinguishedName'],
                                    'GroupDomain': group_domain,
                                    'GroupName': ent['name'].value,
                                    'GroupDistinguishedName': group
                                }
                             }
                            )

        return entries


    def get_domaingroupmember(self, args=None, identity='*', multiple=False):
        # get the identity group information
        entries = self.get_domaingroup(identity=identity)

        if len(entries) == 0:
            logging.info("[Get-DomainGroupMember] No group found")
            return

        if len(entries) > 1 and not multiple:
            logging.info("[Get-DomainGroupMember] Multiple group found. Probably try searching with distinguishedName")
            return

        # create a new entry structure
        new_entries = []
        for ent in entries:
            haveForeign = False
            group_identity_sam = ent['attributes']['sAMAccountName']
            group_identity_dn = ent['attributes']['distinguishedName']
            group_members = ent['attributes']['member']
            if isinstance(group_members, str):
                group_members = [group_members]
            
            for dn in group_members:
                if len(dn) != 0 and dn2domain(dn).casefold() != self.domain.casefold():
                    haveForeign = True
                    break

            if haveForeign:
                for member_dn in group_members:
                    member_root_dn = dn2rootdn(member_dn)
                    member_domain = dn2domain(member_dn)
                    ldap_filter = f"(&(objectCategory=person)(objectClass=user)(|(distinguishedName={member_dn})))"

                    if len(member_domain) != 0 and member_domain.casefold() != self.domain.casefold():
                        _, ldap_session = self.conn.init_ldap_session(ldap_address=member_domain)
                        succeed = ldap_session.search(member_root_dn, ldap_filter, attributes='*')
                        if not succeed:
                            logging.error(f"[Get-DomainGroupMember] Failed to query for {member_dn}")
                            return
                        entries = ldap_session.entries
                    else:
                        self.ldap_session.search(self.root_dn, ldap_filter, attributes='*')
                        entries = self.ldap_session.entries

                    for ent in entries:
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
                            member_infos['MemberDomain'] = ent['userPrincipalName'].value.split("@")[-1]
                        except:
                            member_infos['MemberDomain'] = self.domain
                        try:
                            member_infos['MemberName'] = ent['sAMAccountName'].value
                        except:
                            pass
                        try:
                            member_infos['MemberDistinguishedName'] = ent['distinguishedName'].value
                        except:
                            pass
                        try:
                            member_infos['MemberSID'] = ent['objectSid'].value
                        except:
                            pass

                        attr['attributes'] = member_infos
                        new_entries.append(attr.copy())
            else:
                ldap_filter = f"(&(samAccountType=805306368)(memberof:1.2.840.113556.1.4.1941:={group_identity_dn}))"
                self.ldap_session.search(self.root_dn, ldap_filter, attributes='*')

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
        searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn

        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-DomainGPO] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f"{args.ldapfilter}"

        ldap_filter = f'(&(objectCategory=groupPolicyContainer){identity_filter}{ldap_filter})'
        logging.debug(f'[Get-DomainGPO] LDAP search filter: {ldap_filter}')
        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries

    def get_domaingpolocalgroup(self, args=None, identity='*'):
        new_entries = []
        entries = self.get_domaingpo(identity=identity)
        if len(entries) == 0:
            logging.error("[Get-DomainGPOLocalGroup] No GPO object found")
            return
        for entry in entries:
            new_dict = {}
            try:
                gpcfilesyspath = f"{entry['attributes']['gPCFileSysPath']}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

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
        logging.debug(f'[Get-DomainTrust] LDAP search filter: {ldap_filter}')

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
                logging.debug(f"[ConvertFrom-SID] No objects found for {objectsid}")
                return objectsid
        if output:
            print("%s" % identity)
        return identity

    def get_domain(self, args=None, properties=['*'], identity=None, searchbase=None):
        identity = '*' if not identity else identity

        identity_filter = f"(|(name={identity})(distinguishedName={identity}))"
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
        ldap_filter = ""

        if args:
            if args.ldapfilter:
                logging.debug(f'[Get-Domain] Using additional LDAP filter: {args.ldapfilter}')
                ldap_filter += f'{args.ldapfilter}'

        ldap_filter = f'(&(objectClass=domain){identity_filter}{ldap_filter})'
        logging.debug(f'[Get-Domain] LDAP search filter: {ldap_filter}')

        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties, paged_size = 1000, generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries

    def get_domaindnszone(self, identity=None, properties=[], searchbase=None, args=None):
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
        
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}" 

        identity_filter = f"(name={identity})"
        ldap_filter = f"(&(objectClass=dnsZone){identity_filter})"

        logging.debug(f"[Get-DomainDNSZone] LDAP filter string: {ldap_filter}")

        entries = []
        entry_generator = self.ldap_session.extend.standard.paged_search(searchbase,ldap_filter,attributes=properties,paged_size = 1000,generator=True)
        for _entries in entry_generator:
            if _entries['type'] != 'searchResEntry':
                continue
            strip_entry(_entries)
            entries.append({"attributes":_entries["attributes"]})
        return entries

    def get_domaindnsrecord(self, identity=None, zonename=None, properties=[], searchbase=None, args=None):
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
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}" 

        zones = self.get_domaindnszone(identity=zonename, properties=['distinguishedName'], searchbase=searchbase)
        entries = []
        identity_filter = f"(|(name={identity})(distinguishedName={identity}))"
        ldap_filter = f'(&(objectClass=dnsNode){identity_filter})'
        for zone in zones:
            logging.debug(f"[Get-DomainDNSRecord] Search base: {zone['attributes']['distinguishedName']}")

            entry_generator = self.ldap_session.extend.standard.paged_search(zone['attributes']['distinguishedName'],ldap_filter,attributes=def_prop, paged_size = 1000, generator=True)
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
                    if properties:
                        new_dict = filter_entry(_entries["attributes"], properties)
                    else:
                        new_dict = _entries["attributes"]

                    entries.append({
                        "attributes": new_dict
                    })
        return entries

    def get_domainca(self, args=None, properties=None):
        def_prop = [
            "cn",
            "name",
            "dNSHostName",
            "cACertificateDN",
            "cACertificate",
            "certificateTemplates",
            "objectGUID",
            "distinguishedName",
            "displayName",
        ]
        properties = def_prop if not properties else properties

        ca_fetch = CAEnum(self.ldap_session, self.root_dn)
        entries = ca_fetch.fetch_enrollment_services(properties)

        if args.check_web_enrollment:
            # check for web enrollment
            for i in range(len(entries)):
                target_name = entries[i]['dnsHostName'].value
                web_enrollment = ca_fetch.check_web_enrollment(target_name,self.nameserver)

                if not web_enrollment and self.nameserver:
                    logging.debug("Trying to check web enrollment with IP")
                    web_enrollment = ca_fetch.check_web_enrollment(target_name,self.nameserver,use_ip=True)

                entries[i] = modify_entry(
                    entries[i],
                    new_attributes = {
                        "WebEnrollment": web_enrollment
                    }
                )

        return entries

    def remove_domaincatemplate(self, identity, searchbase=None, args=None):
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        ca_fetch = CAEnum(self.ldap_session, self.root_dn)
        templates = ca_fetch.get_certificate_templates(identity=identity, ca_search_base=searchbase)
        if len(templates) > 1:
            logging.error(f"[Remove-DomainCATemplate] Multiple certificates found with name {identity}")
            return
        if len(templates) == 0:
            logging.error(f"[Remove-DomainCATemplate] Template {identity} not found in domain")
            return

        # delete operation
        # delete template from Certificate Templates
        # unissue the template
        cas = ca_fetch.fetch_enrollment_services()
        for ca in cas:
            if self.ldap_session.modify(ca["distinguishedName"].value, {'certificateTemplates':[(ldap3.MODIFY_DELETE,[templates[0]["name"].value])]}):
                logging.info(f"[Remove-DomainCATemplate] Template {templates[0]['name'].value} is no longer issued")
            else:
                logging.warning(f"[Remove-DomainCATemplate] Failed to remove template from CA. Skipping...")
        
        # delete template oid
        oid = templates[0]["msPKI-Cert-Template-OID"].value
        template_oid = self.get_domainobject(identity_filter=f'(|(msPKI-Cert-Template-OID={oid}))',searchbase=f"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}", properties=['distinguishedName'])
        if len(template_oid) > 1:
            logging.error("[Remove-DomainCATemplate] Multiple OIDs found. Ignoring..")
        elif len(template_oid) == 0:
            logging.error("[Remove-DomainCATemplate] Template OID not found in domain. Ignoring...")

        oid_dn = template_oid[0]['attributes']['distinguishedName']
        logging.debug(f"[Remove-DomainCATemplate] Found template oid {oid_dn}")
        logging.debug(f"[Remove-DomainCATemplate] Deleting {oid_dn}")
        if self.ldap_session.delete(oid_dn):
            logging.info(f"[Remove-DomainCATemplate] Template oid {oid} removed")
        else:
            logging.warning(f"[Remove-DomainCATemplate] Failed to remove template oid {oid}. Ignoring...")

        # delete template
        if self.ldap_session.delete(templates[0].entry_dn):
            logging.info(f"[Remove-DomainCATemplate] {identity} template deleted from certificate store")
            return True
        else:
            logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Remove-DomainCATemplate] Failed to delete template {identity} from certificate store")
            return False

    def add_domaincatemplateacl(self, name, principalidentity, rights=None, ca_fetch=None, args=None):
        if not rights:
            if args and hasattr(args, 'rights') and args.rights:
                rights = args.rights
            else:
                rights = 'all'

        principal_identity = self.get_domainobject(identity=principalidentity, properties=[
            'objectSid',
            'distinguishedName',
            'sAMAccountName'
        ])
        if len(principal_identity) > 1:
            logging.error("[Add-DomainCATemplateAcl] More than one target identity found")
            return
        elif len(principal_identity) == 0:
            logging.error("[Add-DomainCATemplateAcl] Target identity not found in domain")
            return

        logging.debug(f"[Add-DomainCATemplateAcl] Found target identity {principal_identity[0].get('attributes').get('sAMAccountName')}")

        if not ca_fetch:
            ca_fetch = CAEnum(self.ldap_session, self.root_dn)

        template = ca_fetch.get_certificate_templates(identity=name)
        
        if len(template) == 0:
            logging.error(f"[Add-DomainCATemplateAcl] {name} template not found in domain")
            return
        elif len(template) > 1:
            logging.error("[Add-DomainCATemplateAcl] Multiple templates found")
            return

        logging.debug(f"[Add-DomainCATemplateAcle] Template {name} exists")

        template_parser = PARSE_TEMPLATE(template[0])
        secDesc = template_parser.modify_dacl(principal_identity[0].get('attributes').get('objectSid'), rights)
        succeed = self.set_domainobject(  
                                name,
                                _set = {
                                        'attribute': 'nTSecurityDescriptor',
                                        'value': [secDesc]
                                    },
                                searchbase=f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}",
                                sd_flag = 0x04
                              )
        if succeed:
            logging.info(f"[Add-DomainCATemplateAcl] Successfully modified {name} template acl")
            return True
        else:
            logging.error(f"[Add-DomainCATemplateAcl] Failed to modify {name} template ACL")
            return False

    def add_domaincatemplate(self, displayname, name=None, args=None):
        ca_fetch = CAEnum(self.ldap_session, self.root_dn)

        if not name:
            logging.debug("[Add-DomainCATemplate] No certificate name given, using DisplayName instead")
            name = displayname.replace(" ","").strip()

        # check if template exists
        ex_templates = ca_fetch.get_certificate_templates(identity=name)
        if len(ex_templates) > 0:
            logging.error(f"[Add-DomainCATemplate] Template {name} already exists")
            return

        if args.duplicate:
            # query for other cert template
            identity = args.duplicate
            entries = ca_fetch.get_certificate_templates(identity=identity, properties=['*'])
            if len(entries) > 1:
                logging.error("[Add-DomainCATemplate] More than one certificate templates found")
                return False
            elif len(entries) == 0:
                logging.error("[Add-DomainCATemplate] No certificate template found")
                return False

            logging.info(f"[Add-DomainCATemplate] Duplicating existing template {args.duplicate} properties")
            default_template = {
                'DisplayName': displayname,
                'name': name,
                'msPKI-Certificate-Name-Flag' : int(entries[0]['msPKI-Certificate-Name-Flag'].value) if entries[0]['msPKI-Certificate-Name-Flag'] else 1,
                'msPKI-Enrollment-Flag': int(entries[0]['msPKI-Enrollment-Flag'].value) if entries[0]['msPKI-Enrollment-Flag'] else 41,
                'revision': int(entries[0]['revision'].value) if entries[0]['revision'] else 3,
                'pKIDefaultKeySpec': int(entries[0]['pKIDefaultKeySpec'].value) if entries[0]['pKIDefaultKeySpec'] else 1,
                'msPKI-RA-Signature': int(entries[0]['msPKI-RA-Signature'].value) if entries[0]['msPKI-RA-Signature'] else 0,
                'pKIMaxIssuingDepth': int(entries[0]['pKIMaxIssuingDepth'].value) if entries[0]['pKIMaxIssuingDepth'] else 0,
                'msPKI-Template-Schema-Version': int(entries[0]['msPKI-Template-Schema-Version'].value) if entries[0]['msPKI-Template-Schema-Version'] else 1,
                'msPKI-Template-Minor-Revision': int(entries[0]['msPKI-Template-Minor-Revision'].value) if entries[0]['msPKI-Template-Minor-Revision'] else 1,
                'msPKI-Private-Key-Flag': int(entries[0]['msPKI-Private-Key-Flag'].value) if entries[0]['msPKI-Private-Key-Flag'] else 16842768,
                'msPKI-Minimal-Key-Size': int(entries[0]['msPKI-Minimal-Key-Size'].value) if entries[0]['msPKI-Minimal-Key-Size'] else 2048,
                "pKICriticalExtensions": entries[0]['pKICriticalExtensions'].values if entries[0]['pKICriticalExtensions'] else ["2.5.29.19", "2.5.29.15"],
                "pKIExtendedKeyUsage": entries[0]['pKIExtendedKeyUsage'].values if entries[0]['pKIExtendedKeyUsage'] else ["1.3.6.1.4.1.311.10.3.4","1.3.6.1.5.5.7.3.4","1.3.6.1.5.5.7.3.2"],
                'nTSecurityDescriptor': entries[0]['nTSecurityDescriptor'].raw_values[0],
                "pKIExpirationPeriod": entries[0]['pKIExpirationPeriod'].raw_values[0],
                "pKIOverlapPeriod": entries[0]['pKIOverlapPeriod'].raw_values[0],
                "pKIDefaultCSPs": entries[0]['pKIDefaultCSPs'].value if entries[0]['pKIDefaultCSPs'] else b"1,Microsoft Enhanced Cryptographic Provider v1.0",
            }
        else:
            default_template = {
                'DisplayName': displayname,
                'name': name,
                'msPKI-Certificate-Name-Flag' : 1,
                'msPKI-Enrollment-Flag': 41,
                'revision': 3,
                'pKIDefaultKeySpec': 1,
                'msPKI-RA-Signature': 0,
                'pKIMaxIssuingDepth': 0,
                'msPKI-Template-Schema-Version': 1,
                'msPKI-Template-Minor-Revision': 1,
                'msPKI-Private-Key-Flag': 16842768,
                'msPKI-Minimal-Key-Size': 2048,
                "pKICriticalExtensions": ["2.5.29.19", "2.5.29.15"],
                "pKIExtendedKeyUsage": [
                    "1.3.6.1.4.1.311.10.3.4",
                    "1.3.6.1.5.5.7.3.4",
                    "1.3.6.1.5.5.7.3.2"
                ],
                "pKIExpirationPeriod": b"\x00@\x1e\xa4\xe8e\xfa\xff",
                "pKIOverlapPeriod": b"\x00\x80\xa6\n\xff\xde\xff\xff",
                "pKIDefaultCSPs": b"1,M#icrosoft Enhanced Cryptographic Provider v1.0",
            }

        # create certiciate template
        # create oid
        basedn = f"CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        self.ldap_session.search(basedn, "(objectclass=*)" ,attributes=['msPKI-Cert-Template-OID'])

        if len(self.ldap_session.entries) == 0:
            logging.error("[Add-DomainCATemplate] No Forest OID found in domain")

        forest_oid = self.ldap_session.entries[0]['msPKI-Cert-Template-OID'].value
        template_oid, template_name = UTILS.get_template_oid(forest_oid)
        oa = {
                'Name': template_name,
                'DisplayName': displayname,
                'flags' : 0x01,
                'msPKI-Cert-Template-OID': template_oid,
                }
        oidpath = f"CN={template_name},CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        self.ldap_session.add(oidpath, ['top','msPKI-Enterprise-Oid'], oa)
        if self.ldap_session.result['result'] == 0:
            logging.debug(f"[Add-DomainCATemplate] Added new template OID {oidpath}")
            logging.debug(f"[Add-DomainCATemplate] msPKI-Cert-Template-OID: {template_oid}")
            default_template['msPKI-Cert-Template-OID'] = template_oid
        else:
            logging.error(f"[Add-DomainCATemplate] Error adding new template OID ({self.ldap_session.result['description']})")
            return False

        template_base = f"CN={name},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        self.ldap_session.add(template_base, ['top','pKICertificateTemplate'], default_template)
        if self.ldap_session.result['result'] == 0:
            logging.info(f"[Add-DomainCATemplate] Added new certificate template {name}")
        else:
            logging.error(f"[Add-DomainCATemplate] Failed to create certiciate template {name} ({self.ldap_session.result['description']})")
            return False

        # set acl for the template
        if not args.duplicate:
            cur_user = self.conn.who_am_i().split('\\')[1]
            logging.debug("[Add-DomainCATemplate] Modifying template ACL for current user")
            if not self.add_domaincatemplateacl(name,cur_user,ca_fetch=ca_fetch):
                logging.debug("[Add-DomainCATemplate] Failed to modify template ACL. Skipping...")

        # issue certificate
        cas = ca_fetch.fetch_enrollment_services()
        for ca in cas:
            ca_dn = ca['distinguishedName'].value
            ca_name = ca['name'].value
            logging.debug(f"[Add-DomainCATemplate] Issuing certificate template to {ca_name}")
            succeed = self.set_domainobject(
                        ca_name,
                        append={
                            'attribute': 'certificateTemplates',
                            'value': [name]
                        },
                        searchbase = ca_dn
                    )

            if succeed:
                logging.info(f"[Add-DomainCATemplate] Template {name} issued!")
            else:
                logging.error("[Add-DomainCATemplate] Failed to issue template")

        return succeed

    def get_domaincatemplate(self, args=None, properties=[], identity=None, searchbase=None):
        def_prop = [
            "objectClass",
            "cn",
            "distinguishedName",
            "name",
            "displayName",
            "pKIExpirationPeriod",
            "pKIOverlapPeriod",
            "msPKI-Enrollment-Flag",
            "msPKI-Private-Key-Flag",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Cert-Template-OID",
            "msPKI-RA-Signature",
            "pKIExtendedKeyUsage",
            "nTSecurityDescriptor",
            "objectGUID",
        ]

        identity = '*' if not identity else identity
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else f"CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{self.root_dn}"
        resolve_sids = args.resolve_sids if hasattr(args, 'resolve_sids') and args.resolve_sids else None
        args_enabled = args.enabled if hasattr(args, 'enabled') and args.enabled else False
        args_vulnerable = args.vulnerable if hasattr(args, 'vulnerable') and args.vulnerable else False

        entries = []
        template_guids = []
        ca_fetch = CAEnum(self.ldap_session, self.root_dn)

        templates = ca_fetch.get_certificate_templates(def_prop,searchbase,identity)
        cas = ca_fetch.fetch_enrollment_services()

        if len(cas) <= 0:
            logging.error(f"[Get-DomainCATemplate] No certificate authority found")
            return

        logging.debug(f"[Get-DomainCATemplate] Found {len(cas)} CA(s)")
        # Entries only
        list_ca_templates = []
        list_entries = []
        for ca in cas:
            list_ca_templates += ca.certificateTemplates
            for template in templates:
                #template = template.entry_writable()
                vulnerable = False
                vulns = {}
                list_vuln = []

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
                # print(enrollment_flag)
                extended_key_usage = template_ops.get_extended_key_usage()
                validity_period = template_ops.get_validity_period()
                renewal_period = template_ops.get_renewal_period()
                requires_manager_approval = template_ops.get_requires_manager_approval()

                vulns = template_ops.check_vulnerable_template()

                if resolve_sids:
                    template_owner = self.convertfrom_sid(template_ops.get_owner_sid())

                    for i in range(len(parsed_dacl['Extended Rights'])):
                        try:
                            parsed_dacl['Extended Rights'][i] = self.convertfrom_sid(parsed_dacl['Extended Rights'][i])
                        except:
                            pass

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

                    # Resolve Vulnerable (With resolvesids)
                    for y in vulns.keys():
                        try:
                            list_vuln.append(y+" - "+self.convertfrom_sid(vulns[y]))
                        except:
                            list_vuln.append(vulns[y])

                # Resolve Vulnerable (Without resolvesids)
                if not resolve_sids:
                    for y in vulns.keys():
                        try:
                            list_vuln.append(y+" - "+vulns[y])
                        except:
                            list_vuln.append(vulns[y])

                e = modify_entry(template,
                                 new_attributes={
                                    'Owner': template_owner,
                                    'Certificate Authorities': ca.name,
                                    'msPKI-Certificate-Name-Flag': certificate_name_flag,
                                    'msPKI-Enrollment-Flag': enrollment_flag,
                                    'pKIExtendedKeyUsage': extended_key_usage,
                                    'pKIExpirationPeriod': validity_period,
                                    'pKIOverlapPeriod': renewal_period,
                                    'ManagerApproval': requires_manager_approval,
                                    'Enrollment Rights': parsed_dacl['Enrollment Rights'],
                                    'Extended Rights': parsed_dacl['Extended Rights'],
                                    'Write Owner': parsed_dacl['Write Owner'],
                                    'Write Dacl': parsed_dacl['Write Dacl'],
                                    'Write Property': parsed_dacl['Write Property'],
                                    'Enabled': False,
                                    'Vulnerable': list_vuln
                                    # 'Vulnerable': ",\n".join([i+" - "+vulns[i] for i in vulns.keys()]),
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
                new_dict = e["attributes"]
                list_entries.append(new_dict)

        # Enabled + Vulnerable only
        for ent in list_entries:
            # Enabled
            enabled = False
            if ent["cn"][0] in list_ca_templates:
                enabled = True
                ent["Enabled"] = enabled

            if args_enabled and not enabled:
                continue

            # Vulnerable
            vulnerable = False
            if ent["Vulnerable"]:
                vulnerable = True

            if args_vulnerable and not vulnerable:
                continue

            if properties:
                ent = filter_entry(ent,properties)

            entries.append({
                "attributes": ent
            })

        template_guids.clear()
        return entries

    def set_domainobjectowner(self, targetidentity, principalidentity, searchbase=None, args=None):
        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
        
        # verify that the targetidentity exists
        target_identity = self.get_domainobject(identity=targetidentity, properties=[
            'nTSecurityDescriptor',
            'sAMAccountname',
            'ObjectSID',
            'distinguishedName',
            ],
            searchbase=searchbase,
            sd_flag=0x01,
        )
        if len(target_identity) > 1:
            logging.error("[Set-DomainObjectOwner] More than one target identity found")
            return
        elif len(target_identity) == 0:
            logging.error("[Set-DomainObjectOwner] Target identity not found in domain")
            return

        # verify that the principalidentity exists
        principal_identity = self.get_domainobject(identity=principalidentity)
        if len(principal_identity) > 1:
            logging.error("[Set-DomainObjectOwner] More than one principal identity found")
            return
        elif len(principal_identity) == 0:
            logging.error("[Set-DomainObjectOwner] Principal identity not found in domain")
            return

        # create changeowner object
        chown = ObjectOwner(target_identity[0])
        target_identity_owner = chown.read()

        if target_identity_owner == principal_identity[0]["attributes"]["objectSid"]:
            logging.warning("[Set-DomainObjectOwner] %s is already the owner of the %s" % (principal_identity[0]["attributes"]["sAMAccountName"], target_identity[0]["attributes"]["distinguishedName"]))
            return

        logging.info("[Set-DomainObjectOwner] Changing current owner %s to %s" % (target_identity_owner, principal_identity[0]["attributes"]["objectSid"]))

        new_secdesc = chown.modify_securitydescriptor(principal_identity[0])

        succeeded = self.ldap_session.modify(
            target_identity[0]["attributes"]["distinguishedName"],
            {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [
                new_secdesc.getData()
            ])},
            controls=security_descriptor_control(sdflags=0x01)
        )

        if not succeeded:
            logging.error(f"[Set-DomainObjectOwner] Error modifying object owner ({self.ldap_session.result['description']})")
        else:
            logging.info(f'[Set-DomainObjectOwner] Success! modified owner for {target_identity[0]["attributes"]["distinguishedName"]}')

        return succeeded

    def set_domaincatemplate(self, identity, args=None):
        if not args or not identity:
            logging.error("[Set-DomainCATemplate] No identity or args supplied")
            return

        ca_fetch = CAEnum(self.ldap_session, self.root_dn)
        target_template = ca_fetch.get_certificate_templates(identity=identity, properties=['*'])
        if len(target_template) == 0:
            logging.error("[Set-DomainCATemplate] No template found")
            return False
        elif len(target_template) > 1:
            logging.error('[Set-DomainCATemplate] More than one template found')
            return False
        logging.info(f'[Set-DomainCATempalte] Found template dn {target_template[0].entry_dn}')

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
                            logging.error(f"[Set-DomainCATemplate] Value {val} already set in the attribute "+attrs['attribute'])
                            return
                    except KeyError as e:
                        logging.debug("[Set-DomainCATemplate] Attribute %s not found in template" % attrs['attribute'])
            except ldap3.core.exceptions.LDAPKeyError as e:
                logging.error(f"[Set-DomainCATemplate] Key {attrs['attribute']} not found in template attribute. Adding anyway...")

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

        try:
            succeeded = self.ldap_session.modify(target_template[0].entry_dn, {
                attr_key:[
                    (ldap3.MODIFY_REPLACE,attr_val)
                ]
            })
        except ldap3.core.exceptions.LDAPInvalidValueError as e:
            logging.error(f"[Set-DomainCATemplate] {str(e)}")
            succeeded = False

        if not succeeded:
            logging.error(self.ldap_session.result if self.args.debug else "[Set-DomainCATemplate] Failed to modify template")
        else:
            logging.info(f'[Set-DomainCATemplate] Success! modified attribute for {identity} template')

        return succeeded

    def add_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties=['distinguishedName'])
        user_entry = self.get_domainobject(identity=members,properties=['distinguishedName'])
        if len(group_entry) == 0:
            logging.error(f'[Add-DomainGroupMember] Group {identity} not found in domain')
            return
        if len(user_entry) == 0:
            logging.error(f'[Add-DomainGroupMember] User {members} not found in domain. Try to use DN')
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
        
        try:
            succeeded = self.ldap_session.modify(targetobject_dn,{'member': [(ldap3.MODIFY_ADD, [userobject_dn])]})
        except ldap3.core.exceptions.LDAPInvalidValueError as e:
            logging.error(f"[Add-DomainGroupMember] {str(e)}")
            succeeded = False
        
        if not succeeded:
            logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Add-DomainGroupMember] Failed to add {members} to group {identity}")
        return succeeded

    def remove_domaindnsrecord(self, identity=None, args=None):
        if args.zonename:
            zonename = args.zonename.lower()
        else:
            zonename = self.domain.lower()
            logging.debug("[Remove-DomainDNSRecord] Using current domain %s as zone name" % zonename)

        zones = [name['attributes']['name'].lower() for name in self.get_domaindnszone(properties=['name'])]
        if zonename not in zones:
            logging.info("[Remove-DomainDNSRecord] Zone %s not found" % zonename)
            return


        entry = self.get_domaindnsrecord(identity=identity, zonename=zonename)

        if len(entry) == 0:
            logging.info("[Remove-DomainDNSRecord] No record found")
            return
        elif len(entry) > 1:
            logging.info("[Remove-DomainDNSRecord] More than one record found")

        record_dn = entry[0]["attributes"]["distinguishedName"]

        succeeded = self.ldap_session.delete(record_dn)
        if not succeeded:
            logging.error(self.ldap_session.result['message'] if self.args.debug else "[Remove-DomainDNSRecord] Failed to delete record")
            return False
        else:
            logging.info("[Remove-DomainDNSRecord] Success! Deleted the record")
            return True

    def remove_domaingroupmember(self, identity, members, args=None):
        group_entry = self.get_domaingroup(identity=identity,properties=['distinguishedName'])
        user_entry = self.get_domainobject(identity=members,properties=['distinguishedName'])
        if len(group_entry) == 0:
            logging.error(f'[Remove-DomainGroupmember] Group {identity} not found in domain')
            return
        if len(user_entry) == 0:
            logging.error(f'[Remove-DomainGroupMember] User {members} not found in domain, Try to use DN')
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
            logging.error('[Remove-DomainUser] Identity is required')
            return
        entries = self.get_domainuser(identity=identity)
        if len(entries) == 0:
            logging.error('[Remove-DomainUser] Identity not found in domain')
            return
        identity_dn = entries[0]["attributes"]["distinguishedName"]
        au = ADUser(self.ldap_session, self.root_dn)
        au.removeUser(identity_dn)

    def add_domainuser(self, username, userpass, args=None):
        parent_dn_entries = f"CN=Users,{self.root_dn}"
        if args.basedn:
            entries = self.get_domainobject(identity=args.basedn)
            if len(entries) <= 0:
                logging.error(f"[Add-DomainUser] {args.basedn} could not be found in the domain")
                return
            parent_dn_entries = entries[0]["attributes"]["distinguishedName"]

        if len(parent_dn_entries) == 0:
            logging.error('[Add-DomainUser] Users parent DN not found in domain')
            return
        logging.debug(f"[Add-DomainUser] Adding user in {parent_dn_entries}")
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
        )
        try:
            if self.use_ldaps:
                addmachineaccount.run_ldaps()
            else:
                addmachineaccount.run_samr()
        except Exception as e:
            logging.error(str(e))
            return False

        if len(self.get_domainobject(identity=computer_name)) == 0:
            return True
        else:
            return False

    def set_domaindnsrecord(self, args):
        if args.zonename:
            zonename = args.zonename.lower()
        else:
            zonename = self.domain.lower()
            logging.debug("Using current domain %s as zone name" % zonename)

        zones = [name['attributes']['name'].lower() for name in self.get_domaindnszone(properties=['name'])]
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
            zonename = args.zonename.lower()
        else:
            zonename = self.domain.lower()
            logging.debug("Using current domain %s as zone name" % zonename)

        recordname = args.recordname
        recordaddress = args.recordaddress

        zones = [name['attributes']['name'].lower() for name in self.get_domaindnszone(properties=['name'])]
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
        logging.debug("[Add-DomainDNSRecord] Creating DNS record structure")
        record = DNS_UTIL.new_record(addtype, DNS_UTIL.get_next_serial(self.dc_ip, zonename, True), recordaddress)
        search_base = f"DC={zonename},CN=MicrosoftDNS,DC=DomainDnsZones,{self.root_dn}"
        record_dn = 'DC=%s,%s' % (recordname, search_base)
        node_data['dnsRecord'] = [record.getData()]

        succeeded = self.ldap_session.add(record_dn, ['top', 'dnsNode'], node_data)
        if not succeeded:
            logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Add-DomainDNSRecord] Failed adding DNS record to domain ({self.ldap_session.result['description']})")
            return False
        else:
            logging.info('[Add-DomainDNSRecord] Success! Created new record with dn %s' % record_dn)
            return True

    def add_domaincomputer(self, computer_name, computer_pass, args=None):
        if computer_name[-1] != '$':
            computer_name += '$'
        dcinfo = get_dc_host(self.ldap_session, self.domain_dumper, self.args)
        if len(dcinfo)== 0:
            logging.error("[Add-DomainComputer] Cannot get domain info")
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
        try:
            if self.use_ldaps:
                addmachineaccount.run_ldaps()
            else:
                addmachineaccount.run_samr()
        except Exception as e:
            logging.error(str(e))
            return False

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
                logging.debug(f"[Get-NamedPipes] Using FQDN: {host}")
            else:
                host = host_inp

        if self.use_kerberos:
            if is_ipaddress(args.computer) or is_ipaddress(args.computername):
                logging.error('[Get-NamedPipes] FQDN must be used for kerberos authentication')
                return
        else:
            if is_fqdn and self.nameserver:
                host = host2ip(host, self.nameserver, 3, True)

        if not host:
            logging.error('[Get-NamedPipes] Host not found')
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


    def set_domainobject(self, identity, clear=None, _set=None, append=None, searchbase=None, sd_flag=None, args=None):
        if _set and clear and append:
            raise Exception("Set, Clear and Append couldn't be together")

        if not searchbase:
            searchbase = args.searchbase if hasattr(args, 'searchbase') and args.searchbase else self.root_dn
        
        targetobject = self.get_domainobject(identity=identity, searchbase=searchbase, properties=['*'], sd_flag=sd_flag)
        if len(targetobject) > 1:
            logging.error(f"[Set-DomainObject] More than one object found")
            return False
        elif len(targetobject) == 0:
            logging.error(f"[Set-DomainObject] {identity} not found in domain")
            return False

        attr_clear = args.clear if hasattr(args,'clear') and args.clear else clear
        attr_set = args.set if hasattr(args, 'set') and args.set else _set
        attr_append = args.append if hasattr(args, 'append') and args.append else append

        attr_key = ""
        attr_val = []

        if attr_clear:
            attr_key = attr_clear
        else:
            attrs = {}

            if attr_set:
                if isinstance(attr_set, dict):
                    attrs = attr_set
                else:
                    attrs = ini_to_dict(attr_set)
            elif attr_append:
                if isinstance(attr_append, dict):
                    attrs = attr_append
                else:
                    attrs = ini_to_dict(attr_append)

            if not attrs:
                logging.error(f"[Set-DomainObject] Parsing {'-Set' if args.set else '-Append'} value failed")
                return
            
            try:
                if isinstance(attrs['value'], list):
                    for val in attrs['value']:
                        try:
                            values = targetobject[0]["attributes"].get(attrs['attribute'])
                            if isinstance(values, list):
                                for ori_val in values:
                                    if isinstance(ori_val, str):
                                        if val.casefold() == ori_val.casefold():
                                            logging.error(f"[Set-DomainObject] Value {val} already set in the attribute "+attrs['attribute'])
                                            return
                                    else:
                                        if val == values:
                                            logging.error(f"[Set-DomainObject] Value {val} already set in the attribute "+attrs['attribute'])
                                            return
                            elif isinstance(values, str):
                                if val.casefold() == values.casefold():
                                    logging.error(f"[Set-DomainObject] Value {val} already set in the attribute "+attrs['attribute'])
                                    return
                            else:
                                if val == values:
                                    logging.error(f"[Set-DomainObject] Value {val} already set in the attribute "+attrs['attribute'])
                                    return
                        except KeyError as e:
                            logging.debug(f"[Set-DomainObject] Attribute {attrs['attribute']} not exists in object. Modifying anyway...")
            except ldap3.core.exceptions.LDAPKeyError as e:
                logging.error(f"[Set-DomainObject] Key {attrs['attribute']} not found in template attribute. Adding anyway...")

            if attr_append:
                if not targetobject[0]["attributes"].get(attrs['attribute']):
                    logging.warning(f"[Set-DomainObject] {attrs['attribute']} property not found in target identity")
                    logging.warning(f"[Set-DomainObject] Attempting to force add attribute {attrs['attribute']} to target object")
                    return self.set_domainobject(identity, _set={
                            'attribute': attrs['attribute'],
                            'value': attrs['value'],
                        },
                        searchbase=searchbase,
                        sdflags=sdflags
                    )

                temp_list = []
                if isinstance(targetobject[0]["attributes"][attrs['attribute']], str):
                    temp_list.append(targetobject[0]["attributes"][attrs['attribute']])
                elif isinstance(targetobject[0]["attributes"][attrs['attribute']], int):
                    temp_list.append(targetobject[0]["attributes"][attrs['attribute']])
                elif isinstance(targetobject[0]["attributes"][attrs['attribute']], list):
                    temp_list = targetobject[0]["attributes"][attrs['attribute']]

                #In case the value a Distinguished Name we retransform it into a list to append it
                if re.search(r'^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$', str(attrs['value'])):
                    attrs['value'] = list(set(list(attrs['value'].split('\n') + temp_list)))
                else:
                    attrs['value'] = list(set(attrs['value'] + temp_list))
            elif attr_set:
                #In case the value is a Distinguished Name
                if not re.search(r'^((CN=([^,]*)),)?((((?:CN|OU)=[^,]+,?)+),)?((DC=[^,]+,?)+)$', str(attrs['value'])):
                    attrs['value'] = list(set(attrs['value']))

            attr_key = attrs['attribute']
            attr_val = attrs['value']

        try:
            succeeded = self.ldap_session.modify(targetobject[0]["attributes"]["distinguishedName"], {
                attr_key:[
                    (ldap3.MODIFY_REPLACE,attr_val)
                ]
            }, controls=security_descriptor_control(sdflags=sd_flag) if sd_flag else None)
        except ldap3.core.exceptions.LDAPInvalidValueError as e:
            logging.error(f"[Set-DomainObject] {str(e)}")
            succeeded = False

        if not succeeded:
            logging.error(self.ldap_session.result['message'] if self.args.debug else f"[Set-DomainObject] Failed to modify attribute {attr_key} for {targetobject[0]['attributes']['distinguishedName']}")
        else:
            logging.info(f'[Set-DomainObject] Success! modified attribute {attr_key} for {targetobject[0]["attributes"]["distinguishedName"]}')
        
        return succeeded

    def invoke_kerberoast(self, args, properties=[]):
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
            logging.debug("[Invoke-Kerberoast] No identity found")
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
        entries.clear()
        entries = []
        if properties:
            for ent in entries_out:
                entries.append({
                    'attributes': filter_entry(ent['attributes'],properties)
                })
        else:
            entries = entries_out

        return entries

    def find_localadminaccess(self, args):
        host_entries = []
        hosts = {}

        computer = args.computer if args.computer else args.computername

        if not is_valid_fqdn(computer) and self.use_kerberos:
            logging.error('[Find-LocaAdminAccess] FQDN must be used for kerberos authentication')
            return

        if computer:
            if not is_valid_fqdn(computer):
                computer = "%s.%s" % (computer,self.domain)

            if is_ipaddress(computer):
                hosts['address'] = computer
            else:
                if self.nameserver:
                    hosts['address'] = host2ip(computer, self.nameserver, 3, True)
                else:
                    host['address'] = computer
                hosts['hostname'] = computer
            host_entries.append(hosts)
        else:
            entries = self.get_domaincomputer(properties=['dnsHostName'])

            logging.info(f"[Find-LocaAdminAccess] Found {len(entries)} computers in the domain")
            if len(entries) > 100:
                logging.info("[Find-LocalAdminAccess] There are more than 100 computers in the domain. This might take some time")

            for entry in entries:
                try:
                    if len(entry['attributes']['dnsHostName']) <= 0:
                        continue

                    hosts['address'] = host2ip(entry['attributes']['dnsHostName'], self.nameserver, 3, True)
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

    def get_netshare(self, args):
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
                logging.debug(f"[Get-NetShare] Using FQDN: {host}")
            else:
                host = host_inp

        if self.use_kerberos:
            if is_ipaddress(args.computer) or is_ipaddress(args.computername):
                logging.error('[Get-NetShare] FQDN must be used for kerberos authentication')
                return
        else:
            if is_fqdn and self.nameserver:
                host = host2ip(host, self.nameserver, 3, True)

        if not host:
            logging.error(f"[Get-NetShare] Host not found")
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

    def get_netsession(self, args):
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
                logging.debug(f"[Get-NetSession] Using FQDN: {host}")
            else:
                host = host_inp

        if self.use_kerberos:
            if is_ipaddress(args.computer) or is_ipaddress(args.computername):
                logging.error('[Get-NetSession] FQDN must be used for kerberos authentication')
                return
            host = args.computer if args.computer else args.computereturne
        else:
            if is_fqdn and self.nameserver:
                host = host2ip(host, self.nameserver, 3, True)

        if not host:
            logging.error(f"[Get-NetSession] Host not found")
            return

        dce = self.conn.init_rpc_session(host=host, pipe=r'\srvsvc')

        if dce is None:
            return

        try:
            resp = srvs.hNetrSessionEnum(dce, '\x00', NULL, 10)
        except Exception as e:
            if 'rpc_s_access_denied' in str(e):
                logging.info('Access denied while enumerating Sessions on %s' % (host))
            else:
                logging.info(str(e))
            return

        sessions = []
        for session in resp['InfoStruct']['SessionInfo']['Level10']['Buffer']:
            ip = session['sesi10_cname'][:-1]
            userName = session['sesi10_username'][:-1]
            time = session['sesi10_time']
            idleTime = session['sesi10_idle_time']

            if userName[:-1] == "$":
                continue

            sessions.append({
                "attributes": {
                    "IP": ip,
                    "Username": userName,
                    "Time": time,
                    "Idle Time": idleTime,
                    "Computer": host,
                }
            })

        return sessions
