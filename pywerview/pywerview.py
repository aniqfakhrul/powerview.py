#!/usr/bin/env python3
import ldap3 

class PywerView:
    
    def __init__(self,ldap_session,root_dn):
        self.ldap_session = ldap_session
        self.root_dn = root_dn

    def get_domainuser(self, args=None,
    properties=['cn','name','sAMAccountName','distinguishedName','mail','description','lastLogoff','lastLogon','memberof','objectSid','userPrincipalName'],
    identity='*'):
        if args:
            if args.preauthnotrequired:
                ldap_filter = f'(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(sAMAccountName={identity}))'
            elif args.admincount:
                ldap_filter = f'(&(samAccountType=805396368)(sAMAccountName={identity}))'
            elif args.allowdelegation:
                ldap_filter = f'(&(samAccountType=805306368)!(userAccountControl:1.2.840.113556.1.4.803:=1048574)(sAMAccountName={identity}))'
            elif args.trustedtoauth:
                ldap_filter = f'(&(samAccountType=805306368)(msds-allowedtodelegateto=*)(sAMAccountName={identity}))'
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

    def get_domaincomputer(self, args=None, properties='*', identity='*'):
        if args:
            if args.unconstrained:
                ldap_filter = f'(&(samAccountType=805306369)(userAccountControl:1.2.840.113556.1.4.803:=524288)(sAMAccountName={identity}))'
            elif args.trustedtoauth:
                ldap_filter = f'(&(samAccountType=805306369)(msds-allowedtodelegateto=*)(sAMAccountName={identity}))'
            else:
                ldap_filter = f'(&(samAccountType=805306369)(sAMAccountName={identity}))'
        else:
            ldap_filter = f'(&(samAccountType=805306369)(sAMAccountName={identity}))'

        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries
    
    def get_domaingroup(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(&(objectCategory=group)(name={identity}))'
        self.ldap_session.search(self.root_dn,ldap_filter,attributes=properties)
        return self.ldap_session.entries
    
    def get_domaingpo(self, args=None, properties='*', identity='*'):
        ldap_filter = f'(&(objectCategory=groupPolicyContainer)(cn={identity}))'
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
        user_entry = self.get_domainuser(identity=members,properties='distinguishedName')
        targetobject = group_entry[0]
        userobject = user_entry[0]
        succeeded = self.ldap_session.modify(targetobject.entry_dn,{'member': [(ldap3.MODIFY_ADD, [userobject.entry_dn])]})
        if not succeeded: 
            print(self.ldap_session.result['message'])
        return succeeded
