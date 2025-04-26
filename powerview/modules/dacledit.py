#!/usr/bin/env python3
# Impacket - Collection of Python classes for working with network protocols.
#
# SECUREAUTH LABS. Copyright (C) 2021 SecureAuth Corporation. All rights reserved.
#
# This software is provided under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Description:
#   Python script to read and manage the Discretionary Access Control List of an object
#
# Authors:
#   Charlie BROMBERG (@_nwodtuhs)
#   Guillaume DAUMAS (@BlWasp_)
#   Lucien DOUSTALY (@Wlayzz)
#

import argparse
import binascii
import codecs
import json
import logging
import os
import sys
import traceback
import datetime

import ldap3
import ssl
import ldapdomaindump
from binascii import unhexlify
from enum import Enum
from ldap3.protocol.formatters.formatters import format_sid

from impacket import version
from impacket.examples import logger, utils
from impacket.ldap import ldaptypes
from powerview.utils.constants import (
    SCHEMA_OBJECTS,
    EXTENDED_RIGHTS
)
from impacket.smbconnection import SMBConnection
from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
from ldap3.utils.conv import escape_filter_chars
from ldap3.protocol.microsoft import security_descriptor_control
from impacket.uuid import string_to_bin, bin_to_string

from powerview.utils.constants import WELL_KNOWN_SIDS

OBJECT_TYPES_GUID = {}
OBJECT_TYPES_GUID.update(SCHEMA_OBJECTS)
OBJECT_TYPES_GUID.update(EXTENDED_RIGHTS)

# GUID rights enum
# GUID thats permits to identify extended rights in an ACE
# https://docs.microsoft.com/en-us/windows/win32/adschema/a-rightsguid
class RIGHTS_GUID(Enum):
    WriteMembers = "bf9679c0-0de6-11d0-a285-00aa003049e2"
    ResetPassword = "00299570-246d-11d0-a768-00aa006e0529"
    DS_Replication_Get_Changes = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    DS_Replication_Get_Changes_All = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


# ACE flags enum
# New ACE at the end of SACL for inheritance and access return system-audit
# https://docs.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-addauditaccessobjectace
class ACE_FLAGS(Enum):
    CONTAINER_INHERIT_ACE = ldaptypes.ACE.CONTAINER_INHERIT_ACE
    FAILED_ACCESS_ACE_FLAG = ldaptypes.ACE.FAILED_ACCESS_ACE_FLAG
    INHERIT_ONLY_ACE = ldaptypes.ACE.INHERIT_ONLY_ACE
    INHERITED_ACE = ldaptypes.ACE.INHERITED_ACE
    NO_PROPAGATE_INHERIT_ACE = ldaptypes.ACE.NO_PROPAGATE_INHERIT_ACE
    OBJECT_INHERIT_ACE = ldaptypes.ACE.OBJECT_INHERIT_ACE
    SUCCESSFUL_ACCESS_ACE_FLAG = ldaptypes.ACE.SUCCESSFUL_ACCESS_ACE_FLAG

# ACE flags enum
# For an ACE, flags that indicate if the ObjectType and the InheritedObjecType are set with a GUID
# Since these two flags are the same for Allowed and Denied access, the same class will be used from 'ldaptypes'
# https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-access_allowed_object_ace
class OBJECT_ACE_FLAGS(Enum):
    ACE_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
    ACE_INHERITED_OBJECT_TYPE_PRESENT = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_INHERITED_OBJECT_TYPE_PRESENT


# Access Mask enum
# Access mask permits to encode principal's rights to an object. This is the rights the principal behind the specified SID has
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b
# https://docs.microsoft.com/en-us/windows/win32/api/iads/ne-iads-ads_rights_enum?redirectedfrom=MSDN
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


# Simple permissions enum
# Simple permissions are combinaisons of extended permissions
# https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc783530(v=ws.10)?redirectedfrom=MSDN
class SIMPLE_PERMISSIONS(Enum):
    FullControl = 0xf01ff
    Modify = 0x0301bf
    ReadAndExecute = 0x0200a9
    ReadAndWrite = 0x02019f
    Read = 0x20094
    Write = 0x200bc


# Mask ObjectType field enum
# Possible values for the Mask field in object-specific ACE (permitting to specify extended rights in the ObjectType field for example)
# Since these flags are the same for Allowed and Denied access, the same class will be used from 'ldaptypes'
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
class ALLOWED_OBJECT_ACE_MASK_FLAGS(Enum):
    ControlAccess = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
    CreateChild = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CREATE_CHILD
    DeleteChild = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_DELETE_CHILD
    ReadProperty = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP
    WriteProperty = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
    Self = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_SELF

class DACLedit(object):
    """docstring for setrbcd"""

    def __init__(self, ldap_server, ldap_session, base_dn, target_sAMAccountName, target_SID, target_DN, target_sd, principal_sAMAccountName, principal_SID, principal_DN, ace_type, rights, rights_guid, inheritance):
        super(DACLedit, self).__init__()
        self.ldap_server = ldap_server
        self.ldap_session = ldap_session
        self.base_dn = base_dn

        self.target_sAMAccountName = target_sAMAccountName 
        self.target_SID = target_SID
        self.target_DN = target_DN
        self.principal_raw_security_descriptor = target_sd
        self.principal_security_descriptor = ldaptypes.SR_SECURITY_DESCRIPTOR(data=self.principal_raw_security_descriptor)


        self.principal_sAMAccountName = principal_sAMAccountName
        self.principal_SID = principal_SID
        self.principal_DN = principal_DN

        self.ace_type = ace_type
        self.rights = rights
        self.rights_guid = rights_guid
        self.inheritance = inheritance
        if self.inheritance:
            logging.warning("Objects with adminCount=1 will not inherit ACEs from their parent container/OU")

    # Main read funtion
    # Prints the parsed DACL
    def read(self):
        parsed_dacl = self.parseDACL(self.principal_security_descriptor['Dacl'])
        self.printparsedDACL(parsed_dacl)

    # Main write function
    # Attempts to add a new ACE to a DACL
    def write(self):
        # Creates ACEs with the specified GUIDs and the SID, or FullControl if no GUID is specified
        # Append the ACEs in the DACL locally
        if self.rights == "fullcontrol" and self.rights_guid is None:
            logging.warning(f"Adding FullControl to %s" % (self.target_SID if self.target_SID else self.target_DN))
            self.principal_security_descriptor['Dacl'].aces.append(self.create_ace(SIMPLE_PERMISSIONS.FullControl.value, self.principal_SID, self.ace_type))
        elif self.rights == "immutable" and self.rights_guid is None:
            logging.debug(f"Adding Delete and DeleteTree to %s" % (self.target_SID if self.target_SID else self.target_DN))
            self.principal_security_descriptor['Dacl'].aces.insert(0,self.create_ace(ACCESS_MASK.Delete.value + ACCESS_MASK.DeleteTree.value, self.principal_SID, ace_type="denied"))
        elif self.rights == "deletechild" and self.rights_guid is None:
            logging.debug(f"Adding DeleteChild to %s" % (self.target_SID if self.target_SID else self.target_DN))
            self.principal_security_descriptor['Dacl'].aces.insert(0,self.create_ace(ACCESS_MASK.DeleteChild.value, self.principal_SID, ace_type="denied"))
        else:
            for rights_guid in self.build_guids_for_rights():
                logging.debug("Adding %s (%s) to %s)" % (self.principal_SID, rights_guid, format_sid(self.target_SID)))
                self.principal_security_descriptor['Dacl'].aces.append(self.create_object_ace(rights_guid, self.principal_SID, self.ace_type))
        # Backups current DACL before add the new one
        # Effectively push the DACL with the new ACE
        return self.modify_secDesc_for_dn(self.target_DN, self.principal_security_descriptor)


    # Attempts to remove an ACE from the DACL
    # To do it, a new DACL is built locally with all the ACEs that must NOT BE removed, and this new DACL is pushed on the server
    def remove(self):
        compare_aces = []
        # Creates ACEs with the specified GUIDs and the SID, or FullControl if no GUID is specified
        # These ACEs will be used as comparison templates
        if self.rights == "fullcontrol" and self.rights_guid is None:
            compare_aces.append(self.create_ace(SIMPLE_PERMISSIONS.FullControl.value, self.principal_SID, self.ace_type))
        elif self.rights == "immutable" and self.rights_guid is None:
            logging.debug(f"Removing Delete and DeleteTree to %s" % (self.target_SID if self.target_SID else self.target_DN))
            compare_aces.append(self.create_ace(ACCESS_MASK.Delete.value + ACCESS_MASK.DeleteTree.value, self.principal_SID, ace_type="denied"))
        elif self.rights == "deletechild" and self.rights_guid is None:
            logging.debug(f"Removing DeleteChild to %s" % (self.target_SID if self.target_SID else self.target_DN))
            compare_aces.append(self.create_ace(ACCESS_MASK.DeleteChild.value, self.principal_SID, ace_type="denied"))
        else:
            for rights_guid in self.build_guids_for_rights():
                compare_aces.append(self.create_object_ace(rights_guid, self.principal_SID, self.ace_type))
        new_dacl = []
        i = 0
        dacl_must_be_replaced = False
        for ace in self.principal_security_descriptor['Dacl'].aces:
            ace_must_be_removed = False
            for compare_ace in compare_aces:
                # To be sure the good ACEs are removed, multiple fields are compared between the templates and the ACEs in the DACL
                #   - ACE type
                #   - ACE flags
                #   - Access masks
                #   - Revision
                #   - SubAuthorityCount
                #   - SubAuthority
                #   - IdentifierAuthority value
                if ace['AceType'] == compare_ace['AceType'] \
                    and ace['AceFlags'] == compare_ace['AceFlags']\
                    and ace['Ace']['Mask']['Mask'] == compare_ace['Ace']['Mask']['Mask']\
                    and ace['Ace']['Sid']['Revision'] == compare_ace['Ace']['Sid']['Revision']\
                    and ace['Ace']['Sid']['SubAuthorityCount'] == compare_ace['Ace']['Sid']['SubAuthorityCount']\
                    and ace['Ace']['Sid']['SubAuthority'] == compare_ace['Ace']['Sid']['SubAuthority']\
                    and ace['Ace']['Sid']['IdentifierAuthority']['Value'] == compare_ace['Ace']['Sid']['IdentifierAuthority']['Value']:
                    # If the ACE has an ObjectType, the GUIDs must match
                    if 'ObjectType' in ace['Ace'].fields.keys() and 'ObjectType' in compare_ace['Ace'].fields.keys():
                        if ace['Ace']['ObjectType'] == compare_ace['Ace']['ObjectType']:
                            ace_must_be_removed = True
                            dacl_must_be_replaced = True
                    else:
                        ace_must_be_removed = True
                        dacl_must_be_replaced = True
            # If the ACE doesn't match any ACEs from the template list, it is added to the DACL that will be pushed
            if not ace_must_be_removed:
                new_dacl.append(ace)
            elif logging.getLogger().level == logging.DEBUG:
                logging.debug("This ACE will be removed")
                self.printparsedACE(self.parseACE(ace))
            i += 1
        # If at least one ACE must been removed
        if dacl_must_be_replaced:
            self.principal_security_descriptor['Dacl'].aces = new_dacl
            self.modify_secDesc_for_dn(self.target_DN, self.principal_security_descriptor)
        else:
            logging.info("Nothing to remove...")

    
    # Attempts to retieve the SID and Distinguisehd Name from the sAMAccountName
    # Not used for the moment
    #   - samname : a sAMAccountName
    def get_user_info(self, samname):
        self.ldap_session.search(self.base_dn, '(sAMAccountName=%s)' % escape_filter_chars(samname), attributes=['objectSid'])
        try:
            dn = self.ldap_session.entries[0].entry_dn
            sid = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            return dn, sid
        except IndexError:
            logging.error('User not found in LDAP: %s' % samname)
            return False

    
    # Attempts to resolve a SID and return the corresponding samaccountname
    #   - sid : the SID to resolve
    def resolveSID(self, sid):
        # Tries to resolve the SID from the well known SIDs
        if sid in WELL_KNOWN_SIDS.keys():
            return WELL_KNOWN_SIDS[sid]
        # Tries to resolve the SID from the LDAP domain dump
        else:
            self.ldap_session.search(self.base_dn, '(objectSid=%s)' % sid, attributes=['samaccountname'])
            try:
                dn = self.ldap_session.entries[0].entry_dn
                samname = self.ldap_session.entries[0]['samaccountname']
                return samname
            except IndexError:
                logging.debug('SID not found in LDAP: %s' % sid)
                return ""

    
    # Parses a full DACL
    #   - dacl : the DACL to parse, submitted in a Security Desciptor format
    def parseDACL(self, dacl):
        parsed_dacl = []
        logging.info("Parsing DACL")
        i = 0
        for ace in dacl['Data']:
            parsed_ace = self.parseACE(ace)
            parsed_dacl.append(parsed_ace)
            i += 1
        return parsed_dacl

    
    # Parses an access mask to extract the different values from a simple permission
    # https://stackoverflow.com/questions/28029872/retrieving-security-descriptor-and-getting-number-for-filesystemrights
    #   - fsr : the access mask to parse
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

    
    # Parses a specified ACE and extract the different values (Flags, Access Mask, Trustee, ObjectType, InheritedObjectType)
    #   - ace : the ACE to parse
    def parseACE(self, ace):
        # For the moment, only the Allowed and Denied Access ACE are supported
        if ace['TypeName'] in [ "ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_ACE", "ACCESS_DENIED_OBJECT_ACE" ]:
            parsed_ace = {}
            parsed_ace['ACE Type'] = ace['TypeName']
            # Retrieves ACE's flags
            _ace_flags = []
            for FLAG in ACE_FLAGS:
                if ace.hasFlag(FLAG.value):
                    _ace_flags.append(FLAG.name)
            parsed_ace['ACE flags'] = ", ".join(_ace_flags) or "None"

            # For standard ACE
            # Extracts the access mask (by parsing the simple permissions) and the principal's SID
            if ace['TypeName'] in [ "ACCESS_ALLOWED_ACE", "ACCESS_DENIED_ACE" ]:
                parsed_ace['Access mask'] = "%s (0x%x)" % (", ".join(self.parsePerms(ace['Ace']['Mask']['Mask'])), ace['Ace']['Mask']['Mask'])
                parsed_ace['Trustee (SID)'] = "%s (%s)" % (self.resolveSID(ace['Ace']['Sid'].formatCanonical()) or "UNKNOWN", ace['Ace']['Sid'].formatCanonical())

            # For object-specific ACE
            elif ace['TypeName'] in [ "ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_OBJECT_ACE" ]:
                # Extracts the mask values. These values will indicate the ObjectType purpose
                _access_mask_flags = []
                for FLAG in ALLOWED_OBJECT_ACE_MASK_FLAGS:
                    if ace['Ace']['Mask'].hasPriv(FLAG.value):
                        _access_mask_flags.append(FLAG.name)
                parsed_ace['Access mask'] = ", ".join(_access_mask_flags)
                # Extracts the ACE flag values and the trusted SID
                _object_flags = []
                for FLAG in OBJECT_ACE_FLAGS:
                    if ace['Ace'].hasFlag(FLAG.value):
                        _object_flags.append(FLAG.name)
                parsed_ace['Flags'] = ", ".join(_object_flags) or "None"
                # Extracts the ObjectType GUID values
                if ace['Ace']['ObjectTypeLen'] != 0:
                    obj_type = bin_to_string(ace['Ace']['ObjectType']).lower()
                    try:
                        parsed_ace['Object type (GUID)'] = "%s (%s)" % (OBJECT_TYPES_GUID[obj_type], obj_type)
                    except KeyError:
                        parsed_ace['Object type (GUID)'] = "UNKNOWN (%s)" % obj_type
                # Extracts the InheritedObjectType GUID values
                if ace['Ace']['InheritedObjectTypeLen'] != 0:
                    inh_obj_type = bin_to_string(ace['Ace']['InheritedObjectType']).lower()
                    try:
                        parsed_ace['Inherited type (GUID)'] = "%s (%s)" % (OBJECT_TYPES_GUID[inh_obj_type], inh_obj_type)
                    except KeyError:
                        parsed_ace['Inherited type (GUID)'] = "UNKNOWN (%s)" % inh_obj_type
                # Extract the Trustee SID (the object that has the right over the DACL bearer)
                parsed_ace['Trustee (SID)'] = "%s (%s)" % (self.resolveSID(ace['Ace']['Sid'].formatCanonical()) or "UNKNOWN", ace['Ace']['Sid'].formatCanonical())

        else:
            # If the ACE is not an access allowed
            logging.debug("ACE Type (%s) unsupported for parsing yet, feel free to contribute" % ace['TypeName'])
            parsed_ace = {}
            parsed_ace['ACE type'] = ace['TypeName']
            _ace_flags = []
            for FLAG in ACE_FLAGS:
                if ace.hasFlag(FLAG.value):
                    _ace_flags.append(FLAG.name)
            parsed_ace['ACE flags'] = ", ".join(_ace_flags) or "None"
            parsed_ace['DEBUG'] = "ACE type not supported for parsing by dacleditor.py, feel free to contribute"
        return parsed_ace


    # Prints a full DACL by printing each parsed ACE
    #   - parsed_dacl : a parsed DACL from parseDACL()
    def printparsedDACL(self, parsed_dacl):
        # Attempts to retrieve the principal's SID if it's a write action
        if self.principal_SID is None and self.principal_sAMAccountName or self.principal_DN:
            if self.principal_sAMAccountName is not None:
                _lookedup_principal = self.principal_sAMAccountName
                self.ldap_session.search(self.base_dn, '(sAMAccountName=%s)' % escape_filter_chars(_lookedup_principal), attributes=['objectSid'])
            elif self.principal_DN is not None:
                _lookedup_principal = self.principal_DN
                self.ldap_session.search(self.base_dn, '(distinguishedName=%s)' % _lookedup_principal, attributes=['objectSid'])
            try:
                self.principal_SID = format_sid(self.ldap_session.entries[0]['objectSid'].raw_values[0])
            except IndexError:
                logging.error('Principal not found in LDAP (%s)' % _lookedup_principal)
                return False
            logging.debug("Found principal SID to write in ACE(s): %s" % self.principal_SID)

        logging.info("Printing parsed DACL")
        i = 0
        # If a principal has been specified, only the ACE where he is the trustee will be printed
        if self.principal_SID is not None:
            logging.info("Filtering results for SID (%s)" % self.principal_SID)
        for parsed_ace in parsed_dacl:
            print_ace = True
            if self.principal_SID is not None:
                try:
                    if self.principal_SID not in parsed_ace['Trustee (SID)']:
                        print_ace = False
                except Exception as e:
                    logging.error("Error filtering ACE, probably because of ACE type unsupported for parsing yet (%s)" % e)
            if print_ace:
                logging.info("  %-28s" % "ACE[%d] info" % i)
                self.printparsedACE(parsed_ace)
            i += 1


    # Prints properly a parsed ACE
    #   - parsed_ace : a parsed ACE from parseACE()
    def printparsedACE(self, parsed_ace):
        elements_name = list(parsed_ace.keys())
        for attribute in elements_name:
            logging.info("    %-26s: %s" % (attribute, parsed_ace[attribute]))


    # Retrieves the GUIDs for the specified rights
    def build_guids_for_rights(self):
        _rights_guids = []
        if self.rights_guid is not None:
            _rights_guids = [self.rights_guid]
        elif self.rights == "writemembers":
            _rights_guids = [RIGHTS_GUID.WriteMembers.value]
        elif self.rights == "resetpassword":
            _rights_guids = [RIGHTS_GUID.ResetPassword.value]
        elif self.rights == "dcsync":
            _rights_guids = [RIGHTS_GUID.DS_Replication_Get_Changes.value, RIGHTS_GUID.DS_Replication_Get_Changes_All.value]
        logging.debug('Built GUID: %s', _rights_guids)
        return _rights_guids


    # Attempts to push the locally built DACL to the remote server into the security descriptor of the specified principal
    # The target principal is specified with its Distinguished Name
    #   - dn : the principal's Distinguished Name to modify
    #   - secDesc : the Security Descriptor with the new DACL to push
    def modify_secDesc_for_dn(self, dn, secDesc):
        data = secDesc.getData()
        controls = security_descriptor_control(sdflags=0x04)
        logging.debug('Attempts to modify the Security Descriptor.')
        self.ldap_session.modify(dn, {'nTSecurityDescriptor': (ldap3.MODIFY_REPLACE, [data])}, controls=controls)
        if self.ldap_session.result['result'] == 0:
            logging.debug('DACL modified successfully!')
            return True
        else:
            if self.ldap_session.result['result'] == 50:
                logging.error('Could not modify object, the server reports insufficient rights: %s',
                              self.ldap_session.result['message'])
            elif self.ldap_session.result['result'] == 19:
                logging.error('Could not modify object, the server reports a constrained violation: %s',
                              self.ldap_session.result['message'])
            else:
                logging.error('The server returned an error: %s', self.ldap_session.result['message'])
            return False


    # Builds a standard ACE for a specified access mask (rights) and a specified SID (the principal who obtains the right)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/72e7c7ea-bc02-4c74-a619-818a16bf6adb
    #   - access_mask : the allowed access mask
    #   - sid : the principal's SID
    #   - ace_type : the ACE type (allowed or denied)
    def create_ace(self, access_mask, sid, ace_type):
        nace = ldaptypes.ACE()
        if ace_type == "allowed":
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_ACE()
        else:
            nace['AceType'] = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_ACE()
        if self.inheritance:
            nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
        else:
            nace['AceFlags'] = 0x00
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        acedata['Mask']['Mask'] = access_mask
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        nace['Ace'] = acedata
        logging.debug('ACE created.')
        return nace


    # Builds an object-specific for a specified ObjectType (an extended right, a property, etc, to add) for a specified SID (the principal who obtains the right)
    # The Mask is "ADS_RIGHT_DS_CONTROL_ACCESS" (the ObjectType GUID will identify an extended access right)
    # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe
    #   - privguid : the ObjectType (an Extended Right here)
    #   - sid : the principal's SID
    #   - ace_type : the ACE type (allowed or denied)
    def create_object_ace(self, privguid, sid, ace_type):
        nace = ldaptypes.ACE()
        if ace_type == "allowed":
            nace['AceType'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE()
        else:
            nace['AceType'] = ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
            acedata = ldaptypes.ACCESS_DENIED_OBJECT_ACE()
        if self.inheritance:
            nace['AceFlags'] = ldaptypes.ACE.OBJECT_INHERIT_ACE + ldaptypes.ACE.CONTAINER_INHERIT_ACE
        else:
            nace['AceFlags'] = 0x00
        acedata['Mask'] = ldaptypes.ACCESS_MASK()
        # WriteMembers not an extended right, we need read and write mask on the attribute (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c79a383c-2b3f-4655-abe7-dcbb7ce0cfbe)
        if privguid == RIGHTS_GUID.WriteMembers.value:
            acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_READ_PROP + ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_WRITE_PROP
        # Other rights in this script are extended rights and need the DS_CONTROL_ACCESS mask
        else:
            acedata['Mask']['Mask'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ADS_RIGHT_DS_CONTROL_ACCESS
        acedata['ObjectType'] = string_to_bin(privguid)
        acedata['InheritedObjectType'] = b''
        acedata['Sid'] = ldaptypes.LDAP_SID()
        acedata['Sid'].fromCanonical(sid)
        assert sid == acedata['Sid'].formatCanonical()
        # This ACE flag verifes if the ObjectType is valid
        acedata['Flags'] = ldaptypes.ACCESS_ALLOWED_OBJECT_ACE.ACE_OBJECT_TYPE_PRESENT
        nace['Ace'] = acedata
        logging.debug('Object-specific ACE created.')
        return nace
