#!/usr/bin/env python3
import logging
import ntpath
import os
import chardet
from io import BytesIO
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_NO_SCRUB_DATA
from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.dtypes import OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION
from impacket.ldap import ldaptypes
from powerview.modules.ldapattack import ACE_FLAGS, OBJECT_ACE_FLAGS, SIMPLE_PERMISSIONS, ACCESS_MASK
from impacket.uuid import bin_to_string

class SMBClient:
    def __init__(self, client):
        self.client = client

    def shares(self):
        if self.client is None:
            logging.error("[SMBClient: shares] Not logged in")
            return
        return self.client.listShares()

    def share_info(self, share):
        """
        Get detailed information about a share.

        shi503_netname:                  'C$\x00' 
        shi503_type:                     2147483648 
        shi503_remark:                   'Default share\x00' 
        shi503_permissions:              0 
        shi503_max_uses:                 4294967295 
        shi503_current_uses:             0 
        shi503_path:                     'C:\\\x00' 
        shi503_passwd:                   NULL 
        shi503_servername:               '*\x00' 
        shi503_reserved:                 0 
        shi503_security_descriptor:      NULL None
        """
        if self.client is None:
            logging.error("[SMBClient: share_info] Not logged in")
            return
        
        from impacket.dcerpc.v5 import transport, srvs
        rpctransport = transport.SMBTransport(self.client.getRemoteName(), self.client.getRemoteHost(), filename=r'\srvsvc',
                                              smb_connection=self.client)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        resp = srvs.hNetrShareGetInfo(dce, share + '\x00', 503)
        return resp['InfoStruct']['ShareInfo503']

    def ls(self, share, path=''):
        if self.client is None:
            logging.error("[SMBClient: ls] Not logged in")
            return
        
        path = path.replace('/', '\\')
        path = ntpath.join(path, '*')
        
        return self.client.listPath(share, ntpath.normpath(path))

    def mv(self, share, source, destination):
        if self.client is None:
            logging.error("[SMBClient: mv] Not logged in")
            return

        source = source.replace('/', '\\')
        
        self.client.rename(share, source, destination)
    
    def get(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: get] Not logged in")
            return
        
        path = path.replace('/', '\\')
        fh = BytesIO()
        try:
            self.client.getFile(share, ntpath.normpath(path), fh.write)
            return fh.getvalue()
        except:
            raise
        finally:
            fh.close()

    def put(self, share, remote_path, local_path):
        if self.client is None:
            logging.error("[SMBClient: put] Not logged in")
            return
        
        try:
            with open(local_path, 'rb') as fh:
                # Normalize the remote path for the target OS (Windows)
                normalized_remote_path = remote_path.replace('/', '\\')
                final_remote_path = ntpath.normpath(normalized_remote_path)
                logging.debug(f"[SMBClient: put] Uploading local '{local_path}' to share '{share}' path '{final_remote_path}'")
                self.client.putFile(share, final_remote_path, fh.read)
        except FileNotFoundError:
            logging.error(f"[SMBClient: put] Local file not found: {local_path}")
            raise Exception(f"Local file not found: {local_path}")
        except Exception as e:
            logging.error(f"[SMBClient: put] Error during upload to {share}\\{remote_path}: {e}")
            raise e

    def cat(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: cat] Not logged in")
            return
        
        path = path.replace('/', '\\')
        fh = BytesIO()
        try:
            self.client.getFile(share, ntpath.normpath(path), fh.write)
            return fh.getvalue()
        except:
            raise
        finally:
            fh.close()

    def rm(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: rm] Not logged in")
            return
        
        self.client.deleteFile(share, path)

    def rmdir(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: rmdir] Not logged in")
            return

        path = path.replace('/', '\\')
        self.client.deleteDirectory(share, path)

    def mkdir(self, share, path):
        if self.client is None:
            logging.error("[SMBClient: mkdir] Not logged in")
            return
        
        path = path.replace('/', '\\')
        self.client.createDirectory(share, path)

    def _parsePerms(self, fsr):
        _perms = []
        for PERM in SIMPLE_PERMISSIONS:
            if (fsr & PERM.value) == PERM.value:
                _perms.append(PERM.name)
                fsr = fsr & (not PERM.value)
        for PERM in ACCESS_MASK:
            if fsr & PERM.value:
                _perms.append(PERM.name)
        return _perms

    def get_file_info(self, share, path):
        """Get detailed information about a file or directory."""
        if self.client is None:
            logging.error("[SMBClient: get_file_info] Not logged in")
            return None
        
        path = path.replace('/', '\\')
        normalized_path = ntpath.normpath(path)
        
        try:
            # For files, we need the file itself
            file_obj = None
            is_dir = False
            
            # Check if this is a directory by attempting to list it
            try:
                parent_dir = ntpath.dirname(normalized_path)
                file_name = ntpath.basename(normalized_path)
                
                # If path is root or has no parent, adjust accordingly
                if not parent_dir:
                    parent_path = '*'
                    items = self.client.listPath(share, parent_path)
                    for item in items:
                        if item.get_longname() == file_name:
                            file_obj = item
                            break
                else:
                    search_path = ntpath.join(parent_dir, '*')
                    items = self.client.listPath(share, search_path)
                    for item in items:
                        if item.get_longname() == file_name:
                            file_obj = item
                            break
                
                # Try to check if it's a directory
                if file_obj and file_obj.is_directory():
                    is_dir = True
                
            except Exception as e:
                logging.debug(f"[SMBClient: get_file_info] Error checking if path is directory: {e}")
                # If we can't determine if it's a directory, try to get the file directly
                pass
            
            info = {}
            
            if file_obj:
                # Basic file information from FileInfo object
                info = {
                    'name': file_obj.get_longname(),
                    'short_name': file_obj.get_shortname(),
                    'size': file_obj.get_filesize(),
                    'is_directory': is_dir,
                    'created': str(file_obj.get_ctime()),
                    'modified': str(file_obj.get_mtime()),
                    'accessed': str(file_obj.get_atime()),
                    'attributes': file_obj.get_attributes()
                }
                
                # Add attribute flags interpretation
                attr_flags = []
                attr_value = file_obj.get_attributes()
                
                # Standard file attribute flags
                if attr_value & FILE_ATTRIBUTE_READONLY:
                    attr_flags.append("READ_ONLY")
                if attr_value & FILE_ATTRIBUTE_HIDDEN:
                    attr_flags.append("HIDDEN")
                if attr_value & FILE_ATTRIBUTE_SYSTEM:
                    attr_flags.append("SYSTEM")
                if attr_value & FILE_ATTRIBUTE_DIRECTORY:
                    attr_flags.append("DIRECTORY")
                if attr_value & FILE_ATTRIBUTE_ARCHIVE:
                    attr_flags.append("ARCHIVE")
                if attr_value & FILE_ATTRIBUTE_NORMAL:
                    attr_flags.append("NORMAL")
                if attr_value & FILE_ATTRIBUTE_TEMPORARY:
                    attr_flags.append("TEMPORARY")
                if attr_value & FILE_ATTRIBUTE_SPARSE_FILE:
                    attr_flags.append("SPARSE_FILE")
                if attr_value & FILE_ATTRIBUTE_REPARSE_POINT:
                    attr_flags.append("REPARSE_POINT")
                if attr_value & FILE_ATTRIBUTE_COMPRESSED:
                    attr_flags.append("COMPRESSED")
                if attr_value & FILE_ATTRIBUTE_OFFLINE:
                    attr_flags.append("OFFLINE")
                if attr_value & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED:
                    attr_flags.append("NOT_CONTENT_INDEXED")
                if attr_value & FILE_ATTRIBUTE_ENCRYPTED:
                    attr_flags.append("ENCRYPTED")
                
                info['attribute_flags'] = attr_flags

                # get security descriptor of the file
                try:
                    rpctransport = transport.SMBTransport(
                        self.client.getRemoteName(),
                        self.client.getRemoteHost(),
                        filename=r'\srvsvc',
                        smb_connection=self.client
                    )
                    dce = rpctransport.get_dce_rpc()
                    dce.connect()
                    dce.bind(srvs.MSRPC_UUID_SRVS)

                    security_flags = OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION

                    if path.startswith('\\'):
                        path = path[1:]  # Remove leading backslash if present
                    path = path.replace('/', '\\')

                    resp = srvs.hNetrpGetFileSecurity(dce, share+'\x00', path+'\x00', security_flags)
                    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
                    sd.fromString(resp)

                    security_info = {}
                    if sd['OwnerSid'] is not None:
                        security_info['OwnerSid'] = sd['OwnerSid'].formatCanonical()
                    if sd['GroupSid'] is not None:
                        security_info['GroupSid'] = sd['GroupSid'].formatCanonical()
                    
                    try:
                        dacl_data = sd['Dacl']['Data']
                        aces = []
                        for ace_obj in dacl_data:
                            ace_type_name = ace_obj['TypeName']
                            
                            # Filter for ACE types we can parse well
                            if ace_type_name not in ["ACCESS_ALLOWED_ACE", "ACCESS_DENIED_ACE", 
                                                     "ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_OBJECT_ACE",
                                                     "SYSTEM_AUDIT_ACE", "SYSTEM_ALARM_ACE",
                                                     "SYSTEM_AUDIT_OBJECT_ACE", "SYSTEM_ALARM_OBJECT_ACE"]:
                                logging.debug(f"[SMBClient: get_file_info] Skipping unhandled ACE type: {ace_type_name}")
                                continue

                            trustee_sid_str = ace_obj['Ace']['Sid'].formatCanonical()
                            
                            ace_flags_int = ace_obj['AceFlags']
                            parsed_ace_flags_list = [FLAG.name for FLAG in ACE_FLAGS if ace_flags_int & FLAG.value]

                            access_mask_int = ace_obj['Ace']['Mask']['Mask']
                            parsed_permissions_list = self._parsePerms(access_mask_int)
                            
                            if not parsed_permissions_list and access_mask_int != 0: # If no known flags matched but mask is not zero
                                parsed_permissions_list.append(f"UNKNOWN_MASK_0x{access_mask_int:08X}")

                            # Initialize object-specific fields
                            parsed_object_ace_specific_flags_list = None
                            obj_type_guid_str = None
                            inh_obj_type_guid_str = None

                            if ace_type_name in ["ACCESS_ALLOWED_OBJECT_ACE", "ACCESS_DENIED_OBJECT_ACE", "SYSTEM_AUDIT_OBJECT_ACE", "SYSTEM_ALARM_OBJECT_ACE"]:
                                object_ace_specific_flags_int = ace_obj['Ace']['Flags']
                                parsed_object_ace_specific_flags_list = [FLAG.name for FLAG in OBJECT_ACE_FLAGS if object_ace_specific_flags_int & FLAG.value]
                                
                                if ace_obj['Ace']['ObjectTypeLen'] != 0:
                                    obj_type_guid_str = bin_to_string(ace_obj['Ace']['ObjectType']).lower()
                                
                                if ace_obj['Ace']['InheritedObjectTypeLen'] != 0:
                                    inh_obj_type_guid_str = bin_to_string(ace_obj['Ace']['InheritedObjectType']).lower()

                            ace_info_entry = {
                                'type': ace_type_name,
                                'trustee': trustee_sid_str,
                                'ace_flags': parsed_ace_flags_list,
                                'access_mask_raw': access_mask_int,
                                'permissions': parsed_permissions_list,
                                'object_ace_specific_flags': parsed_object_ace_specific_flags_list,
                                'object_type_guid': obj_type_guid_str,
                                'inherited_object_type_guid': inh_obj_type_guid_str
                            }
                            aces.append(ace_info_entry)
                        
                        security_info['Dacl'] = aces
                        info['sd_info'] = security_info
                    except Exception as e:
                        logging.error(f"[SMBClient: get_file_info] Error parsing security descriptor: {e}")
                        import traceback
                        logging.debug(f"[SMBClient: get_file_info] Traceback: {traceback.format_exc()}")
                        # Store partial info if available
                        if 'security_info' not in locals(): security_info = {} # ensure security_info exists
                        if 'Dacl' not in security_info : security_info['Dacl'] = [] # ensure Dacl list exists
                        info['sd_info'] = security_info # Assign even if parsing failed mid-way
                except Exception as rpc_error:
                    logging.debug(f"[SMBClient: get_file_info] RPC error: {rpc_error}")
            return info
            
        except Exception as e:
            logging.error(f"[SMBClient: get_file_info] Error: {e}")
            raise
