#!/usr/bin/env python3

import logging

from impacket.ldap import ldaptypes
from impacket.uuid import bin_to_string
from powerview.modules.ldapattack import ACE_FLAGS, OBJECT_ACE_FLAGS, SIMPLE_PERMISSIONS, ACCESS_MASK

class AccessControl:
	@staticmethod
	def get_default_sd():
		return AccessControl.create_empty_sd()

	@staticmethod
	def create_empty_sd(
		owner_sid: str='S-1-5-32-544', 
		control: int=32772,
		acl_revision: int=4,
		sbz1: int=0,
		sbz2: int=0
	):
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		sd['Revision'] = b'\x01'
		sd['Sbz1'] = b'\x00'
		sd['Control'] = control
		sd['OwnerSid'] = ldaptypes.LDAP_SID()
		sd['OwnerSid'].fromCanonical(owner_sid)
		sd['GroupSid'] = b''
		sd['Sacl'] = b''
		acl = ldaptypes.ACL()
		acl['AclRevision'] = acl_revision
		acl['Sbz1'] = sbz1
		acl['Sbz2'] = sbz2
		acl.aces = []
		sd['Dacl'] = acl
		return sd

	@staticmethod
	def create_ace(
		sid: str, 
		mask: int=983551, 
		ace_type: int=ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE, 
		ace_flags: int=0x00
	):
		nace = ldaptypes.ACE()
		nace['AceType'] = ace_type
		nace['AceFlags'] = ace_flags
		acedata = ldaptypes.ACCESS_ALLOWED_ACE()
		acedata['Mask'] = ldaptypes.ACCESS_MASK()
		acedata['Mask']['Mask'] = mask
		acedata['Sid'] = ldaptypes.LDAP_SID()
		acedata['Sid'].fromCanonical(sid)
		nace['Ace'] = acedata
		return nace

	@staticmethod
	def parse_perms(fsr):
		_perms = []
		for PERM in SIMPLE_PERMISSIONS:
			if (fsr & PERM.value) == PERM.value:
				_perms.append(PERM.name)
				fsr = fsr & (not PERM.value)
		for PERM in ACCESS_MASK:
			if fsr & PERM.value:
				_perms.append(PERM.name)
		return _perms

	@staticmethod
	def get_user_sid(secDesc):
		sids = []
		if not secDesc:
			return

		for dacl in ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDesc)['Dacl']['Data']:
			sids.append(dacl['Ace']['Sid'].formatCanonical())
		return sids
		
	@staticmethod
	def parse_sd(secDesc, raw=False):
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		if isinstance(secDesc, list):
			secDesc = b''.join(secDesc)
		sd.fromString(secDesc)

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
				if raw:
					parsed_permissions_list = access_mask_int
				else:
					parsed_permissions_list = AccessControl.parse_perms(access_mask_int)
				
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
			return security_info
		except Exception as e:
			logging.error(f"[SMBClient: get_file_info] Error parsing security descriptor: {e}")
			import traceback
			logging.debug(f"[SMBClient: get_file_info] Traceback: {traceback.format_exc()}")
			if 'security_info' not in locals(): security_info = {}
			if 'Dacl' not in security_info : security_info['Dacl'] = []
			return security_info

	@staticmethod
	def sort_dacl_aces(sd):
		"""
		Sort ACEs in the DACL according to Windows canonical order:
		1. Explicit DENY ACEs
		2. Explicit ALLOW ACEs  
		3. Inherited DENY ACEs
		4. Inherited ALLOW ACEs
		"""
		if not sd['Dacl'] or not hasattr(sd['Dacl'], 'aces'):
			return sd
			
		aces = sd['Dacl'].aces
		if not aces:
			return sd
			
		def ace_sort_key(ace):
			ace_type = ace['AceType']
			ace_flags = ace['AceFlags']
			
			is_inherited = bool(ace_flags & 0x10)
			
			is_deny = ace_type in [
				ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE,
				ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE
			]
			
			if not is_inherited and is_deny:
				return (0, ace_type)
			elif not is_inherited and not is_deny:
				return (1, ace_type)
			elif is_inherited and is_deny:
				return (2, ace_type)
			else:
				return (3, ace_type)
		
		sorted_aces = sorted(aces, key=ace_sort_key)
		sd['Dacl'].aces = sorted_aces
		
		return sd

	@staticmethod
	def add_allow_ace(
		secDesc: bytes,
		sid: str,
		mask: int=SIMPLE_PERMISSIONS.FullControl.value, # Full Control
		inherit: bool=True
	):
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		if isinstance(secDesc, list):
			secDesc = b''.join(secDesc)
		sd.fromString(secDesc)
		ace_flags = 0x00
		if inherit:
			ace_flags = ACE_FLAGS.CONTAINER_INHERIT_ACE.value + ACE_FLAGS.OBJECT_INHERIT_ACE.value
		sd['Dacl'].aces.append(
			AccessControl.create_ace(
				sid,
				mask,
				ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE,
				ace_flags
			)
		)
		sd = AccessControl.sort_dacl_aces(sd)
		return sd.getData()

	@staticmethod
	def add_deny_ace(
		secDesc: bytes,
		sid: str,
		mask: int=SIMPLE_PERMISSIONS.FullControl.value,
		inherit: bool=True
	):
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		if isinstance(secDesc, list):
			secDesc = b''.join(secDesc)
		sd.fromString(secDesc)
		ace_flags = 0x00
		if inherit:
			ace_flags = ACE_FLAGS.CONTAINER_INHERIT_ACE.value + ACE_FLAGS.OBJECT_INHERIT_ACE.value
		sd['Dacl'].aces.append(
			AccessControl.create_ace(
				sid,
				mask,
				ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE,
				ace_flags
			)
		)
		sd = AccessControl.sort_dacl_aces(sd)
		return sd.getData()

	@staticmethod
	def remove_ace(
		secDesc: bytes,
		sid: str,
		mask: int=None,
		ace_type: int=None
	):
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		if isinstance(secDesc, list):
			secDesc = b''.join(secDesc)
		sd.fromString(secDesc)
		
		aces_to_remove = []
		for ace in sd['Dacl'].aces:
			ace_sid = ace['Ace']['Sid'].formatCanonical()
			ace_mask = ace['Ace']['Mask']['Mask']
			ace_type_val = ace['AceType']
			
			if ace_sid == sid:
				if mask is None or ace_mask == mask:
					if ace_type is None or ace_type_val == ace_type:
						aces_to_remove.append(ace)
		
		for ace in aces_to_remove:
			sd['Dacl'].aces.remove(ace)
		
		sd = AccessControl.sort_dacl_aces(sd)
		
		return sd.getData(), len(aces_to_remove)

	@staticmethod
	def fix_dacl_ordering(secDesc: bytes):
		"""
		Fix the ordering of ACEs in an existing DACL to match Windows canonical order.
		This is useful for cleaning up DACLs that may have been created with incorrect ordering.
		"""
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		if isinstance(secDesc, list):
			secDesc = b''.join(secDesc)
		sd.fromString(secDesc)
		
		sd = AccessControl.sort_dacl_aces(sd)
		
		return sd.getData()