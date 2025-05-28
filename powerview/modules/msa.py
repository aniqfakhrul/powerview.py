#!/usr/bin/env python3
from powerview.utils.accesscontrol import AccessControl
from powerview.utils.constants import MSDS_MANAGEDPASSWORD_BLOB
from Cryptodome.Hash import MD4
from impacket.ldap import ldaptypes
import logging
import binascii

class MSA:
	@staticmethod
	def decrypt(blob):
		blob = MSDS_MANAGEDPASSWORD_BLOB(blob)
		hash = MD4.new()
		hash.update(blob["CurrentPassword"][:-2])
		passwd = (
		    binascii.hexlify(hash.digest()).decode()
		)
		return passwd

	@staticmethod
	def read_acl(secDesc):
		return AccessControl.get_user_sid(secDesc)

	@staticmethod
	def create_msamembership(principal_sid: str):
		sd = AccessControl.create_empty_sd()
		acl = AccessControl.create_ace(principal_sid)
		sd['Dacl'].aces.append(acl)
		return sd.getData() 

	@staticmethod
	def set_hidden_secdesc(sec_desc: bytes, whitelisted_sids: list[str]):
		"""
		Change the ntSecurityDescriptor to only allow the principal to access the account
		"""
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR(data=sec_desc)
		new_dacl = []
		for ace in sd['Dacl'].aces:
			if ace['Ace']['Sid'].formatCanonical() in whitelisted_sids or ace['AceType'] == ldaptypes.ACCESS_DENIED_OBJECT_ACE.ACE_TYPE:
				new_dacl.append(ace)
		sd['Dacl'].aces = new_dacl
		return sd.getData()