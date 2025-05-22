#!/usr/bin/env python3
from powerview.utils.constants import MSDS_MANAGEDPASSWORD_BLOB
from Cryptodome.Hash import MD4
from impacket.ldap import ldaptypes

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
		sids = []
		if not secDesc:
			return

		for dacl in ldaptypes.SR_SECURITY_DESCRIPTOR(data=secDesc)['Dacl']['Data']:
			sids.append(dacl['Ace']['Sid'].formatCanonical())

		return sids

	@staticmethod
	def create_msamembership(principal_sid: str):
		sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
		sd['Revision'] = b'\x01'
		sd['Sbz1'] = b'\x00'
		sd['Control'] = 32772
		sd['OwnerSid'] = ldaptypes.LDAP_SID()
		sd['OwnerSid'].fromCanonical('S-1-5-32-544')
		sd['GroupSid'] = b''
		sd['Sacl'] = b''
		acl = ldaptypes.ACL()
		acl['AclRevision'] = 4
		acl['Sbz1'] = 0
		acl['Sbz2'] = 0
		acl.aces = []
		nace = ldaptypes.ACE()
		nace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
		nace['AceFlags'] = 0x00
		acedata = ldaptypes.ACCESS_ALLOWED_ACE()
		acedata['Mask'] = ldaptypes.ACCESS_MASK()
		acedata['Mask']['Mask'] = 983551
		acedata['Sid'] = ldaptypes.LDAP_SID()
		acedata['Sid'].fromCanonical(principal_sid)
		nace['Ace'] = acedata
		acl.aces.append(nace)
		sd['Dacl'] = acl
		return sd.getData()
