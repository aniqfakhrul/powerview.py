#!/usr/bin/env python3
from powerview.utils.constants import MSDS_MANAGEDPASSWORD_BLOB
from Cryptodome.Hash import MD4
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR

import binascii

class GMSA:
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

		for dacl in SR_SECURITY_DESCRIPTOR(data=secDesc)['Dacl']['Data']:
			sids.append(dacl['Ace']['Sid'].formatCanonical())

		return sids
