#!/usr/bin/env python3
import struct
import logging

from impacket.dcerpc.v5 import drsuapi, transport, epm
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_PKT_PRIVACY


class DRSHandler:
	"""Handle DRS (Directory Replication Services) operations.

	Provides IDL_DRSWriteNgcKey (opnum 29) and IDL_DRSReadNgcKey (opnum 30)
	for writing/reading NGC keys via the replication channel.
	"""

	def __init__(self, connection):
		self.connection = connection
		self.dce = None
		self.handle = None

	def connect(self, target=None):
		"""EPM map -> TCP connect -> DRSBind. Returns self."""
		if not target:
			target = self.connection.dc_ip

		string_binding = epm.hept_map(
			target,
			drsuapi.MSRPC_UUID_DRSUAPI,
			protocol='ncacn_ip_tcp',
		)
		rpctransport = transport.DCERPCTransportFactory(string_binding)
		rpctransport.set_credentials(
			self.connection.username,
			self.connection.password,
			self.connection.domain,
			self.connection.lmhash,
			self.connection.nthash,
			TGT=self.connection.TGT,
		)

		if hasattr(rpctransport, 'set_kerberos') and self.connection.use_kerberos:
			rpctransport.set_kerberos(True, kdcHost=self.connection.kdcHost)

		rpctransport.setRemoteHost(target)

		dce = rpctransport.get_dce_rpc()
		dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
		dce.connect()
		dce.bind(drsuapi.MSRPC_UUID_DRSUAPI)

		# DRSBind
		request = drsuapi.DRSBind()
		request['puuidClientDsa'] = drsuapi.NTDSAPI_CLIENT_GUID
		drs_ext = drsuapi.DRS_EXTENSIONS_INT()
		drs_ext['cb'] = len(drs_ext) - 4
		drs_ext['dwFlags'] = (
			drsuapi.DRS_EXT_GETCHGREQ_V6
			| drsuapi.DRS_EXT_GETCHGREPLY_V6
			| 0x04000000
		)
		drs_ext['SiteObjGuid'] = drsuapi.NULLGUID
		drs_ext['Pid'] = 0
		drs_ext['dwReplEpoch'] = 0
		drs_ext['dwFlagsExt'] = 0
		drs_ext['ConfigObjGUID'] = drsuapi.NULLGUID
		drs_ext['dwExtCaps'] = 0xffffffff
		request['pextClient']['cb'] = len(drs_ext)
		request['pextClient']['rgb'] = list(drs_ext.getData())

		resp = dce.request(request)
		handle = resp['phDrs']
		if not isinstance(handle, bytes):
			handle = handle.getData()

		self.dce = dce
		self.handle = handle
		return self

	def disconnect(self):
		"""Clean close of DRS handle + DCE."""
		if self.dce:
			try:
				self.dce.disconnect()
			except Exception:
				pass
			self.dce = None
			self.handle = None

	def write_ngc_key(self, dn, key_data):
		"""IDL_DRSWriteNgcKey (opnum 29). Returns retval (0 = success)."""
		acct_utf16 = dn.encode('utf-16-le') + b'\x00\x00'
		cc = len(dn) + 1

		data = self.handle + struct.pack('<II', 1, 1)
		# Pointer to structure
		data += struct.pack('<I', 0x00020000)
		# Key length
		data += struct.pack('<I', len(key_data))
		# Key pointer (non-null if key_data present, null otherwise)
		if len(key_data) > 0:
			data += struct.pack('<I', 0x00020004)
		else:
			data += struct.pack('<I', 0)
		# DN as conformant UTF-16LE string
		data += struct.pack('<III', cc, 0, cc)
		data += acct_utf16
		pad = (4 - len(acct_utf16) % 4) % 4
		data += b'\x00' * pad
		# Key data
		if len(key_data) > 0:
			data += struct.pack('<I', len(key_data))
			data += key_data
			pad = (4 - len(key_data) % 4) % 4
			data += b'\x00' * pad

		self.dce.call(29, data)
		resp = self.dce.recv()
		ret = struct.unpack('<I', resp[-4:])[0]
		return ret

	def read_ngc_key(self, dn):
		"""IDL_DRSReadNgcKey (opnum 30). Returns (retval, key_data)."""
		acct_utf16 = dn.encode('utf-16-le') + b'\x00\x00'
		cc = len(dn) + 1

		data = self.handle + struct.pack('<II', 1, 1)
		data += struct.pack('<I', 0x00020000)
		data += struct.pack('<III', cc, 0, cc)
		data += acct_utf16
		pad = (4 - len(acct_utf16) % 4) % 4
		data += b'\x00' * pad

		self.dce.call(30, data)
		resp = self.dce.recv()
		ret = struct.unpack('<I', resp[-4:])[0]
		key_data = None
		if ret == 0 and len(resp) > 24:
			c_ngc = struct.unpack('<I', resp[12:16])[0]
			if c_ngc > 0 and len(resp) >= 24 + c_ngc:
				key_data = resp[24:24 + c_ngc]
		return ret, key_data

	@staticmethod
	def rsa_to_bcrypt_blob(private_key):
		"""Convert RSA private key's public component to BCRYPT_RSAKEY_BLOB.

		BCRYPT_RSAKEY_BLOB structure:
			Magic (ULONG)       = 0x31415352 ("RSA1" for public key)
			BitLength (ULONG)   = key bit length (e.g. 2048)
			cbPublicExp (ULONG) = size of public exponent in bytes
			cbModulus (ULONG)   = size of modulus in bytes
			cbPrime1 (ULONG)    = 0 (not included for public)
			cbPrime2 (ULONG)    = 0 (not included for public)
		Followed by:
			PublicExponent (cbPublicExp bytes, big-endian)
			Modulus (cbModulus bytes, big-endian)
		"""
		pub_numbers = private_key.public_key().public_numbers()
		modulus = pub_numbers.n
		exponent = pub_numbers.e

		key_size = private_key.key_size
		modulus_bytes = modulus.to_bytes(key_size // 8, byteorder='big')
		exp_bytes = exponent.to_bytes(
			(exponent.bit_length() + 7) // 8, byteorder='big'
		)

		blob = struct.pack('<I', 0x31415352)        # Magic = "RSA1"
		blob += struct.pack('<I', key_size)          # BitLength
		blob += struct.pack('<I', len(exp_bytes))    # cbPublicExp
		blob += struct.pack('<I', len(modulus_bytes)) # cbModulus
		blob += struct.pack('<I', 0)                 # cbPrime1
		blob += struct.pack('<I', 0)                 # cbPrime2
		blob += exp_bytes                            # PublicExponent
		blob += modulus_bytes                        # Modulus

		return blob
