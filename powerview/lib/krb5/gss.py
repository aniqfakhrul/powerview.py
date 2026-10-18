import os
import struct
from dataclasses import dataclass
from hmac import compare_digest

from Cryptodome.Cipher import ARC4
from Cryptodome.Hash import HMAC, MD5
from pyasn1.codec.der import decoder
from ldap3.core.exceptions import LDAPSignatureVerificationFailedError

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, EncAPRepPart, KRB_ERROR
from impacket.krb5.crypto import Key, InvalidChecksum, _enctype_table
from impacket.krb5.gssapi import KRB_OID, KG_USAGE_ACCEPTOR_SEAL, KG_USAGE_INITIATOR_SEAL
from impacket.krb5.types import KerberosTime

KRB5_AP_REP = b'\x02\x00'
KRB5_ERROR = b'\x03\x00'
AP_REP_KEY_USAGE = 12

class GSSError(LDAPSignatureVerificationFailedError):
	pass

@dataclass(frozen=True)
class WrapResult:
	message: bytes
	encrypted: bool = True

def _der_length(length):
	if length < 0x80:
		return bytes([length])
	encoded = length.to_bytes((length.bit_length() + 7) // 8, 'big')
	return bytes([0x80 | len(encoded)]) + encoded

def frame_token(inner):
	body = KRB_OID + inner
	return b'\x60' + _der_length(len(body)) + body

def unframe_token(token):
	if len(token) < 2 or token[0] != 0x60:
		raise GSSError('Missing GSS-API token header')
	size, offset = token[1], 2
	if size & 0x80:
		count = size & 0x7f
		if not count or len(token) < 2 + count or token[2] == 0:
			raise GSSError('Malformed Kerberos GSS-API token length')
		size, offset = int.from_bytes(token[2:2 + count], 'big'), 2 + count
		if size < 0x80:
			raise GSSError('Noncanonical Kerberos GSS-API token length')
	body = token[offset:offset + size]
	if offset + size != len(token) or not body.startswith(KRB_OID):
		raise GSSError('Malformed Kerberos GSS-API token')
	return body[len(KRB_OID):]

def _rotate(data, count):
	count %= len(data)
	return data[-count:] + data[:-count] if count else data

def _unrotate(data, count):
	count %= len(data)
	return data[count:] + data[:count]

class SecurityContext:
	overhead = 0

	def __init__(self, key, send_sequence, receive_sequence, acceptor_subkey=False):
		self._key = key
		self._send_sequence = send_sequence
		self._receive_sequence = receive_sequence

	def get_wrap_size_limit(self, output_size, confidential=True):
		return output_size - self.overhead

	def wrap(self, message, encrypt=True):
		if not encrypt:
			raise GSSError('Integrity-only wrap tokens are not supported')
		sequence = self._send_sequence
		self._send_sequence += 1
		return WrapResult(self._seal(message, sequence))

	def unwrap(self, token):
		message, sequence = self._unseal(token)
		if sequence != self._receive_sequence:
			raise GSSError(f'Out of sequence wrap token (expected {self._receive_sequence}, got {sequence})')
		self._receive_sequence += 1
		return WrapResult(message)

	def _seal(self, message, sequence):
		raise NotImplementedError

	def _unseal(self, token):
		raise NotImplementedError

class CfxContext(SecurityContext):
	TOKEN_ID = b'\x05\x04'
	SENT_BY_ACCEPTOR = 0x01
	SEALED = 0x02
	ACCEPTOR_SUBKEY = 0x04
	ROTATION = 28
	HEADER = struct.Struct('>2sBBHHQ')

	def __init__(self, key, send_sequence, receive_sequence, acceptor_subkey=False):
		super().__init__(key, send_sequence, receive_sequence, acceptor_subkey)
		self._cipher = _enctype_table[key.enctype]
		self._flags = self.SEALED | (self.ACCEPTOR_SUBKEY if acceptor_subkey else 0)
		self.overhead = 2 * self.HEADER.size + self._cipher.blocksize + self._cipher.macsize

	def _header(self, flags, extra_count, rotation, sequence):
		return self.HEADER.pack(self.TOKEN_ID, flags, 0xff, extra_count, rotation, sequence)

	def _seal(self, message, sequence):
		sealed = self._cipher.encrypt(self._key, KG_USAGE_INITIATOR_SEAL, message + self._header(self._flags, 0, 0, sequence), None)
		return self._header(self._flags, 0, self.ROTATION, sequence) + _rotate(sealed, self.ROTATION)

	def _unseal(self, token):
		if len(token) < self.overhead:
			raise GSSError('Truncated Kerberos wrap token')
		token_id, flags, filler, extra_count, rotation, sequence = self.HEADER.unpack(token[:self.HEADER.size])
		if token_id != self.TOKEN_ID or filler != 0xff:
			raise GSSError('Malformed Kerberos wrap token')
		if flags & ~self.ACCEPTOR_SUBKEY != self.SENT_BY_ACCEPTOR | self.SEALED:
			raise GSSError(f'Unexpected Kerberos wrap token flags 0x{flags:02x}')
		try:
			plain = self._cipher.decrypt(self._key, KG_USAGE_ACCEPTOR_SEAL, _unrotate(token[self.HEADER.size:], rotation))
		except InvalidChecksum as e:
			raise GSSError('Integrity check failed for a Kerberos wrap token') from e
		trailer = len(plain) - self.HEADER.size
		if trailer < extra_count or not compare_digest(plain[trailer:], self._header(flags, extra_count, 0, sequence)):
			raise GSSError('Kerberos wrap token header does not match its encrypted copy')
		return plain[:trailer - extra_count], sequence

class Rc4Context(SecurityContext):
	HEADER = b'\x02\x01\x11\x00\x10\x00\xff\xff'
	SEAL_SALT = 13
	INITIATOR_DIRECTION = b'\x00' * 4
	ACCEPTOR_DIRECTION = b'\xff' * 4
	PADDING = b'\x01'
	TOKEN_SIZE = len(HEADER) + 24
	overhead = 1 + 5 + len(KRB_OID) + TOKEN_SIZE + len(PADDING)

	def _hmac(self, key, data):
		return HMAC.new(key, data, MD5).digest()

	def _checksum(self, data):
		signing_key = self._hmac(self._key.contents, b'signaturekey\x00')
		return self._hmac(signing_key, MD5.new(struct.pack('<I', self.SEAL_SALT) + self.HEADER + data).digest())[:8]

	def _sequence_cipher(self, checksum):
		return ARC4.new(self._hmac(self._hmac(self._key.contents, struct.pack('<I', 0)), checksum))

	def _data_cipher(self, sequence):
		local_key = bytes(byte ^ 0xf0 for byte in self._key.contents)
		return ARC4.new(self._hmac(self._hmac(local_key, struct.pack('<I', 0)), sequence))

	def _seal(self, message, sequence):
		sequence_bytes = struct.pack('>I', sequence)
		plain = os.urandom(8) + message + self.PADDING
		checksum = self._checksum(plain)
		encrypted_sequence = self._sequence_cipher(checksum).encrypt(sequence_bytes + self.INITIATOR_DIRECTION)
		return frame_token(self.HEADER + encrypted_sequence + checksum + self._data_cipher(sequence_bytes).encrypt(plain))

	def _unseal(self, token):
		inner = unframe_token(token)
		if len(inner) <= self.TOKEN_SIZE or not inner.startswith(self.HEADER):
			raise GSSError('Malformed Kerberos wrap token')
		encrypted_sequence, checksum, sealed = inner[8:16], inner[16:24], inner[24:]
		sequence_bytes = self._sequence_cipher(checksum).decrypt(encrypted_sequence)
		if sequence_bytes[4:] != self.ACCEPTOR_DIRECTION:
			raise GSSError('Kerberos wrap token was not sent by the acceptor')
		plain = self._data_cipher(sequence_bytes[:4]).decrypt(sealed)
		if not compare_digest(self._checksum(plain), checksum):
			raise GSSError('Integrity check failed for a Kerberos wrap token')
		padding = plain[-1]
		if not 1 <= padding <= 8:
			raise GSSError('Invalid padding in a Kerberos wrap token')
		return plain[8:-padding], struct.unpack('>I', sequence_bytes[:4])[0]

_CONTEXTS = {
	constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value: CfxContext,
	constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value: CfxContext,
	constants.EncryptionTypes.rc4_hmac.value: Rc4Context,
}

def security_context(key, send_sequence=0, receive_sequence=0, acceptor_subkey=False):
	context = _CONTEXTS.get(key.enctype)
	if context is None:
		raise GSSError(f'Unsupported Kerberos encryption type {key.enctype} for message protection')
	return context(key, send_sequence, receive_sequence, acceptor_subkey)

def accept_ap_rep(token, cipher, session_key, authenticator_time, send_sequence=0):
	inner = unframe_token(token)
	token_id, payload = inner[:2], inner[2:]
	if token_id == KRB5_ERROR:
		error_code = int(decoder.decode(payload, asn1Spec=KRB_ERROR())[0]['error-code'])
		name, description = constants.ERROR_MESSAGES.get(error_code, (str(error_code), 'Unknown error'))
		raise GSSError(f'Kerberos mutual authentication failed: {name} ({description})')
	if token_id != KRB5_AP_REP:
		raise GSSError('Expected a Kerberos AP-REP token')

	ap_rep = decoder.decode(payload, asn1Spec=AP_REP())[0]
	try:
		plain = cipher.decrypt(session_key, AP_REP_KEY_USAGE, ap_rep['enc-part']['cipher'].asOctets())
	except InvalidChecksum as e:
		raise GSSError('Kerberos AP-REP failed its integrity check') from e
	enc_part = decoder.decode(plain, asn1Spec=EncAPRepPart())[0]
	if (str(enc_part['ctime']) != KerberosTime.to_asn1(authenticator_time)
			or int(enc_part['cusec']) != authenticator_time.microsecond):
		raise GSSError('Kerberos AP-REP does not match the initiating authenticator')

	subkey = enc_part['subkey']
	key = Key(int(subkey['keytype']), subkey['keyvalue'].asOctets()) if subkey.isValue else session_key
	receive_sequence = int(enc_part['seq-number']) if enc_part['seq-number'].isValue else 0
	return security_context(key, send_sequence, receive_sequence, acceptor_subkey=subkey.isValue)
