# This code is adapted from https://github.dev/xforcered/SoaPy/
import logging
import socket
import struct

import impacket.examples.logger
import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from impacket.hresult_errors import ERROR_MESSAGES
from impacket.krb5.gssapi import GSSAPI

from .encoder.records.utils import Net7BitInteger


def hexdump(data, length=16):
	def to_ascii(byte):
		if 32 <= byte <= 126:
			return chr(byte)
		else:
			return "."

	def format_line(offset, line_bytes):
		hex_part = " ".join(f"{byte:02X}" for byte in line_bytes)
		ascii_part = "".join(to_ascii(byte) for byte in line_bytes)
		return f"{offset:08X}  {hex_part:<{length*3}}  {ascii_part}"

	lines = []
	for i in range(0, len(data), length):
		line_bytes = data[i : i + length]
		lines.append(format_line(i, line_bytes))

	return "\n".join(lines)


class NNS_pkt(impacket.structure.Structure):
	structure: tuple[tuple[str, str], ...]

	def send(self, sock: socket.socket):
		sock.sendall(self.getData())


class NNS_handshake(NNS_pkt):
	structure = (
		("message_id", ">B"),
		("major_version", ">B"),
		("minor_version", ">B"),
		("payload_len", ">H-payload"),
		("payload", ":"),
	)

	# During negotitiate, payload will be the GSSAPI, containing SPNEGO
	# w/ NTLMSSP for NTLM or
	# w/ krb5_blob for the AP REQ)

	# For NTLM
	# NNS Headers
	# |_ Payload ( GSS-API )
	#   |_ SPNEGO ( NegTokenInit )
	#     |_ NTLMSSP

	# For Kerberos
	# NNS Headers
	# |_ Payload ( GSS-API )
	#   |_ SPNEGO ( NegTokenInit )
	#     |_ krb5_blob
	#       |_ Kerberos ( AP REQ )

	###

	# During challenge, payload will be the GSSAPI, containing SPNEGO
	# w/ NTLMSSP for NTLM or
	# w/ krb5_blob for the AP REQ)

	# For NTLM
	# NNS Headers
	# |_ Payload ( GSS-API, SPNEGO, no GSS-API headers )
	#     |_ NegTokenTarg ( NegTokenResp )
	#       |_ NTLMSSP

	def __init__(
		self, message_id: int, major_version: int, minor_version: int, payload: bytes
	):
		impacket.structure.Structure.__init__(self)
		self["message_id"] = message_id
		self["major_version"] = major_version
		self["minor_version"] = minor_version
		self["payload"] = payload


class NNS_data(NNS_pkt):
	# NNS data message, used after auth is completed

	structure = (
		("payload_size", "<L-payload"),
		("payload", ":"),
	)


class NNS_Signed_payload(impacket.structure.Structure):
	structure = (
		("signature", ":"),
		("cipherText", ":"),
	)


class MessageID:
	IN_PROGRESS: int = 0x16
	ERROR: int = 0x15
	DONE: int = 0x14


class NNS:
	"""[MS-NNS]: .NET NegotiateStream Protocol

	The .NET NegotiateStream Protocol provides mutually authenticated
	and confidential communication over a TCP connection.

	It defines a framing mechanism used to transfer (GSS-API) security tokens
	between a client and server. It also defines a framing mechanism used
	to transfer signed and/or encrypted application data once the GSS-API
	security context initialization has completed.
	"""

	def __init__(
		self,
		socket: socket.socket,
		fqdn: str,
		domain: str,
		username: str,
		password: str | None = None,
		nt: str = "",
		lm: str = "",
		aesKey: str = "",
		kdcHost: str | None = None,
		use_kerberos: bool = False,
		no_pass: bool = False,
	):
		self._sock = socket

		self._nt = self._fix_hashes(nt)
		self._lm = self._fix_hashes(lm)

		self._username = username
		self._password = password

		self._domain = domain
		self._fqdn = fqdn

		self._session_key: bytes = b""
		self._flags: int = -1
		self._sequence: int = 0

		# Kerberos-specific
		self._aesKey = aesKey
		self._kdcHost = kdcHost
		self._use_kerberos = use_kerberos
		self._no_pass = no_pass
		self._auth_type: str = ""  # set to 'ntlm' or 'kerberos' after auth
		self._gss = None           # GSSAPI wrapper (Kerberos only)
		self._krb_session_key = None  # impacket Key object (Kerberos only)

	def _fix_hashes(self, hash: str | bytes) -> bytes | str:
		"""fixes up hash if present into bytes and
		ensures length is 32.

		If no hash is present, returns empty bytes

		Args:
			hash (str | bytes): nt or lm hash

		Returns:
			bytes: bytes version
		"""

		if not hash:
			return ""

		if len(hash) % 2:
			hash = hash.zfill(32)

		return bytes.fromhex(hash) if isinstance(hash, str) else hash

	def _recv_handshake(self) -> 'NNS_handshake':
		"""Receive an NNS handshake message from the server."""
		return NNS_handshake(
			message_id=int.from_bytes(self._sock.recv(1), "big"),
			major_version=int.from_bytes(self._sock.recv(1), "big"),
			minor_version=int.from_bytes(self._sock.recv(1), "big"),
			payload=self._sock.recv(int.from_bytes(self._sock.recv(2), "big")),
		)

	def seal(self, data: bytes) -> tuple[bytes, bytes]:
		"""seals data with the current context (NTLM only)

		Args:
			data (bytes): bytes to seal

		Returns:
			tuple[bytes, bytes]: output_data, signature
		"""

		server = bool(
			self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		)

		output, sig = impacket.ntlm.SEAL(
			self._flags,
			self._server_signing_key if server else self._client_signing_key,
			self._server_sealing_key if server else self._client_sealing_key,
			data,
			data,
			self._sequence,
			self._server_sealing_handle if server else self._client_sealing_handle,
		)

		return output, sig.getData()

	def recv(self, _: int = 0) -> bytes:
		"""Recive an NNS packet and return the entire
		decrypted contents.

		The paramiter is used to allow interoperability with socket.socket.recv.
		Does not respect any passed buffer sizes.

		Args:
			_ (int, optional): For interoperability with socket.socket. Defaults to 0.

		Returns:
			bytes: unsealed nns message
		"""
		first_pkt = self._recv()

		# if it isnt an envelope, throw it back
		if first_pkt[0] != 0x06:
			return first_pkt

		nmfsize, nmflenlen = Net7BitInteger.decode7bit(first_pkt[1:])

		# its all just one packet
		if nmfsize < 0xFC30:
			return first_pkt

		# otherwise, we have a multi part message
		pkt = first_pkt
		nmfsize -= len(first_pkt[nmflenlen:])

		while nmfsize > 0:
			thisFragment = self._recv()

			pkt += thisFragment
			nmfsize -= len(thisFragment)

		return pkt

	def _strip_gss_header(self, data: bytes) -> bytes:
		"""Strip MechIndepToken GSS-API header (Application tag + length + OID).

		Returns the raw mechanism token (Token ID + WRAP + data).
		"""
		if data[0] != 0x60:
			return data  # No GSS wrapping, return as-is
		offset = 1
		if data[offset] < 128:
			offset += 1  # short form DER length
		else:
			offset += 1 + (data[offset] - 128)  # long form DER length
		# Skip OID: 06 <len> <value bytes>
		oid_len = data[offset + 1]
		offset += 2 + oid_len
		return data[offset:]

	def _krb_rc4_unwrap(self, data: bytes) -> bytes:
		"""Correctly unwrap RC4 GSS WRAP token.

		Works around impacket MechIndepToken.from_bytes() parsing bug
		that misaligns the WRAP structure for short-form DER lengths.
		"""
		from Cryptodome.Cipher import ARC4 as ARC4_cipher
		from Cryptodome.Hash import HMAC, MD5

		# Strip GSS header to get raw mechanism token
		inner = self._strip_gss_header(data)

		# Parse WRAP structure (32 bytes):
		# TOK_ID(2) + SGN_ALG(2) + SEAL_ALG(2) + Filler(2) +
		# SND_SEQ(8) + SGN_CKSUM(8) + Confounder(8)
		snd_seq_enc = inner[8:16]
		sgn_cksum = inner[16:24]
		confounder_enc = inner[24:32]
		encrypted_payload = inner[32:]

		session_key = self._krb_session_key.contents

		# Derive Klocal (XOR key with 0xF0)
		klocal = bytes(b ^ 0xF0 for b in session_key)

		# Derive Kseq and decrypt SND_SEQ
		kseq = HMAC.new(session_key, struct.pack('<L', 0), MD5).digest()
		kseq = HMAC.new(kseq, sgn_cksum, MD5).digest()
		snd_seq = ARC4_cipher.new(kseq).encrypt(snd_seq_enc)

		# Derive Kcrypt using decrypted sequence number
		kcrypt = HMAC.new(klocal, struct.pack('<L', 0), MD5).digest()
		kcrypt = HMAC.new(kcrypt, snd_seq[:4], MD5).digest()

		# Decrypt confounder + data, skip 8-byte confounder, strip 1-byte padding
		rc4 = ARC4_cipher.new(kcrypt)
		plaintext = rc4.decrypt(confounder_enc + encrypted_payload)
		return plaintext[8:-1]

	def _recv(self, _: int = 0) -> bytes:
		"""Recive an NNS packet and return the entire
		decrypted contents.

		The paramiter is used to allow interoperability with socket.socket.recv.
		Does not respect any passed buffer sizes.
		"""
		size = int.from_bytes(self._sock.recv(4), "little")

		payload = b""
		while len(payload) != size:
			payload += self._sock.recv(size - len(payload))

		if self._auth_type == 'kerberos':
			from impacket.krb5.gssapi import GSSAPI_RC4
			if isinstance(self._gss, GSSAPI_RC4):
				# RC4: payload is MechIndepToken-wrapped (GSS header + WRAP + data)
				return self._krb_rc4_unwrap(payload)
			else:
				# AES: payload is raw [16-byte WRAP header][ciphertext]
				clearText, _ = self._gss.GSS_Unwrap_LDAP(
					self._krb_session_key, payload, self._sequence, direction='init'
				)
				return clearText

		# NTLM: payload is [16-byte signature][ciphertext]
		signature = payload[0:16]
		cipherText = payload[16:]
		clearText, sig = self.seal(cipherText)
		return clearText

	def sendall(self, data: bytes):
		"""Send data in a sealed NNS data packet via tcp socket.

		Args:
			data (bytes): payload data to send
		"""

		if self._auth_type == 'kerberos':
			# Kerberos GSS_Wrap: returns (cipherText, token_header)
			cipherText, token_header = self._gss.GSS_Wrap_LDAP(
				self._krb_session_key, data, self._sequence
			)
			pkt = NNS_data()
			pkt["payload"] = token_header + cipherText
			self._sock.sendall(pkt.getData())
			self._sequence += 1
			return

		# NTLM SEAL path
		cipherText, sig = impacket.ntlm.SEAL(
			self._flags,
			self._client_signing_key,
			self._client_sealing_key,
			data,
			data,
			self._sequence,
			self._client_sealing_handle,
		)

		# build the NNS data packet to use
		pkt = NNS_data()

		# then we build the payload, which is the signature prepended
		# on the actual ciphertext.  This goes in the payload of
		# the NNS data packet
		payload = NNS_Signed_payload()
		payload["signature"] = sig
		payload["cipherText"] = cipherText
		pkt["payload"] = payload.getData()

		self._sock.sendall(pkt.getData())

		# and we increment the sequence number after sending
		self._sequence += 1

	def authenticate(self) -> None:
		"""Dispatch to the appropriate authentication method."""
		if self._use_kerberos:
			self.auth_kerberos()
		else:
			self.auth_ntlm()

	def auth_kerberos(self) -> None:
		"""Authenticate using Kerberos via SPNEGO (2-leg, no DCE_STYLE)."""
		from powerview.lib.krb5.kerberosv5 import getKerberosType1
		from impacket.krb5.asn1 import AP_REP, EncAPRepPart
		from impacket.krb5.crypto import _enctype_table, Key
		from pyasn1.codec.der import decoder

		logging.debug("[NNS] Starting Kerberos authentication")

		# Step 1: Build SPNEGO NegTokenInit with AP-REQ (no DCE_STYLE = 2-leg)
		cipher, sessionKey, blob = getKerberosType1(
			self._username,
			self._password or '',
			self._domain,
			self._lm,
			self._nt,
			aesKey=self._aesKey or '',
			targetName=self._fqdn,
			kdcHost=self._kdcHost,
			useCache=self._no_pass,
			dce_style=False,
		)

		# Step 2: Send NegTokenInit in NNS handshake
		NNS_handshake(
			message_id=MessageID.IN_PROGRESS,
			major_version=1,
			minor_version=0,
			payload=blob,
		).send(self._sock)

		# Step 3: Receive server response (DONE with AP-REP payload)
		server_resp = self._recv_handshake()
		if server_resp["message_id"] == MessageID.ERROR:
			raise SystemExit("[-] Kerberos Auth Failed: server rejected token")

		# Step 4: Extract subkey from AP-REP (no third message needed)
		negTokenResp = impacket.spnego.SPNEGO_NegTokenResp(server_resp["payload"])
		response_token = negTokenResp["ResponseToken"]

		# Without DCE_STYLE, ResponseToken has KRB5 GSS header prefix.
		# Try raw decode first, then strip prefix if needed.
		try:
			ap_rep = decoder.decode(response_token, asn1Spec=AP_REP())[0]
		except Exception:
			# Strip KRB5 GSS-API header to find raw AP-REP
			idx = response_token.find(b'\x6f')
			if idx < 0:
				raise ConnectionError("Failed to parse AP-REP from server response")
			ap_rep = decoder.decode(response_token[idx:], asn1Spec=AP_REP())[0]

		cipherText = ap_rep['enc-part']['cipher']

		# Key Usage 12: AP-REP encrypted part (contains subkey)
		plainText = cipher.decrypt(sessionKey, 12, cipherText)
		encAPRepPart = decoder.decode(plainText, asn1Spec=EncAPRepPart())[0]

		cipher2 = _enctype_table[int(encAPRepPart['subkey']['keytype'])]()
		sessionKey2 = Key(cipher2.enctype, encAPRepPart['subkey']['keyvalue'].asOctets())

		# Step 5: If server sent IN_PROGRESS, receive the DONE message
		if server_resp["message_id"] == MessageID.IN_PROGRESS:
			server_done = self._recv_handshake()
			if server_done["message_id"] == MessageID.ERROR:
				raise SystemExit("[-] Kerberos Auth Failed: server rejected auth")

		# Step 6: Set up Kerberos GSS-API context for message protection
		self._gss = GSSAPI(cipher2)
		self._krb_session_key = sessionKey2
		self._auth_type = 'kerberos'
		self._sequence = 0

		logging.debug("[NNS] Kerberos authentication successful")

	def auth_ntlm(self) -> None:
		"""Authenticate to the dest with NTLMV2 authentication"""

		# Initial negotiation sent from client
		NegTokenInit: impacket.spnego.SPNEGO_NegTokenInit
		NtlmSSP_nego: impacket.ntlm.NTLMAuthNegotiate

		# Generate a NTLMSSP
		NtlmSSP_nego = impacket.ntlm.getNTLMSSPType1(
			workstation="",  # These fields don't get populated for some reason
			domain="",  # These fields don't get populated for some reason
			signingRequired=True,  # TODO: Somehow determine this; can we send a Negotiate Protocol Request and derive this dynamically?
			use_ntlmv2=True,  # TODO: See above comment
		)

		# Generate the NegTokenInit
		# Impacket has this inherit from GSSAPI, so we will also have the OID and other headers :D
		NegTokenInit = impacket.spnego.SPNEGO_NegTokenInit()
		NegTokenInit["MechTypes"] = [
			impacket.spnego.TypesMech[
				"NTLMSSP - Microsoft NTLM Security Support Provider"
			],
			impacket.spnego.TypesMech["MS KRB5 - Microsoft Kerberos 5"],
			impacket.spnego.TypesMech["KRB5 - Kerberos 5"],
			impacket.spnego.TypesMech[
				"NEGOEX - SPNEGO Extended Negotiation Security Mechanism"
			],
		]
		NegTokenInit["MechToken"] = NtlmSSP_nego.getData()

		# Fit it all into an NNS NTLMSSP_NEGOTIATE Message
		# Begin authentication ( NTLMSSP_NEGOTIATE )
		NNS_handshake(
			message_id=MessageID.IN_PROGRESS,
			major_version=1,
			minor_version=0,
			payload=NegTokenInit.getData(),
		).send(self._sock)

		# Response with challenge from server
		NNS_msg_chall: NNS_handshake
		s_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
		NTLMSSP_chall: impacket.ntlm.NTLMAuthChallenge

		# Receive the NNS NTLMSSP_Challenge
		NNS_msg_chall = self._recv_handshake()

		# Extract the NegTokenResp ( NegTokenTarg )
		# Note: Potentially consider SupportedMech from s_NegTokenTarg for determining stuff like signing?
		s_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp(NNS_msg_chall["payload"])

		# Create an NtlmAuthChallenge from the NTLMSSP ( ResponseToken )
		NTLMSSP_chall = impacket.ntlm.NTLMAuthChallenge(s_NegTokenTarg["ResponseToken"])

		# TODO: see if this is relevant https://github.com/fortra/impacket/blob/15eff8805116007cfb59332a64194a5b9c8bcf25/impacket/smb3.py#L1015
		# if NTLMSSP_chall[ 'TargetInfoFields_len' ] > 0:
		#     av_pairs   = impacket.ntlm.AV_PAIRS( NTLMSSP_chall[ 'TargetInfoFields' ][ :NTLMSSP_chall[ 'TargetInfoFields_len' ] ] )
		#     if av_pairs[ impacket.ntlm.NTLMSSP_AV_HOSTNAME ] is not None:
		#         print( "TODO AV PAIRS IDK IF ITS RELEVANT" )

		# Response with authentication from client
		c_NegTokenTarg: impacket.spnego.SPNEGO_NegTokenResp
		NTLMSSP_chall_resp: impacket.ntlm.NTLMAuthChallengeResponse

		# Create the NTLMSSP challenge response
		# If password is used, then the lm and nt hashes must be pass
		# an empty str, NOT, empty byte str.......
		NTLMSSP_chall_resp, self._session_key = impacket.ntlm.getNTLMSSPType3(
			type1=NtlmSSP_nego,
			type2=NTLMSSP_chall.getData(),
			user=self._username,
			password=self._password,
			domain=self._domain,
			lmhash=self._lm,
			nthash=self._nt,
		)

		# set up info for crypto
		self._flags = NTLMSSP_chall_resp["flags"]
		self._sequence = 0
		self._auth_type = 'ntlm'

		if self._flags & impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
			self._client_signing_key = impacket.ntlm.SIGNKEY(
				self._flags, self._session_key
			)
			self._server_signing_key = impacket.ntlm.SIGNKEY(
				self._flags, self._session_key, "Server"
			)
			self._client_sealing_key = impacket.ntlm.SEALKEY(
				self._flags, self._session_key
			)
			self._server_sealing_key = impacket.ntlm.SEALKEY(
				self._flags, self._session_key, "Server"
			)

			# prepare keys to handle states
			cipher1 = ARC4.new(self._client_sealing_key)
			self._client_sealing_handle = cipher1.encrypt
			cipher2 = ARC4.new(self._server_sealing_key)
			self._server_sealing_handle = cipher2.encrypt

		else:
			logging.debug("We are doing basic ntlm auth")
			# same key for both ways
			self._client_signing_key = self._session_key
			self._server_signing_key = self._session_key
			self._client_sealing_key = self._session_key
			self._server_sealing_key = self._session_key
			cipher = ARC4.new(self._client_sealing_key)
			self._client_sealing_handle = cipher.encrypt
			self._server_sealing_handle = cipher.encrypt

		# Fit the challenge response into the ResponseToken of our NegTokenTarg
		c_NegTokenTarg = impacket.spnego.SPNEGO_NegTokenResp()
		c_NegTokenTarg["ResponseToken"] = NTLMSSP_chall_resp.getData()

		# Fit our challenge response into an NNS message
		# Send the NTLMSSP_AUTH ( challenge response )
		NNS_handshake(
			message_id=MessageID.IN_PROGRESS,
			major_version=1,
			minor_version=0,
			payload=c_NegTokenTarg.getData(),
		).send(self._sock)

		# Response from server ending handshake
		NNS_msg_done: NNS_handshake

		# Check for success
		NNS_msg_done = self._recv_handshake()

		# check for errors
		if NNS_msg_done["message_id"] == 0x15:
			err_type, err_msg = ERROR_MESSAGES[
				int.from_bytes(NNS_msg_done["payload"], "big")
			]
			raise SystemExit(f"[-] NTLM Auth Failed with error {err_type} {err_msg}")
