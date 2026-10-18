# This code is adapted from https://github.dev/xforcered/SoaPy/
import logging
import socket
import struct
from datetime import datetime, timezone
from hmac import compare_digest

import impacket.examples.logger
import impacket.ntlm
import impacket.spnego
import impacket.structure
from Cryptodome.Cipher import ARC4
from impacket.hresult_errors import ERROR_MESSAGES
from ldap3.core.exceptions import LDAPSignatureVerificationFailedError

from powerview.lib.krb5.gss import accept_ap_rep

from .encoder.records.utils import Net7BitInteger
from .transport import receive_exactly


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
		TGT: dict | None = None,
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
		self._TGT = TGT  # Pre-cached TGT to avoid re-requesting from KDC
		self._cached_tgt = None  # Populated after auth for caller to cache
		self._auth_type: str = ""  # set to 'ntlm' or 'kerberos' after auth
		self._krb_ctx = None

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
		header = receive_exactly(self._sock, 5)
		return NNS_handshake(
			message_id=header[0],
			major_version=header[1],
			minor_version=header[2],
			payload=receive_exactly(self._sock, int.from_bytes(header[3:5], 'big')),
		)

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

		expected_size = 1 + nmflenlen + nmfsize
		pkt = bytearray(first_pkt)
		while len(pkt) < expected_size:
			pkt.extend(self._recv())
		if len(pkt) != expected_size:
			raise ConnectionError('ADWS envelope exceeded its declared size')
		return bytes(pkt)

	def _recv(self, _: int = 0) -> bytes:
		"""Recive an NNS packet and return the entire
		decrypted contents.

		The paramiter is used to allow interoperability with socket.socket.recv.
		Does not respect any passed buffer sizes.
		"""
		size = int.from_bytes(receive_exactly(self._sock, 4), 'little')
		if not 16 <= size <= 64 * 1024 * 1024:
			raise ConnectionError(f'Invalid ADWS frame size: {size}')
		payload = receive_exactly(self._sock, size)

		if self._auth_type == 'kerberos':
			return self._krb_ctx.unwrap(payload).message

		# NTLM: payload is [16-byte signature][ciphertext]
		signature = payload[0:16]
		cipherText = payload[16:]
		clearText = self._server_sealing_handle(cipherText)
		expected = impacket.ntlm.MAC(
			self._flags, self._server_sealing_handle, self._server_signing_key,
			struct.unpack('<i', signature[12:16])[0], clearText,
		).getData()
		if not compare_digest(expected, signature):
			raise LDAPSignatureVerificationFailedError('ADWS NTLM signature verification failed')
		return clearText

	def sendall(self, data: bytes):
		"""Send data in a sealed NNS data packet via tcp socket.

		Args:
			data (bytes): payload data to send
		"""

		if self._auth_type == 'kerberos':
			pkt = NNS_data()
			pkt["payload"] = self._krb_ctx.wrap(data).message
			self._sock.sendall(pkt.getData())
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

		logging.debug("[NNS] Starting Kerberos authentication")

		# Step 1: Build SPNEGO NegTokenInit with AP-REQ (no DCE_STYLE = 2-leg)
		tgt_cache = {}
		authenticator_time = datetime.now(timezone.utc)
		cipher, sessionKey, blob = getKerberosType1(
			self._username,
			self._password or '',
			self._domain,
			self._lm,
			self._nt,
			aesKey=self._aesKey or '',
			TGT=self._TGT,
			targetName=self._fqdn,
			kdcHost=self._kdcHost,
			useCache=self._no_pass if self._TGT is None else False,
			dce_style=False,
			tgt_cache=tgt_cache,
			authenticator_time=authenticator_time,
		)
		# Cache TGT for reuse on reconnections
		if tgt_cache:
			self._cached_tgt = tgt_cache
		elif self._TGT:
			self._cached_tgt = self._TGT

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

		# Step 4: Build the message protection context from the AP-REP
		negTokenResp = impacket.spnego.SPNEGO_NegTokenResp(server_resp["payload"])
		krb_ctx = accept_ap_rep(negTokenResp["ResponseToken"], cipher, sessionKey, authenticator_time)

		# Step 5: If server sent IN_PROGRESS, receive the DONE message
		if server_resp["message_id"] == MessageID.IN_PROGRESS:
			server_done = self._recv_handshake()
			if server_done["message_id"] == MessageID.ERROR:
				raise SystemExit("[-] Kerberos Auth Failed: server rejected auth")

		self._krb_ctx = krb_ctx
		self._auth_type = 'kerberos'

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
