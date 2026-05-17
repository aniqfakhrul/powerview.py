#!/usr/bin/env python3
import logging
import ntpath
import cmd
import socket
import struct
import sys
import time
from io import BytesIO
import impacket.smb3 as _smb3mod
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_NO_SCRUB_DATA
from impacket.smb3structs import (
	SMB2_TREE_CONNECT, SMB2_CREATE, SMB2_CLOSE,
	SMB2TreeConnect, SMB2TreeConnect_Response,
	SMB2Create, SMB2Create_Response, SMB2Close, SMB2Packet,
	SMB2_FLAGS_SIGNED, SMB2_FLAGS_RELATED_OPERATIONS,
)
from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.dtypes import OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION

from powerview.utils.accesscontrol import AccessControl, SIMPLE_PERMISSIONS

STATUS_SUCCESS = 0x00000000
STATUS_ACCESS_DENIED = 0xC0000022

_SESSION_FLAG_ENCRYPT = 0x4
_FULL_CONTROL = 0x001F01FF
_TRANSFORM_LEN = len(_smb3mod.SMB2_TRANSFORM_HEADER())


class SMBReconError(Exception):
	"""Raised for unexpected protocol-level failures."""

class SMBShell(cmd.Cmd):
	def __init__(self, smbConnection, tcpShell=None):
		if tcpShell is not None:
			cmd.Cmd.__init__(self, stdin=tcpShell.stdin, stdout=tcpShell.stdout)
			sys.stdout = tcpShell.stdout
			sys.stdin = tcpShell.stdin
			sys.stderr = tcpShell.stdout
			self.use_rawinput = False
			self.shell = tcpShell
		else:
			cmd.Cmd.__init__(self)
			self.shell = None

		self.prompt = '# '
		self.conn = smbConnection
		self.smbclient = SMBClient(smbConnection)
		self.username, self.password, self.domain, self.lmhash, self.nthash, self.aesKey, self.TGT, self.TGS = smbConnection.getCredentials()
		self.tid = None
		self.intro = 'Type help for list of commands'
		self.pwd = ''
		self.share = None
		self.loggedIn = True

	def onecmd(self,s):
		retVal = False
		try:
		   retVal = cmd.Cmd.onecmd(self,s)
		except Exception as e:
		   logging.error(e)
		   logging.debug('Exception info', exc_info=True)

		return retVal

	def parse_line(self, line):
		normalized_line = line.replace('/', '\\').replace('\\\\', '\\')
		if not normalized_line:
			share = None
			path = ''
		elif '\\' not in normalized_line:
			share = normalized_line
			path = ''
		else:
			tokenized = normalized_line.split('\\')
			share = tokenized[0]
			path = '\\'.join(tokenized[1:]) if len(tokenized) > 1 else ''
		return share, path

	def do_help(self,line):
		output = """
 shares - list available shares
 ls <share>\\<path> - list files in share
 cat <share>\\<path> - get file from share
 rm <share>\\<path> - delete file from share
 rmdir <share>\\<path> - delete directory from share
"""
		return output

	def do_shares(self, line):
		shares = self.smbclient.shares()

		formatted_shares = []
		for share in shares:
			entry = {
				"Name": share['shi1_netname'][:-1],
				"Remark": share['shi1_remark'][:-1],
				"Address": self.conn.getRemoteHost()
			}
			formatted_shares.append(entry)

		return formatted_shares
	
	def do_ls(self, line):
		share, path = self.parse_line(line)
		
		files = self.smbclient.ls(share, path)
		
		file_list = []
		for f in files:
			name = f.get_longname()
			if name in ['.', '..']:
				continue
			
			file_info = {
				"name": name,
				"size": f.get_filesize(),
				"is_directory": f.is_directory() > 0,
				"created": time.ctime(float(f.get_ctime_epoch())),
				"modified": time.ctime(float(f.get_mtime_epoch())),
				"accessed": time.ctime(float(f.get_atime_epoch()))
			}
			file_list.append(file_info)
		
		return file_list

	def do_cat(self, line):
		try:
			share, path = self.parse_line(line)
			content = self.smbclient.cat(share, path)
			if content is None or len(content) == 0:
				return "File not found"
			return content
		except Exception as e:
			return f"Error reading file: {e}"

	def do_rm(self, line):
		try:
			share, path = self.parse_line(line)
			self.smbclient.rm(share, path)
			return "File deleted successfully"
		except Exception as e:
			return f"Error deleting file: {e}"

	def do_rmdir(self, line):
		try:
			share, path = self.parse_line(line)
			self.smbclient.rmdir(share, path)
			return "Directory deleted successfully"
		except Exception as e:
			return f"Error deleting directory: {e}"

	def do_mkdir(self, line):
		try:
			share, path = self.parse_line(line)
			self.smbclient.mkdir(share, path)
			return "Directory created successfully"
		except Exception as e:
			return f"Error creating directory: {e}"

	def do_mv(self, line):
		try:
			tokenized = line.split(' ')
			src_share, source = self.parse_line(tokenized[0])
			dst_share, destination = self.parse_line(tokenized[1])
			if src_share.lower() != dst_share.lower():
				return "Source and destination must be on the same share"
			
			self.smbclient.mv(src_share, source, destination)
			return "File moved successfully"
		except Exception as e:
			return f"Error moving file: {e}"

class SMBClient:
	FILE_READ_DATA = 0x00000001
	FILE_WRITE_DATA = 0x00000002
	FILE_APPEND_DATA = 0x00000004
	DELETE = 0x00010000
	READ_CONTROL = 0x00020000
	WRITE_DAC = 0x00040000
	WRITE_OWNER = 0x00080000

	_ADMIN_SHARES = ("C$", "ADMIN$", "NETLOGON")

	def __init__(self, client):
		self.client = client

	@property
	def _smb3(self):
		smb3 = self.client._SMBConnection
		if not hasattr(smb3, "_Session"):
			raise SMBReconError("connection is not SMB2/3 (SMB1 not supported)")
		return smb3

	def admin_probe(self):
		"""Compound-probe the admin shares in a single SMB2 round trip.

		Returns ``{share: (ntstatus, maximal_access_or_None)}`` for C$, ADMIN$
		and NETLOGON. Building block for :meth:`is_local_admin`.
		"""
		msgs = [(SMB2_TREE_CONNECT, 0, False, self._tree_connect_data(s))
			for s in self._ADMIN_SHARES]
		out = {}
		for share, resp in zip(self._ADMIN_SHARES, self._compound(msgs)):
			st = resp["Status"] & 0xFFFFFFFF
			mask = None
			if st == STATUS_SUCCESS:
				try:
					mask = SMB2TreeConnect_Response(resp["Data"])["MaximalAccess"]
				except Exception:
					pass
			out[share] = (st, mask)
		return out

	def is_local_admin(self, probe=None):
		"""Return True if the authenticated user is a local admin on the target.

		Primary signal: a TREE_CONNECT to C$ succeeds only for Administrators /
		Backup Operators. If the admin shares are disabled the method falls back
		to the NETLOGON share's MaximalAccess (DC targets only).
		"""
		probe = probe or self.admin_probe()
		c_status, _ = probe.get("C$", (None, None))
		if c_status == STATUS_SUCCESS:
			return True
		if c_status == STATUS_ACCESS_DENIED:
			return False
		n_status, n_mask = probe.get("NETLOGON", (None, None))
		return n_status == STATUS_SUCCESS and n_mask == _FULL_CONTROL

	def share_access(self, share):
		"""Return the caller's *effective* (NTFS) maximal-access mask for a
		share's root, or None if it cannot be reached.

		Uses the SMB2 MxAc (QUERY_MAXIMAL_ACCESS) create context: the server
		reports effective access in the CREATE response. Nothing is written.
		Note: the TREE_CONNECT MaximalAccess field is share-level only and
		overstates -- this method returns the true share-and-NTFS access.
		"""
		try:
			tid = self.client.connectTree(share)
		except Exception:
			return None
		try:
			resp = self._compound([
				(SMB2_CREATE, tid, False, self._create_root_data()),
				(SMB2_CLOSE, tid, True, self._close_data()),
			])
			create = resp[0]
			if (create["Status"] & 0xFFFFFFFF) != STATUS_SUCCESS:
				return None
			qstatus, mask = self._parse_mxac(create)
			return mask if qstatus == STATUS_SUCCESS else None
		finally:
			try:
				self.client.disconnectTree(tid)
			except Exception:
				pass

	def share_rw(self, share):
		"""Return ``(readable, writable)`` booleans for a share. Non-intrusive."""
		mask = self.share_access(share)
		if mask is None:
			return (False, False)
		readable = bool(mask & self.FILE_READ_DATA)
		writable = bool(mask & (self.FILE_WRITE_DATA | self.FILE_APPEND_DATA))
		return (readable, writable)

	@classmethod
	def decode_access(cls, mask):
		"""Render an access mask as a human-readable string."""
		if mask is None:
			return "no-access"
		parts = []
		if mask & cls.FILE_READ_DATA:
			parts.append("READ")
		if mask & (cls.FILE_WRITE_DATA | cls.FILE_APPEND_DATA):
			parts.append("WRITE")
		if mask & cls.DELETE:
			parts.append("DELETE")
		if mask & cls.WRITE_DAC:
			parts.append("WRITE_DAC")
		if mask & cls.WRITE_OWNER:
			parts.append("WRITE_OWNER")
		return ",".join(parts) or "none"

	def _compound(self, messages):
		"""Send ``messages`` as one compounded SMB2 request, return responses.

		``messages`` is a list of ``(command, tree_id, related, data_bytes)``.
		Each sub-message is signed individually (if the session signs) with the
		inter-message padding baked into Data so the signature covers the
		8-byte-aligned length; the whole chain is encrypted as one unit when the
		session negotiated encryption.
		"""
		smb3 = self._smb3
		sess, conn = smb3._Session, smb3._Connection
		sign = bool(sess.get("SigningActivated"))
		encrypt = bool(sess.get("SessionFlags", 0) & _SESSION_FLAG_ENCRYPT)
		mid0 = conn["SequenceWindow"]

		parts = []
		for i, (command, tree_id, related, data) in enumerate(messages):
			pkt = smb3.SMB_PACKET()
			pkt["Command"] = command
			pkt["MessageID"] = mid0 + i
			pkt["SessionID"] = sess["SessionID"]
			pkt["TreeID"] = tree_id
			pkt["CreditCharge"] = 1
			pkt["CreditRequestResponse"] = 127
			flags = 0
			if related:
				flags |= SMB2_FLAGS_RELATED_OPERATIONS
			if sign:
				flags |= SMB2_FLAGS_SIGNED
			pkt["Flags"] = flags
			size = 64 + len(data)
			if i == len(messages) - 1:
				pkt["Data"], pkt["NextCommand"] = data, 0
			else:
				aligned = (size + 7) & ~7
				pkt["Data"] = data + b"\x00" * (aligned - size)
				pkt["NextCommand"] = aligned
			if sign:
				smb3.signSMB(pkt)
			parts.append(pkt.getData())
		conn["SequenceWindow"] = mid0 + len(messages)

		plain = b"".join(parts)
		wire = self._encrypt(plain) if encrypt else plain
		smb3._NetBIOSSession.send_packet(wire)

		responses = []
		while len(responses) < len(messages):
			trailer = smb3._NetBIOSSession.recv_packet().get_trailer()
			if trailer[:4] == b"\xfdSMB":
				trailer = self._decrypt(trailer)
			responses += self._split_compound(trailer)
		return responses

	def _encrypt(self, plain):
		sess = self._smb3._Session
		th = _smb3mod.SMB2_TRANSFORM_HEADER()
		th["Nonce"] = "".join(_smb3mod.rand.choice(_smb3mod.string.ascii_letters)
			for _ in range(11))
		th["OriginalMessageSize"] = len(plain)
		th["EncryptionAlgorithm"] = _smb3mod.SMB2_ENCRYPTION_AES128_CCM
		th["SessionID"] = sess["SessionID"]
		cipher = _smb3mod.AES.new(sess["EncryptionKey"], _smb3mod.AES.MODE_CCM,
			_smb3mod.b(th["Nonce"]))
		cipher.update(th.getData()[20:])
		ciphertext = cipher.encrypt(plain)
		th["Signature"] = cipher.digest()
		return th.getData() + ciphertext

	def _decrypt(self, blob):
		sess = self._smb3._Session
		th = _smb3mod.SMB2_TRANSFORM_HEADER(blob)
		cipher = _smb3mod.AES.new(sess["DecryptionKey"], _smb3mod.AES.MODE_CCM,
			th["Nonce"][:11])
		cipher.update(th.getData()[20:])
		return cipher.decrypt(blob[_TRANSFORM_LEN:])

	@staticmethod
	def _split_compound(payload):
		out, off = [], 0
		while off < len(payload):
			next_cmd = struct.unpack("<I", payload[off + 20:off + 24])[0]
			end = off + next_cmd if next_cmd else len(payload)
			out.append(SMB2Packet(payload[off:end]))
			if next_cmd == 0:
				break
			off += next_cmd
		return out

	def _server_ip(self):
		ip = self._smb3._Connection["ServerIP"]
		try:
			return socket.getaddrinfo(ip, 80, 0, 0, socket.IPPROTO_TCP)[0][4][0]
		except Exception:
			return ip

	def _tree_connect_data(self, share):
		tc = SMB2TreeConnect()
		tc["Buffer"] = ("\\\\" + self._server_ip() + "\\" + share).encode("utf-16le")
		tc["PathLength"] = len(tc["Buffer"])
		return tc.getData()

	@staticmethod
	def _mxac_context():
		return (struct.pack("<IHHHHI", 0, 16, 4, 0, 24, 8)
			+ b"MxAc" + b"\x00" * 4 + b"\x00" * 8)

	def _create_root_data(self):
		cr = SMB2Create()
		cr["SecurityFlags"] = 0
		cr["RequestedOplockLevel"] = 0
		cr["ImpersonationLevel"] = 2
		cr["DesiredAccess"] = self.READ_CONTROL
		cr["FileAttributes"] = 0
		cr["ShareAccess"] = 7
		cr["CreateDisposition"] = 1
		cr["CreateOptions"] = 1
		cr["NameLength"] = 0
		cr["Buffer"] = b"\x00"
		base = len(SMB2Packet()) + SMB2Create.SIZE
		cr["CreateContextsOffset"] = base + len(cr["Buffer"])
		if cr["CreateContextsOffset"] % 8:
			cr["Buffer"] += b"\x00" * (8 - (cr["CreateContextsOffset"] % 8))
			cr["CreateContextsOffset"] = base + len(cr["Buffer"])
		ctx = self._mxac_context()
		cr["CreateContextsLength"] = len(ctx)
		cr["Buffer"] += ctx
		return cr.getData()

	@staticmethod
	def _close_data():
		cl = SMB2Close()
		cl["Flags"] = 0
		cl["FileID"] = b"\xff" * 16
		return cl.getData()

	@staticmethod
	def _parse_mxac(create_response_pkt):
		cr = SMB2Create_Response(create_response_pkt["Data"])
		full = create_response_pkt.getData()
		blob = full[cr["CreateContextsOffset"]:
			cr["CreateContextsOffset"] + cr["CreateContextsLength"]]
		off = 0
		while off + 16 <= len(blob):
			nxt, noff, nlen, _r, doff, dlen = struct.unpack("<IHHHHI", blob[off:off + 16])
			if blob[off + noff:off + noff + nlen] == b"MxAc":
				data = blob[off + doff:off + doff + dlen]
				if len(data) >= 8:
					return struct.unpack("<II", data[:8])
			if nxt == 0:
				break
			off += nxt
		return (None, None)

	def shares(self):
		if self.client is None:
			logging.error("[SMBClient: shares] Not logged in")
			return
		
		return self.client.listShares()

	def add_share(self, share, path):
		if self.client is None:
			logging.error("[SMBClient: add_share] Not logged in")
			return
		
		rpctransport = transport.SMBTransport(self.client.getRemoteName(), self.client.getRemoteHost(), filename=r'\srvsvc',
											  smb_connection=self.client)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(srvs.MSRPC_UUID_SRVS)

		# Use SHARE_INFO_2 instead of 502 for simpler structure
		info_2 = srvs.SHARE_INFO_2()
		info_2['shi2_netname'] = share.replace('/', '\\').replace('\\\\', '\\') + '\x00'
		info_2['shi2_type'] = 0  # STYPE_DISKTREE
		info_2['shi2_remark'] = 'Created by PowerView\x00'
		info_2['shi2_permissions'] = 0x00000000
		info_2['shi2_max_uses'] = 0xFFFFFFFF  # No limit
		info_2['shi2_current_uses'] = 0
		info_2['shi2_path'] = path + '\x00'
		info_2['shi2_passwd'] = '\x00'
		
		try:
			resp = srvs.hNetrShareAdd(
				dce,
				2,  # Use level 2
				info_2
			)
			if resp['ErrorCode'] != 0:
				error_msg = f"Error code: 0x{resp['ErrorCode']:x}"
				logging.error(f"[SMBClient: add_share] Error adding share: {error_msg}")
				raise Exception(f"[SMBClient: add_share] Error adding share: {error_msg}")
			else:
				logging.debug(f"[SMBClient: add_share] Successfully added share: {share}")
				return True
		except Exception as e:
			logging.error(f"[SMBClient: add_share] Error adding share: {e}")
			return False

	def delete_share(self, share):
		if self.client is None:
			logging.error("[SMBClient: delete_share] Not logged in")
			return
		
		rpctransport = transport.SMBTransport(self.client.getRemoteName(), self.client.getRemoteHost(), filename=r'\srvsvc',
											  smb_connection=self.client)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(srvs.MSRPC_UUID_SRVS)
		
		try:
			resp = srvs.hNetrShareDel(dce, share.replace('/', '\\').replace('\\\\', '\\') + '\x00')
			if resp['ErrorCode'] != 0:
				error_msg = f"Error code: 0x{resp['ErrorCode']:x}"
				logging.error(f"[SMBClient: delete_share] Error deleting share: {error_msg}")
				raise Exception(f"[SMBClient: delete_share] Error deleting share: {error_msg}")
			else:
				logging.debug(f"[SMBClient: delete_share] Successfully deleted share: {share}")
				return True
		except Exception as e:
			logging.error(f"[SMBClient: delete_share] Error deleting share: {e}")
			return False

	def share_info(self, share):
		if self.client is None:
			logging.error("[SMBClient: share_info] Not logged in")
			return
		
		rpctransport = transport.SMBTransport(self.client.getRemoteName(), self.client.getRemoteHost(), filename=r'\srvsvc',
											  smb_connection=self.client)
		dce = rpctransport.get_dce_rpc()
		dce.connect()
		dce.bind(srvs.MSRPC_UUID_SRVS)
		
		share_info = {
			'name': None,
			'type': None,
			'remark': None,
			'path': None,
			'permissions': None,
			'max_uses': None,
			'current_uses': None,
			'passwd': None,
			'servername': None,
			'reserved': None,
			'sd_info': None
		}

		try:
			base_info = srvs.hNetrShareGetInfo(dce, share + '\x00', 1)
			share_info['name'] = base_info['InfoStruct']['ShareInfo1']['shi1_netname'][:-1]
			share_info['type'] = base_info['InfoStruct']['ShareInfo1']['shi1_type']
			share_info['remark'] = base_info['InfoStruct']['ShareInfo1']['shi1_remark'][:-1]
		except Exception as e:
			logging.error(f"[SMBClient: share_info] Error getting share info via NetrShareGetInfo(Level 1): {e}")

		try:
			resp = srvs.hNetrShareGetInfo(dce, share + '\x00', 502)
			share_info['path'] = resp['InfoStruct']['ShareInfo502']['shi502_path'][:-1]
			share_info['permissions'] = resp['InfoStruct']['ShareInfo502']['shi502_permissions']
			share_info['max_uses'] = resp['InfoStruct']['ShareInfo502']['shi502_max_uses']
			share_info['current_uses'] = resp['InfoStruct']['ShareInfo502']['shi502_current_uses']
			share_info['passwd'] = resp['InfoStruct']['ShareInfo502']['shi502_passwd']
			share_info['reserved'] = resp['InfoStruct']['ShareInfo502']['shi502_reserved']
			secDesc = resp['InfoStruct']['ShareInfo502']['shi502_security_descriptor']
			if secDesc and len(secDesc) > 0:
				share_info['sd_info'] = AccessControl.parse_sd(secDesc)
		except Exception as e:
			logging.error(f"[SMBClient: share_info] Error getting share info via NetrShareGetInfo(Level 502): {e}")
		
		return share_info

	def set_share_security(self, share, sid, mask='fullcontrol', ace_type='allow'):
		if self.client is None:
			logging.error("[SMBClient: set_share_security] Not logged in")
			return

		# convert mask to integer
		mask = mask.lower()
		if mask == 'fullcontrol':
			mask = SIMPLE_PERMISSIONS.FullControl.value
		elif mask == 'modify':
			mask = SIMPLE_PERMISSIONS.Modify.value
		elif mask == 'readandexecute':
			mask = SIMPLE_PERMISSIONS.ReadAndExecute.value
		elif mask == 'readandwrite':
			mask = SIMPLE_PERMISSIONS.ReadAndWrite.value
		elif mask == 'read':
			mask = SIMPLE_PERMISSIONS.Read.value
		elif mask == 'write':
			mask = SIMPLE_PERMISSIONS.Write.value
		else:
			raise Exception(f"[SMBClient: set_share_security] Invalid mask: {mask}")
		
		try:
			rpctransport = transport.SMBTransport(self.client.getRemoteName(), self.client.getRemoteHost(), filename=r'\srvsvc',
											  smb_connection=self.client)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			dce.bind(srvs.MSRPC_UUID_SRVS)
			
			logging.debug(f"[SMBClient: set_share_security] Getting share security")
			resp = srvs.hNetrShareGetInfo(dce, share + '\x00', 502)
			secDesc = resp['InfoStruct']['ShareInfo502']['shi502_security_descriptor']

			if ace_type == 'allow':
				security_descriptor = AccessControl.add_allow_ace(
					secDesc,
					sid,
					mask
				)
			elif ace_type == 'deny':
				security_descriptor = AccessControl.add_deny_ace(
					secDesc,
					sid,
					mask
				)
			else:
				raise Exception(f"[SMBClient: set_share_security] Invalid ace_type: {ace_type}")

			logging.debug(f"[SMBClient: set_share_security] Setting share security")
			info_1501 = srvs.SHARE_INFO_1501()
			info_1501['shi1501_security_descriptor'] = security_descriptor

			resp = srvs.hNetrShareSetInfo(dce, share + '\x00', 1501, info_1501)
			if resp['ErrorCode'] != 0:
				raise Exception(f"[SMBClient: set_share_security] Error setting share security")
			else:
				logging.debug(f"[SMBClient: set_share_security] Successfully set share security")
		except Exception as e:
			logging.error(f"[SMBClient: set_share_security] Error setting share security: {e}")
			return False
		
		return True

	def remove_share_security(self, share, sid, mask=None, ace_type=None):
		if self.client is None:
			logging.error("[SMBClient: remove_share_security] Not logged in")
			return
		
		try:
			rpctransport = transport.SMBTransport(self.client.getRemoteName(), self.client.getRemoteHost(), filename=r'\srvsvc',
											  smb_connection=self.client)
			dce = rpctransport.get_dce_rpc()
			dce.connect()
			dce.bind(srvs.MSRPC_UUID_SRVS)
			
			logging.debug(f"[SMBClient: remove_share_security] Getting share security")
			resp = srvs.hNetrShareGetInfo(dce, share + '\x00', 502)
			secDesc = resp['InfoStruct']['ShareInfo502']['shi502_security_descriptor']

			mask_value = None
			if mask:
				if mask == 'fullcontrol':
					mask_value = SIMPLE_PERMISSIONS.FullControl.value
				elif mask == 'modify':
					mask_value = SIMPLE_PERMISSIONS.Modify.value
				elif mask == 'readandexecute':
					mask_value = SIMPLE_PERMISSIONS.ReadAndExecute.value
				elif mask == 'readandwrite':
					mask_value = SIMPLE_PERMISSIONS.ReadAndWrite.value
				elif mask == 'read':
					mask_value = SIMPLE_PERMISSIONS.Read.value
				elif mask == 'write':
					mask_value = SIMPLE_PERMISSIONS.Write.value
				else:
					raise Exception(f"[SMBClient: remove_share_security] Invalid mask: {mask}")

			ace_type_value = None
			if ace_type:
				if ace_type == 'allow':
					from impacket.ldap import ldaptypes
					ace_type_value = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
				elif ace_type == 'deny':
					from impacket.ldap import ldaptypes
					ace_type_value = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
				else:
					raise Exception(f"[SMBClient: remove_share_security] Invalid ace_type: {ace_type}")

			security_descriptor, removed_count = AccessControl.remove_ace(
				secDesc,
				sid,
				mask_value,
				ace_type_value
			)

			if removed_count == 0:
				logging.warning(f"[SMBClient: remove_share_security] No matching ACEs found to remove")
				return False

			logging.debug(f"[SMBClient: remove_share_security] Setting share security")
			info_1501 = srvs.SHARE_INFO_1501()
			info_1501['shi1501_security_descriptor'] = security_descriptor

			resp = srvs.hNetrShareSetInfo(dce, share + '\x00', 1501, info_1501)
			if resp['ErrorCode'] != 0:
				raise Exception(f"[SMBClient: remove_share_security] Error setting share security")
			else:
				logging.debug(f"[SMBClient: remove_share_security] Successfully removed {removed_count} ACE(s)")
			return True
		except Exception as e:
			logging.error(f"[SMBClient: remove_share_security] Error removing share security: {e}")
			return False

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
					if resp and len(resp) > 0:
						info['sd_info'] = AccessControl.parse_sd(resp)
				except Exception as rpc_error:
					raise Exception(f"[SMBClient: get_file_info] RPC error: {rpc_error}")
			return info
			
		except Exception as e:
			logging.error(f"[SMBClient: get_file_info] Error: {e}")
			raise

	def set_file_security(self, share, path, sid, ace_type='allow', mask='fullcontrol'):
		if self.client is None:
			logging.error("[SMBClient: set_file_security] Not logged in")
			return
		
		path = path.replace('/', '\\')
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
				path = path[1:]
			path = path.replace('/', '\\')

			secDesc = srvs.hNetrpGetFileSecurity(
				dce, 
				share+'\x00', 
				path+'\x00', 
				security_flags
			)

			mask = mask.lower()
			if mask == 'fullcontrol':
				mask = SIMPLE_PERMISSIONS.FullControl.value
			elif mask == 'modify':
				mask = SIMPLE_PERMISSIONS.Modify.value
			elif mask == 'readandexecute':
				mask = SIMPLE_PERMISSIONS.ReadAndExecute.value
			elif mask == 'readandwrite':
				mask = SIMPLE_PERMISSIONS.ReadAndWrite.value
			elif mask == 'read':
				mask = SIMPLE_PERMISSIONS.Read.value
			elif mask == 'write':
				mask = SIMPLE_PERMISSIONS.Write.value
			else:
				raise Exception(f"[SMBClient: set_file_security] Invalid mask: {mask}")

			if ace_type == 'allow':
				security_descriptor = AccessControl.add_allow_ace(
					secDesc,
					sid,
					mask
				)
			elif ace_type == 'deny':
				security_descriptor = AccessControl.add_deny_ace(
					secDesc,
					sid,
					mask
				)
			else:
				raise Exception(f"[SMBClient: set_file_security] Invalid ace_type: {ace_type}")

			resp = srvs.hNetrpSetFileSecurity(
				dce,
				share+'\x00',
				path+'\x00',
				security_flags,
				security_descriptor
			)
			if resp['ErrorCode'] != 0:
				raise Exception(f"[SMBClient: set_file_security] Error setting file security")
			else:
				logging.debug(f"[SMBClient: set_file_security] Successfully set file security")
			return True
		except Exception as rpc_error:
			raise Exception(f"[SMBClient: set_file_security] RPC error: {rpc_error}")

	def remove_file_security(self, share, path, sid, mask=None, ace_type=None):
		if self.client is None:
			logging.error("[SMBClient: remove_file_security] Not logged in")
			return
		
		path = path.replace('/', '\\')
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
				path = path[1:]
			path = path.replace('/', '\\')

			secDesc = srvs.hNetrpGetFileSecurity(
				dce, 
				share+'\x00', 
				path+'\x00', 
				security_flags
			)

			mask_value = None
			if mask:
				if mask == 'fullcontrol':
					mask_value = SIMPLE_PERMISSIONS.FullControl.value
				elif mask == 'modify':
					mask_value = SIMPLE_PERMISSIONS.Modify.value
				elif mask == 'readandexecute':
					mask_value = SIMPLE_PERMISSIONS.ReadAndExecute.value
				elif mask == 'readandwrite':
					mask_value = SIMPLE_PERMISSIONS.ReadAndWrite.value
				elif mask == 'read':
					mask_value = SIMPLE_PERMISSIONS.Read.value
				elif mask == 'write':
					mask_value = SIMPLE_PERMISSIONS.Write.value
				else:
					raise Exception(f"[SMBClient: remove_file_security] Invalid mask: {mask}")

			ace_type_value = None
			if ace_type:
				if ace_type == 'allow':
					ace_type_value = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE
				elif ace_type == 'deny':
					ace_type_value = ldaptypes.ACCESS_DENIED_ACE.ACE_TYPE
				else:
					raise Exception(f"[SMBClient: remove_file_security] Invalid ace_type: {ace_type}")

			security_descriptor, removed_count = AccessControl.remove_ace(
				secDesc,
				sid,
				mask_value,
				ace_type_value
			)

			if removed_count == 0:
				logging.warning(f"[SMBClient: remove_file_security] No matching ACEs found to remove")
				return False

			resp = srvs.hNetrpSetFileSecurity(
				dce,
				share+'\x00',
				path+'\x00',
				security_flags,
				security_descriptor
			)
			if resp['ErrorCode'] != 0:
				raise Exception(f"[SMBClient: remove_file_security] Error setting file security")
			else:
				logging.debug(f"[SMBClient: remove_file_security] Successfully removed {removed_count} ACE(s)")
			return True
		except Exception as rpc_error:
			raise Exception(f"[SMBClient: remove_file_security] RPC error: {rpc_error}")