#!/usr/bin/env python3
import logging
import ntpath
import cmd
import sys
import time
from io import BytesIO
from impacket.smbconnection import SMBConnection
from impacket.smb3structs import FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_INTEGRITY_STREAM, FILE_ATTRIBUTE_NO_SCRUB_DATA
from impacket.dcerpc.v5 import transport, srvs
from impacket.dcerpc.v5.dtypes import OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION

from powerview.utils.accesscontrol import AccessControl, SIMPLE_PERMISSIONS

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
	def __init__(self, client):
		self.client = client

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