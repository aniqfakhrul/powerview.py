#!/usr/bin/env python3
# original script: https://gist.github.com/GeisericII/6849bc86620c7a764d88502df5187bd0

import logging
import re
import time
from impacket.dcerpc.v5 import transport, rrp
from impacket.dcerpc.v5.dtypes import READ_CONTROL
from impacket.smbconnection import SessionError
import binascii

class RemoteOperations:
	KNOWN_PROTOCOLS = {
		139: {'bindstr': r'ncacn_np:%s[\pipe\winreg]', 'set_host': True},
		445: {'bindstr': r'ncacn_np:%s[\pipe\winreg]', 'set_host': True},
	}

	def __init__(self, connection, port=445):
		self.connection = connection
		self.port = port
		self.pipetriggered = False

	def __strip_root_key(self, dce, keyName):
		try:
			rootKey = keyName.split('\\')[0]
			subKey = '\\'.join(keyName.split('\\')[1:])
		except Exception:
			raise Exception('Error parsing keyName %s' % keyName)
		if rootKey.upper() == 'HKLM':
			ans = rrp.hOpenLocalMachine(dce)
		elif rootKey.upper() == 'HKCU':
			ans = rrp.hOpenCurrentUser(dce)
		elif rootKey.upper() == 'HKU':
			ans = rrp.hOpenUsers(dce)
		elif rootKey.upper() == 'HKCR':
			ans = rrp.hOpenClassesRoot(dce)
		else:
			raise Exception('Invalid root key %s ' % rootKey)
		hRootKey = ans['phKey']
		return hRootKey, subKey

	# stolen from impacket.examples.reg
	def triggerWinReg(self):
		# original idea from https://twitter.com/splinter_code/status/1715876413474025704
		tid = self.connection.connectTree('IPC$')
		try:
			self.connection.openFile(tid, r'\winreg', 0x12019f, creationOption=0x40, fileAttributes=0x80)
		except SessionError:
			# STATUS_PIPE_NOT_AVAILABLE error is expected
			pass
		# give remote registry time to start
		time.sleep(1)

	def connect(self, target):
		stringBinding = self.KNOWN_PROTOCOLS[self.port]['bindstr'] % target
		try:
			dce = self.connection.connectRPCTransport(host=target, stringBindings=stringBinding, interface_uuid=rrp.MSRPC_UUID_RRP, raise_exceptions=True)
			return dce
		except SessionError as e:
			if str(e).find('STATUS_PIPE_NOT_AVAILABLE') >= 0:
				logging.warning("Trying to start the Remote Registry...")
				time.sleep(1)
				if not self.pipetriggered:
					return self.connect(target)
				else:
					logging.error("Failed to bind")
			else:
				logging.error(str(e))
				return
		except Exception as e:
			self.triggerWinReg()
			return self.connect(target)

	# stolen from impacket.examples.reg
	def add(self, dce, keyName: str, valueName: str, valueType: str, valueData: str):
		hRootKey, subKey = self.__strip_root_key(dce, keyName)
		ans2 = rrp.hBaseRegOpenKey(dce, hRootKey, subKey,
                                       samDesired=READ_CONTROL | rrp.KEY_SET_VALUE | rrp.KEY_CREATE_SUB_KEY)


		dwType = getattr(rrp, valueType, None)

		if dwType is None or not valueType.startswith('REG_'):
			raise Exception('Error parsing value type %s' % valueType)

		if dwType == rrp.REG_MULTI_SZ:
			vd = '\0'.join(valueData)
			valueData = vd + 2 * '\0'
			valueDataToPrint = vd.replace('\0', '\n\t\t')
		else:
			vd = valueData[0] if len(valueData) > 0 else ''
			if dwType in (
				rrp.REG_DWORD, rrp.REG_DWORD_BIG_ENDIAN, rrp.REG_DWORD_LITTLE_ENDIAN,
				rrp.REG_QWORD, rrp.REG_QWORD_LITTLE_ENDIAN
			):
				valueData = int(vd)
			elif dwType == rrp.REG_BINARY:
				bin_value_len = len(vd)
				bin_value_len += (bin_value_len & 1)
				valueData = binascii.a2b_hex(vd.ljust(bin_value_len, '0'))
			else:
				valueData = vd + "\0"
			valueDataToPrint = valueData

		ans3 = rrp.hBaseRegSetValue(
			dce, ans2['phkResult'], valueName, dwType, valueData
		)

		if ans3['ErrorCode'] == 0:
			logging.debug('Registry key modification successful: %s\\%s [%s] = %s' % (
				keyName, valueName, valueType, valueDataToPrint
			))
			return True
		else:
			logging.error('Registry modification failed with error 0x%08x for %s\\%s [%s] = %s' % (
				ans3['ErrorCode'], keyName, valueName, valueType, valueDataToPrint
			))
			return False

	def query_logged_on(self, dce):
		sidRegex = "^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-[0-9]+$"
		resp = rrp.hOpenUsers(dce)
		hKey = resp['phKey']
		users = list()
		index = 1
		while True:
			try:
				resp = rrp.hBaseRegEnumKey(dce, hKey, index)
				userSid = resp['lpNameOut'][:-1]
				res = re.match(sidRegex, userSid)
				if res:
					users.append(userSid)
				index += 1
			except Exception as e:
				break

		rrp.hBaseRegCloseKey(dce, hKey)
		dce.disconnect()

		return users

	# def enable_rdp(self, dce, target):
	# 	# self.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections', 'REG_DWORD', 0)
	# 	# self.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 'UserAuthentication', 'REG_DWORD', 0)
	# 	# self.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp', 'UserAuthentication', 'REG_DWORD', 0)
	# 	return self.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections', 'REG_DWORD', 0)

	# def disable_rdp(self, dce, target):
	# 	return self.add(dce, 'HKLM\\System\\CurrentControlSet\\Control\\Terminal Server', 'fDenyTSConnections', 'REG_DWORD', 1)