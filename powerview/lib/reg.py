#!/usr/bin/env python3
# original script: https://gist.github.com/GeisericII/6849bc86620c7a764d88502df5187bd0

import logging
import re
import time
from impacket.dcerpc.v5 import transport, rrp
from impacket.smbconnection import SessionError

class RemoteOperations:
	KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\winreg]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\winreg]', 'set_host': True},
    }

	def __init__(self, connection, port=445):
		self.connection = connection
		self.port = port
		self.pipetriggered = False

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