from impacket.dcerpc.v5 import tsts as TSTS
from impacket.dcerpc.v5 import transport, lsat, lsad
from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, DCERPCException
import logging
import traceback

class TSHandler:
	def __init__(self, smb_connection, target_ip, doKerberos=False):
		self.__target_ip = target_ip
		self.__doKerberos = doKerberos
		self.__smbConnection = smb_connection

	def get_session_list(self):
		# Retreive session list
		with TSTS.TermSrvEnumeration(self.__smbConnection, self.__target_ip, self.__doKerberos) as lsm:
			handle = lsm.hRpcOpenEnum()
			rsessions = lsm.hRpcGetEnumResult(handle, Level=1)['ppSessionEnumResult']
			lsm.hRpcCloseEnum(handle)
			self.sessions = {}
			for i in rsessions:
				sess = i['SessionInfo']['SessionEnum_Level1']
				state = TSTS.enum2value(TSTS.WINSTATIONSTATECLASS, sess['State']).split('_')[-1]
				self.sessions[sess['SessionId']] = { 'state'        :state,
													'SessionName'   :sess['Name'],
													'RemoteIp'      :'',
													'ClientName'    :'',
													'Username'      :'',
													'Domain'        :'',
													'Resolution'    :'',
													'ClientTimeZone':''
												}

	def enumerate_sessions_config(self):
		# Get session config one by one
		if len(self.sessions):
			with TSTS.RCMPublic(self.__smbConnection, self.__target_ip, self.__doKerberos) as termsrv:
				for SessionId in self.sessions:
					resp = termsrv.hRpcGetClientData(SessionId)
					if resp is not None:
						self.sessions[SessionId]['RemoteIp']       = resp['ppBuff']['ClientAddress']
						self.sessions[SessionId]['ClientName']     = resp['ppBuff']['ClientName']
						if len(resp['ppBuff']['UserName']) and not len(self.sessions[SessionId]['Username']):
							self.sessions[SessionId]['Username']   = resp['ppBuff']['UserName']
						if len(resp['ppBuff']['Domain']) and not len(self.sessions[SessionId]['Domain']):
							self.sessions[SessionId]['Domain']     = resp['ppBuff']['Domain']
						self.sessions[SessionId]['Resolution']     = '{}x{}'.format(
																		resp['ppBuff']['HRes'],
																		resp['ppBuff']['VRes']
																	)
						self.sessions[SessionId]['ClientTimeZone'] = resp['ppBuff']['ClientTimeZone']['StandardName']

	def enumerate_sessions_info(self):
		# Get session info one by one
		if len(self.sessions):
			with TSTS.TermSrvSession(self.__smbConnection, self.__target_ip, self.__doKerberos) as TermSrvSession:
				for SessionId in self.sessions.keys():
					sessdata = TermSrvSession.hRpcGetSessionInformationEx(SessionId)
					sessflags = TSTS.enum2value(TSTS.SESSIONFLAGS, sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['SessionFlags'])
					self.sessions[SessionId]['flags']    = sessflags
					domain = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DomainName']
					if not len(self.sessions[SessionId]['Domain']) and len(domain):
						self.sessions[SessionId]['Domain'] = domain
					username = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['UserName']
					if not len(self.sessions[SessionId]['Username']) and len(username):
						self.sessions[SessionId]['Username'] = username
					self.sessions[SessionId]['ConnectTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['ConnectTime']
					self.sessions[SessionId]['DisconnectTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['DisconnectTime']
					self.sessions[SessionId]['LogonTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LogonTime']
					self.sessions[SessionId]['LastInputTime'] = sessdata['LSMSessionInfoExPtr']['LSM_SessionInfo_Level1']['LastInputTime']

	def do_qwinsta(self):
		desktop_states = {
			'WTS_SESSIONSTATE_UNKNOWN': '',
			'WTS_SESSIONSTATE_LOCK'   : 'Locked',
			'WTS_SESSIONSTATE_UNLOCK' : 'Unlocked',
		}
		self.get_session_list()
		if not len(self.sessions):
			return []
		self.enumerate_sessions_info()
		self.enumerate_sessions_config()
		
		result = []
		
		for i in self.sessions:
			connectTime = self.sessions[i]['ConnectTime']
			connectTime = connectTime.strftime(r'%Y/%m/%d %H:%M:%S') if connectTime.year > 1601 else 'None'

			disconnectTime = self.sessions[i]['DisconnectTime']
			disconnectTime = disconnectTime.strftime(r'%Y/%m/%d %H:%M:%S') if disconnectTime.year > 1601 else 'None'
			userName = self.sessions[i]['Domain'] + '\\' + self.sessions[i]['Username'] if len(self.sessions[i]['Username']) else ''

			session_entry = {
				"attributes": {
					"SessionName": self.sessions[i]['SessionName'],
					"Username": userName,
					"ID": str(i),
					"State": self.sessions[i]['state'],
					"Desktop": desktop_states[self.sessions[i]['flags']],
					"ConnectTime": connectTime,
					"DisconnectTime": disconnectTime,
					"ClientName": self.sessions[i]['ClientName'],
					"RemoteAddress": self.sessions[i]['RemoteIp'],
					"Resolution": self.sessions[i]['Resolution'],
					"ClientTimeZone": self.sessions[i]['ClientTimeZone']
				}
			}
			result.append(session_entry)

		return result

	def lookupSids(self):
		# Slightly modified code from lookupsid.py
		try:
			stringbinding = r'ncacn_np:%s[\pipe\lsarpc]' % self.__target_ip
			rpctransport = transport.DCERPCTransportFactory(stringbinding)
			rpctransport.set_smb_connection(self.__smbConnection)
			dce = rpctransport.get_dce_rpc()
			if self.__doKerberos:
				dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
			dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
			dce.connect()

			dce.bind(lsat.MSRPC_UUID_LSAT)
			sids = list(self.sids.keys())
			if len(sids) > 32:
				sids = sids[:32] # TODO in future update
			resp = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED | lsat.POLICY_LOOKUP_NAMES)
			policyHandle = resp['PolicyHandle']
			try:
				resp = lsat.hLsarLookupSids(dce, policyHandle, sids, lsat.LSAP_LOOKUP_LEVEL.LsapLookupWksta)
			except DCERPCException as e:
				if str(e).find('STATUS_SOME_NOT_MAPPED') >= 0:
					resp = e.get_packet()
				else: 
					raise
			for sid, item in zip(sids,resp['TranslatedNames']['Names']):
				# if item['Use'] != SID_NAME_USE.SidTypeUnknown:
				domainIndex = item['DomainIndex']
				if domainIndex == -1: # Unknown domain
					self.sids[sid] = '{}\\{}'.format('???', item['Name'])
				elif domainIndex >= 0:
					name = '{}\\{}'.format(resp['ReferencedDomains']['Domains'][item['DomainIndex']]['Name'], item['Name'])
					self.sids[sid] = name
			dce.disconnect()
		except:
			logging.debug(traceback.format_exc())

	def sidToUser(self, sid):
		if sid[:2] == 'S-' and sid in self.sids:
			return self.sids[sid]
		return sid

	def do_tasklist(self, pid=None, name=None):
		with TSTS.LegacyAPI(self.__smbConnection, self.__target_ip, self.__doKerberos) as legacy:
			handle = legacy.hRpcWinStationOpenServer()
			r = legacy.hRpcWinStationGetAllProcesses(handle)
			if not len(r):
				return None

			self.sids = {}
			for procInfo in r:
				sid = procInfo['pSid']
				if sid[:2] == 'S-' and sid not in self.sids:
					self.sids[sid] = sid
			
			self.lookupSids()

			results = []
			self.get_session_list()
			self.enumerate_sessions_config()
			
			for procInfo in r:
				if pid is not None and pid not in str(procInfo['UniqueProcessId']):
					continue
				if name is not None and name.lower() not in procInfo['ImageName'].lower():
					continue
				
				sessId = procInfo['SessionId']
				fullUserName = ''
				if len(self.sessions[sessId]['Domain']):
					fullUserName += self.sessions[sessId]['Domain'] + '\\'
				if len(self.sessions[sessId]['Username']):
					fullUserName += self.sessions[sessId]['Username']
				
				entry = {
					"attributes": {
						"ImageName": procInfo['ImageName'],
						"PID": procInfo['UniqueProcessId'],
						"SessionID": procInfo['SessionId'],
						"SessionName": self.sessions[sessId]['SessionName'],
						"State": self.sessions[sessId]['state'],
						"SessionUser": fullUserName,
						"SID": self.sidToUser(procInfo['pSid']),
						"MemUsage": f"{procInfo['WorkingSetSize']//1000:,} K"
					}
				}
				results.append(entry)
			
			return results

	def do_taskkill(self, pid=None, name=None):
		if pid is None and name is None:
			logging.error('One of the following is required: -pid, -name')
			return
		if pid is not None and name is not None:
			logging.error('Only one of the following is required: -pid, -name')
			return

		pidList = []
		with TSTS.LegacyAPI(self.__smbConnection, self.__target_ip, self.__doKerberos) as legacy:
			handle = legacy.hRpcWinStationOpenServer()
			if pid is None and name is not None:
				r = legacy.hRpcWinStationGetAllProcesses(handle)
				if not len(r):
					logging.error('Could not get process list')
					return
				pidList = [i['UniqueProcessId'] for i in r if name.lower() in i['ImageName'].lower()]
				if not len(pidList):
					logging.error('Could not find %r in process list' % name)
					return
			else:
				pidList = [pid]

			for pid in pidList:
				logging.warning(f'Terminating PID: {pid} ...')
				try:
					if legacy.hRpcWinStationTerminateProcess(handle, pid)['ErrorCode']:
						return True
					else:
						return False
				except Exception as e:
					logging.error(f'Error terminating pid: {pid}')
					logging.error(str(e))
					return False

	def do_tscon(self):
		options = self.__options
		with TSTS.TermSrvSession(self.__smbConnection, self.__target_ip, self.__doKerberos) as TSSession:
			try:
				session_handle = None
				logging.debug('Connecting SessionID %d to %d ...' % (options.source, options.dest))
				try:
					session_handle = TSSession.hRpcOpenSession(options.source)
				except Exception as e:
					return False
					if e.error_code == 0x80070002:
						logging.error('Could not find source SessionID: %d' % options.source)
					else:
						logging.error(str(e))
					return False
				if TSSession.hRpcConnect(hSession = session_handle,
										 TargetSessionId = options.dest,
										 Password = options.password)['ErrorCode'] == 0:
					return True
				else:
					return False
			except Exception as e:
				return False
				if e.error_code == 0x80070002:
					logging.error('Could not find destination SessionID: %d' % options.dest)
				elif e.error_code == 0x8007139f:
					logging.error('Session in the invalid state. Did you mean %d -> %d?' % (options.dest, options.source))
				else:
					logging.error(str(e))

	def do_tsdiscon(self, session_id):
		with TSTS.TermSrvSession(self.__smbConnection, self.__target_ip, self.__doKerberos) as TSSession:
			try:
				logging.debug('Disconnecting SessionID: %d ...' % session_id)
				session_handle = TSSession.hRpcOpenSession(session_id)
				if TSSession.hRpcDisconnect(session_handle)['ErrorCode'] == 0:
					return True
				else:
					return False
			except Exception as e:
				return False
				if e.error_code == 1:
					logging.error('Maybe it is already disconnected?')
				elif e.error_code == 0x80070002:
					logging.error('Could not find SessionID: %d' % session_id)
				else:
					logging.error(str(e))

	def do_logoff(self, session_id):
		with TSTS.TermSrvSession(self.__smbConnection, self.__target_ip, self.__doKerberos) as TSSession:
			try:
				logging.warning('Signing-out SessionID: %d ...' % session_id)
				session_handle = TSSession.hRpcOpenSession(session_id)
				
				if TSSession.hRpcLogoff(session_handle)['ErrorCode'] == 0:
					return True
				else:
					return False
			except Exception as e:
				if e.error_code == 0x10000000:
					return True
				return False
				if e.error_code == 0x80070002:
					logging.error('Could not find SessionID: %d' % session_id)
				else:
					logging.error(str(e))

	def do_shutdown(self, logoff=False, shutdown=False, reboot=False, poweroff=False):
		if not logoff and not shutdown and not reboot and not poweroff:
			logging.error('No shutdown flags provided')
			return
		
		with TSTS.LegacyAPI(self.__smbConnection, self.__target_ip, self.__doKerberos) as legacy:
			handle = legacy.hRpcWinStationOpenServer()
			flags = 0
			flagsList = []
			shutdown_flags = [logoff, shutdown, reboot, poweroff]
			for k,v in zip(shutdown_flags, ['logoff', 'shutdown', 'reboot', 'poweroff']):
				if k:
					flagsList.append(v)
			flagsList = '|'.join(flagsList)
			for k,v in zip(shutdown_flags, [1,2,4,8]):
				if k:
					flags |= v
			try:
				logging.debug('Sending shutdown (%s) event ...' % (flagsList))
				resp = legacy.hRpcWinStationShutdownSystem(handle, 0, flags)
				if resp['ErrorCode']:
					return True
				else:
					resp.dump()
					return False
			except Exception as e:
				return False
				logging.error(str(e))
	

	def do_msg(self, session_id, title, message):
		with TSTS.TermSrvSession(self.__smbConnection, self.__target_ip, self.__doKerberos) as TSSession:
			try:
				logging.debug(f'Sending message to SessionID: {session_id} ...')
				session_handle = TSSession.hRpcOpenSession(session_id)
				if TSSession.hRpcShowMessageBox(session_handle, title, message)['ErrorCode'] == 0:
					return True
				else:
					return False
			except Exception as e:
				return False
				if e.error_code == 0x80070002:
					logging.error(f'Could not find SessionID: {session_id}')
				else:
					logging.error(str(e))