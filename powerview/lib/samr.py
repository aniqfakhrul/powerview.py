#!/usr/bin/env python3
import logging
from impacket.dcerpc.v5 import transport, samr

class SamrObject:
	KNOWN_PROTOCOLS = {
        139: {'bindstr': r'ncacn_np:%s[\pipe\samr]', 'set_host': True},
        445: {'bindstr': r'ncacn_np:%s[\pipe\samr]', 'set_host': True},
    }

	def __init__(self, connection, port=445):
		self.connection = connection
		self.port = port
		self.pipetriggered = False

	def connect(self, target):
		stringBinding = self.KNOWN_PROTOCOLS[self.port]['bindstr'] % target
		dce = self.connection.connectRPCTransport(
			host=target,
			stringBindings=stringBinding,
			interface_uuid=samr.MSRPC_UUID_SAMR,
			raise_exceptions=True
		)
		return dce

	def open_handle(self, dce, builtin=False):
		index = 1 if builtin else 0
		server_handle = samr.hSamrConnect(dce)['ServerHandle']
		domain_name = samr.hSamrEnumerateDomainsInSamServer(dce, server_handle)['Buffer']['Buffer'][index]['Name']
		domain_id = samr.hSamrLookupDomainInSamServer(dce, server_handle, domain_name)['DomainId']
		domain_handle = samr.hSamrOpenDomain(dce, server_handle, domainId=domain_id)['DomainHandle']
		return domain_handle

	def get_object_rid(self, dce, domain_handle, object_name):
		object_id = None
		try:
			response = samr.hSamrLookupNamesInDomain(dce, domain_handle, (object_name,))
			object_id = response['RelativeIds']['Element'][0]['Data']
		except samr.DCERPCSessionError as e:
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				logging.error("[SAMR] No object found for {}".format(object_name))
		return object_id

	def get_user_handle(self, dce, domain_handle, user_rid):
		response = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)
		return response['UserHandle']

	def close_handle(self, dce, handle):
		samr.hSamrCloseHandle(dce, handle)

	def get_all_local_users(self, dce, domain_handle):
		try:
			response = samr.hSamrEnumerateUsersInDomain(dce, domain_handle, samr.USER_NORMAL_ACCOUNT)
			for item in response['Buffer']['Buffer']:
				yield item
		except samr.DCERPCSessionError as e:
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
		finally:
			self.close_handle(dce, domain_handle)

	def get_local_group(self, dce, domain_handle, gid):
		group_handle = samr.hSamrOpenGroup(dce, domain_handle, groupId=gid)['GroupHandle']
		group_sid = samr.hSamrRidToSid(dce, group_handle, gid)['Sid']
		si = samr.PSAMPR_SID_INFORMATION()
		si['SidPointer'] = group_sid
		self.close_handle(dce, group_handle)
		return si

	def get_local_user(self, dce, domain_handle, user_rid):
		try:
			user_handle = self.get_user_handle(dce, domain_handle, user_rid)
			response = samr.hSamrQueryInformationUser2(dce, user_handle, samr.USER_INFORMATION_CLASS.UserAllInformation)
			response = response['Buffer']['All']

			# Get groups that user is member of
			groups = samr.hSamrGetGroupsForUser(dce, user_handle)['Groups']['Groups']
			group_id_list = list(map(lambda g: g['RelativeId'], groups))
			
			sidArray = samr.SAMPR_PSID_ARRAY()
			for gid in group_id_list:
				si = self.get_local_group(dce, domain_handle, gid)
				sidArray['Sids'].append(si)

			global_lookup_ids = samr.hSamrLookupIdsInDomain(dce, domain_handle, group_id_list)
			response.fields['GlobalGroups'] = list(map(lambda a: a['Data'], global_lookup_ids['Names']['Element']))
			self.close_handle(dce, domain_handle)

			domain_handle = self.open_handle(dce, builtin=True)
			alias_membership = samr.hSamrGetAliasMembership(dce, domain_handle, sidArray)
			alias_id_list = list(map(lambda a: a['Data'], alias_membership['Membership']['Element']))

			local_lookup_ids = samr.hSamrLookupIdsInDomain(dce, domain_handle, alias_id_list)
			response.fields['LocalGroups'] = list(map(lambda a: a['Data'], local_lookup_ids['Names']['Element']))
			return response
		except samr.DCERPCSessionError as e:
			if str(e).find('STATUS_MORE_ENTRIES') < 0:
				raise
		finally:
			self.close_handle(dce, domain_handle)



		