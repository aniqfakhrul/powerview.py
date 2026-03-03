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

	def add_computer_opnum12(self, dce, domain_handle, computer_name, computer_password, no_password=False):
		user_handle = None
		try:
			# Step 1: Create normal user via Opnum 12 (SamrCreateUserInDomain)
			# Server hardcodes AccountType=USER_NORMAL_ACCOUNT (0x10)
			try:
				create_user = samr.hSamrCreateUserInDomain(
					dce, domain_handle, computer_name,
					samr.USER_FORCE_PASSWORD_CHANGE
				)
			except samr.DCERPCSessionError as e:
				if e.error_code == 0xc0000022:
					raise Exception("Insufficient rights to create a machine account!")
				elif e.error_code == 0xc00002e7:
					raise Exception("Machine account quota exceeded!")
				raise

			user_handle = create_user['UserHandle']

			# Step 2: Set password before UAC change
			if not no_password:
				samr.hSamrSetPasswordInternal4New(dce, user_handle, computer_password)

			# Step 3: Re-open with MAXIMUM_ALLOWED for UAC change
			user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [computer_name])['RelativeIds']['Element'][0]
			self.close_handle(dce, user_handle)
			user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)['UserHandle']

			# Step 4: Morph normal user -> workstation trust account via UserControlInformation (Opnum 37)
			req = samr.SAMPR_USER_INFO_BUFFER()
			req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT | (0x20 if no_password else 0)
			samr.hSamrSetInformationUser2(dce, user_handle, req)
			return True
		finally:
			if user_handle is not None:
				self.close_handle(dce, user_handle)

	def add_computer(self, dce, domain_handle, computer_name, computer_password, no_password=False):
		"""Create computer via Opnum 50 (SamrCreateUser2InDomain) with explicit workstation trust type."""
		user_handle = None
		try:
			# Create the computer account via Opnum 50 (SamrCreateUser2InDomain)
			try:
				create_user = samr.hSamrCreateUser2InDomain(
					dce, domain_handle, computer_name,
					samr.USER_WORKSTATION_TRUST_ACCOUNT,
					samr.USER_FORCE_PASSWORD_CHANGE
				)
			except samr.DCERPCSessionError as e:
				if e.error_code == 0xc0000022:
					raise Exception("Insufficient rights to create a machine account!")
				elif e.error_code == 0xc00002e7:
					raise Exception("Machine account quota exceeded!")
				raise

			user_handle = create_user['UserHandle']

			# Set password
			if not no_password:
				samr.hSamrSetPasswordInternal4New(dce, user_handle, computer_password)

			# Set UAC flags
			user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, [computer_name])['RelativeIds']['Element'][0]
			self.close_handle(dce, user_handle)
			user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.MAXIMUM_ALLOWED, user_rid)['UserHandle']

			req = samr.SAMPR_USER_INFO_BUFFER()
			req['tag'] = samr.USER_INFORMATION_CLASS.UserControlInformation
			req['Control']['UserAccountControl'] = samr.USER_WORKSTATION_TRUST_ACCOUNT | (0x20 if no_password else 0)
			samr.hSamrSetInformationUser2(dce, user_handle, req)
			return True
		finally:
			if user_handle is not None:
				self.close_handle(dce, user_handle)

	def set_password(self, dce, domain_handle, account_name, new_password):
		"""Admin password reset via SamrSetInformationUser2 / UserInternal4InformationNew.
		Uses impacket's hSamrSetPasswordInternal4New which encrypts the password with
		the actual SMB session key (MD5(salt + session_key) for RC4).
		Requires admin privileges. Does NOT require the old password."""
		user_rid = samr.hSamrLookupNamesInDomain(dce, domain_handle, (account_name,))['RelativeIds']['Element'][0]
		user_handle = samr.hSamrOpenUser(dce, domain_handle, userId=user_rid)['UserHandle']
		try:
			samr.hSamrSetPasswordInternal4New(dce, user_handle, new_password)
			return True
		finally:
			self.close_handle(dce, user_handle)

	def add_group(self, dce, domain_handle, group_name):
		"""Create a domain global group via SamrCreateGroupInDomain (Opnum 10)."""
		try:
			resp = samr.hSamrCreateGroupInDomain(dce, domain_handle, group_name, samr.GROUP_ALL_ACCESS)
		except samr.DCERPCSessionError as e:
			if e.error_code == 0xc0000022:
				raise Exception("Insufficient rights to create group!")
			raise

		group_handle = resp['GroupHandle']
		rid = resp['RelativeId']
		samr.hSamrCloseHandle(dce, group_handle)
		return rid

	def change_password(self, dce, account_name, old_password, new_password, old_pwd_hash_nt='', old_pwd_hash_lm=''):
		try:
			samr.hSamrUnicodeChangePasswordUser2(dce=dce, serverName='\x00', userName=account_name, oldPassword=old_password, newPassword=new_password, oldPwdHashLM=old_pwd_hash_lm, oldPwdHashNT=old_pwd_hash_nt)
			return True
		except samr.DCERPCSessionError as e:
			if e.error_code == 0xc0000073:
				raise Exception("Account %s not found!" % account_name)
			raise

	def delete_computer(self, dce, domain_handle, computer_name):
		user_handle = None
		try:
			try:
				computer_info = samr.hSamrLookupNamesInDomain(dce, domain_handle, [computer_name])
			except samr.DCERPCSessionError as e:
				if e.error_code == 0xc0000073:
					raise Exception("Account %s not found!" % computer_name)
				raise

			user_rid = computer_info['RelativeIds']['Element'][0]
			try:
				user_handle = samr.hSamrOpenUser(dce, domain_handle, samr.DELETE, user_rid)['UserHandle']
			except samr.DCERPCSessionError as e:
				if e.error_code == 0xc0000022:
					raise Exception("Insufficient rights to delete %s!" % computer_name)
				raise

			samr.hSamrDeleteUser(dce, user_handle)
			user_handle = None
			return True
		finally:
			if user_handle is not None:
				self.close_handle(dce, user_handle)