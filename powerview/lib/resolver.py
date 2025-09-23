import datetime
from dateutil.relativedelta import relativedelta

from ldap3.protocol.formatters.formatters import format_sid
from impacket.ldap.ldaptypes import SR_SECURITY_DESCRIPTOR
from impacket.uuid import bin_to_string

from powerview.modules.msa import MSA
from powerview.utils.constants import (
	UAC_DICT,
	LDAP_ERROR_STATUS,
	SUPPORTED_sAMAccountType,
	SUPPORTED_ENCRYPTION_TYPES,
	switcher_trustDirection,
	switcher_trustType,
	switcher_trustAttributes,
	PWD_FLAGS,
	FOREST_TRUST_INFO,
	switcher_dsa_delegated_msa_state
)
from powerview.modules.ldapattack import (
	RBCD
)
from powerview.utils.helpers import filetime_to_str

class UAC:
	@staticmethod
	def parse_value(uac_value):
		uac_value = int(uac_value)
		flags = []

		for key, value in UAC_DICT.items():
			if uac_value & key:
				flags.append(value)

		return flags

	@staticmethod
	def parse_value_tolist(uac_value):
		uac_value = int(uac_value)
		flags = []

		for key, value in UAC_DICT.items():
			if uac_value & key:
				flags.append([value, key])

		return flags

	@staticmethod
	def parse_uac_namestrings_to_value(uac_names, type=list):
		"""Convert UAC flag names to numeric value
		Args:
			uac_names (str): UAC flag names
		Returns:
			int: Combined UAC numeric value
		"""
		if not uac_names:
			return 0
		if isinstance(uac_names, str):
			names = [name.strip() for name in uac_names.split(",")]
		elif isinstance(uac_names, list):
			names = [name.strip() for name in uac_names]
		else:
			raise TypeError("uac_names must be a string or a list")

		uac_value = 0
		reverse_uac = {value: key for key, value in UAC_DICT.items()}

		for name in names:
			if name in reverse_uac:
				uac_value |= reverse_uac[name]
			else:
				raise ValueError(f"Invalid UAC name: {name}")
		
		if type == list:
			return [uac_value]
		elif type == int:
			return int(uac_value)
		else:
			return uac_value

class ENCRYPTION_TYPE:
	@staticmethod
	def parse_value(enc_value):
		enc_value = int(enc_value)
		flags = []

		for key, value in SUPPORTED_ENCRYPTION_TYPES.items():
			if enc_value & key:
				flags.append(value)

		return flags

class sAMAccountType:
	@staticmethod
	def parse_value(enc_value):
		enc_value = int(enc_value)

		if enc_value in SUPPORTED_sAMAccountType:
			return SUPPORTED_sAMAccountType[enc_value]
		else:
			return enc_value

class LDAP:
	@staticmethod
	def resolve_pKIExpirationPeriod(data):
		try:
			return filetime_to_str(data)
		except Exception as e:
			return data

	@staticmethod
	def resolve_delegated_msa_state(data):
		if isinstance(data, list):
			return switcher_dsa_delegated_msa_state.get(int(data[0]))
		elif isinstance(data, bytes):
			return switcher_dsa_delegated_msa_state.get(int(data.decode()))
		else:
			return switcher_dsa_delegated_msa_state.get(int(data))

	@staticmethod
	def resolve_pKIOverlapPeriod(data):
		try:
			return filetime_to_str(data)
		except Exception as e:
			return data

	@staticmethod
	def resolve_msDSTrustForestTrustInfo(data):
		sids = []
		parser = FOREST_TRUST_INFO(data)
		for record in parser['Records']:
			try:
				sids.append(record['Data']['Sid'].formatCanonical())
			except KeyError:
				pass
		return sids

	@staticmethod
	def resolve_msDSAllowedToActOnBehalfOfOtherIdentity(data):
		sids = []
		sd = SR_SECURITY_DESCRIPTOR(data=data)
		if len(sd['Dacl'].aces) > 0:
			for ace in sd['Dacl'].aces:
				sids.append(ace['Ace']['Sid'].formatCanonical())
			return sids
		else:
			return data

	@staticmethod
	def resolve_err_status(error_status):
		return LDAP_ERROR_STATUS.get(error_status)

	@staticmethod
	def resolve_enc_type(enc_type):
		if isinstance(enc_type, list):
			return ENCRYPTION_TYPE.parse_value(enc_type[0])
		elif isinstance(enc_type, bytes):
			return ENCRYPTION_TYPE.parse_value(enc_type.decode())
		else:
			return ENCRYPTION_TYPE.parse_value(enc_type)

	@staticmethod
	def resolve_samaccounttype(enc_type):
		if isinstance(enc_type, list):
			return sAMAccountType.parse_value(enc_type[0])
		elif isinstance(enc_type, bytes):
			return sAMAccountType.parse_value(enc_type.decode())
		else:
			return sAMAccountType.parse_value(enc_type)

	@staticmethod
	def resolve_uac(uac_val):
		# resolve userAccountControl
		if isinstance(uac_val, list):
			val =  UAC.parse_value(uac_val[0])
		elif isinstance(uac_val, bytes):
			val = UAC.parse_value(uac_val.decode())
		else:
			val = UAC.parse_value(uac_val)

		return val

	@staticmethod
	def parse_uac_name_to_value(uac_names, delimiter=','):
		"""Convert UAC flag names to numeric value
		Args:
			uac_names (str): Comma-separated UAC flag names
		Returns:
			int: Combined UAC numeric value
		"""
		if not uac_names:
			return 0
			
		uac_value = 0
		names = [name.strip() for name in uac_names.split(delimiter)]
		
		# Create reverse mapping of name->value
		reverse_uac = {value: key for key, value in UAC_DICT.items()}
		
		for name in names:
			if name in reverse_uac:
				uac_value |= reverse_uac[name]
				
		return uac_value

	@staticmethod
	def ldap2datetime(ts):
		if isinstance(ts, datetime.datetime):
			return ts
		else:
			ts = int(ts)
			dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ts / 10000000)
		#return datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ts/10000000)
		return f"{dt.strftime('%d/%m/%Y %H:%M:%S')} ({LDAP.human_readable_time_diff(dt)})"

	@staticmethod
	def human_readable_time_diff(past_date):
		now = datetime.datetime.now()
		diff = relativedelta(now, past_date)

		if diff.years > 0:
			return f"{diff.years} year{'s' if diff.years > 1 else ''}, {diff.months} month{'s' if diff.months > 1 else ''} ago"
		elif diff.months > 0:
			return f"{diff.months} month{'s' if diff.months > 1 else ''}, {diff.days} day{'s' if diff.days > 1 else ''} ago"
		elif diff.days > 0:
			return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
		else:
			return "today"

	@staticmethod
	def resolve_generalized_time(ldap_time):
		if isinstance(ldap_time, datetime.datetime):
			dt = ldap_time
		else:
			if isinstance(ldap_time, bytes):
				ldap_time = ldap_time.decode()
			dt = datetime.datetime.strptime(ldap_time, "%Y%m%d%H%M%S.%fZ")
		
		return f"{dt.strftime('%d/%m/%Y %H:%M:%S')} ({LDAP.human_readable_time_diff(dt)})"

	@staticmethod
	def bin_to_guid(guid):
		return "{%s}" % bin_to_string(guid).lower()

	@staticmethod
	def bin_to_sid(sid):
		return format_sid(sid)

	@staticmethod
	def formatGMSApass(managedPassword):
		return MSA.decrypt(managedPassword)

	@staticmethod
	def parseMSAMembership(secDesc):
		return MSA.read_acl(secDesc)

	@staticmethod
	def resolve_pwdProperties(flag):
		prop =  PWD_FLAGS.get(int(flag))
		return f"({flag.decode()}) {prop}" if prop else flag

class TRUST:
	@staticmethod
	def resolve_trustDirection(flag):
		flag = int(flag)
		types = []
		for bit, name in switcher_trustDirection.items():
			if flag & bit:
				types.append(name)
		return types

	@staticmethod
	def resolve_trustType(flag):
		flag = int(flag)
		types = []
		for bit, name in switcher_trustType.items():
			if flag & bit:
				types.append(name)
		return types

	@staticmethod
	def resolve_trustAttributes(flag):
		flag = int(flag)
		attributes = []
		for bit, name in switcher_trustAttributes.items():
			if flag & bit:
				attributes.append(name)
		return attributes

class EXCHANGE:
	@staticmethod
	def resolve_msExchVersion(version_num):
		"""
		Convert an msExchVersion number to human-readable Exchange version
		
		Args:
			version_num: The msExchVersion value as a string or integer
			
		Returns:
			String with decoded version information
		"""
		try:
			if isinstance(version_num, list):
				version_num = version_num[0]
			elif isinstance(version_num, bytes):
				version_num = version_num.decode()
				
			version_num = int(version_num)
			
			# Extract components
			major_version = (version_num >> 48) & 0xFFFF
			minor_version = (version_num >> 32) & 0xFFFF
			build = (version_num >> 16) & 0xFFFF
			revision = version_num & 0xFFFF
			
			# Determine Exchange version
			exchange_version = ""
			if major_version == 15:
				if minor_version >= 2:
					exchange_version = "Exchange 2019"
				elif minor_version == 1:
					exchange_version = "Exchange 2016"
				elif minor_version == 0:
					exchange_version = "Exchange 2013"
			elif major_version == 14:
				exchange_version = "Exchange 2010"
			elif major_version == 8:
				exchange_version = "Exchange 2007"
			elif major_version == 6:
				exchange_version = "Exchange 2003"
			else:
				exchange_version = f"Unknown Exchange (Version {major_version})"
			
			version_str = f"{major_version}.{minor_version}.{build}.{revision}"
			return f"{exchange_version} ({version_str})"
		except (ValueError, TypeError) as e:
			return f"Unknown format: {version_num}"
