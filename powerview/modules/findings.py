#!/usr/bin/env python3
"""
1. kerberoastable accounts
2. kerberoastable admin accounts
"""
import logging
from datetime import datetime
from powerview.utils.parsers import powerview_arg_parse

CHECK_REGISTRY = []

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}


def register_check(cls):
	CHECK_REGISTRY.append(cls)
	return cls


def _first(value):
	if isinstance(value, list):
		return value[0] if value else None
	return value


def _entries(result):
	if result is None:
		return []
	return list(result)


def _attrs(entry):
	if isinstance(entry, dict):
		return entry.get('attributes') or {}
	return getattr(entry, 'attributes', {}) or {}


def _name(attrs):
	for key in ('sAMAccountName', 'name', 'cn', 'displayName', 'dNSHostName'):
		value = _first(attrs.get(key))
		if value:
			return str(value)
	return None


def _is_disabled(uac):
	if uac is None:
		return False
	try:
		return bool(int(uac) & 2)
	except (TypeError, ValueError):
		return 'DISABLE' in str(uac).upper()


def _coerce_datetime(value):
	if isinstance(value, datetime):
		return value.replace(tzinfo=None) if value.tzinfo else value
	if isinstance(value, str):
		for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S',
				'%a, %d %b %Y %H:%M:%S %Z'):
			try:
				return datetime.strptime(value, fmt)
			except ValueError:
				continue
	return None


def _repl_right(obj_type):
	value = str(obj_type or '').lower()
	if '1131f6ad' in value or 'get-changes-all' in value or 'changes all' in value:
		return 'all'
	if 'in-filtered-set' in value or 'filtered set' in value or '89e95b76' in value:
		return None
	if '1131f6aa' in value or 'get-changes' in value or 'replicating directory changes' in value:
		return 'base'
	return None


def _query(powerview, getter_name, tokens):
	args = powerview_arg_parse(tokens)
	if args is None:
		raise ValueError('failed to parse query: ' + ' '.join(tokens))
	getter = getattr(powerview, getter_name, None)
	if getter is None:
		raise ValueError('powerview has no method ' + getter_name)
	return _entries(getter(args=args))


class Check:
	id = None
	code = None
	title = ''
	severity = 'low'
	category = 'general'
	mode = 'passive'
	unit = 'item(s)'
	detail = ''
	remediation = ''
	references = []

	def run(self, powerview):
		raise NotImplementedError

	def finding(self, count, affected=None, subject=None):
		affected = affected or []
		return {
			'id': self.id,
			'code': self.code,
			'title': self.title,
			'severity': self.severity,
			'category': self.category,
			'mode': self.mode,
			'count': count,
			'unit': self.unit,
			'subject': subject if subject is not None else '%d %s' % (count, self.unit),
			'affected': affected[:50],
			'detail': self.detail,
			'remediation': self.remediation,
			'references': list(self.references),
		}


@register_check
class KerberoastableCheck(Check):
	id = 'kerberoastable'
	code = 'KERB'
	title = 'Kerberoastable accounts'
	severity = 'medium'
	category = 'kerberos'
	unit = 'account(s)'
	detail = 'These user accounts have a service principal name set. Any domain user can request a ticket for them and crack the password offline.'
	remediation = 'Give service accounts long random passwords or use group managed service accounts. Remove SPNs that are no longer needed.'
	references = ['https://attack.mitre.org/techniques/T1558/003/']

	def run(self, powerview):
		entries = _query(powerview, 'get_domainuser', ['Get-DomainUser', '-SPN'])
		affected = [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]

@register_check
class KerberoastableAdminCheck(Check):
	id = 'kerberoastable-admins'
	code = 'KERBADM'
	title = 'Kerberoastable admin accounts'
	severity = 'medium'
	category = 'kerberos'
	unit = 'account(s)'
	detail = 'These user accounts with admin privileges have a service principal name set. Any domain user can request a ticket for them and crack the password offline.'
	remediation = 'Give service accounts long random passwords or use group managed service accounts. Remove SPNs that are no longer needed.'
	references = ['https://attack.mitre.org/techniques/T1558/003/']

	def run(self, powerview):
		entries = _query(powerview, 'get_domainuser', ['Get-DomainUser', '-AdminCount', '-SPN'])
		affected = [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]

@register_check
class ASREPRoastableCheck(Check):
	id = 'asrep-roastable'
	code = 'ASREP'
	title = 'AS-REP roastable accounts'
	severity = 'high'
	category = 'kerberos'
	unit = 'account(s)'
	detail = 'These accounts do not require Kerberos pre-authentication. Anyone can request their login response and crack it offline.'
	remediation = 'Turn Kerberos pre-authentication back on for these accounts unless an application really needs it off.'
	references = ['https://attack.mitre.org/techniques/T1558/004/']

	def run(self, powerview):
		entries = _query(powerview, 'get_domainuser', ['Get-DomainUser', '-PreauthNotRequired'])
		affected = [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]

@register_check
class ConstrainedDelegationCheck(Check):
	id = 'constrained-delegation'
	code = 'KCD'
	title = 'Constrained delegation with protocol transition'
	severity = 'medium'
	category = 'delegation'
	unit = 'account(s)'
	detail = 'These user and computer accounts are trusted to authenticate for delegation (protocol transition). They can request a ticket for any user to their allowed services.'
	remediation = 'Review whether delegation is required, and remove protocol transition where it is not needed.'

	def run(self, powerview):
		affected = []
		for getter, command in (('get_domainuser', 'Get-DomainUser'),
				('get_domaincomputer', 'Get-DomainComputer')):
			entries = _query(powerview, getter, [command, '-TrustedToAuth'])
			affected += [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]

@register_check
class ObsoleteComputerCheck(Check):
	id = 'obsolete-computers'
	code = 'OBSCOMP'
	title = 'Obsolete computer accounts'
	severity = 'medium'
	category = 'hygiene'
	unit = 'computer account(s)'
	detail = (
		'These computer accounts appear to be obsolete or inactive. '
		'Stale computer accounts are often forgotten, unmanaged, and may still '
		'retain old privileges or delegation settings.'
	)
	remediation = (
		'Review and remove unused computer accounts. '
		'Disable inactive systems and clean up stale AD objects regularly.'
	)
	references = []

	def run(self, powerview):
		entries = _query(
			powerview,
			'get_domaincomputer',
			['Get-DomainComputer', '-Obsolete', '-Enabled']
		)

		affected = []

		for entry in entries:
			attrs = _attrs(entry)

			name = _name(attrs)
			if not name:
				continue

			last_logon = (
				_first(attrs.get('lastLogonTimestamp')) or
				_first(attrs.get('lastLogon')) or
				_first(attrs.get('pwdLastSet'))
			)

			if last_logon:
				affected.append('%s (last seen: %s)' % (name, last_logon))
			else:
				affected.append(name)

		return [self.finding(len(affected), affected)]

@register_check
class RBCDCheck(Check):
	id = 'rbcd'
	code = 'RBCD'
	title = 'Resource based constrained delegation accounts'
	severity = 'medium'
	category = 'delegation'
	unit = 'account(s)'
	detail = 'These accounts let another object impersonate users to them through resource based constrained delegation (RBCD).'
	remediation = 'Review whether delegation is required.'

	def run(self, powerview):
		entries = _query(
			powerview,
			'get_domaincomputer',
			['Get-DomainComputer', '-RBCD' , '-Enabled']
		)
		affected = [
			_name(_attrs(e))
			for e in entries
			if _name(_attrs(e))
		]
		return [self.finding(len(affected), affected)]

@register_check
class UnconstrainedDelegationCheck(Check):
	id = 'unconstrained-delegation'
	code = 'UNCDEL'
	title = 'Unconstrained delegation hosts'
	severity = 'high'
	category = 'delegation'
	unit = 'host(s)'
	detail = 'These computers are trusted for unconstrained delegation. If one is compromised, an attacker can capture tickets sent to it, including domain controller tickets.'
	remediation = 'Switch them to constrained delegation, and mark sensitive accounts as not allowed to be delegated.'
	references = ['https://attack.mitre.org/techniques/T1187/']

	def run(self, powerview):
		entries = _query(powerview, 'get_domaincomputer', ['Get-DomainComputer', '-Unconstrained', '-Enabled'])
		affected = [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]


@register_check
class VulnerableCertTemplateCheck(Check):
	id = 'esc-vuln-template'
	code = 'ESC'
	title = 'Vulnerable ADCS certificate templates'
	severity = 'high'
	category = 'adcs'
	unit = 'template(s)'
	detail = 'These certificate templates are misconfigured (ESC1 to ESC16) and can be abused to escalate privileges.'
	remediation = 'Limit who can enroll, turn off "supply subject in request", and require manager approval.'
	references = ['https://posts.specterops.io/certified-pre-owned-d95910965cd2']

	def run(self, powerview):
		entries = _entries(powerview.get_domaincatemplate(vulnerable=True))
		affected = [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]


@register_check
class PrivilegedAccountCheck(Check):
	id = 'privileged-accounts'
	code = 'ADMIN'
	title = 'Privileged (protected) accounts'
	severity = 'low'
	category = 'privilege'
	unit = 'account(s)'
	detail = 'These accounts have adminCount set to 1. They are, or used to be, members of a protected admin group.'
	remediation = 'Check who really needs to be in Tier 0 groups, and clear adminCount on accounts that are no longer privileged.'
	references = []

	def run(self, powerview):
		entries = _query(powerview, 'get_domainuser', ['Get-DomainUser', '-AdminCount'])
		affected = [n for n in (_name(_attrs(e)) for e in entries) if n]
		return [self.finding(len(affected), affected)]


@register_check
class StalePasswordCheck(Check):
	id = 'stale-password'
	code = 'STALE'
	title = 'Stale account passwords'
	severity = 'medium'
	category = 'hygiene'
	unit = 'account(s)'
	detail = 'Enabled accounts whose password has not changed in over 365 days.'
	remediation = 'Enforce a maximum password age and rotate or disable dormant accounts.'
	references = []

	def run(self, powerview):
		entries = _query(powerview, 'get_domainuser', ['Get-DomainUser', '-Raw'])
		now = datetime.now()
		affected = []
		for entry in entries:
			attrs = _attrs(entry)
			if _is_disabled(_first(attrs.get('userAccountControl'))):
				continue
			when = _coerce_datetime(_first(attrs.get('pwdLastSet')))
			if when is None or when.year < 1971:
				continue
			if (now - when).days > 365:
				name = _name(attrs)
				if name:
					affected.append(name)
		return [self.finding(len(affected), affected)]


@register_check
class DnsCreateChildCheck(Check):
	id = 'dns-authenticated-users-create'
	code = 'DNSACL'
	title = 'Authenticated Users can create DNS records'
	severity = 'low'
	category = 'dns'
	unit = 'zone(s)'
	detail = 'Authenticated Users can create child objects on these DNS zones, so any domain user can add DNS records. This opens the door to ADIDNS spoofing.'
	remediation = 'Remove the CreateChild right for Authenticated Users on the DNS zone unless every user needs to add records.'
	references = ['https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications/adidns-spoofing']

	def run(self, powerview):
		zones = _entries(powerview.get_domaindnszone(get_all=True))
		affected = []
		for zone in zones:
			zone_dn = _first(_attrs(zone).get('distinguishedName'))
			if not zone_dn:
				continue
			try:
				aces = powerview.get_domainobjectacl(identity=zone_dn, searchbase=zone_dn,
					security_identifier='S-1-5-11')
			except Exception:
				continue
			for entry in (aces or []):
				for ace in (entry.get('attributes') or []):
					rights = str(ace.get('ActiveDirectoryRights') or ace.get('AccessMask') or '')
					if 'CreateChild' in rights or 'GenericAll' in rights:
						if zone_dn not in affected:
							affected.append(zone_dn)
		return [self.finding(len(affected), affected)]


@register_check
class DCSyncCheck(Check):
	id = 'dcsync-rights'
	code = 'DCSYNC'
	title = 'Non-default principals with DCSync rights'
	severity = 'high'
	category = 'privilege'
	unit = 'principal(s)'
	detail = 'These principals can replicate directory secrets (DCSync) and dump every account hash in the domain, including krbtgt. Default Tier 0 groups are not listed.'
	remediation = 'Remove the replication rights from any principal that is not a domain controller or a Tier 0 admin group.'
	references = ['https://attack.mitre.org/techniques/T1003/006/']

	_DEFAULTS = ('domain admins', 'enterprise admins', 'administrators',
		'domain controllers', 'enterprise domain controllers', 'system')

	def run(self, powerview):
		root_dn = getattr(powerview, 'root_dn', None)
		if not root_dn:
			return []
		aces = powerview.get_domainobjectacl(identity=root_dn, searchbase=root_dn, resolveguids=True)
		granted = {}
		for entry in (aces or []):
			for ace in (entry.get('attributes') or []):
				if 'ALLOWED' not in str(ace.get('ACEType', '')):
					continue
				principal = ace.get('SecurityIdentifier')
				if not principal:
					continue
				bucket = granted.setdefault(str(principal), set())
				if 'GenericAll' in str(ace.get('ActiveDirectoryRights') or ''):
					bucket.update(('base', 'all'))
				right = _repl_right(ace.get('ObjectAceType'))
				if right:
					bucket.add(right)
		affected = []
		for principal, rights in granted.items():
			if 'base' in rights and 'all' in rights \
					and not any(d in principal.lower() for d in self._DEFAULTS):
				affected.append(principal)
		return [self.finding(len(affected), sorted(affected))]


@register_check
class MachineAccountQuotaCheck(Check):
	id = 'machine-account-quota'
	code = 'MAQ'
	title = 'Non-zero MachineAccountQuota'
	severity = 'medium'
	category = 'config'
	unit = 'domain'
	detail = 'MachineAccountQuota is above 0, so any domain user can add computer accounts. This helps RBCD and sAMAccountName spoofing attacks.'
	remediation = 'Set MachineAccountQuota to 0 and give machine join rights only to a specific group.'
	references = ['https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing']

	def run(self, powerview):
		root_dn = getattr(powerview, 'root_dn', None)
		if not root_dn:
			return []
		entries = _entries(powerview.get_domainobject(identity=root_dn, properties=['ms-DS-MachineAccountQuota']))
		quota = None
		for entry in entries:
			value = _first(_attrs(entry).get('ms-DS-MachineAccountQuota'))
			if value is not None and value != '':
				quota = value
				break
		try:
			quota = int(quota)
		except (TypeError, ValueError):
			return []
		if quota <= 0:
			return [self.finding(0, [], subject='MachineAccountQuota = 0')]
		return [self.finding(1, ['MachineAccountQuota = %d' % quota],
			subject='MachineAccountQuota = %d' % quota)]


@register_check
class LockoutPolicyCheck(Check):
	id = 'no-lockout-policy'
	code = 'LOCKOUT'
	title = 'No account lockout policy'
	severity = 'medium'
	category = 'config'
	unit = 'domain'
	detail = 'The domain lockout threshold is 0, so accounts are never locked out. An attacker can run password spraying and brute force attacks without any limit.'
	remediation = 'Set an account lockout threshold (for example 5 to 10 failed attempts) in the domain password policy.'
	references = []

	def run(self, powerview):
		root_dn = getattr(powerview, 'root_dn', None)
		if not root_dn:
			return []
		entries = _entries(powerview.get_domainobject(identity=root_dn, properties=['lockoutThreshold']))
		threshold = None
		for entry in entries:
			value = _first(_attrs(entry).get('lockoutThreshold'))
			if value is not None and value != '':
				threshold = value
				break
		try:
			threshold = int(threshold)
		except (TypeError, ValueError):
			return []
		if threshold > 0:
			return [self.finding(0, [], subject='lockout threshold = %d' % threshold)]
		return [self.finding(1, ['lockout threshold = 0'], subject='no lockout threshold set')]


@register_check
class LdapEnforcementCheck(Check):
	id = 'ldap-enforcement'
	code = 'LDAP'
	title = 'LDAP signing or channel binding not enforced'
	severity = 'high'
	category = 'config'
	unit = 'setting(s)'
	detail = 'The domain controller does not require LDAP signing or LDAPS channel binding. An attacker can relay NTLM authentication to LDAP and take over the domain.'
	remediation = 'Require LDAP signing and enable LDAPS channel binding on all domain controllers through Group Policy.'
	references = ['https://attack.mitre.org/techniques/T1557/']

	def run(self, powerview):
		conn = getattr(powerview, 'conn', None)
		if conn is None:
			raise ValueError('no active connection available')
		signing, channel_binding = conn.check_ldap_enforcement()
		if signing is None and channel_binding is None:
			return [self.finding(0, [], subject='could not probe LDAP enforcement')]
		missing = []
		if signing is False:
			missing.append('LDAP signing')
		if channel_binding is False:
			missing.append('channel binding')
		if not missing:
			return [self.finding(0, [], subject='LDAP signing and channel binding enforced')]
		return [self.finding(len(missing), missing, subject='not enforced: ' + ', '.join(missing))]


@register_check
class NoPacCheck(Check):
	id = 'nopac'
	code = 'NOPAC'
	title = 'DC vulnerable to noPac (CVE-2021-42278/42287)'
	severity = 'critical'
	category = 'escalation'
	mode = 'active'
	unit = 'domain'
	detail = 'The domain controller hands out a ticket without a PAC when asked. A normal user can use this to act as a Domain Admin.'
	remediation = 'Install the November 2021 update or later on every domain controller.'
	references = ['https://github.com/Ridter/noPac',
		'https://www.thehacker.recipes/ad/movement/kerberos/samaccountname-spoofing']

	def run(self, powerview):
		from binascii import unhexlify
		from impacket.krb5.kerberosv5 import getKerberosTGT
		from impacket.krb5 import constants
		from impacket.krb5.types import Principal

		conn = getattr(powerview, 'conn', None)
		if conn is None:
			raise ValueError('no active connection available')
		username = conn.get_username()
		if not username:
			raise ValueError('a username is required to request TGTs')

		principal = Principal(username, type=constants.PrincipalNameType.NT_PRINCIPAL.value)
		lmhash = unhexlify(conn.lmhash) if conn.lmhash else b''
		nthash = unhexlify(conn.nthash) if conn.nthash else b''
		domain = conn.get_domain()
		creds = (principal, conn.password or '', domain, lmhash, nthash, conn.auth_aes_key or '')

		tgt_with_pac, _, _, _ = getKerberosTGT(*creds, kdcHost=conn.kdcHost, requestPAC=True)
		tgt_without_pac, _, _, _ = getKerberosTGT(*creds, kdcHost=conn.kdcHost, requestPAC=False)

		if len(tgt_without_pac) < len(tgt_with_pac):
			return [self.finding(1, [domain], subject='%s gave out a ticket with no PAC' % domain)]
		return [self.finding(0, [], subject='%s looks patched' % domain)]


@register_check
class PetitPotamCheck(Check):
	id = 'petitpotam'
	code = 'PETIT'
	title = 'DC exposes the MS-EFSRPC coercion interface (PetitPotam)'
	severity = 'high'
	category = 'coercion'
	mode = 'active'
	unit = 'host'
	detail = 'The MS-EFSRPC interface is reachable on the domain controller. It can be used to force the DC to authenticate elsewhere, which is often relayed to ADCS to take over the domain.'
	remediation = 'Install the CVE-2021-36942 patch, turn on SMB signing and LDAP channel binding, and limit or disable EFS on domain controllers.'
	references = ['https://github.com/topotam/PetitPotam',
		'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942']

	_pipes = (
		('lsarpc', ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')),
		('efsrpc', ('df1941c5-fe89-4e79-bf10-463657acf44d', '1.0')),
		('netlogon', ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')),
		('samr', ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')),
		('lsass', ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')),
	)

	def run(self, powerview):
		import contextlib
		from impacket.dcerpc.v5 import transport, epm
		from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_GSS_NEGOTIATE, RPC_C_AUTHN_LEVEL_PKT_PRIVACY
		from impacket.uuid import uuidtup_to_bin

		conn = getattr(powerview, 'conn', None)
		if conn is None:
			raise ValueError('no active connection available')
		target = getattr(conn, 'targetIp', None) or getattr(conn, 'dc_ip', None) \
			or getattr(conn, 'ldap_address', None)
		if not target:
			raise ValueError('could not determine the target DC address')
		do_kerberos = bool(getattr(conn, 'use_kerberos', False))

		with contextlib.suppress(Exception):
			efs_iface = uuidtup_to_bin(('df1941c5-fe89-4e79-bf10-463657acf44d', '0.0'))
			epm_transport = transport.DCERPCTransportFactory('ncacn_ip_tcp:%s[135]' % target)
			epm_transport.set_connect_timeout(3)
			epm_dce = epm_transport.get_dce_rpc()
			epm_dce.connect()
			epm.hept_map(target, efs_iface, protocol='ncacn_ip_tcp', dce=epm_dce)
			epm_dce.disconnect()

		bound_pipe = None
		last_error = None
		for pipe, uuid in self._pipes:
			dce = None
			try:
				rpctransport = transport.DCERPCTransportFactory(
					r'ncacn_np:%s[\PIPE\%s]' % (target, pipe))
				rpctransport.set_dport(445)
				if hasattr(rpctransport, 'set_credentials'):
					rpctransport.set_credentials(
						username=conn.username, password=conn.password or '',
						domain=conn.get_domain(), lmhash=conn.lmhash or '',
						nthash=conn.nthash or '', aesKey=conn.auth_aes_key or '')
				if do_kerberos:
					rpctransport.set_kerberos(do_kerberos, kdcHost=conn.kdcHost)
				rpctransport.setRemoteHost(target)
				dce = rpctransport.get_dce_rpc()
				if do_kerberos:
					dce.set_auth_type(RPC_C_AUTHN_GSS_NEGOTIATE)
				dce.set_auth_level(RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
				dce.connect()
				dce.bind(uuidtup_to_bin(uuid))
				bound_pipe = pipe
				break
			except Exception as e:
				last_error = str(e)
			finally:
				if dce is not None:
					try:
						dce.disconnect()
					except Exception:
						pass

		if bound_pipe:
			return [self.finding(1, [r'%s (\PIPE\%s)' % (target, bound_pipe)],
				subject=r'%s EFSR reachable on \PIPE\%s' % (target, bound_pipe))]
		subject = '%s EFSR interface not reachable' % target
		if last_error:
			subject += ' (last error: %s)' % last_error
		return [self.finding(0, [], subject=subject)]


class FindingsEngine:
	def __init__(self, powerview):
		self.powerview = powerview

	def run(self, active=False):
		findings = []
		errors = []
		for check_cls in CHECK_REGISTRY:
			check = check_cls()
			if check.mode == 'active' and not active:
				continue
			try:
				findings.extend(check.run(self.powerview) or [])
			except Exception as e:
				logging.error("[FindingsEngine] check '%s' failed: %s" % (check.id, e))
				errors.append({'check': check.id, 'error': str(e)})
		findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.get('severity'), 9), -f.get('count', 0)))
		return {'findings': findings, 'errors': errors, 'active': active}
