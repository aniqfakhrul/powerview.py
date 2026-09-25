import unittest
from argparse import Namespace
from unittest.mock import MagicMock

from powerview.powerview import PowerView

ROOT = 'DC=example,DC=test'
POLICIES = f'CN=Policies,CN=System,{ROOT}'
GPO_DN = f'CN={{AAAA}},{POLICIES}'
OU_DN = f'OU=Staff,{ROOT}'


def make_powerview(add_result=0):
	powerview = PowerView.__new__(PowerView)
	powerview.root_dn = ROOT
	powerview.domain = 'example.test'
	powerview.use_kerberos = True
	powerview.args = Namespace(debug=False)
	powerview.get_domainobject = MagicMock(return_value=[{'attributes': {'distinguishedName': POLICIES}}])
	powerview.get_domaincontroller = MagicMock(return_value=[{'attributes': {'dnsHostName': 'dc.example.test'}}])
	powerview.set_domainobject = MagicMock(return_value=True)
	powerview.add_gplink = MagicMock(return_value=True)
	powerview.smb = MagicMock()
	powerview.conn = MagicMock()
	powerview.conn.init_smb_session.return_value = powerview.smb
	powerview.ldap_session = MagicMock()
	powerview.ldap_session.result = {'result': add_result, 'description': 'constraintViolation' if add_result else 'success'}
	powerview.ldap_session.extend.standard.paged_search.return_value = iter([])
	return powerview


class AddDomainGPOTests(unittest.TestCase):
	def test_web_call_without_args_creates_the_gpo(self):
		powerview = make_powerview()
		self.assertIs(powerview.add_domaingpo('Staff Policy'), True)
		dn, classes, data = powerview.ldap_session.add.call_args.args
		self.assertTrue(dn.startswith('CN={') and dn.endswith(POLICIES))
		self.assertEqual(data['displayName'], 'Staff Policy')
		written = powerview.smb.writeFile.call_args.args[2]
		self.assertEqual(written, b'[General]\r\nVersion=0\r\n')
		powerview.add_gplink.assert_not_called()
		powerview.set_domainobject.assert_not_called()

	def test_description_and_link_follow_a_successful_add(self):
		powerview = make_powerview()
		self.assertIs(powerview.add_domaingpo('Staff Policy', description='For staff', linkto=OU_DN), True)
		dn = powerview.ldap_session.add.call_args.args[0]
		self.assertEqual(powerview.ldap_session.add.call_args.args[2]['description'], 'For staff')
		powerview.set_domainobject.assert_not_called()
		powerview.add_gplink.assert_called_once()
		self.assertEqual(powerview.add_gplink.call_args.kwargs['targetidentity'], OU_DN)

	def test_unicode_name_and_literal_description_are_created_together(self):
		powerview = make_powerview()
		self.assertIs(powerview.add_domaingpo('日本語 Policy', description='@Helpdesk'), True)
		data = powerview.ldap_session.add.call_args.args[2]
		self.assertEqual(data['displayName'], '日本語 Policy')
		self.assertEqual(data['description'], '@Helpdesk')
		powerview.set_domainobject.assert_not_called()
		# Exercise the SMB serializer rather than letting MagicMock accept any text.
		from impacket.smb3structs import SMB2Write
		packet = SMB2Write()
		packet['FileID'] = b'\0' * 16
		packet['Buffer'] = powerview.smb.writeFile.call_args.args[2]
		self.assertIn(b'[General]\r\nVersion=0', packet.getData())

	def test_cli_link_option_is_still_honoured(self):
		powerview = make_powerview()
		powerview.add_domaingpo('Staff Policy', args=Namespace(identity='Staff Policy', linkto=OU_DN))
		powerview.add_gplink.assert_called_once()

	def test_failed_add_removes_the_sysvol_folder(self):
		powerview = make_powerview(add_result=19)
		self.assertIs(powerview.add_domaingpo('Staff Policy', linkto=OU_DN), False)
		powerview.smb.deleteFile.assert_called_once()
		self.assertEqual(powerview.smb.deleteDirectory.call_count, 3)
		powerview.add_gplink.assert_not_called()


class GPLinkTests(unittest.TestCase):
	def linker(self, existing):
		powerview = make_powerview()
		powerview.get_domaingpo = MagicMock(return_value=[{'attributes': {'distinguishedName': GPO_DN, 'name': '{AAAA}'}}])
		powerview.get_domainobject = MagicMock(return_value=[{'attributes': {'distinguishedName': OU_DN, 'gPLink': existing}}])
		return powerview

	def test_add_reads_the_target_fresh_and_appends(self):
		powerview = self.linker(f'[LDAP://cn={{BBBB}},{POLICIES.lower()};0]')
		self.assertIs(PowerView.add_gplink(powerview, '{AAAA}', OU_DN, enforced='Yes'), True)
		self.assertIs(powerview.get_domainobject.call_args.kwargs['no_cache'], True)
		value = powerview.set_domainobject.call_args.kwargs['_set']['value'][0]
		self.assertEqual(value, f'[LDAP://cn={{BBBB}},{POLICIES.lower()};0][LDAP://{GPO_DN};2]')

	def test_add_detects_an_existing_link_regardless_of_case(self):
		powerview = self.linker(f'[LDAP://{GPO_DN.lower()};0]')
		self.assertIs(PowerView.add_gplink(powerview, '{AAAA}', OU_DN), False)
		powerview.set_domainobject.assert_not_called()

	def test_remove_keeps_other_links(self):
		powerview = self.linker(f'[LDAP://cn={{BBBB}},{POLICIES};0][LDAP://{GPO_DN.lower()};2]')
		self.assertIs(PowerView.remove_gplink(powerview, '{aaaa}', OU_DN), True)
		self.assertIs(powerview.get_domainobject.call_args.kwargs['no_cache'], True)
		self.assertEqual(powerview.set_domainobject.call_args.kwargs['_set']['value'], [f'[LDAP://cn={{BBBB}},{POLICIES};0]'])

	def test_missing_gpo_returns_false(self):
		powerview = self.linker('')
		powerview.get_domaingpo = MagicMock(return_value=[])
		self.assertIs(PowerView.remove_gplink(powerview, '{AAAA}', OU_DN), False)
		self.assertIs(PowerView.add_gplink(powerview, '{AAAA}', OU_DN), False)


class GetDomainGPOTests(unittest.TestCase):
	def test_partial_args_from_the_web_are_accepted(self):
		powerview = make_powerview()
		for args in [Namespace(), Namespace(ldapfilter='(flags=0)')]:
			with self.subTest(args=vars(args)):
				powerview.ldap_session.extend.standard.paged_search.return_value = iter([])
				list(powerview.get_domaingpo(args=args, properties=['name']))
		self.assertEqual(powerview.ldap_session.extend.standard.paged_search.call_args.args[1], '(&(objectCategory=groupPolicyContainer)(flags=0))')


if __name__ == '__main__':
	unittest.main()
