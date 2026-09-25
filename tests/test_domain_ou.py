import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock

from powerview.powerview import PowerView

ROOT = 'DC=example,DC=test'


def make_powerview(add_result=0):
	powerview = PowerView.__new__(PowerView)
	powerview.root_dn = ROOT
	powerview.get_domainobject = MagicMock(return_value=[{'attributes': {'distinguishedName': ROOT}}])
	powerview.add_domainobjectacl = MagicMock(return_value=True)
	powerview.ldap_session = MagicMock()
	powerview.ldap_session.result = {'result': add_result, 'description': 'entryAlreadyExists' if add_result else 'success'}
	powerview.ldap_session.extend.standard.paged_search.return_value = iter([])
	return powerview


class AddDomainOUTests(unittest.TestCase):
	def test_web_call_without_args_creates_the_ou(self):
		powerview = make_powerview()
		self.assertIs(powerview.add_domainou('Staff', basedn=ROOT), True)
		dn, classes, data = powerview.ldap_session.add.call_args.args
		self.assertEqual((dn, classes, data), (f'OU=Staff,{ROOT}', ['organizationalUnit'], {'name': 'Staff'}))
		powerview.add_domainobjectacl.assert_not_called()

	def test_protection_targets_the_new_ou_by_dn(self):
		powerview = make_powerview()
		self.assertIs(powerview.add_domainou('Staff', basedn=ROOT, protected=True), True)
		powerview.add_domainobjectacl.assert_called_once_with(f'OU=Staff,{ROOT}', 'Everyone', rights='immutable', ace_type='denied')

	def test_cli_protection_flag_is_still_honoured(self):
		powerview = make_powerview()
		powerview.add_domainou('Staff', args=Namespace(identity='Staff', basedn=None, protectedfromaccidentaldeletion=True))
		powerview.add_domainobjectacl.assert_called_once()

	def test_failed_add_reports_failure_and_skips_protection(self):
		powerview = make_powerview(add_result=68)
		self.assertIs(powerview.add_domainou('Staff', basedn=ROOT, protected=True), False)
		powerview.add_domainobjectacl.assert_not_called()


class GetDomainOUTests(unittest.TestCase):
	def test_partial_args_from_the_web_are_accepted(self):
		powerview = make_powerview()
		for args in [Namespace(), Namespace(ldapfilter='(description=*)'), Namespace(gplink='31B2F340')]:
			with self.subTest(args=vars(args)):
				powerview.ldap_session.extend.standard.paged_search.return_value = iter([])
				self.assertEqual(powerview.get_domainou(args=args, properties=['name']), [])
		search_filter = powerview.ldap_session.extend.standard.paged_search.call_args.args[1]
		self.assertEqual(search_filter, '(&(objectCategory=organizationalUnit)(gplink=*31B2F340*))')


if __name__ == '__main__':
	unittest.main()
