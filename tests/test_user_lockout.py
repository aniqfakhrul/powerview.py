import unittest
from argparse import Namespace
from unittest.mock import MagicMock

from powerview.powerview import PowerView


def entry(name, computed):
	return {'attributes': {'name': name, 'msDS-User-Account-Control-Computed': computed}}


class LockedOutFilterTests(unittest.TestCase):
	def run_search(self, rows, **args):
		powerview = PowerView.__new__(PowerView)
		powerview.root_dn = 'DC=example,DC=test'
		powerview.args = Namespace()
		powerview.ldap_session = MagicMock()
		powerview.ldap_session.extend.standard.paged_search.return_value = iter(rows)
		result = powerview.get_domainuser(args=Namespace(**args), properties=['name'])
		call = powerview.ldap_session.extend.standard.paged_search.call_args
		return list(result), call.args[1], set(call.kwargs['attributes'])

	def test_locked_out_uses_the_computed_flag(self):
		rows = [entry('Locked', 0x10), entry('Expired', 0x800000), entry('Both', [0x810])]
		result, search_filter, attributes = self.run_search(rows, lockedout=True)
		self.assertEqual([item['attributes']['name'] for item in result], ['Locked', 'Both'])
		self.assertIn('(lockoutTime>=1)', search_filter)
		self.assertNotIn('1.2.840.113556.1.4.803:=16', search_filter)
		self.assertIn('msDS-User-Account-Control-Computed', attributes)
		self.assertNotIn('msDS-User-Account-Control-Computed', result[0]['attributes'])

	def test_other_searches_are_unchanged(self):
		result, search_filter, attributes = self.run_search([entry('Any', 0)])
		self.assertEqual(len(result), 1)
		self.assertNotIn('lockoutTime', search_filter)
		self.assertEqual(attributes, {'name'})


if __name__ == '__main__':
	unittest.main()
