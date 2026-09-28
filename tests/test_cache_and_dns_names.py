import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from powerview.lib.ldap3.extend import CustomStandardExtendedOperations
from powerview.lib.dns import DNS_UTIL

BASE = 'DC=example.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=test'
FRESH = [{'type': 'searchResEntry', 'dn': f'DC=web01,{BASE}', 'attributes': {'name': 'web01'}}]
STALE = [{'dn': f'DC=old,{BASE}', 'attributes': {'name': 'old'}}]


class PagedSearchCacheTests(unittest.TestCase):
	def make_operations(self, global_no_cache=False):
		operations = CustomStandardExtendedOperations.__new__(CustomStandardExtendedOperations)
		operations._connection = MagicMock()
		operations.cache_namespace = 'test-session'
		operations.server = SimpleNamespace(host='dc.example.test')
		operations.obfuscate = False
		operations.no_cache = global_no_cache
		operations.no_vuln_check = True
		operations.use_adws = False
		operations.raw = False
		operations.storage = MagicMock()
		operations.storage.get_cached_results.return_value = [dict(entry) for entry in STALE]
		return operations

	def search(self, operations, **kwargs):
		with patch('powerview.lib.ldap3.extend.paged_search_generator', return_value=iter([dict(entry) for entry in FRESH])):
			return operations.paged_search(BASE, '(objectClass=dnsNode)', attributes=['name'], **kwargs)

	def test_cached_read_returns_cache_without_querying(self):
		operations = self.make_operations()
		self.assertEqual(self.search(operations)[0]['dn'], STALE[0]['dn'])
		operations.storage.cache_results.assert_not_called()

	def test_per_request_no_cache_skips_read_and_refreshes_cache(self):
		operations = self.make_operations()
		results = self.search(operations, no_cache=True)
		self.assertEqual([entry['dn'] for entry in results], [FRESH[0]['dn']])
		operations.storage.get_cached_results.assert_not_called()
		operations.storage.cache_results.assert_called_once()
		self.assertEqual(operations.storage.cache_results.call_args.kwargs['results'], results)

	def test_global_no_cache_never_touches_cache(self):
		operations = self.make_operations(global_no_cache=True)
		self.search(operations)
		operations.storage.get_cached_results.assert_not_called()
		operations.storage.cache_results.assert_not_called()


class RelativeDnsNameTests(unittest.TestCase):
	def test_strips_zone_only_at_label_boundary(self):
		cases = [
			('web01', 'web01'),
			('web01.example.test', 'web01'),
			('WEB01.Example.Test.', 'WEB01'),
			('myexample.test', 'myexample.test'),
			('a.b.example.test', 'a.b'),
			('example.test', ''),
			('Example.Test.', ''),
			('  ', ''),
		]
		for name, expected in cases:
			with self.subTest(name=name):
				self.assertEqual(DNS_UTIL.relative_name(name, 'example.test'), expected)


	def test_recognises_dns_node_distinguished_names(self):
		self.assertTrue(DNS_UTIL.is_node_dn('DC=web01,DC=example.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=test'))
		self.assertTrue(DNS_UTIL.is_node_dn('dc=@,dc=example.test,cn=MicrosoftDNS,CN=System,DC=example,DC=test'))
		for value in ['web01', 'CN=Users,DC=example,DC=test', 'DC=example,DC=test', '', None]:
			with self.subTest(value=value):
				self.assertFalse(DNS_UTIL.is_node_dn(value))

	def test_lists_a_records_with_their_index_and_address(self):
		stored = [DNS_UTIL.new_record(1, 1, '10.0.0.1').getData(), DNS_UTIL.new_record(1, 1, '10.0.0.2').getData()]
		stored[0] = stored[0][:2] + (28).to_bytes(2, 'little') + stored[0][4:]
		self.assertEqual([(index, address) for index, _, address in DNS_UTIL.a_records(stored)], [(1, '10.0.0.2')])


if __name__ == '__main__':
	unittest.main()
