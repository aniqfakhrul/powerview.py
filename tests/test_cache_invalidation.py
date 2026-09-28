import unittest
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from powerview.lib.ldap3.extend import install_cache_invalidation
from powerview.powerview import PowerView
from powerview.utils.query_cache import QueryCache
from tests import test_cache_and_dns_names


class CacheInvalidationTests(unittest.TestCase):
	def operations(self):
		operations = test_cache_and_dns_names.PagedSearchCacheTests().make_operations()
		operations.cache = QueryCache()
		operations._connection.user = 'alice'
		return operations

	def test_write_hooks_invalidate_only_success_and_install_once(self):
		for name in ('add', 'modify', 'delete', 'modify_dn', 'set_password', 'change_password'):
			with self.subTest(name=name):
				connection = SimpleNamespace(**{name: lambda success: success})
				install_cache_invalidation(connection)
				install_cache_invalidation(connection)
				generation = QueryCache.generation()
				self.assertIs(getattr(connection, name)(False), False)
				self.assertEqual(QueryCache.generation(), generation)
				self.assertIs(getattr(connection, name)(True), True)
				self.assertEqual(QueryCache.generation(), generation + 1)

	def test_failed_write_exception_keeps_generation(self):
		def fail():
			raise RuntimeError('denied')
		connection = SimpleNamespace(modify=fail)
		install_cache_invalidation(connection)
		generation = QueryCache.generation()
		with self.assertRaises(RuntimeError):
			connection.modify()
		self.assertEqual(QueryCache.generation(), generation)

	def test_inflight_read_cannot_repopulate_invalidated_cache(self):
		operations = self.operations()
		def search(*args):
			QueryCache.invalidate_all()
			return deepcopy(test_cache_and_dns_names.FRESH)
		with patch('powerview.lib.ldap3.extend.paged_search_generator', side_effect=search) as query:
			for _ in range(2):
				operations.paged_search('DC=test', '(name=alice)', attributes=['name'])
			self.assertEqual(query.call_count, 2)

	def test_annotations_and_caller_mutations_do_not_pollute_cache(self):
		operations = self.operations()
		operations.no_vuln_check = False
		operations.vulnerability_detector = MagicMock()
		operations.vulnerability_detector.detect_vulnerabilities.return_value = [{'id': 'test', 'description': 'finding', 'severity': 'low'}]
		with patch('powerview.lib.ldap3.extend.paged_search_generator', return_value=deepcopy(test_cache_and_dns_names.FRESH)) as query:
			first = operations.paged_search('DC=test', '(name=alice)', attributes=['name'])
			self.assertIn('vulnerabilities', first[0]['attributes'])
			first[0]['attributes']['name'] = 'modified'
			second = operations.paged_search('DC=test', '(name=alice)', attributes=['name'], no_vuln_check=True)
			self.assertNotIn('vulnerabilities', second[0]['attributes'])
			self.assertEqual(second[0]['attributes']['name'], 'web01')
			self.assertEqual(query.call_count, 1)

	def test_sid_names_refresh_and_invalidate_with_directory_cache(self):
		operations = self.operations()
		view = PowerView.__new__(PowerView)
		view.root_dn = 'DC=test'
		view.flatName = 'TEST'
		view.ldap_session = SimpleNamespace(extend=SimpleNamespace(standard=operations))
		sid = 'S-1-5-21-1-2-3-1000'
		def entry(name):
			return [{'type': 'searchResEntry', 'attributes': {'sAMAccountName': name}}]
		with patch('powerview.lib.ldap3.extend.paged_search_generator', side_effect=[entry('alice'), entry('renamed'), entry('after-write')]) as query:
			self.assertEqual(view.convertfrom_sid(sid), 'TEST\\alice')
			self.assertEqual(view.convertfrom_sid(sid), 'TEST\\alice')
			self.assertEqual(view.convertfrom_sid(sid, no_cache=True), 'TEST\\renamed')
			self.assertEqual(view.convertfrom_sid(sid), 'TEST\\renamed')
			QueryCache.invalidate_all()
			self.assertEqual(view.convertfrom_sid(sid), 'TEST\\after-write')
			self.assertEqual(query.call_count, 3)

	def test_successful_write_makes_next_read_fresh(self):
		operations = self.operations()
		connection = SimpleNamespace(modify=lambda success: success)
		install_cache_invalidation(connection)
		with patch('powerview.lib.ldap3.extend.paged_search_generator', side_effect=lambda *args: deepcopy(test_cache_and_dns_names.FRESH)) as query:
			read = lambda: operations.paged_search('DC=test', '(name=alice)', attributes=['name'])
			read()
			connection.modify(False)
			self.assertTrue(read()[0]['from_cache'])
			self.assertEqual(query.call_count, 1)
			connection.modify(True)
			self.assertNotIn('from_cache', read()[0])
			self.assertEqual(query.call_count, 2)

	def test_samr_password_write_invalidates_cache(self):
		from powerview.lib.samr import SamrObject
		client = SamrObject(connection=None)
		with patch('powerview.lib.samr.samr.hSamrUnicodeChangePasswordUser2'):
			generation = QueryCache.generation()
			self.assertTrue(client.change_password(None, 'alice', 'old', 'new'))
			self.assertEqual(QueryCache.generation(), generation + 1)

	def test_safe_sync_result_is_preserved(self):
		result = (True, {'result': 0}, [], {})
		connection = SimpleNamespace(modify=lambda: result)
		install_cache_invalidation(connection)
		generation = QueryCache.generation()
		self.assertIs(connection.modify(), result)
		self.assertEqual(QueryCache.generation(), generation + 1)
