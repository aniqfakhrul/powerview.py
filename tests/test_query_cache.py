import os
import tempfile
import unittest
from unittest.mock import patch

from powerview.utils.query_cache import QueryCache

QUERY = ('DC=example,DC=test', '(objectClass=user)', 'SUBTREE', ['name'], 'dc.example.test')


class QueryCacheTests(unittest.TestCase):
	def setUp(self):
		self.home = tempfile.TemporaryDirectory()
		self.addCleanup(self.home.cleanup)
		patcher = patch('os.path.expanduser', return_value=self.home.name)
		patcher.start()
		self.addCleanup(patcher.stop)
		self.now = [1000.0]

	def cache(self, **kwargs):
		return QueryCache(clock=lambda: self.now[0], **kwargs)

	def test_results_are_copied_in_and_out(self):
		cache = self.cache()
		results = [{'attributes': {'name': 'alice'}}]
		cache.put(*QUERY, results=results)
		results[0]['attributes']['name'] = 'changed'
		first = cache.get(*QUERY)
		first[0]['attributes']['name'] = 'mutated'
		self.assertEqual(cache.get(*QUERY), [{'attributes': {'name': 'alice'}}])

	def test_entries_expire(self):
		cache = self.cache(cache_ttl=60)
		cache.put(*QUERY, results=[1])
		self.now[0] += 59
		self.assertEqual(cache.get(*QUERY), [1])
		self.now[0] += 1
		self.assertIsNone(cache.get(*QUERY))

	def test_lru_eviction_preserves_recently_read_entry(self):
		cache = self.cache(max_entries=2)
		for name in ('first', 'second'):
			cache.put(*QUERY, results=[name], cache_context=name)
		cache.get(*QUERY, cache_context='first')
		cache.put(*QUERY, results=['third'], cache_context='third')
		self.assertIsNone(cache.get(*QUERY, cache_context='second'))
		self.assertEqual(cache.get(*QUERY, cache_context='first'), ['first'])

	def test_byte_limit_evicts_entries_and_rejects_oversized_refresh(self):
		cache = self.cache(max_bytes=300)
		cache.put(*QUERY, results=['a'], cache_context='a')
		cache.put(*QUERY, results=['b'], cache_context='b')
		self.assertIsNone(cache.get(*QUERY, cache_context='a'))
		self.assertEqual(cache.get(*QUERY, cache_context='b'), ['b'])
		cache.put(*QUERY, results=['x' * 1000], cache_context='b')
		self.assertIsNone(cache.get(*QUERY, cache_context='b'))

	def test_filter_values_remain_case_sensitive(self):
		cache = self.cache()
		query = list(QUERY)
		query[1] = '(name=Alice)'
		cache.put(*query, results=['Alice'])
		query[1] = '(name=alice)'
		self.assertIsNone(cache.get(*query))

	def test_clear_invalidates_all_instances_and_inflight_generation(self):
		first, second = self.cache(), self.cache()
		generation = QueryCache.generation()
		for cache in (first, second):
			cache.put(*QUERY, results=['old'])
		self.assertTrue(first.invalidate_all())
		second.put(*QUERY, results=['stale'], generation=generation)
		for cache in (first, second):
			self.assertIsNone(cache.get(*QUERY))

	def test_no_query_files_are_created(self):
		cache = self.cache()
		cache.put(*QUERY, results=['sensitive'])
		cache.get(*QUERY)
		self.assertEqual(os.listdir(self.home.name), [])

	def test_concurrent_reads_writes_and_clears(self):
		from concurrent.futures import ThreadPoolExecutor
		cache = self.cache(max_entries=8)
		def work(index):
			for _ in range(20):
				generation = QueryCache.generation()
				cache.put(*QUERY, results=[index], cache_context=index, generation=generation)
				result = cache.get(*QUERY, cache_context=index)
				self.assertIn(result, (None, [index]))
				if index % 3 == 0:
					cache.invalidate_all()
		with ThreadPoolExecutor(max_workers=8) as executor:
			list(executor.map(work, range(8)))
