import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from threading import Barrier

from powerview.utils.query_reads import record_query_read, track_query_reads


class QueryReadTests(unittest.TestCase):
    def test_multiple_reads_keep_oldest_time_and_any_cache_hit(self):
        now = datetime.now(timezone.utc)
        earlier = now - timedelta(minutes=10)
        with track_query_reads() as reads:
            record_query_read(now)
            record_query_read(earlier, cached=True)
            record_query_read(now)
        self.assertEqual(reads.read_at, earlier)
        self.assertTrue(reads.cached)

    def test_exception_restores_previous_scope(self):
        now = datetime.now(timezone.utc)
        with track_query_reads() as outer:
            with self.assertRaises(ValueError):
                with track_query_reads():
                    record_query_read(now, cached=True)
                    raise ValueError('failed query')
            record_query_read(now)
        self.assertEqual(outer.read_at, now)
        self.assertFalse(outer.cached)
        record_query_read(now, cached=True)
        with track_query_reads() as next_read:
            self.assertIsNone(next_read.read_at)
            self.assertFalse(next_read.cached)

    def test_concurrent_reads_have_independent_metadata(self):
        barrier = Barrier(2)
        now = datetime.now(timezone.utc)

        def read(cached):
            with track_query_reads() as reads:
                record_query_read(now - timedelta(minutes=int(cached)), cached)
                barrier.wait(timeout=5)
                return reads

        with ThreadPoolExecutor(max_workers=2) as pool:
            fresh, cached = list(pool.map(read, [False, True]))
        self.assertFalse(fresh.cached)
        self.assertTrue(cached.cached)
        self.assertEqual(fresh.read_at - cached.read_at, timedelta(minutes=1))
