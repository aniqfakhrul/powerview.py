#!/usr/bin/env python3
import hashlib
import json
import sys
from collections import OrderedDict
from collections.abc import Mapping
from copy import deepcopy
from threading import RLock
from time import monotonic
from weakref import WeakSet


class QueryCache:
    _lock = RLock()
    _generation = 0
    _instances = WeakSet()

    def __init__(self, max_entries=256, max_bytes=64 * 1024 * 1024, cache_ttl=1800, clock=monotonic):
        self.max_entries = max_entries
        self.max_bytes = max_bytes
        self.cache_ttl = cache_ttl
        self._clock = clock
        self._entries = OrderedDict()
        self._bytes = 0
        with self._lock:
            self._instances.add(self)

    @classmethod
    def generation(cls):
        with cls._lock:
            return cls._generation

    @classmethod
    def invalidate_all(cls):
        with cls._lock:
            cls._generation += 1
            for cache in cls._instances:
                cache._entries.clear()
                cache._bytes = 0
        return True

    def _generate_cache_key(self, search_base, search_filter, search_scope, attributes, host, raw=False, cache_context=None):
        attributes = [attributes] if isinstance(attributes, str) else attributes
        query = [search_base, search_filter, search_scope, sorted(attributes) if attributes else None, host.lower(), raw, cache_context]
        return hashlib.sha256(json.dumps(query, sort_keys=True).encode()).hexdigest()

    def _result_size(self, value, seen=None):
        seen = set() if seen is None else seen
        if id(value) in seen:
            return 0
        seen.add(id(value))
        size = sys.getsizeof(value)
        if isinstance(value, Mapping):
            size += sum(self._result_size(key, seen) + self._result_size(item, seen) for key, item in value.items())
        elif isinstance(value, (list, tuple, set, frozenset)):
            size += sum(self._result_size(item, seen) for item in value)
        return size

    def _remove(self, key):
        self._bytes -= self._entries.pop(key)[2]

    def put(self, search_base, search_filter, search_scope, attributes, host, results, raw=False, cache_context=None, generation=None):
        generation = self.generation() if generation is None else generation
        key = self._generate_cache_key(search_base, search_filter, search_scope, attributes, host, raw, cache_context)
        size = self._result_size(results) + sys.getsizeof(key)
        with self._lock:
            if generation != self._generation:
                return
            if key in self._entries:
                self._remove(key)
            if self.max_entries <= 0 or size > self.max_bytes:
                return
            now = self._clock()
            for expired in [key for key, (created, _, _) in self._entries.items() if now - created >= self.cache_ttl]:
                self._remove(expired)
            while self._entries and (len(self._entries) >= self.max_entries or self._bytes + size > self.max_bytes):
                self._remove(next(iter(self._entries)))
            self._entries[key] = (now, deepcopy(results), size)
            self._bytes += size

    def get(self, search_base, search_filter, search_scope, attributes, host, raw=False, cache_context=None, generation=None):
        key = self._generate_cache_key(search_base, search_filter, search_scope, attributes, host, raw, cache_context)
        with self._lock:
            if generation is not None and generation != self._generation:
                return None
            entry = self._entries.get(key)
            if entry is None:
                return None
            created, results, _ = entry
            if self._clock() - created >= self.cache_ttl:
                self._remove(key)
                return None
            self._entries.move_to_end(key)
            return deepcopy(results)
