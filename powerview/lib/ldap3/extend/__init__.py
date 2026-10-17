#!/usr/bin/env python3
from ldap3.extend.standard.PagedSearch import paged_search_generator, paged_search_accumulator
from powerview.lib.adws.extend.standard.PagedSearch import adws_paged_search_generator, adws_paged_search_accumulator
from ldap3.extend import StandardExtendedOperations, ExtendedOperationsRoot
from ldap3 import SUBTREE, DEREF_ALWAYS

import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from uuid import uuid4
from ldap3.protocol.convert import build_controls_list
from pyasn1.codec.ber.encoder import encode
from powerview.utils.query_cache import QueryCache
from powerview.utils.query_reads import record_query_read
from powerview.utils.session import session_locked
from powerview.modules.vulnerabilities import VulnerabilityDetector
from powerview.utils.helpers import strip_entry
from powerview.utils.hints import patch_ldap3_exceptions

# Patch ldap3's LDAPOperationResult to include error hints
patch_ldap3_exceptions()

def invalidate_on_success(operation):
	@wraps(operation)
	def wrapped(*args, **kwargs):
		try:
			result = operation(*args, **kwargs)
		except KeyboardInterrupt:
			QueryCache.invalidate_all()
			raise
		if result is True or (isinstance(result, tuple) and result and result[0] is True):
			QueryCache.invalidate_all()
		return result
	wrapped._powerview_cache_invalidation = True
	return wrapped


def install_cache_invalidation(connection):
	for name in ('add', 'modify', 'delete', 'modify_dn', 'set_password', 'change_password'):
		operation = getattr(connection, name, None)
		if callable(operation) and not getattr(operation, '_powerview_cache_invalidation', False):
			setattr(connection, name, invalidate_on_success(operation))


class CustomStandardExtendedOperations(StandardExtendedOperations):
	def __init__(self, connection, server=None, no_cache=False, no_vuln_check=False, use_adws=False, raw=False):
		super().__init__(connection)
		self.server = server
		self.no_cache = no_cache
		self.no_vuln_check = no_vuln_check
		self.use_adws = use_adws
		self.raw = raw
		if '_powerview_query_cache' not in vars(connection):
			connection._powerview_query_cache = (uuid4().hex, QueryCache())
		self.cache_namespace, self.cache = connection._powerview_query_cache
		install_cache_invalidation(connection)
		self.vulnerability_detector = VulnerabilityDetector()
	
	def _format_vulnerability(self, vuln_dict):
		"""Format a vulnerability dictionary as a string"""
		vuln_id = vuln_dict.get('id', 'VULN')
		description = vuln_dict.get('description', '')
		sev_colored = vuln_dict.get('severity_colored')
		if sev_colored:
			formatted = f"[{vuln_id}] {description} ({sev_colored})"
		else:
			severity = vuln_dict.get('severity', '').upper()
			formatted = f"[{vuln_id}] {description} ({severity})"
		if 'details' in vuln_dict:
			formatted += f" - {vuln_dict['details']}"
		return formatted

	@session_locked
	def paged_search(self,
					 search_base,
					 search_filter,
					 search_scope=SUBTREE,
					 dereference_aliases=DEREF_ALWAYS,
					 attributes=None,
					 size_limit=0,
					 time_limit=0,
					 types_only=False,
					 get_operational_attributes=False,
					 controls=None,
					 paged_size=100,
					 paged_criticality=False,
					 generator=True,
					 no_cache=False,
					 no_vuln_check=False,
					 strip_entries=True,
					 raw=False):
		
		skip_cache_read = no_cache or self.no_cache
		no_vuln_check = no_vuln_check or self.no_vuln_check
		raw = raw or self.raw

		generation = QueryCache.generation()
		cache_context = {
			'session': self.cache_namespace,
			'user': str(getattr(self._connection, 'user', '')),
			'controls': encode(build_controls_list(controls)).hex() if controls else None,
			'options': [dereference_aliases, size_limit, time_limit, types_only, get_operational_attributes, strip_entries, paged_size, paged_criticality],
		}

		original_formatter = None
		if raw and self.server and hasattr(self.server, 'custom_formatter'):
			logging.debug("[CustomStandardExtendedOperations] Unsetting custom formatter")
			original_formatter = self.server.custom_formatter
			self.server.custom_formatter = None

		try:
			if not skip_cache_read:
				cached = self.cache.lookup(search_base, search_filter, search_scope, attributes, host=self.server.host, raw=raw, cache_context=cache_context, generation=generation)
				if cached is not None:
					logging.debug("[CustomStandardExtendedOperations] Returning cached results for query")
					age, cached_results = cached
					read_at = datetime.now(timezone.utc) - timedelta(seconds=age)
					record_query_read(read_at, cached=True)
					read_at = read_at.isoformat()
					for entry in cached_results:
						if 'attributes' in entry:
							entry['from_cache'] = True
							entry['read_at'] = read_at
					
					if not no_vuln_check:
						for entry in cached_results:
							if 'attributes' in entry:
								vulnerabilities = self.vulnerability_detector.detect_vulnerabilities(entry['attributes'])
								if vulnerabilities:
									entry['attributes']['vulnerabilities'] = [self._format_vulnerability(v) for v in vulnerabilities]
					
					return cached_results
			
			requested_attributes = tuple(attributes) if isinstance(attributes, list) else attributes
			read_at = datetime.now(timezone.utc)
			if generator:
				if self.use_adws:
					results = list(adws_paged_search_generator(self._connection, search_base, search_filter, search_scope, requested_attributes, size_limit, time_limit, types_only, get_operational_attributes, controls, paged_size, paged_criticality))
				else:
					results = list(paged_search_generator(self._connection,
												search_base,
												search_filter,
												search_scope,
												dereference_aliases,
												requested_attributes,
												size_limit,
												time_limit,
												types_only,
												get_operational_attributes,
												controls,
												paged_size,
												paged_criticality))
			else:
				if self.use_adws:
					results = list(adws_paged_search_accumulator(
						self._connection,
						search_base,
						search_filter,
						search_scope,
						requested_attributes,
						size_limit,
						time_limit,
						types_only,
						get_operational_attributes,
						controls,
						paged_size,
						paged_criticality
					))
				else:
					results = list(paged_search_accumulator(
						self._connection,
						search_base,
						search_filter,
						search_scope,
						dereference_aliases,
						requested_attributes,
						size_limit,
						time_limit,
						types_only,
						get_operational_attributes,
						controls,
						paged_size,
						paged_criticality
					))

			filtered_results = []
			for entry in results:
				if entry.get('type') != 'searchResEntry':
					continue

				if strip_entries:
					strip_entry(entry)

				filtered_results.append(entry)

			if not self.no_cache:
				for entry in filtered_results:
					if 'attributes' in entry and 'from_cache' in entry['attributes']:
						del entry['attributes']['from_cache']

				self.cache.put(search_base, search_filter, search_scope, attributes, host=self.server.host, results=filtered_results, raw=raw, cache_context=cache_context, generation=generation)

			if not no_vuln_check:
				for entry in filtered_results:
					if 'attributes' in entry:
						vulnerabilities = self.vulnerability_detector.detect_vulnerabilities(entry['attributes'])
						if vulnerabilities:
							entry['attributes']['vulnerabilities'] = [self._format_vulnerability(v) for v in vulnerabilities]
			record_query_read(read_at)
			return filtered_results
		finally:
			if raw and original_formatter is not None and self.server:
				self.server.custom_formatter = original_formatter

class CustomExtendedOperationsRoot(ExtendedOperationsRoot):
	def __init__(self, connection, server=None, no_cache=False, no_vuln_check=False, use_adws=False, raw=False):
		super().__init__(connection)
		self.standard = CustomStandardExtendedOperations(
			self._connection,
			server=server,
			no_cache=no_cache,
			no_vuln_check=no_vuln_check,
			use_adws=use_adws,
			raw=raw,
		)
