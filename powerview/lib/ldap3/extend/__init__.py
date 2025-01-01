#!/usr/bin/env python3
from ldap3.extend.standard.PagedSearch import paged_search_generator, paged_search_accumulator
from ldap3.extend import StandardExtendedOperations, ExtendedOperationsRoot
from ldap3 import SUBTREE, DEREF_ALWAYS
from .obfuscate import (
	LdapParser,
	DNParser,
	AttributeParser,
	LdapObfuscate
)

import logging
from powerview.utils.storage import Storage

class CustomStandardExtendedOperations(StandardExtendedOperations):
	def __init__(self, connection, obfuscate=False, no_cache=False):
		super().__init__(connection)
		self.obfuscate = obfuscate
		self.no_cache = no_cache
		self.storage = Storage()

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
					 no_cache=False):
		
		no_cache = no_cache or self.no_cache

		if not no_cache:
			cached_results = self.storage.get_cached_results(search_base, search_filter, search_scope, attributes)
			if cached_results is not None:
				logging.debug("[CustomStandardExtendedOperations] Returning cached results for query")
				if generator:
					# Return a generator that yields each cached result
					return (entry for entry in cached_results)
				return cached_results
		
		modified_filter = search_filter
		modified_dn = search_base
		
		if self.obfuscate:
			parser = LdapParser(search_filter)
			tokenized_filter = parser.parse()
			#pprint(tokenized_filter)
			#parser.modify_token("Value", "admin", "modifiedSamAccountName")
			parser.comparison_operator_obfuscation()
			parser.prepend_zeros()
			parser.random_wildcards()
			parser.random_hex()
			parser.boolean_operator_obfuscation()
			parser.append_garbage()
			parser.randomize_oid()
			parser.random_casing()
			parser.random_spacing()
			#pprint(parser.get_parsed_structure())
			modified_filter = parser.convert_to_ldap()
			logging.debug("[CustomStandardExtendedOperations] Modified Filter: {}".format(modified_filter))

			dn_parser = DNParser(search_base)
			tokenized_dn = dn_parser.parse()
			dn_parser.dn_hex()
			dn_parser.dn_randomcase()
			dn_parser.random_spacing()
			#dn_parser.dn_random_oid()
			modified_dn = dn_parser.convert_to_dn()
			logging.debug("[CustomStandardExtendedOperations] Modified DN: {}".format(modified_dn))
			#pprint(modified_dn)

			attribute_parser = AttributeParser(attributes)
			attribute_parser.random_oid()
			attribute_parser.random_casing()
			modified_attributes = attribute_parser.get_attributes()
			logging.debug("[CustomStandardExtendedOperations] Modified Attributes: {}".format(modified_attributes))

		if generator:
			results = list(paged_search_generator(self._connection,
										  modified_dn,
										  modified_filter,
										  search_scope,
										  dereference_aliases,
										  attributes,
										  size_limit,
										  time_limit,
										  types_only,
										  get_operational_attributes,
										  controls,
										  paged_size,
										  paged_criticality))
			
			if not no_cache:
				self.storage.cache_results(search_base, search_filter, search_scope, attributes, results)
			return results
		else:
			results = list(paged_search_accumulator(self._connection,
											search_base,
											search_filter,
											search_scope,
											dereference_aliases,
											attributes,
											size_limit,
											time_limit,
											types_only,
											get_operational_attributes,
											controls,
											paged_size,
											paged_criticality))
			
			if not no_cache:
				self.storage.cache_results(search_base, search_filter, search_scope, attributes, results)
			
			return results

class CustomExtendedOperationsRoot(ExtendedOperationsRoot):
	def __init__(self, connection, obfuscate=False, no_cache=False):
		super().__init__(connection)
		self.standard = CustomStandardExtendedOperations(self._connection, obfuscate, no_cache)
