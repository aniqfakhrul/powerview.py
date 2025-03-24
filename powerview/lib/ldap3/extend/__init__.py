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
from powerview.utils.vulnerabilities import VulnerabilityDetector
from powerview.utils.helpers import strip_entry

class CustomStandardExtendedOperations(StandardExtendedOperations):
	def __init__(self, connection, obfuscate=False, no_cache=False, no_vuln_check=False):
		super().__init__(connection)
		self.obfuscate = obfuscate
		self.no_cache = no_cache
		self.no_vuln_check = no_vuln_check
		self.storage = Storage()
		self.vulnerability_detector = VulnerabilityDetector(self.storage)
	
	def _format_vulnerability(self, vuln_dict):
		"""Format a vulnerability dictionary as a string"""
		vuln_id = vuln_dict.get('id', 'VULN')
		description = vuln_dict.get('description', '')
		severity = vuln_dict.get('severity', '').upper()
		formatted = f"[{vuln_id}] {description} ({severity})"
		if 'details' in vuln_dict:
			formatted += f" - {vuln_dict['details']}"
		return formatted

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
					 strip_entries=True):
		
		no_cache = no_cache or self.no_cache
		no_vuln_check = no_vuln_check or self.no_vuln_check

		if not no_cache:
			cached_results = self.storage.get_cached_results(search_base, search_filter, search_scope, attributes)
			if cached_results is not None:
				logging.debug("[CustomStandardExtendedOperations] Returning cached results for query")
				
				# Process vulnerabilities for all objects
				if not no_vuln_check:
					for entry in cached_results:
						if 'attributes' in entry:
							vulnerabilities = self.vulnerability_detector.detect_vulnerabilities(entry['attributes'])
							if vulnerabilities:
								# Convert dictionary vulnerabilities to formatted strings
								entry['attributes']['vulnerabilities'] = [self._format_vulnerability(v) for v in vulnerabilities]
				
				return cached_results
		
		modified_filter = search_filter
		modified_dn = search_base
		
		if self.obfuscate:
			parser = LdapParser(search_filter)
			tokenized_filter = parser.parse()
			parser.comparison_operator_obfuscation()
			parser.prepend_zeros()
			parser.random_wildcards()
			parser.random_hex()
			parser.boolean_operator_obfuscation()
			parser.append_garbage()
			parser.randomize_oid()
			parser.random_casing()
			parser.random_spacing()
			modified_filter = parser.convert_to_ldap()
			logging.debug("[CustomStandardExtendedOperations] Modified Filter: {}".format(modified_filter))

			dn_parser = DNParser(search_base)
			tokenized_dn = dn_parser.parse()
			dn_parser.dn_hex()
			dn_parser.dn_randomcase()
			dn_parser.random_spacing()
			modified_dn = dn_parser.convert_to_dn()
			logging.debug("[CustomStandardExtendedOperations] Modified DN: {}".format(modified_dn))

			attribute_parser = AttributeParser(attributes)
			attribute_parser.random_oid()
			attribute_parser.random_casing()
			modified_attributes = attribute_parser.get_attributes()
			logging.debug("[CustomStandardExtendedOperations] Modified Attributes: {}".format(modified_attributes))

		if generator:
			# Get all results first so we can post-process them
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
			
			# Filter out non-search results
			filtered_results = []
			for entry in results:
				if entry['type'] != 'searchResEntry':
					continue
					
				# Strip entries if requested
				if strip_entries:
					strip_entry(entry)
					
				filtered_results.append(entry)
				
			# Process vulnerabilities for all objects
			if not no_vuln_check:
				for entry in filtered_results:
					if 'attributes' in entry:
						vulnerabilities = self.vulnerability_detector.detect_vulnerabilities(entry['attributes'])
						if vulnerabilities:
							# Convert dictionary vulnerabilities to formatted strings
							entry['attributes']['vulnerabilities'] = [self._format_vulnerability(v) for v in vulnerabilities]
			
			if not no_cache:
				self.storage.cache_results(search_base, search_filter, search_scope, attributes, filtered_results)
				
			return filtered_results
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
			
			# Filter out non-search results and strip entries if requested
			filtered_results = []
			for entry in results:
				if entry['type'] != 'searchResEntry':
					continue
					
				# Strip entries if requested
				if strip_entries:
					strip_entry(entry)
					
				filtered_results.append(entry)
			
			# Process vulnerabilities for all objects
			if not no_vuln_check:
				for entry in filtered_results:
					if 'attributes' in entry:
						vulnerabilities = self.vulnerability_detector.detect_vulnerabilities(entry['attributes'])
						if vulnerabilities:
							# Convert dictionary vulnerabilities to formatted strings
							entry['attributes']['vulnerabilities'] = [self._format_vulnerability(v) for v in vulnerabilities]
			
			if not no_cache:
				self.storage.cache_results(search_base, search_filter, search_scope, attributes, filtered_results)
			
			return filtered_results

class CustomExtendedOperationsRoot(ExtendedOperationsRoot):
	def __init__(self, connection, obfuscate=False, no_cache=False, no_vuln_check=False):
		super().__init__(connection)
		self.standard = CustomStandardExtendedOperations(self._connection, obfuscate, no_cache, no_vuln_check)
