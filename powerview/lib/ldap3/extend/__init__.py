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
from pprint import pprint

class CustomStandardExtendedOperations(StandardExtendedOperations):
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
					 generator=True):
		
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
		logging.debug("Modified Filter: {}".format(modified_filter))

		dn_parser = DNParser(search_base)
		tokenized_dn = dn_parser.parse()
		dn_parser.dn_hex()
		dn_parser.dn_randomcase()
		dn_parser.random_spacing()
		#dn_parser.dn_random_oid()
		mofidied_dn = dn_parser.convert_to_dn()
		logging.debug("Modified DN: {}".format(mofidied_dn))
		#pprint(mofidied_dn)

		attribute_parser = AttributeParser(attributes)
		attribute_parser.random_oid()
		attribute_parser.random_casing()
		modified_attributes = attribute_parser.get_attributes()
		logging.debug("Modified Attributes: {}".format(modified_attributes))

		if generator:
			return paged_search_generator(self._connection,
										  mofidied_dn,
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
										  paged_criticality)
		else:
			return paged_search_accumulator(self._connection,
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
											paged_criticality)

class CustomExtendedOperationsRoot(ExtendedOperationsRoot):
	def __init__(self, connection):
		super().__init__(connection)
		self.standard = CustomStandardExtendedOperations(self._connection)