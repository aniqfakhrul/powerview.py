#!/usr/bin/env python3
from ldap3.extend.standard.PagedSearch import paged_search_generator, paged_search_accumulator
from ldap3.extend import StandardExtendedOperations, ExtendedOperationsRoot
from ldap3 import SUBTREE, DEREF_ALWAYS
from .obfuscate import LDAPFilter

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
        
        print("This is the customized paged_search function")
        LDAPFilter.randomize_case(search_filter)

        if generator:
            return paged_search_generator(self._connection,
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