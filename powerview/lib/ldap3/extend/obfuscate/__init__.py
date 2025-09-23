#!/usr/bin/env python3

from .core import (
	LdapParserException, Operators, LdapToken, 
	AttributeParser, DNParser, FilterParser,
	WILDCARD, ATTRIBUTE_OID, EXCEPTION_ATTRIBUTES
)

from .utils import in_exception, LdapObfuscate

from .strategies import (
	oid_attribute_obfuscation, anr_attribute_obfuscation, random_casing_obfuscation,
	prepend_zeros_obfuscation, hex_value_obfuscation, spacing_obfuscation,
	equality_to_approximation_obfuscation, wildcard_expansion_obfuscation
)

class LdapParser(FilterParser):
	"""
	Extended LDAP Filter Parser with modular obfuscation strategies.
	Maintains backward compatibility while providing new modular approach.
	"""
	
	def random_casing(self, parsed_structure=None, probability=0.7):
		"""Random case obfuscation with type awareness"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		random_casing_obfuscation(parsed_structure, self._apply_to_filter_leaves, probability)

	def prepend_zeros_obfuscation(self, parsed_structure=None, max_zeros=5):
		"""Prepend zeros to numeric values and SID components"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		prepend_zeros_obfuscation(parsed_structure, self._apply_to_filter_leaves, max_zeros)

	def hex_value_obfuscation(self, parsed_structure=None, probability=0.5):
		"""Hex encode DN string values"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		hex_value_obfuscation(parsed_structure, self._apply_to_filter_leaves, probability)

	def spacing_obfuscation(self, parsed_structure=None, max_spaces=3):
		"""Add context-aware spacing to attribute values"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		spacing_obfuscation(parsed_structure, self._apply_to_filter_leaves, max_spaces)

	def oid_attribute_obfuscation(self, parsed_structure=None, max_spaces=3, max_zeros=5, include_prefix=True):
		"""Convert attributes to OIDs with spacing and zero padding"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		oid_attribute_obfuscation(parsed_structure, self._apply_to_filter_leaves, max_spaces, max_zeros, include_prefix)

	def anr_attribute_obfuscation(self, parsed_structure=None, anr_set=None):
		"""Convert compatible attributes to ANR"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		anr_attribute_obfuscation(parsed_structure, self._apply_to_filter_leaves, anr_set)

	def equality_to_approximation_obfuscation(self, parsed_structure=None):
		"""Convert equality matches to approximation matches"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		equality_to_approximation_obfuscation(parsed_structure)

	def wildcard_expansion_obfuscation(self, parsed_structure=None):
		"""Safe wildcard expansion for broader matching"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure
		wildcard_expansion_obfuscation(parsed_structure, self._apply_to_filter_leaves)

	def prepend_zeros(self, parsed_structure=None):
		"""Legacy wrapper for prepend_zeros_obfuscation"""
		self.prepend_zeros_obfuscation(parsed_structure)

	def random_hex(self, parsed_structure=None):
		"""Legacy wrapper for hex_value_obfuscation"""
		self.hex_value_obfuscation(parsed_structure)

	def random_wildcards(self, parsed_structure=None):
		"""Legacy wrapper for wildcard_expansion_obfuscation"""
		self.wildcard_expansion_obfuscation(parsed_structure)

	def randomize_oid(self, parsed_structure=None):
		"""Legacy wrapper for oid_attribute_obfuscation"""
		self.oid_attribute_obfuscation(parsed_structure)

	def comparison_operator_obfuscation(self, parsed_structure=None):
		"""Legacy wrapper for equality_to_approximation_obfuscation"""
		self.equality_to_approximation_obfuscation(parsed_structure)

	def boolean_operator_obfuscation(self, parsed_structure=None):
		"""
		Boolean operator obfuscation.
		"""
		return NotImplementedError("Boolean operator obfuscation not yet implemented")

	def append_garbage(self, parsed_structure=None):
		"""
		Append garbage method.
		"""
		return NotImplementedError("Append garbage method not yet implemented")

FilterParser = LdapParser

__all__ = [
	'FilterParser', 'LdapParser', 'DNParser', 'AttributeParser', 'LdapObfuscate',
	'LdapParserException', 'Operators', 'LdapToken', 'in_exception'
] 