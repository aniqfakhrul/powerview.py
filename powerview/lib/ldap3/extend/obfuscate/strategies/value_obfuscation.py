#!/usr/bin/env python3

from ..utils.helpers import in_exception, LdapObfuscate
from ..utils.validators import (
	is_sid_attribute, is_dn_attribute, randomly_hex_encode_dn_string
)

def prepend_zeros_obfuscation(parsed_structure, transform_func, max_zeros=5):
	"""
	Prepend zeros obfuscation following Go RandPrependZerosFilterObf pattern.
	Adds leading zeros to numeric values and SID components.
	"""
	def obfuscate_prepend_zeros(attr, operator, value):
		if in_exception(attr):
			return attr, value
		
		if LdapObfuscate.is_number(value):
			return attr, LdapObfuscate.prepend_zeros_to_number(value, max_zeros)
		
		if is_sid_attribute(attr) and value.startswith("S-"):
			return attr, LdapObfuscate.prepend_zeros_to_sid(value, max_zeros)
		
		return attr, value

	transform_func(parsed_structure, obfuscate_prepend_zeros)

def hex_value_obfuscation(parsed_structure, transform_func, probability=0.5):
	"""
	Hex value obfuscation following Go RandHexValueFilterObf pattern.
	Applies hex encoding to DN string values.
	"""
	def obfuscate_hex_value(attr, operator, value):
		if in_exception(attr) or value == "*":
			return attr, value
		
		if is_dn_attribute(attr):
			return attr, randomly_hex_encode_dn_string(value, probability)
		
		return attr, value

	transform_func(parsed_structure, obfuscate_hex_value)

def spacing_obfuscation(parsed_structure, transform_func, max_spaces=3):
	"""
	Spacing obfuscation following Go RandSpacingFilterObf pattern.
	Adds context-aware spacing to attribute values.
	"""
	def obfuscate_spacing(attr, operator, value):
		if in_exception(attr):
			return attr, value
		
		if attr.lower() == "anr":
			return attr, LdapObfuscate.add_spacing_to_value(value, "anr", max_spaces)
		elif is_dn_attribute(attr):
			return attr, LdapObfuscate.add_spacing_to_value(value, "dn", max_spaces)
		elif is_sid_attribute(attr):
			return attr, LdapObfuscate.add_spacing_to_value(value, "sid", max_spaces)
		
		return attr, value

	transform_func(parsed_structure, obfuscate_spacing) 