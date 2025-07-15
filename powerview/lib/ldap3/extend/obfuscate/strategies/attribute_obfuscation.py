#!/usr/bin/env python3
import random

from ..core.constants import (
	ATTRIBUTE_OID, WILDCARD, DEFAULT_ANR_ATTRIBUTES
)
from ..utils.helpers import in_exception, LdapObfuscate
from ..utils.validators import is_oid, randomly_prepend_zeros_oid

def oid_attribute_obfuscation(parsed_structure, transform_func, max_spaces=3, max_zeros=5, include_prefix=True):
	"""
	OID attribute obfuscation following Go OIDAttributeFilterObf pattern.
	Converts attributes to OIDs with spacing, zero padding, and OID prefix.
	"""
	def obfuscate_oid_attribute(attr, operator, value):
		if in_exception(attr):
			return attr, value
		
		attr_name = attr
		oid = ATTRIBUTE_OID.get(attr)
		if oid:
			attr_name = oid
		
		if is_oid(attr_name):
			if max_spaces > 0:
				spaces = ' ' * random.randint(1, max_spaces)
				attr_name += spaces
			
			if max_zeros > 0:
				attr_name = randomly_prepend_zeros_oid(attr_name, max_zeros)
			
			if include_prefix and not attr_name.lower().startswith("oid."):
				attr_name = "oID." + attr_name
		
		return attr_name, value

	transform_func(parsed_structure, obfuscate_oid_attribute)

def anr_attribute_obfuscation(parsed_structure, transform_func, anr_set=None):
	"""
	ANR attribute obfuscation following Go ANRAttributeFilterObf pattern.
	Converts specified attributes to ANR (Ambiguous Name Resolution).
	"""
	if anr_set is None:
		anr_set = DEFAULT_ANR_ATTRIBUTES
	
	anr_set_lower = [attr.lower() for attr in anr_set]

	def obfuscate_anr_attribute(attr, operator, value):
		if attr.lower() in anr_set_lower:
			if WILDCARD in value:
				return attr, value
			
			if in_exception(attr):
				return attr, value
			
			if operator in ['=', '~=']:
				return LdapObfuscate.random_anr_casing(), value
		return attr, value

	transform_func(parsed_structure, obfuscate_anr_attribute)

def random_casing_obfuscation(parsed_structure, transform_func, probability=0.7):
	"""
	Random case obfuscation following Go RandCaseFilterObf pattern.
	Applies case randomization to attributes and values with type awareness.
	"""
	def obfuscate_case(attr, operator, value):
		if in_exception(attr):
			return attr, value
		
		if attr.lower() in ['objectsid', 'sid', 'msds-allowedtoactonbehalfofotheridentity'] and value and not value.startswith("S-"):
			return attr, value
		
		if value == WILDCARD or LdapObfuscate.is_number(value):
			return attr, value
			
		obf_attr = LdapObfuscate.random_case_string(attr, probability)
		obf_value = LdapObfuscate.random_case_string(value, probability)
		
		return obf_attr, obf_value

	transform_func(parsed_structure, obfuscate_case) 