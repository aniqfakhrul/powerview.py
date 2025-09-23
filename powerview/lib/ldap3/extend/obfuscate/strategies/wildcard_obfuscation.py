#!/usr/bin/env python3
import random

from ..core.constants import (
	WILDCARD, EXACT_MATCH_ATTRIBUTES, WILDCARD_SAFE_ATTRIBUTES
)
from ..utils.helpers import in_exception, LdapObfuscate
from ..utils.validators import is_sid_attribute

def wildcard_expansion_obfuscation(parsed_structure, transform_func):
	"""
	Expand wildcards with additional characters for evasion.
	Following pattern of safe wildcard transformations.
	"""
	def obfuscate_wildcards(attr, operator, value):
		if in_exception(attr) or value == WILDCARD:
			return attr, value
		
		if LdapObfuscate.is_number(value):
			return attr, value
		
		if attr.lower() in EXACT_MATCH_ATTRIBUTES:
			return attr, value
			
		if is_sid_attribute(attr):
			return attr, value
		
		if operator == "=" and value and WILDCARD not in value:
			if attr.lower() in WILDCARD_SAFE_ATTRIBUTES:
				if random.choice([True, False]):
					if random.choice([True, False]):
						value = WILDCARD + value
					if random.choice([True, False]):
						value = value + WILDCARD
		
		return attr, value

	transform_func(parsed_structure, obfuscate_wildcards) 