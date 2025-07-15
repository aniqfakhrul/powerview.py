#!/usr/bin/env python3
import random
import string
import binascii

from ..core.constants import (
	WILDCARD, EXCEPTION_CHARS, ATTRIBUTE_OID, EXCEPTION_ATTRIBUTES
)

def in_exception(attribute):
	attribute_casefolded = attribute.casefold()

	in_exception_attributes = attribute_casefolded in (e.casefold() for e in EXCEPTION_ATTRIBUTES)
	in_exception_oid = attribute_casefolded in (val.casefold() for val in ATTRIBUTE_OID.values())

	return in_exception_attributes or in_exception_oid

class LdapObfuscate:
	@staticmethod
	def random_spaces(min_spaces=0, max_spaces=3):
		return ' ' * random.randint(min_spaces, max_spaces)

	@staticmethod
	def is_number(value):
		if not value:
			return False
		return value.lstrip('-').isdigit()

	@staticmethod
	def randhex(chars):
		if not chars:
			return chars
			
		result = []
		for i in range(len(chars)):
			if chars[i] == WILDCARD or LdapObfuscate.is_number(chars[i]):
				result.append(chars[i])
			else:
				result.append(
					random.choice(
						[
							chars[i],
							"\\{}".format(binascii.hexlify(chars[i].encode('utf-8')).decode('utf-8'))
						]
					)
				)

		return ''.join(result)

	@staticmethod
	def casing(chars):
		if not chars:
			return chars
			
		result = []
		for i in range(len(chars)):
			if chars[i] in string.ascii_letters:
				result.append(random.choice([chars[i].lower(), chars[i].upper()]))
			else:
				result.append(chars[i])

		return ''.join(result)

	@staticmethod
	def get_context_aware_spacing(prev_char, next_char):
		"""
		Helper method to determine appropriate spacing based on context
		Handles None values for prev_char and next_char
		"""
		prev_char = str(prev_char) if prev_char is not None else ''
		next_char = str(next_char) if next_char is not None else ''
		
		if prev_char in EXCEPTION_CHARS or next_char in EXCEPTION_CHARS:
			return ""
			
		if prev_char in '&|!=><' or next_char in '&|!=><':
			return LdapObfuscate.random_spaces(1, 3)
			
		if prev_char in '()' or next_char in '()':
			return LdapObfuscate.random_spaces(0, 1)
			
		return LdapObfuscate.random_spaces(0, 2)

	@staticmethod
	def random_anr_casing():
		"""
		Returns 'anr' with random casing
		"""
		anr = "anr"
		return ''.join(random.choice([c.upper(), c.lower()]) for c in anr)

	@staticmethod
	def random_case_string(text, probability=0.7):
		"""
		Randomly change case of characters in string with given probability.
		Following Go helpers.RandomlyChangeCaseString pattern.
		"""
		if not text:
			return text
		
		result = []
		for char in text:
			if char.isalpha() and random.random() < probability:
				result.append(random.choice([char.upper(), char.lower()]))
			else:
				result.append(char)
		
		return ''.join(result)

	@staticmethod
	def prepend_zeros_to_number(value, max_zeros):
		"""Prepend random number of zeros to numeric value"""
		if not value or not value.isdigit():
			return value
		num_zeros = random.randint(1, max_zeros)
		return '0' * num_zeros + value

	@staticmethod
	def prepend_zeros_to_sid(value, max_zeros):
		"""Prepend zeros to SID components"""
		if not value or not value.startswith("S-"):
			return value
		
		parts = value.split('-')
		if len(parts) < 3:
			return value
		
		for i in range(2, len(parts)):
			if parts[i].isdigit() and random.choice([True, False]):
				num_zeros = random.randint(1, max_zeros)
				parts[i] = '0' * num_zeros + parts[i]
		
		return '-'.join(parts)

	@staticmethod
	def add_spacing_to_value(value, attr_type, max_spaces):
		"""Add context-aware spacing to values based on attribute type"""
		if not value:
			return value
		
		if attr_type == "dn":
			parts = value.split(',')
			spaced_parts = []
			for part in parts:
				if '=' in part:
					key, val = part.split('=', 1)
					spaces = ' ' * random.randint(0, max_spaces)
					spaced_parts.append(f"{key.strip()}{spaces}={spaces}{val.strip()}")
				else:
					spaced_parts.append(part)
			return ','.join(spaced_parts)
		
		elif attr_type == "sid":
			if value.startswith("S-"):
				parts = value.split('-')
				spaced_parts = [parts[0]]
				for part in parts[1:]:
					spaces = ' ' * random.randint(0, max_spaces)
					spaced_parts.append(spaces + part + spaces)
				return '-'.join(spaced_parts)
		
		elif attr_type == "anr":
			spaces = ' ' * random.randint(0, max_spaces)
			return spaces + value + spaces
		
		return value 