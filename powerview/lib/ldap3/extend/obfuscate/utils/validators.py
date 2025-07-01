#!/usr/bin/env python3

from ..core.constants import (
	SID_ATTRIBUTES, DN_ATTRIBUTES, BITWISE_ATTRIBUTES
)

def is_sid_attribute(attr):
	"""Check if attribute typically contains SID values"""
	return attr.lower() in SID_ATTRIBUTES

def is_dn_attribute(attr):
	"""Check if attribute typically contains DN values"""
	return attr.lower() in DN_ATTRIBUTES

def is_bitwise_attribute(attr):
	"""Check if attribute supports bitwise operations"""
	return attr.lower() in BITWISE_ATTRIBUTES

def is_oid(text):
	"""Check if text is an OID (contains dots and numeric components)"""
	if not text or '.' not in text:
		return False
	parts = text.strip().split('.')
	return len(parts) >= 2 and all(part.isdigit() for part in parts if part)

def randomly_prepend_zeros_oid(oid, max_zeros):
	"""Randomly prepend zeros to OID components"""
	import random
	parts = oid.strip().split('.')
	for i in range(len(parts)):
		if parts[i].isdigit() and random.choice([True, False]):
			num_zeros = random.randint(1, max_zeros)
			parts[i] = '0' * num_zeros + parts[i]
	return '.'.join(parts)

def randomly_hex_encode_dn_string(value, probability):
	"""Randomly hex encode characters in DN string"""
	import random
	if not value:
		return value
	
	result = []
	for char in value:
		if char not in [',', '=', ' '] and random.random() < probability:
			hex_encoded = f"\\{ord(char):02x}"
			result.append(hex_encoded)
		else:
			result.append(char)
	
	return ''.join(result) 