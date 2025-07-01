#!/usr/bin/env python3
import random
import re

from powerview.utils.helpers import is_valid_dn
from .constants import ATTRIBUTE_OID, WILDCARD
from .exceptions import LdapParserException
from ..utils.helpers import in_exception, LdapObfuscate
from ..utils.validators import (
	is_sid_attribute, is_dn_attribute, is_bitwise_attribute
)

class Operators:
	NOT = '!'
	AND = '&'
	OR = '|'

class LdapToken:
	def __init__(self, content, token_type):
		self.content = content
		self.type = token_type

	def __repr__(self):
		return f"{self.type}: {self.content}"

class AttributeParser:
	def __init__(self, attributes):
		if attributes is None:
			self.attributes = []
		elif isinstance(attributes, str):
			self.attributes = [attributes]
		elif isinstance(attributes, (list, tuple)):
			self.attributes = list(attributes)
		else:
			self.attributes = []

	def get_attributes(self):
		return self.attributes

	def random_oid(self):
		for i in range(len(self.attributes)):
			if in_exception(self.attributes[i]):
				continue
				
			if random.choice([True, False]):
				oid = ATTRIBUTE_OID.get(self.attributes[i])
				self.attributes[i] = oid if oid else self.attributes[i]

	def random_casing(self):
		for i in range(len(self.attributes)):
			if in_exception(self.attributes[i]):
				continue
				
			self.attributes[i] = LdapObfuscate.casing(self.attributes[i])

class DNParser:
	def __init__(self, dn):
		self.dn = str(dn) if dn is not None else ""
		self.enable_spacing = False
		self.parsed_structure = []

	def parse(self):
		if not self.dn:
			return []
		pattern = re.compile(r'([A-Za-z]+)=([^,]+)')
		matches = pattern.findall(self.dn)
		self.parsed_structure = [{"attribute": attr, "value": val} for attr, val in matches]
		return self.parsed_structure

	def dn_hex(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			parsed_structure[i]["value"] = LdapObfuscate.randhex(parsed_structure[i]["value"])

	def dn_randomcase(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			parsed_structure[i]["attribute"] = LdapObfuscate.casing(parsed_structure[i]["attribute"])
			parsed_structure[i]["value"] = LdapObfuscate.casing(parsed_structure[i]["value"])

	def convert_to_dn(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		if not parsed_structure:
			return ""
		return ','.join([f"{item['attribute']}={item['value']}" for item in parsed_structure])

	def random_spacing(self):
		self.enable_spacing = True

class FilterParser:
	"""
	LDAP Filter Parser class to parse LDAP filters and obfuscate them
	
	Reference: https://i.blackhat.com/BH-US-24/Presentations/US24-Bohannon-MaLDAPtive-Diving-Deep-Into-LDAP-Wednesday.pdf
	"""
	TOKEN_PATTERNS = {
		'group_start': re.compile(r'\('),
		'group_end': re.compile(r'\)'),
		'boolean_operator': re.compile(r'[&|!]'),
		'comparison_operator': re.compile(r'([<>]?=|:=)'),
		'attribute': re.compile(r'([a-zA-Z0-9-]+)'),
		'extensible_match': re.compile(r':([0-9.]+):'),
		'value': re.compile(r'([^)]*?)(?=\)|$)')
	}

	def __init__(self, ldap_filter):
		if not ldap_filter or not isinstance(ldap_filter, str):
			raise LdapParserException("Invalid LDAP filter: must be a non-empty string")
		self.ldap_filter = ldap_filter.strip()
		self.tokens = []
		self.parsed_structure = []
		self.enable_spacing = False

	def get_parsed_structure(self):
		return self.parsed_structure

	def _is_sid_attribute(self, attr):
		"""Check if attribute typically contains SID values"""
		return is_sid_attribute(attr)

	def _is_dn_attribute(self, attr):
		"""Check if attribute typically contains DN values"""
		return is_dn_attribute(attr)

	def _is_bitwise_attribute(self, attr):
		"""Check if attribute supports bitwise operations"""
		return is_bitwise_attribute(attr)

	def _apply_to_filter_leaves(self, parsed_structure, transform_func):
		"""
		Apply transformation function to leaf filter elements (attribute-operator-value triplets).
		Following Go LeafApplierFilterMiddleware pattern.
		"""
		if not parsed_structure:
			return

		for i in range(len(parsed_structure)):
			if isinstance(parsed_structure[i], list):
				self._apply_to_filter_leaves(parsed_structure[i], transform_func)
			elif (isinstance(parsed_structure[i], dict) and 
				  parsed_structure[i].get("type") == "Attribute" and
				  i + 2 < len(parsed_structure) and
				  isinstance(parsed_structure[i+1], dict) and
				  parsed_structure[i+1].get("type") == "ComparisonOperator" and
				  isinstance(parsed_structure[i+2], dict) and
				  parsed_structure[i+2].get("type") == "Value"):
				
				attr = parsed_structure[i].get("content", "")
				operator = parsed_structure[i+1].get("content", "")
				value = parsed_structure[i+2].get("content", "")
				
				new_attr, new_value = transform_func(attr, operator, value)
				
				if new_attr != attr:
					parsed_structure[i]["content"] = new_attr
				if new_value != value:
					parsed_structure[i+2]["content"] = new_value

	def parse(self):
		try:
			self.tokenize()
			self.parsed_structure = self.build_filter_structure()
			return self.parsed_structure
		except Exception as e:
			raise LdapParserException(f"Failed to parse LDAP filter: {str(e)}")

	def handle_escaped_chars(self, value):
		"""Handle LDAP escaped characters properly"""
		if not value:
			return value
		value = value.replace('\\)', ')')
		value = value.replace('\\(', '(')
		value = value.replace('\\*', '*')
		value = value.replace('\\\\', '\\')
		return value

	def tokenize(self):
		cursor = 0
		max_iterations = len(self.ldap_filter) * 2
		iterations = 0
		
		while cursor < len(self.ldap_filter) and iterations < max_iterations:
			iterations += 1
			
			if cursor >= len(self.ldap_filter):
				break
				
			char = self.ldap_filter[cursor]

			if self.TOKEN_PATTERNS['group_start'].match(char):
				self.tokens.append(LdapToken(char, 'GroupStart'))
				cursor += 1
			elif self.TOKEN_PATTERNS['group_end'].match(char):
				self.tokens.append(LdapToken(char, 'GroupEnd'))
				cursor += 1
			elif self.TOKEN_PATTERNS['boolean_operator'].match(char):
				self.tokens.append(LdapToken(char, 'BooleanOperator'))
				cursor += 1
			else:
				attribute_match = self.TOKEN_PATTERNS['attribute'].match(self.ldap_filter[cursor:])
				if attribute_match:
					attribute = attribute_match.group(1)
					cursor += len(attribute)

					extensible_match = self.TOKEN_PATTERNS['extensible_match'].match(self.ldap_filter[cursor:])
					if extensible_match:
						oid = extensible_match.group(1)
						self.tokens.append(LdapToken(attribute, 'Attribute'))
						self.tokens.append(LdapToken(oid, 'ExtensibleMatchFilter'))
						cursor += len(extensible_match.group(0))

						comparison_match = self.TOKEN_PATTERNS['comparison_operator'].match(self.ldap_filter[cursor:])
						if comparison_match:
							comparison = comparison_match.group(1)
							self.tokens.append(LdapToken(comparison, 'ComparisonOperator'))
							cursor += len(comparison)

							value_match = self.TOKEN_PATTERNS['value'].match(self.ldap_filter[cursor:])
							if value_match:
								value = value_match.group(1)
								value = self.handle_escaped_chars(value)
								self.tokens.append(LdapToken(value, 'Value'))
								cursor += len(value_match.group(1))
							else:
								raise LdapParserException(f"Malformed LDAP filter: value missing after {attribute}")
					else:
						self.tokens.append(LdapToken(attribute, 'Attribute'))

						comparison_match = self.TOKEN_PATTERNS['comparison_operator'].match(self.ldap_filter[cursor:])
						if comparison_match:
							comparison = comparison_match.group(1)
							self.tokens.append(LdapToken(comparison, 'ComparisonOperator'))
							cursor += len(comparison)

							value_match = self.TOKEN_PATTERNS['value'].match(self.ldap_filter[cursor:])
							if value_match:
								value = value_match.group(1)
								value = self.handle_escaped_chars(value)
								self.tokens.append(LdapToken(value, 'Value'))
								cursor += len(value_match.group(1))
							else:
								raise LdapParserException(f"Malformed LDAP filter: value missing after {attribute}")
					continue
				else:
					if char.isspace():
						cursor += 1
						continue
					else:
						raise LdapParserException(f"Unexpected character '{char}' at position {cursor}")

	def build_filter_structure(self):
		if not self.tokens:
			return []
			
		stack = []
		current_filter = []

		for token in self.tokens:
			if token.type == 'GroupStart':
				stack.append(current_filter)
				current_filter = []
			elif token.type == 'GroupEnd':
				if not stack:
					raise LdapParserException("Malformed LDAP filter: unmatched closing parenthesis")
				last_filter = current_filter
				current_filter = stack.pop()
				current_filter.append(last_filter)
			else:
				current_filter.append({
					"type": token.type,
					"content": token.content
				})

		if stack:
			raise LdapParserException("Malformed LDAP filter: unmatched opening parenthesis")

		return current_filter

	def random_spacing(self):
		self.enable_spacing = True

	def convert_to_ldap(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		if not parsed_structure:
			return ""

		ldap_string = []
		skip_random_spacing = False

		def get_last_char(string_list):
			for s in reversed(string_list):
				if s and isinstance(s, str) and s:
					return s[-1]
			return None

		for i in range(len(parsed_structure)):
			token = parsed_structure[i]
			if isinstance(token, list):
				prev_char = get_last_char(ldap_string)
				spacing_before = "" if not ldap_string else LdapObfuscate.get_context_aware_spacing(prev_char, '(')
				
				nested_result = self.convert_to_ldap(token)
				if nested_result:
					ldap_string.append(f"{spacing_before}({nested_result})")
					
					if i < len(parsed_structure) - 1:
						next_token = parsed_structure[i+1]
						next_char = '(' if isinstance(next_token, list) else (
							next_token.get('content', '')[0] if next_token.get('content') else None
						)
						spacing_after = LdapObfuscate.get_context_aware_spacing(')', next_char)
						ldap_string.append(spacing_after)
			else:
				if token["type"] == "Attribute":
					if in_exception(token["content"]) or (i+1 < len(parsed_structure) and 
					   parsed_structure[i+1].get("type") == "ExtensibleMatchFilter"):
						skip_random_spacing = True
					else:
						skip_random_spacing = False

					prev_char = get_last_char(ldap_string)
					next_char = (parsed_structure[i+1].get("content", "")[0] 
							   if i+1 < len(parsed_structure) and parsed_structure[i+1].get("content") 
							   else None)
					spacing = "" if not ldap_string else LdapObfuscate.get_context_aware_spacing(prev_char, next_char)
					
					if token.get('content'):
						ldap_string.append(f"{spacing}{token['content']}")

				elif token["type"] == "ComparisonOperator":
					spacing = "" if skip_random_spacing else LdapObfuscate.random_spaces(1, 2)
					if token.get('content'):
						ldap_string.append(f"{spacing}{token['content']}")

				elif token["type"] == "Value":
					content = token.get('content', '')
					spacing = "" if skip_random_spacing else LdapObfuscate.get_context_aware_spacing(
						'=', 
						content[0] if content else None
					)
					ldap_string.append(f"{spacing}{content}")

				elif token["type"] == "ExtensibleMatchFilter":
					if token.get('content'):
						ldap_string.append(f":{token['content']}:")

				else:
					spacing = "" if skip_random_spacing or not ldap_string else LdapObfuscate.random_spaces(0, 2)
					if token.get('content'):
						ldap_string.append(f"{spacing}{token['content']}")

		result = ''.join(s for s in ldap_string if s is not None)
		return result if result else "" 