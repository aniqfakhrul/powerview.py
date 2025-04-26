#!/usr/bin/env python3
import random
import string
import re
import binascii

from powerview.utils.helpers import (
	is_valid_dn, 
	IDict
)
from powerview.utils.constants import ATTRIBUTE_OID

WILDCARD = "*"
COMMA = ","
COLON = ":"
MAX_RAND = 10

ATTRIBUTE_OID = IDict(ATTRIBUTE_OID)
EXCEPTION_ATTRIBUTES = [
	"objectClass",
	"objectCategory",
	"userAccountControl",
	"msDS-AllowedToActOnBehalfOfOtherIdentity"
]

EXCEPTION_CHARS = [
	WILDCARD,
	COMMA,
	COLON
]

def in_exception(attribute):
	attribute_casefolded = attribute.casefold()

	in_exception_attributes = attribute_casefolded in (e.casefold() for e in EXCEPTION_ATTRIBUTES)
	in_exception_oid = attribute_casefolded in (val.casefold() for val in ATTRIBUTE_OID.values())

	return in_exception_attributes or in_exception_oid

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

class LdapParserException(Exception):
	def __init__(self, message):
		super().__init__(message)

class AttributeParser:
	def __init__(self, attributes):
		self.attributes = attributes

	def get_attributes(self):
		return self.attributes

	def random_oid(self):
		for i in range(len(self.attributes)):
			if random.choice([True, False]):
				oid = ATTRIBUTE_OID.get(self.attributes[i])
				self.attributes[i] = oid if oid else self.attributes[i]

	def random_casing(self):
		for i in range(len(self.attributes)):
			self.attributes[i] = LdapObfuscate.casing(self.attributes[i])

class DNParser:
	def __init__(self, dn):
		self.dn = dn
		self.enable_spacing = False

	def parse(self):
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

	def dn_random_oid(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			parsed_structure[i]["attribute"] = ATTRIBUTE_OID.get(parsed_structure[i]["attribute"])

	def convert_to_dn(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		return ','.join([f"{item['attribute']}={item['value']}" for item in parsed_structure])

	def random_spacing(self):
		self.enable_spacing = True

class LdapParser:
	"""
	LDAP Parser class to parse LDAP filters and obfuscate them
	
	Reference: https://i.blackhat.com/BH-US-24/Presentations/US24-Bohannon-MaLDAPtive-Diving-Deep-Into-LDAP-Wednesday.pdf
	"""
	TOKEN_PATTERNS = {
		'group_start': re.compile(r'\('),
		'group_end': re.compile(r'\)'),
		'boolean_operator': re.compile(r'[&|!]'),
		'comparison_operator': re.compile(r'([<>]?=|:=)'),  # Capture = and :=
		'attribute': re.compile(r'([a-zA-Z0-9-]+)'),  # Match base attributes, including hyphen
		'extensible_match': re.compile(r':([0-9.]+):'),  # Match OID pattern with colons as ExtensibleMatchFilter
		'value': re.compile(r'([^\)]*)')  # Value part (anything not a closing parenthesis)
	}

	def __init__(self, ldap_filter):
		self.ldap_filter = ldap_filter
		self.tokens = []
		self.parsed_structure = []
		self.enable_spacing = False

	def get_parsed_structure(self):
		return self.parsed_structure

	def parse(self):
		self.tokenize()
		self.parsed_structure = self.build_filter_structure()
		return self.parsed_structure

	def tokenize(self):
		cursor = 0
		while cursor < len(self.ldap_filter):
			char = self.ldap_filter[cursor]

			# Match the start of a group
			if self.TOKEN_PATTERNS['group_start'].match(char):
				self.tokens.append(LdapToken(char, 'GroupStart'))
				cursor += 1
			# Match the end of a group
			elif self.TOKEN_PATTERNS['group_end'].match(char):
				self.tokens.append(LdapToken(char, 'GroupEnd'))
				cursor += 1
			# Match boolean operators (&, |, !)
			elif self.TOKEN_PATTERNS['boolean_operator'].match(char):
				self.tokens.append(LdapToken(char, 'BooleanOperator'))
				cursor += 1
			else:
				# Handle attributes with potential extensible match
				attribute_match = self.TOKEN_PATTERNS['attribute'].match(self.ldap_filter[cursor:])
				if attribute_match:
					attribute = attribute_match.group(1)
					cursor += len(attribute)

					# Check if there's an extensible match filter (OID with colons)
					extensible_match = self.TOKEN_PATTERNS['extensible_match'].match(self.ldap_filter[cursor:])
					if extensible_match:
						oid = extensible_match.group(1)
						self.tokens.append(LdapToken(attribute, 'Attribute'))
						self.tokens.append(LdapToken(oid, 'ExtensibleMatchFilter'))
						cursor += len(extensible_match.group(0))  # Move cursor past the OID and colons

						# Match the comparison operator
						comparison_match = self.TOKEN_PATTERNS['comparison_operator'].match(self.ldap_filter[cursor:])
						if comparison_match:
							comparison = comparison_match.group(1)
							self.tokens.append(LdapToken(comparison, 'ComparisonOperator'))
							cursor += len(comparison)

							# Match the value
							value_match = self.TOKEN_PATTERNS['value'].match(self.ldap_filter[cursor:])
							if value_match:
								value = value_match.group(1).strip()
								self.tokens.append(LdapToken(value, 'Value'))
								cursor += len(value)
							else:
								raise ValueError(f"Malformed LDAP filter: value missing after {attribute}")
					else:
						# Handle regular attributes with = or similar comparison operator
						self.tokens.append(LdapToken(attribute, 'Attribute'))

						# Match comparison operator for regular attributes
						comparison_match = self.TOKEN_PATTERNS['comparison_operator'].match(self.ldap_filter[cursor:])
						if comparison_match:
							comparison = comparison_match.group(1)
							self.tokens.append(LdapToken(comparison, 'ComparisonOperator'))
							cursor += len(comparison)

							# Match the value
							value_match = self.TOKEN_PATTERNS['value'].match(self.ldap_filter[cursor:])
							if value_match:
								value = value_match.group(1).strip()
								self.tokens.append(LdapToken(value, 'Value'))
								cursor += len(value)
							else:
								raise ValueError(f"Malformed LDAP filter: value missing after {attribute}")
					
					continue

				cursor += 1  # move forward if no match is found

	def build_filter_structure(self):
		stack = []
		current_filter = []

		for token in self.tokens:
			if token.type == 'GroupStart':
				stack.append(current_filter)
				current_filter = []
			elif token.type == 'GroupEnd':
				last_filter = current_filter
				current_filter = stack.pop()
				current_filter.append(last_filter)
			else:
				current_filter.append({
					"type": token.type,
					"content": token.content
				})

		if stack:
			raise ValueError("Malformed LDAP filter: unmatched parentheses")

		return current_filter

	def random_spacing(self):
		self.enable_spacing = True

	def convert_to_ldap(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		ldap_string = []
		previous_token_type = None
		skip_random_spacing = False

		def get_last_char(string_list):
			"""Safely get the last character from the last non-empty string in the list"""
			for s in reversed(string_list):
				if s and isinstance(s, str):
					return s[-1] if s else None
			return None

		for i in range(len(parsed_structure)):
			token = parsed_structure[i]
			if isinstance(token, list):
				# Get context characters for proper spacing
				prev_char = get_last_char(ldap_string)
				spacing_before = LdapObfuscate.get_context_aware_spacing(prev_char, '(')
				
				nested_result = self.convert_to_ldap(token)
				if nested_result:  # Only append if we got a result
					ldap_string.append(f"{spacing_before}({nested_result})")
					
					# Add context-aware spacing after nested structure
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
					   parsed_structure[i+1]["type"] == "ExtensibleMatchFilter"):
						skip_random_spacing = True
					else:
						skip_random_spacing = False

					# Add context-aware spacing around attributes
					prev_char = get_last_char(ldap_string)
					next_char = (parsed_structure[i+1].get("content", "")[0] 
							   if i+1 < len(parsed_structure) and parsed_structure[i+1].get("content") 
							   else None)
					spacing = LdapObfuscate.get_context_aware_spacing(prev_char, next_char)
					
					if token.get('content'):  # Only append if content exists
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
					spacing = "" if skip_random_spacing else LdapObfuscate.random_spaces(0, 2)
					if token.get('content'):
						ldap_string.append(f"{spacing}{token['content']}")

				previous_token_type = token["type"]

		result = ''.join(s for s in ldap_string if s)  # Filter out any None or empty strings
		return result if result else ""  # Return empty string instead of None

	def modify_token(self, token_type, old_value, new_value, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.modify_token(token_type, old_value, new_value, token)
			elif token["type"] == token_type and token["content"] == old_value:
				token["content"] = new_value

	def remove_token(self, attribute, operator, value, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			if isinstance(parsed_structure[i], list):
				self.remove_token(attribute, operator, value, parsed_structure[i])
			elif parsed_structure[i]["type"] == "Attribute" and parsed_structure[i]["content"].lower() == attribute.lower() and parsed_structure[i+1]["type"] == "BooleanOperator" and parsed_structure[i+1]["content"].lower() == operator.lower() and parsed_structure[i+2]["type"] == "Value" and parsed_structure[i+2]["content"].lower() == value.lower():
				parsed_structure.pop(i)

	def append_token(self, new_token, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		current = parsed_structure
		while isinstance(current[0], list):
			current = current[0]

		current.append(new_token)

	def append_inner_token(self, new_token, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		current = parsed_structure
		second_last_list = None

		while isinstance(current[-1], list):
			second_last_list = current
			current = current[-1]

		if second_last_list is not None:
			valid_indices = [i for i, token in enumerate(second_last_list) if isinstance(token, dict) and token['type'] != 'BooleanOperator']

			if valid_indices:
				random_index = random.choice(valid_indices)
				second_last_list.insert(random_index + 1, new_token) 
			else:
				second_last_list.append(new_token)

	def random_casing(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.random_casing(token)
			elif (token["type"] == "Attribute" and in_exception(token["content"])) or (token["type"] == "Value" and token["content"] == WILDCARD) or LdapObfuscate.is_number(token["content"]):
				break
			elif token["type"] == "Value" or token["type"] == "Attribute":
				token["content"] = LdapObfuscate.casing(token["content"])

	def prepend_zeros(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.prepend_zeros(token)
			elif token["type"] == "Value" and token["content"].isdigit():
				token["content"] = '0' * random.randint(1, MAX_RAND) + token["content"]

	def random_hex(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.random_hex(token)
			elif (token["type"] == "Attribute" and in_exception(token["content"])) or (token["type"] == "Value" and token["content"] == WILDCARD) or LdapObfuscate.is_number(token["content"]):
				break
			elif token["type"] == "Value":
				token["content"] = LdapObfuscate.randhex(token["content"])

	def random_wildcards(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.random_wildcards(token)
			elif (token["type"] == "Attribute" and in_exception(token["content"])) or (token["type"] == "Value" and token["content"] == WILDCARD) or LdapObfuscate.is_number(token["content"]) or is_valid_dn(token["content"]):
				break
			elif token["type"] == "Value":
				token["content"] = LdapObfuscate.randwildcards(token["content"])

	def boolean_operator_obfuscation(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		new_structure = parsed_structure[0]
		nested_boolean_count = random.randint(1, MAX_RAND)
		not_operator_count = 0

		for _ in range(nested_boolean_count):
			random_operator = random.choice([Operators.AND, Operators.OR, Operators.NOT])
			if random_operator == Operators.NOT:
				not_operator_count += 1
			new_structure = [{'type': 'BooleanOperator', 'content': random_operator}, new_structure]

		if not_operator_count % 2 != 0:
			new_structure = [{'type': 'BooleanOperator', 'content': Operators.NOT}, new_structure]

		self.parsed_structure = [new_structure]

	def append_garbage(self, parsed_structure=None):
		"""
		Enhanced append_garbage with ANR support.
		ANR (Ambiguous Name Resolution) can be used as: anr=value or anr=value*garbage
		"""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			duplicate = random.choice([True, False])
			if isinstance(parsed_structure[i], list):
				self.append_garbage(parsed_structure[i])
			elif (parsed_structure[i]["type"] == "Attribute" and in_exception(parsed_structure[i]["content"])) or (parsed_structure[i]["type"] == "Value" and parsed_structure[i]["content"] == WILDCARD):
				break
			elif parsed_structure[i]["type"] == "Attribute" and duplicate:
				attribute = parsed_structure[i]["content"]
				operator = parsed_structure[i+1]["content"]
				value = parsed_structure[i+2]["content"]
				
				if LdapObfuscate.is_number(value):
					break

				# Decide whether to use regular garbage or ANR
				use_anr = random.choice([True, False])
				
				if use_anr:
					base_value = value.strip('*')
					if base_value:
						if random.choice([True, False]):
							anr_value = f"{base_value}*{LdapObfuscate.random_string()}"
						else:
							anr_value = base_value

						new_token = [
							{"type": "Attribute", "content": LdapObfuscate.random_anr_casing()},
							{"type": "ComparisonOperator", "content": "="},
							{"type": "Value", "content": anr_value}
						]
						self.append_inner_token(new_token)
				else:
					new_token = [
						{"type": "Attribute", "content": attribute},
						{"type": "ComparisonOperator", "content": operator},
						{"type": "Value", "content": LdapObfuscate.random_string()}
					]
					self.append_inner_token(new_token)

	def randomize_oid(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			token = parsed_structure[i]
			if isinstance(token, list):
				self.randomize_oid(token)
			elif token['type'] == 'Attribute':
				if random.choice([True, False]):
					break
				attribute = token['content']
				oid = ATTRIBUTE_OID.get(attribute)
				if oid and random.choice([True, False]):
					token['content'] = oid

	def comparison_operator_obfuscation(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			token = parsed_structure[i]
			if isinstance(token, list):
				self.comparison_operator_obfuscation(token)
			elif token["type"] == "Attribute" and in_exception(token["content"]):
				break
			elif token["type"] == "ComparisonOperator":
				attribute = parsed_structure[i-1]["content"]
				value = parsed_structure[i+1]["content"]
				if token["content"] == "=" and value == WILDCARD:
					token["content"] = random.choice(
						[
							'>' + '=' * random.randint(2, MAX_RAND),
							'>' + '=' * random.randint(2, MAX_RAND) + '!' * random.randint(2, MAX_RAND),
							'<=' + ''.join(random.choice(['z', 'Z']) for _ in range(random.randint(1, MAX_RAND))) + ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(5, MAX_RAND)))
						]
					)
					parsed_structure[i+1]["content"] = ""

				if LdapObfuscate.is_number(value):
					new = [
						{'content': 'objectCategory', 'type': 'Attribute'},
						{'content': '>=', 'type': 'ComparisonOperator'},
						{'content': 'person', 'type': 'Value'}
					]
					numbers = LdapObfuscate.generate_random_number(int(value))
					for condition in numbers.keys():
						for number in numbers[condition]:
							new_token = []
							if condition == "lower":
								new_token.extend([
									{'content': attribute, 'type': 'Attribute'},
									{'content': '>=', 'type': 'ComparisonOperator'},
									{'content': number, 'type': 'Value'}
								])
							elif condition == "greater":
								new_token.extend([
									{'content': attribute, 'type': 'Attribute'},
									{'content': '<=', 'type': 'ComparisonOperator'},
									{'content': number, 'type': 'Value'}
								])
							self.remove_token(
								attribute=attribute,
								operator=token["content"],
								value=value
							)
							self.append_inner_token(new_token)

class LdapObfuscate:
	@staticmethod
	def whitespace(chars):
		result = []
		for i in range(len(chars)):
			prev_char = chars[i-1] if i > 0 else None
			next_char = chars[i+1] if i < len(chars) - 1 else None

			if chars[i] not in string.ascii_letters and next_char not in EXCEPTION_CHARS and prev_char not in EXCEPTION_CHARS:
				spaces = " " * random.randint(0, MAX_RAND)
				result.append(chars[i] + spaces)
			else:
				result.append(chars[i])

		return ''.join(result)

	@staticmethod
	def random_spaces(min_spaces=0, max_spaces=3):
		return ' ' * random.randint(min_spaces, max_spaces)

	@staticmethod
	def random_string(N=10):
		characters = string.ascii_letters + string.digits
		return ''.join(random.choice(characters) for _ in range(N))

	@staticmethod
	def is_number(value):
		return value.lstrip('-').isdigit()

	@staticmethod
	def randhex(chars):
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
		result = []
		for i in range(len(chars)):
			if chars[i] in string.ascii_letters:
				result.append(random.choice([chars[i].lower(), chars[i].upper()]))
			else:
				result.append(chars[i])

		return ''.join(result)

	@staticmethod
	def generate_random_number(value: int) -> dict[str, list[int]]:
		random_numbers = {
			"lower": [],
			"greater": []
		}
		
		for _ in range(random.randint(1, 3)):
			random_numbers["lower"].append(str(random.randrange(-random.randint(1, 100000), value - 1)))
		
		for _ in range(random.randint(1, 3)):
			random_numbers["greater"].append(str(random.randrange(value + 1, value + random.randint(1, 100000))))
		
		return random_numbers

	@staticmethod
	def randwildcards(chars):
		result = []
		length = len(chars)
		for i in range(length):
			if i == 0 or i == length - 1:
				result.append(chars[i])
			elif chars[i] in EXCEPTION_CHARS or chars[i-1] in EXCEPTION_CHARS or chars[i+1] in EXCEPTION_CHARS:
				result.append(chars[i])
			else:
				result.append(random.choice([chars[i], WILDCARD + chars[i]]))

		return ''.join(result)

	@staticmethod
	def get_context_aware_spacing(prev_char, next_char):
		"""
		Helper method to determine appropriate spacing based on context
		Handles None values for prev_char and next_char
		"""
		# Handle None values
		prev_char = str(prev_char) if prev_char is not None else ''
		next_char = str(next_char) if next_char is not None else ''
		
		# No space around wildcards or special characters
		if prev_char in EXCEPTION_CHARS or next_char in EXCEPTION_CHARS:
			return ""
			
		# More spaces around operators
		if prev_char in '&|!=><' or next_char in '&|!=><':
			return LdapObfuscate.random_spaces(1, 3)
			
		# Less space around parentheses
		if prev_char in '()' or next_char in '()':
			return LdapObfuscate.random_spaces(0, 1)
			
		# Default spacing
		return LdapObfuscate.random_spaces(0, 2)

	@staticmethod
	def random_anr_casing():
		"""
		Returns 'anr' with random casing
		"""
		anr = "anr"
		return ''.join(random.choice([c.upper(), c.lower()]) for c in anr)