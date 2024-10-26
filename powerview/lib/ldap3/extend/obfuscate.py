#!/usr/bin/env python3
import logging
import random
import string
import re
import binascii

WILDCARD = "*"
MAX_RAND = 10

EXCEPTION_ATTRIBUTES = [
	"objectClass",
	"objectCategory",
	"userAccountControl"
]

EXCEPTION_CHARS = [
	WILDCARD
]

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

class LdapParser:
	TOKEN_PATTERNS = {
		'group_start': re.compile(r'\('),
		'group_end': re.compile(r'\)'),
		'boolean_operator': re.compile(r'[&|!]'),
		'comparison_operator': re.compile(r'([<>]?=|:=)'),  # Capture = and :=
		'attribute': re.compile(r'([a-zA-Z0-9:.\-]+)'),  # Updated to match attributes with colon and dot
		'value': re.compile(r'([^\)]*)')  # Value part (anything not a closing parenthesis)
	}

	def __init__(self, ldap_filter):
		self.ldap_filter = ldap_filter
		self.tokens = []
		self.parsed_structure = []

	def parse(self):
		self.tokenize()
		self.parsed_structure = self.build_filter_structure()
		return self.parsed_structure

	def tokenize(self):
		cursor = 0
		while cursor < len(self.ldap_filter):
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
				# Handle attributes with extended comparison operators
				attribute_match = self.TOKEN_PATTERNS['attribute'].match(self.ldap_filter[cursor:])
				if attribute_match:
					attribute = attribute_match.group(1)
					self.tokens.append(LdapToken(attribute, 'Attribute'))

					# Move the cursor forward
					cursor += len(attribute)

					# Now match the comparison operator
					comparison_match = self.TOKEN_PATTERNS['comparison_operator'].match(self.ldap_filter[cursor:])
					if comparison_match:
						comparison = comparison_match.group(1)
						self.tokens.append(LdapToken(comparison, 'ComparisonOperator'))
						cursor += len(comparison)

						# Now match the value
						value_match = self.TOKEN_PATTERNS['value'].match(self.ldap_filter[cursor:])
						if value_match:
							value = value_match.group(1)
							self.tokens.append(LdapToken(value.strip(), 'Value'))
							cursor += len(value)

					continue

				cursor += 1  # move forward if nothing matches

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

		return current_filter

	def convert_to_ldap(self, parsed_structure=None):
		"""Recursively convert the parsed filter structure back into its original LDAP string form."""
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		ldap_string = []
		previous_token_type = None

		for token in parsed_structure:
			if isinstance(token, list):
				# Recurse into nested group
				ldap_string.append(f"({self.convert_to_ldap(token)})")
			else:
				# Avoid appending an extra "=" after attributes
				if token["type"] == "Attribute" and previous_token_type != "ComparisonOperator":
					ldap_string.append(f"{token['content']}")
				elif token["type"] == "ComparisonOperator":
					ldap_string.append(f"{token['content']}")
				elif token["type"] == "Value":
					ldap_string.append(f"{token['content']}")
				else:
					ldap_string.append(f"{token['content']}")

				previous_token_type = token["type"]

		return ''.join(ldap_string)

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

	def random_casing(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.random_casing(token)
			elif (token["type"] == "Attribute" and any(e in token["content"] for e in EXCEPTION_ATTRIBUTES)) or (token["type"] == "Value" and token["content"] == WILDCARD) or LdapObfuscate.is_number(token["content"]):
				break
			elif token["type"] == "Value" or token["type"] == "Attribute":
				token["content"] = LdapObfuscate.casing(token["content"])

	def random_spacing(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		def random_spaces():
			return ' ' * random.randint(0, 3)

	def prepend_zeros(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.prepend_zeros(token)
			elif token["type"] == "Value" and token["content"].isdigit():
				token["content"] = '0' * random.randint(1, 10) + token["content"]

	def random_hex(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.random_hex(token)
			elif (token["type"] == "Attribute" and any(e in token["content"] for e in EXCEPTION_ATTRIBUTES)) or (token["type"] == "Value" and token["content"] == WILDCARD) or LdapObfuscate.is_number(token["content"]):
				break
			elif token["type"] == "Value":
				token["content"] = LdapObfuscate.randhex(token["content"])

	def random_wildcards(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for token in parsed_structure:
			if isinstance(token, list):
				self.random_wildcards(token)
			elif (token["type"] == "Attribute" and any(e in token["content"] for e in EXCEPTION_ATTRIBUTES)) or (token["type"] == "Value" and token["content"] == WILDCARD) or LdapObfuscate.is_number(token["content"]):
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

	def comparison_operator_obfuscation(self, parsed_structure=None):
		if parsed_structure is None:
			parsed_structure = self.parsed_structure

		for i in range(len(parsed_structure)):
			token = parsed_structure[i]
			if isinstance(token, list):
				self.comparison_operator_obfuscation(token)
			elif token["type"] == "Attribute" and any(e in token["content"] for e in EXCEPTION_ATTRIBUTES):
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

				if value.isdigit():
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
								# Extend the list with multiple dictionaries at once
								new_token.extend([
									{'content': attribute, 'type': 'Attribute'},
									{'content': '>=', 'type': 'ComparisonOperator'},
									{'content': number, 'type': 'Value'}
								])
							elif condition == "greater":
								# Extend the list with multiple dictionaries at once
								new_token.extend([
									{'content': attribute, 'type': 'Attribute'},
									{'content': '<=', 'type': 'ComparisonOperator'},
									{'content': number, 'type': 'Value'}
								])
							# Append the new token to the structure
							self.remove_token(
								attribute=attribute,
								operator=token["content"],
								value=value
							)
							self.append_token(new_token)

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
	def is_number(value):
		return value.lstrip('-').isdigit()

	@staticmethod
	def randhex(chars):
		result = []
		for i in range(len(chars)):
			if chars[i] == WILDCARD:
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
			elif chars[i-1] == WILDCARD or chars[i+1] == WILDCARD:
				result.append(chars[i])
			else:
				result.append(random.choice([chars[i], WILDCARD + chars[i]]))

		return ''.join(result)