#!/usr/bin/env python3
import random

from ..utils.helpers import in_exception

def equality_to_approximation_obfuscation(parsed_structure):
	"""
	Convert equality matches to approximation matches following Go EqualityToApproxMatchFilterObf pattern.
	This is safer than complex range transformations.
	"""
	def transform_operators(structure):
		if not structure:
			return
		
		for i in range(len(structure)):
			if isinstance(structure[i], list):
				transform_operators(structure[i])
			elif (isinstance(structure[i], dict) and 
				  structure[i].get("type") == "ComparisonOperator" and
				  structure[i].get("content") == "=" and
				  i > 0 and i + 1 < len(structure)):
				
				attr_token = structure[i-1]
				if (isinstance(attr_token, dict) and 
					attr_token.get("type") == "Attribute" and
					not in_exception(attr_token.get("content", ""))):
					
					if random.choice([True, False]):
						structure[i]["content"] = "~="
	
	transform_operators(parsed_structure) 