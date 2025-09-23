#!/usr/bin/env python3

class LdapParserException(Exception):
	def __init__(self, message):
		super().__init__(message) 