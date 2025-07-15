#!/usr/bin/env python3

from powerview.utils.helpers import IDict
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

EXACT_MATCH_ATTRIBUTES = [
	'samaccounttype', 'admincount', 'useraccountcontrol', 
	'primarygroupid', 'objectclass', 'objectcategory',
	'instancetype', 'systemflags', 'options'
]

DEFAULT_ANR_ATTRIBUTES = [
	'samaccountname', 'displayname', 'name', 'cn', 'commonname',
	'givenname', 'surname', 'mail', 'userprincipalname'
]

SID_ATTRIBUTES = ['objectsid', 'sid', 'msds-allowedtoactonbehalfofotheridentity']

DN_ATTRIBUTES = ['distinguishedname', 'dn', 'manager', 'member', 'memberof']

BITWISE_ATTRIBUTES = ['useraccountcontrol', 'systemflags', 'instancetype', 'options']

WILDCARD_SAFE_ATTRIBUTES = ['name', 'cn', 'displayname', 'description', 'mail', 'userprincipalname'] 