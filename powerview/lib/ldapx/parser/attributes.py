import re

from powerview.lib.ldapx.gostd import to_lower
from powerview.lib.ldapx.parser._schema import ATTR_FORMATS, OIDS_MAP, TokenFormat

_OID = re.compile(r"(?i:oid\.)?[0-9]+(?:\.[0-9]+)* *")


def is_oid(value: str) -> bool:
	return _OID.fullmatch(value) is not None


def token_format(attribute: str) -> TokenFormat | None:
	return ATTR_FORMATS.get(to_lower(attribute))


def map_to_oid(attribute: str) -> str | None:
	return OIDS_MAP.get(to_lower(attribute))
