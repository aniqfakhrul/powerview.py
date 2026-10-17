from collections.abc import Callable

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import equal_fold, from_bytes, to_bytes, to_lower
from powerview.lib.ldapx.middlewares.helpers._tables import (
	ALT_SPACE_RUNES,
	VISIBLE_ALT_SPACE_RUNES,
)
from powerview.lib.ldapx.middlewares.helpers.strings import (
	randomly_change_case_string,
	randomly_hex_encode_string,
	randomly_prepend_zeros_oid,
)
from powerview.lib.ldapx.middlewares.helpers.unicode import (
	FoldSubstituter,
	ignorable_mode_runes,
	insert_runes,
	substitute_spaces,
	transform_dn_values,
)
from powerview.lib.ldapx.parser._schema import OIDS_MAP
from powerview.lib.ldapx.parser.attributes import is_oid

BaseDNMiddleware = Callable[[str], str]

REFERENCE_ONLY_FORMS = frozenset(("SIDFormat", "GUIDFormat", "WKGUIDFormat"))

WELL_KNOWN_CONTAINERS = {
	"CN=Users,": "a9d1ca15768811d1aded00c04fd8d5cd",
	"CN=Computers,": "aa312825768811d1aded00c04fd8d5cd",
	"CN=System,": "ab1d30f3768811d1aded00c04fd8d5cd",
	"OU=Domain Controllers,": "a361b2ffffd211d1aa4b00c04fd7d83a",
	"CN=LostAndFound,": "ab8153b7768811d1aded00c04fd8d5cd",
	"CN=ForeignSecurityPrincipals,": "22b70c67d56e4efb91e9300fca3dc1aa",
	"CN=Program Data,": "09460c08ae1e4a4ea0f64aee7daa1e5a",
	"CN=Microsoft,CN=Program Data,": "f4be92a4c777485e878e9421d53087db",
	"CN=NTDS Quotas,": "6227f0af1fc2410d8e3bb10615bb5b0f",
	"CN=Infrastructure,": "2fbac1870ade11d297c400c04fd8d5cd",
	"CN=Deleted Objects,": "18e2ea80684f11d2b9aa00c04f79f805",
	"CN=Managed Service Accounts,": "1eb93889e40c45df9f0c64d23bbb6237",
}

_WKGUID_PREFIX = "<WKGUID="


def _starts_with_fold(value: str, prefix: str) -> bool:
	head = to_bytes(value)[:len(to_bytes(prefix))]
	return equal_fold(from_bytes(head), prefix)


def rand_case(prob: float) -> BaseDNMiddleware:
	return lambda dn: randomly_change_case_string(dn, prob)


def oid_attribute(max_spaces: int, max_zeros: int, include_prefix: bool) -> BaseDNMiddleware:
	def middleware(dn: str) -> str:
		parts = dn.split(",")
		for index, part in enumerate(parts):
			kv = part.split("=", 1)
			if len(kv) != 2:
				continue
			name = OIDS_MAP.get(to_lower(kv[0]), kv[0])
			if is_oid(name):
				if max_spaces > 0:
					name += " " * (1 + rand.intn(max_spaces))
				if max_zeros > 0:
					name = randomly_prepend_zeros_oid(name, max_zeros)
				# Upstream always applies the prefix and ignores include_prefix.
				if not to_lower(name).startswith("oid."):
					name = "oID." + name
			parts[index] = name + "=" + kv[1]
		return ",".join(parts)

	return middleware


def rand_spacing(max_spaces: int) -> BaseDNMiddleware:
	def middleware(dn: str) -> str:
		if not dn or max_spaces <= 0:
			return dn
		first = " " * (1 + rand.intn(max_spaces))
		second = " " * (1 + rand.intn(max_spaces))
		choice = rand.intn(3)
		if choice == 0:
			return dn + first
		if choice == 1:
			return first + dn
		return first + dn + second

	return middleware


def double_quotes() -> BaseDNMiddleware:
	def middleware(dn: str) -> str:
		parts = dn.split(",")
		for index, part in enumerate(parts):
			kv = part.split("=", 1)
			if len(kv) != 2 or "\\" in kv[1]:
				continue
			value = kv[1]
			if index == len(parts) - 1 and value.endswith(" "):
				trimmed = value.rstrip(" ")
				parts[index] = kv[0] + '="' + trimmed + '"' + " " * (len(value) - len(trimmed))
			else:
				parts[index] = kv[0] + '="' + value + '"'
		return ",".join(parts)

	return middleware


def _should_replace(dn: str, match: str) -> bool:
	if not dn:
		return False
	return not match or equal_fold(dn, match)


def guid_format(guid_hex: str, match: str) -> BaseDNMiddleware:
	def middleware(dn: str) -> str:
		if not guid_hex or not _should_replace(dn, match):
			return dn
		return "<GUID=" + guid_hex + ">"

	return middleware


def sid_format(sid: str, match: str) -> BaseDNMiddleware:
	def middleware(dn: str) -> str:
		if not sid or not _should_replace(dn, match):
			return dn
		return "<SID=" + sid + ">"

	return middleware


def wkguid_format() -> BaseDNMiddleware:
	prefixes = sorted(WELL_KNOWN_CONTAINERS, key=len, reverse=True)

	def middleware(dn: str) -> str:
		raw = to_bytes(dn)
		for prefix in prefixes:
			if len(raw) <= len(prefix) or not _starts_with_fold(dn, prefix):
				continue
			return _WKGUID_PREFIX + WELL_KNOWN_CONTAINERS[prefix] + "," + from_bytes(raw[len(prefix):]) + ">"
		return dn

	return middleware


def rand_hex_value(prob: float) -> BaseDNMiddleware:
	def middleware(dn: str) -> str:
		parts = dn.split(",")
		for index, part in enumerate(parts):
			kv = part.split("=", 1)
			if len(kv) != 2:
				continue
			value = kv[1]
			if value[:1] == '"' or value[-1:] == '"':
				continue
			trimmed = value.rstrip(" ")
			spaces = " " * (len(value) - len(trimmed))
			parts[index] = kv[0] + "=" + randomly_hex_encode_string(trimmed, prob) + spaces
		return ",".join(parts)

	return middleware


def rand_ignorable_unicode(prob: float, mode: str) -> BaseDNMiddleware:
	pool = ignorable_mode_runes(mode)
	return lambda dn: transform_dn_values(dn, lambda value: insert_runes(value, pool, prob))


def rand_alt_space(prob: float, include_visible: bool) -> BaseDNMiddleware:
	pool = ALT_SPACE_RUNES + VISIBLE_ALT_SPACE_RUNES if include_visible else ALT_SPACE_RUNES
	return lambda dn: transform_dn_values(dn, lambda value: substitute_spaces(value, pool, prob))


def rand_sort_key_fold(prob: float, classes: str) -> BaseDNMiddleware:
	substituter = FoldSubstituter(classes)
	return lambda dn: transform_dn_values(dn, lambda value: substituter.apply(value, prob))


def split_wkguid(dn: str) -> tuple[str, str] | None:
	raw = to_bytes(dn)
	if len(raw) <= len(_WKGUID_PREFIX) or not _starts_with_fold(dn, _WKGUID_PREFIX) or not dn.endswith(">"):
		return None
	body = from_bytes(raw[len(_WKGUID_PREFIX):-1])
	guid, separator, object_dn = body.partition(",")
	if not separator:
		return None
	return guid, object_dn


def apply_to_dn_part(middleware: BaseDNMiddleware) -> BaseDNMiddleware:
	def apply(dn: str) -> str:
		if not dn.startswith("<"):
			return middleware(dn)
		parts = split_wkguid(dn)
		if parts is None:
			return dn
		guid, object_dn = parts
		return _WKGUID_PREFIX + guid + "," + middleware(object_dn) + ">"

	return apply
