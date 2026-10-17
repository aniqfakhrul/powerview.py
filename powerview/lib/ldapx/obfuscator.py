from collections.abc import Iterable, Mapping

from powerview.lib.ldapx.chains import (
	build_attrentries_chain,
	build_attrlist_chain,
	build_basedn_chain,
	build_filter_chain,
)
from powerview.lib.ldapx.options import Options
from powerview.lib.ldapx.parser.attributes import AttrEntries
from powerview.lib.ldapx.parser.filter import (
	Filter,
	filter_to_ldap_string,
	query_to_filter,
)


class Obfuscator:
	def __init__(
		self,
		filter_chain: str = "",
		basedn_chain: str = "",
		attrlist_chain: str = "",
		attrentries_chain: str = "",
		options: Options | Mapping[str, str] | None = None,
	):
		self.options = options if isinstance(options, Options) else Options(options)
		self._filter = build_filter_chain(filter_chain, self.options)
		self._basedn = build_basedn_chain(basedn_chain, self.options)
		self._attrlist = build_attrlist_chain(attrlist_chain, self.options)
		self._attrentries = build_attrentries_chain(attrentries_chain, self.options)

	@property
	def strips_ranges(self) -> bool:
		return "Range" in self._attrlist.names

	def filter(self, f: Filter) -> Filter:
		"""Obfuscate a filter; like upstream, leaves of the given tree may be modified in place."""
		return self._filter.execute(f)

	def basedn(self, dn: str) -> str:
		return self._basedn.execute(dn)

	def basedn_safe(self, dn: str) -> str:
		return self._basedn.execute(dn, allow_reference_forms=False)

	def attrlist(self, attrs: Iterable[str]) -> list[str]:
		return self._attrlist.execute(list(attrs))

	def attrentries(self, entries: AttrEntries) -> AttrEntries:
		return self._attrentries.execute(entries)

	def search_strings(self, base: str, query: str, attrs: Iterable[str] | None) -> tuple[str, str, list[str] | None]:
		obfuscated = filter_to_ldap_string(self.filter(query_to_filter(query)))
		new_attrs = self.attrlist(attrs) if attrs is not None else None
		return self.basedn(base), obfuscated, new_attrs
