from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import to_lower
from powerview.lib.ldapx.middlewares.helpers.strings import (
	randomly_change_case_string,
	randomly_prepend_zeros_oid,
)
from powerview.lib.ldapx.parser._schema import OIDS_MAP
from powerview.lib.ldapx.parser.attributes import is_oid


@dataclass(slots=True)
class Attribute:
	name: str
	values: list[Any] = field(default_factory=list)


AttrEntries = list[Attribute]
AttrEntriesMiddleware = Callable[[AttrEntries], AttrEntries]


def rand_case(prob: float) -> AttrEntriesMiddleware:
	return lambda entries: [Attribute(randomly_change_case_string(entry.name, prob), entry.values) for entry in entries]


def oid_attribute(max_spaces: int, max_zeros: int, include_prefix: bool) -> AttrEntriesMiddleware:
	def obfuscate(attribute: str) -> str:
		name = OIDS_MAP.get(to_lower(attribute), attribute)
		if is_oid(name):
			if max_spaces > 0:
				name += " " * (1 + rand.intn(max_spaces))
			if max_zeros > 0:
				name = randomly_prepend_zeros_oid(name, max_zeros)
			# Upstream always applies the prefix and ignores include_prefix.
			if not to_lower(name).startswith("oid."):
				name = "oID." + name
		return name

	return lambda entries: [Attribute(obfuscate(entry.name), entry.values) for entry in entries]


def reorder_list() -> AttrEntriesMiddleware:
	def middleware(entries: AttrEntries) -> AttrEntries:
		result = list(entries)

		def swap(i: int, j: int) -> None:
			result[i], result[j] = result[j], result[i]

		rand.shuffle(len(result), swap)
		return result

	return middleware
