from collections.abc import Callable

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.middlewares.helpers.strings import (
	obfuscate_oid_name,
	randomly_change_case_string,
)
from powerview.lib.ldapx.parser.attributes import AttrEntries, Attribute

AttrEntriesMiddleware = Callable[[AttrEntries], AttrEntries]


def rand_case(prob: float) -> AttrEntriesMiddleware:
	return lambda entries: [Attribute(randomly_change_case_string(entry.name, prob), entry.values) for entry in entries]


def oid_attribute(max_spaces: int, max_zeros: int) -> AttrEntriesMiddleware:
	return lambda entries: [Attribute(obfuscate_oid_name(entry.name, max_spaces, max_zeros), entry.values) for entry in entries]


def reorder_list() -> AttrEntriesMiddleware:
	def middleware(entries: AttrEntries) -> AttrEntries:
		result = list(entries)

		def swap(i: int, j: int) -> None:
			result[i], result[j] = result[j], result[i]

		rand.shuffle(len(result), swap)
		return result

	return middleware
