from collections.abc import Callable

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import equal_fold, to_lower
from powerview.lib.ldapx.middlewares.helpers.strings import (
	generate_garbage_string,
	obfuscate_oid_name,
	randomly_change_case_string,
)
from powerview.lib.ldapx.parser._schema import (
	ATTR_FORMATS,
	OIDS_MAP,
	RFC_OPERATIONAL_ATTRS,
	ROOTDSE_OPERATIONAL_ATTRS,
)

AttrListMiddleware = Callable[[list[str]], list[str]]


def attr_is_decorable(attribute: str) -> bool:
	return attribute not in ("", "*", "+") and ";" not in attribute


def _is_operational(attribute: str) -> bool:
	name = to_lower(attribute)
	return name in ROOTDSE_OPERATIONAL_ATTRS or name in RFC_OPERATIONAL_ATTRS


def rand_case(prob: float) -> AttrListMiddleware:
	return lambda attrs: [randomly_change_case_string(attr, prob) for attr in attrs]


def oid_attribute(max_spaces: int, max_zeros: int) -> AttrListMiddleware:
	return lambda attrs: [obfuscate_oid_name(attr, max_spaces, max_zeros) for attr in attrs]


def duplicate(prob: float) -> AttrListMiddleware:
	def middleware(attrs: list[str]) -> list[str]:
		result = []
		for attr in attrs:
			copies = 2 if rand.float64() < prob else 1
			result.extend([attr] * copies)
		if attrs and len(result) == len(attrs):
			result.append(attrs[rand.intn(len(attrs))])
		return result

	return middleware


def garbage_existing(max_garbage: int) -> AttrListMiddleware:
	existing = tuple(ATTR_FORMATS)

	def middleware(attrs: list[str]) -> list[str]:
		if not attrs or max_garbage <= 0:
			return attrs
		count = 1 + rand.intn(max_garbage)
		return list(attrs) + [existing[rand.intn(len(existing))] for _ in range(count)]

	return middleware


def garbage_non_existing(max_garbage: int, garbage_size: int, charset: str) -> AttrListMiddleware:
	def fresh_garbage() -> str:
		while True:
			garbage = generate_garbage_string(garbage_size, charset)
			if to_lower(garbage) not in OIDS_MAP:
				return garbage

	def middleware(attrs: list[str]) -> list[str]:
		if not attrs or max_garbage <= 0:
			return attrs
		count = 1 + rand.intn(max_garbage)
		return list(attrs) + [fresh_garbage() for _ in range(count)]

	return middleware


def add_wildcard() -> AttrListMiddleware:
	return lambda attrs: list(attrs) + ["*"]


def add_plus() -> AttrListMiddleware:
	return lambda attrs: list(attrs) + (["+"] if attrs else ["*", "+"])


def replace_with_wildcard() -> AttrListMiddleware:
	def middleware(attrs: list[str]) -> list[str]:
		return ["*"] + [attr for attr in attrs if attr == "+" or _is_operational(attr)]

	return middleware


def replace_with_empty() -> AttrListMiddleware:
	def middleware(attrs: list[str]) -> list[str]:
		kept = [attr for attr in attrs if attr == "+" or _is_operational(attr)]
		return (["*"] + kept) if kept else []

	return middleware


def reorder_list() -> AttrListMiddleware:
	def middleware(attrs: list[str]) -> list[str]:
		result = list(attrs)

		def swap(i: int, j: int) -> None:
			result[i], result[j] = result[j], result[i]

		rand.shuffle(len(result), swap)
		return result

	return middleware


def range_option(option: str) -> AttrListMiddleware:
	return lambda attrs: [attr + ";range=" + option if attr_is_decorable(attr) else attr for attr in attrs]


def is_completed_range_option(option: str) -> bool:
	prefix = "range="
	if len(option) < len(prefix) or not equal_fold(option[:len(prefix)], prefix):
		return False
	low, separator, high = option[len(prefix):].partition("-")
	return bool(separator) and low != "" and high == "*" and all("0" <= char <= "9" for char in low)


def strip_completed_range_option(description: str) -> str:
	name, *options = description.split(";")
	return ";".join([name] + [option for option in options if not is_completed_range_option(option)])
