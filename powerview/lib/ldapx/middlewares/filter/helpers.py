import re
from collections.abc import Callable

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import atoi, byte_len, byte_slice, trim_space, wrap_int64
from powerview.lib.ldapx.middlewares.helpers.strings import (
	generate_garbage_string,
	randomly_hex_encode_string,
)
from powerview.lib.ldapx.parser.filter import Filter, FilterAnd, FilterNot, FilterOr

FilterMiddleware = Callable[[Filter], Filter]

CHAR_ORDERING = "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"

_TIMESTAMP = re.compile(r"^([0-9]{14})[.,](.*)(Z|[+-].{4})(.*)")


def leaf_applier(middleware: FilterMiddleware) -> FilterMiddleware:
	def apply(f: Filter) -> Filter:
		if isinstance(f, FilterAnd):
			return FilterAnd([apply(sub) for sub in f.filters])
		if isinstance(f, FilterOr):
			return FilterOr([apply(sub) for sub in f.filters])
		if isinstance(f, FilterNot):
			return FilterNot(apply(f.filter))
		return middleware(f)

	return apply


def split_slice(items: list, index: int) -> tuple[list, list]:
	return list(items[:index]), list(items[index + 1:])


def randomly_hex_encode_dn_string(dn: str, prob: float) -> str:
	parts = dn.split(",")
	for index, part in enumerate(parts):
		kv = part.split("=", 1)
		if len(kv) == 2:
			parts[index] = kv[0] + "=" + randomly_hex_encode_string(kv[1], prob)
	return ",".join(parts)


def replace_timestamp(value: str, max_chars: int, charset: str, use_comma: bool) -> str:
	def replace(match: re.Match) -> str:
		prepend = append = ""
		first = generate_garbage_string(max_chars, charset)
		second = generate_garbage_string(max_chars, charset)
		choice = rand.intn(3)
		if choice == 0:
			prepend = first
		elif choice == 1:
			append = second
		else:
			prepend, append = first, second
		separator = "," if use_comma else "."
		digits, fraction, zone, rest = match.groups()
		return digits + separator + fraction + prepend + zone + append + rest

	return _TIMESTAMP.sub(replace, value, count=1)


def prepend_zeros_to_sid(sid: str, max_zeros: int) -> str:
	if max_zeros <= 0:
		return sid
	parts = sid.split("-")
	for index in range(1, len(parts)):
		part = parts[index]
		for position, char in enumerate(part):
			if "0" <= char <= "9":
				parts[index] = part[:position] + "0" * (1 + rand.intn(max_zeros)) + part[position:]
				break
	return "-".join(parts)


def prepend_zeros_to_number(value: str, max_zeros: int) -> str:
	if max_zeros <= 0:
		return value
	zeros = "0" * (1 + rand.intn(max_zeros))
	if value.startswith("-"):
		return "-" + zeros + value[1:]
	return zeros + value


def add_anr_spacing(value: str, max_spaces: int) -> str:
	if max_spaces <= 0:
		return value
	spaces_first = " " * (1 + rand.intn(max_spaces))
	spaces_equal = " " * (1 + rand.intn(max_spaces))
	spaces_last = " " * (1 + rand.intn(max_spaces))
	if trim_space(value).startswith("="):
		index = value.find("=")
		if index != -1 and index + 1 < len(value) and rand.float64() < 0.5:
			value = value[:index + 1] + spaces_equal + value[index + 1:]

	choice = rand.intn(3)
	if choice == 0:
		return spaces_first + value
	if choice == 1:
		return value + spaces_last
	return spaces_first + value + spaces_last


def add_dn_spacing(value: str, max_spaces: int) -> str:
	if max_spaces <= 0:
		return value
	parts = value.split(",")
	for index, part in enumerate(parts):
		kv = part.split("=", 1)
		if len(kv) != 2:
			continue
		choice = rand.intn(4)
		spaces = " " * (1 + rand.intn(max_spaces))
		if choice == 0:
			kv[0] += spaces
		elif choice == 1:
			kv[1] = spaces + kv[1]
		elif choice == 2:
			kv[0] = spaces + kv[0]
		else:
			kv[1] += spaces
		parts[index] = "=".join(kv)
	return ",".join(parts)


def add_sid_spacing(sid: str, max_spaces: int) -> str:
	if max_spaces <= 0:
		return sid
	parts = sid.split("-")
	if len(parts) >= 3:
		parts[1] = " " * rand.intn(max_spaces + 1) + parts[1]
		parts[2] = " " * rand.intn(max_spaces + 1) + parts[2]
	return "-".join(parts)


def get_next_string(value: str) -> str:
	chars = list(value)
	for index in range(len(chars) - 1, -1, -1):
		position = CHAR_ORDERING.find(chars[index])
		if position < len(CHAR_ORDERING) - 1:
			chars[index] = CHAR_ORDERING[position + 1]
			return "".join(chars)
		chars[index] = CHAR_ORDERING[0]
	return value + CHAR_ORDERING[0]


def get_previous_string(value: str) -> str:
	chars = list(value)
	for index in range(len(chars) - 1, -1, -1):
		position = CHAR_ORDERING.find(chars[index])
		if position > 0:
			chars[index] = CHAR_ORDERING[position - 1]
			return "".join(chars)
		chars[index] = CHAR_ORDERING[-1]
	if byte_len(value) > 1:
		return byte_slice(value, 0, byte_len(value) - 1)
	return value


def get_next_sid(sid: str) -> str:
	parts = sid.split("-")
	number = atoi(parts[-1])
	if number is not None:
		parts[-1] = str(wrap_int64(number + 1))
	return "-".join(parts)


def get_previous_sid(sid: str) -> str:
	parts = sid.split("-")
	number = atoi(parts[-1])
	if number is not None and number > 0:
		parts[-1] = str(number - 1)
	return "-".join(parts)
