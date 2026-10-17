"""Go standard library semantics (strconv, strings, unicode) that upstream ldapx relies on."""

import math
import re

from powerview.lib.ldapx._casing import FOLD_CANONICAL, SIMPLE_LOWER, SIMPLE_UPPER

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1

_SPACES = frozenset(
	"\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006"
	"\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"
)
_SIGNED = re.compile(r"[+-]?[0-9]+")
_UNSIGNED = re.compile(r"[0-9]+")
_HEX_DIGITS = "0123456789abcdefABCDEF"


def to_bytes(value: str) -> bytes:
	return value.encode("utf-8", "surrogateescape")


def from_bytes(value: bytes) -> str:
	return value.decode("utf-8", "surrogateescape")


def byte_len(value: str) -> int:
	return len(to_bytes(value))


def byte_slice(value: str, start: int = 0, stop: int | None = None) -> str:
	return from_bytes(to_bytes(value)[start:stop])


def to_lower(value: str) -> str:
	if value.isascii():
		return value.lower()
	return "".join(SIMPLE_LOWER.get(char, char) for char in value)


def to_upper(value: str) -> str:
	if value.isascii():
		return value.upper()
	return "".join(SIMPLE_UPPER.get(char, char) for char in value)


def equal_fold(left: str, right: str) -> bool:
	if len(left) != len(right):
		return False
	return all(a == b or FOLD_CANONICAL.get(a, a) == FOLD_CANONICAL.get(b, b) for a, b in zip(left, right))


def trim_space(value: str) -> str:
	start, end = 0, len(value)
	while start < end and value[start] in _SPACES:
		start += 1
	while end > start and value[end - 1] in _SPACES:
		end -= 1
	return value[start:end]


def wrap_int64(value: int) -> int:
	return (value - INT64_MIN) % (1 << 64) + INT64_MIN


def _bounded_digits(digits: str, limit: int) -> int | None:
	significant = digits.lstrip("0") or "0"
	return int(significant) if len(significant) <= limit else None


def atoi(value: str) -> int | None:
	if not _SIGNED.fullmatch(value):
		return None
	magnitude = _bounded_digits(value.lstrip("+-"), 19)
	if magnitude is None:
		return None
	number = -magnitude if value.startswith("-") else magnitude
	return number if INT64_MIN <= number <= INT64_MAX else None


def parse_uint(value: str, bits: int) -> int | None:
	if not _UNSIGNED.fullmatch(value):
		return None
	number = _bounded_digits(value, 20)
	return number if number is not None and number < (1 << bits) else None


def parse_float(value: str) -> float | None:
	special = _special_float(value)
	if special is not None:
		return special
	if not _is_float_syntax(value):
		return None
	digits = value.replace("_", "")
	try:
		number = float.fromhex(digits) if _is_hex_float(digits) else float(digits)
	except OverflowError:
		return None
	return None if math.isinf(number) else number


def _special_float(value: str) -> float | None:
	lowered = value.lower()
	unsigned = lowered[1:] if lowered[:1] in ("+", "-") else lowered
	if unsigned in ("inf", "infinity"):
		return -math.inf if lowered.startswith("-") else math.inf
	if lowered == "nan":
		return math.nan
	return None


def _is_hex_float(value: str) -> bool:
	unsigned = value[1:] if value[:1] in ("+", "-") else value
	return unsigned[:2].lower() == "0x"


def _is_float_syntax(value: str) -> bool:
	index = 1 if value[:1] in ("+", "-") else 0
	hexadecimal = len(value) > index + 2 and value[index] == "0" and value[index + 1] in "xX"
	if hexadecimal:
		index += 2
	digits = _HEX_DIGITS if hexadecimal else "0123456789"
	saw_dot = saw_digits = underscores = False
	while index < len(value):
		char = value[index]
		if char == "_":
			underscores = True
		elif char == ".":
			if saw_dot:
				break
			saw_dot = True
		elif char in digits:
			saw_digits = True
		else:
			break
		index += 1
	if not saw_digits:
		return False
	if index < len(value) and value[index] in ("pP" if hexadecimal else "eE"):
		index += 1
		if index < len(value) and value[index] in "+-":
			index += 1
		if index >= len(value) or not "0" <= value[index] <= "9":
			return False
		while index < len(value) and ("0" <= value[index] <= "9" or value[index] == "_"):
			underscores = underscores or value[index] == "_"
			index += 1
	elif hexadecimal:
		return False
	return index == len(value) and (not underscores or _underscores_ok(value))


def _underscores_ok(value: str) -> bool:
	saw = "^"
	index = 0
	if value[:1] in ("+", "-"):
		value = value[1:]
	hexadecimal = False
	if len(value) >= 2 and value[0] == "0" and value[1].lower() in "box":
		index = 2
		saw = "0"
		hexadecimal = value[1].lower() == "x"
	for char in value[index:]:
		if "0" <= char <= "9" or (hexadecimal and char in _HEX_DIGITS):
			saw = "0"
		elif char == "_":
			if saw != "0":
				return False
			saw = "_"
		else:
			if saw == "_":
				return False
			saw = "!"
	return saw != "_"
