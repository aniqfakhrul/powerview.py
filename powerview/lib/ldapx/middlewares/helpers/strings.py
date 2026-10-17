from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import from_bytes, to_bytes, to_lower, to_upper

CASE_FOLD_BREAKERS = frozenset("\u0261\u0266\u026a\u026c\u0282\u0287\u029d\u029e\u1d8e")


def generate_garbage_string(n: int, chars: str) -> str:
	pool = to_bytes(chars)
	if n <= 0 or not pool:
		return ""
	return from_bytes(bytes(pool[rand.intn(len(pool))] for _ in range(n)))


def hex_encode_char(char: str) -> str:
	code = ord(char)
	if 0xDC80 <= code <= 0xDCFF:
		code -= 0xDC00
	return "\\%02x" % code


def randomly_hex_encode_string(value: str, prob: float) -> str:
	return "".join(hex_encode_char(char) if rand.float64() < prob else char for char in value)


def randomly_change_case_string(value: str, prob: float) -> str:
	result = []
	for char in value:
		if rand.float64() < prob and char not in CASE_FOLD_BREAKERS:
			result.append(to_lower(char) if rand.intn(2) == 0 else to_upper(char))
		else:
			result.append(char)
	return "".join(result)


def randomly_prepend_zeros_oid(oid: str, max_zeros: int) -> str:
	if max_zeros <= 0:
		return oid
	parts = oid.split(".")
	for index, part in enumerate(parts):
		if to_lower(part) != "oid":
			parts[index] = "0" * (1 + rand.intn(max_zeros)) + part
	return ".".join(parts)
