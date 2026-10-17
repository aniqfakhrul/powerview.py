from collections.abc import Callable

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import to_lower, trim_space
from powerview.lib.ldapx.middlewares.helpers._tables import (
	COMBINING_RUNES,
	FOLD_CLASS_MEMBERS,
	FOLD_LIGATURES,
	IGNORABLE_RUNES,
	MODIFIER_LETTER_RUNES,
	MODIFIER_SYMBOL_RUNES,
	PUNCTUATION_RUNES,
	SORT_KEY_FOLD_MAP,
	SYMBOL_RUNES,
)

MAX_STRIPPABLE_VALUE_LEN = 127

IGNORABLE_MODE_CATEGORIES = {
	"invisible": IGNORABLE_RUNES,
	"marks": COMBINING_RUNES,
	"modlet": MODIFIER_LETTER_RUNES,
	"modsym": MODIFIER_SYMBOL_RUNES,
	"symbols": SYMBOL_RUNES,
	"punct": PUNCTUATION_RUNES,
}


def _csv_tokens(value: str) -> list[str]:
	return [token for token in (to_lower(trim_space(part)) for part in value.split(",")) if token]


def _utf16_len(char: str) -> int:
	return 2 if ord(char) > 0xFFFF else 1


def ignorable_mode_runes(mode: str) -> str:
	tokens = set(_csv_tokens(mode))
	select_all = not tokens or "all" in tokens
	pool = dict.fromkeys(
		char
		for name, runes in IGNORABLE_MODE_CATEGORIES.items()
		if select_all or name in tokens
		for char in runes
	)
	return "".join(pool)


def insert_runes(value: str, pool: str, prob: float) -> str:
	if prob <= 0 or not pool:
		return value

	budget = MAX_STRIPPABLE_VALUE_LEN - sum(_utf16_len(char) for char in value)
	result = []

	def insert():
		nonlocal budget
		if budget <= 0 or rand.float64() >= prob:
			return
		char = pool[rand.intn(len(pool))]
		cost = _utf16_len(char)
		if cost <= budget:
			result.append(char)
			budget -= cost

	for char in value:
		insert()
		result.append(char)
	insert()
	return "".join(result)


def substitute_spaces(value: str, pool: str, prob: float) -> str:
	if prob <= 0 or not pool:
		return value
	return "".join(
		pool[rand.intn(len(pool))] if char == " " and rand.float64() < prob else char
		for char in value
	)


def _fold_class_set(classes: str) -> frozenset | None:
	names = _csv_tokens(classes)
	if not names or "all" in names:
		return None
	return frozenset(char for name in names for char in FOLD_CLASS_MEMBERS.get(name, ""))


def _fold_key(char: str) -> str:
	return chr(ord(char) + 32) if "A" <= char <= "Z" else char


class FoldSubstituter:
	def __init__(self, classes: str):
		allowed = _fold_class_set(classes)

		def restrict(pool: str) -> str:
			return pool if allowed is None else "".join(char for char in pool if char in allowed)

		self.single = {base: restricted for base, pool in SORT_KEY_FOLD_MAP.items() if (restricted := restrict(pool))}
		self.ligatures = tuple((ascii_seq, restricted) for ascii_seq, pool in FOLD_LIGATURES if (restricted := restrict(pool)))

	def apply(self, value: str, prob: float) -> str:
		if prob <= 0:
			return value
		out = []
		index = 0
		while index < len(value):
			ligature = self._match_ligature(value, index)
			if ligature and rand.float64() < prob:
				pool, width = ligature
				out.append(pool[rand.intn(len(pool))])
				index += width
				continue
			pool = self.single.get(_fold_key(value[index]))
			if pool and rand.float64() < prob:
				out.append(pool[rand.intn(len(pool))])
			else:
				out.append(value[index])
			index += 1
		return "".join(out)

	def _match_ligature(self, value: str, index: int):
		for ascii_seq, pool in self.ligatures:
			if index + len(ascii_seq) > len(value):
				continue
			if all(_fold_key(value[index + offset]) == ascii_seq[offset] for offset in range(len(ascii_seq))):
				return pool, len(ascii_seq)
		return None


def transform_dn_values(dn: str, transform: Callable[[str], str]) -> str:
	parts = dn.split(",")
	for index, part in enumerate(parts):
		kv = part.split("=", 1)
		if len(kv) == 2:
			parts[index] = kv[0] + "=" + transform(kv[1])
	return ",".join(parts)
