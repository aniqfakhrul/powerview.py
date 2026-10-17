import hashlib
import json
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import to_bytes, wrap_int64
from powerview.lib.ldapx.parser.filter import (
	FilterAnd,
	FilterApproxMatch,
	FilterEqualityMatch,
	FilterExtensibleMatch,
	FilterGreaterOrEqual,
	FilterLessOrEqual,
	FilterNot,
	FilterOr,
	FilterPresent,
	FilterSubstring,
)

FIXTURES = Path(__file__).parent / "fixtures"

_RNG_LEN = 607
_RNG_TAP = 273
_INT32_MAX = (1 << 31) - 1
_INT63_MASK = (1 << 63) - 1
_UINT32_MASK = (1 << 32) - 1
_UINT64_MASK = (1 << 64) - 1


@lru_cache(maxsize=1)
def _cooked() -> tuple[int, ...]:
	return tuple(int(line) for line in (FIXTURES / "gorand_cooked.txt").read_text().split())


@lru_cache(maxsize=1)
def parity_fixture() -> dict:
	return json.loads((FIXTURES / "parity.json").read_text())


def _seedrand(x: int) -> int:
	hi, lo = divmod(x, 44488)
	x = 48271 * lo - 3399 * hi
	return x + _INT32_MAX if x < 0 else x


class GoRand:
	def __init__(self, seed: int):
		cooked = _cooked()
		self._tap = 0
		self._feed = _RNG_LEN - _RNG_TAP
		self._vec = [0] * _RNG_LEN
		seed = abs(seed) % _INT32_MAX * (-1 if seed < 0 else 1)
		if seed < 0:
			seed += _INT32_MAX
		if seed == 0:
			seed = 89482311
		x = seed
		for i in range(-20, _RNG_LEN):
			x = _seedrand(x)
			if i >= 0:
				u = wrap_int64(x << 40)
				x = _seedrand(x)
				u ^= x << 20
				x = _seedrand(x)
				u ^= x
				self._vec[i] = u ^ cooked[i]

	def _uint64(self) -> int:
		self._tap = (self._tap - 1) % _RNG_LEN
		self._feed = (self._feed - 1) % _RNG_LEN
		value = wrap_int64(self._vec[self._feed] + self._vec[self._tap])
		self._vec[self._feed] = value
		return value & _UINT64_MASK

	def int63(self) -> int:
		return self._uint64() & _INT63_MASK

	def _int31(self) -> int:
		return self.int63() >> 32

	def _uint32(self) -> int:
		return (self.int63() >> 31) & _UINT32_MASK

	def _int31n(self, n: int) -> int:
		if n & (n - 1) == 0:
			return self._int31() & (n - 1)
		maximum = (1 << 31) - 1 - (1 << 31) % n
		value = self._int31()
		while value > maximum:
			value = self._int31()
		return value % n

	def _int63n(self, n: int) -> int:
		if n & (n - 1) == 0:
			return self.int63() & (n - 1)
		maximum = (1 << 63) - 1 - (1 << 63) % n
		value = self.int63()
		while value > maximum:
			value = self.int63()
		return value % n

	def _lemire_int31n(self, n: int) -> int:
		product = self._uint32() * n
		low = product & _UINT32_MASK
		if low < n:
			threshold = ((-n) & _UINT32_MASK) % n
			while low < threshold:
				product = self._uint32() * n
				low = product & _UINT32_MASK
		return product >> 32

	def intn(self, n: int) -> int:
		if n <= 0:
			raise ValueError("invalid argument to Intn")
		return self._int31n(n) if n <= _INT32_MAX else self._int63n(n)

	def float64(self) -> float:
		while True:
			value = float(self.int63()) / (1 << 63)
			if value != 1:
				return value

	def shuffle(self, n: int, swap) -> None:
		i = n - 1
		while i > (1 << 31) - 2:
			swap(i, self._int63n(i + 1))
			i -= 1
		while i > 0:
			swap(i, self._lemire_int31n(i + 1))
			i -= 1


@contextmanager
def go_rand(seed: int):
	previous = rand.use(GoRand(seed))
	try:
		yield
	finally:
		rand.use(previous)


def _hex(value: str) -> str:
	return to_bytes(value).hex()


_ASSERTION_TYPES = {
	FilterEqualityMatch: "equality",
	FilterGreaterOrEqual: "greater_or_equal",
	FilterLessOrEqual: "less_or_equal",
	FilterApproxMatch: "approx",
}


def encode_filter(f) -> dict:
	if isinstance(f, (FilterAnd, FilterOr)):
		return {"type": "and" if isinstance(f, FilterAnd) else "or", "filters": [encode_filter(sub) for sub in f.filters]}
	if isinstance(f, FilterNot):
		return {"type": "not", "filter": encode_filter(f.filter)}
	if type(f) in _ASSERTION_TYPES:
		return {"type": _ASSERTION_TYPES[type(f)], "attribute": _hex(f.attribute_desc), "value": _hex(f.assertion_value)}
	if isinstance(f, FilterPresent):
		return {"type": "present", "attribute": _hex(f.attribute_desc)}
	if isinstance(f, FilterSubstring):
		parts = [[_hex(part.initial), _hex(part.any), _hex(part.final)] for part in f.substrings]
		return {"type": "substring", "attribute": _hex(f.attribute_desc), "substrings": parts}
	if isinstance(f, FilterExtensibleMatch):
		return {"type": "extensible", "rule": _hex(f.matching_rule), "attribute": _hex(f.attribute_desc), "value": _hex(f.match_value), "dn": f.dn_attributes}
	raise TypeError(type(f).__name__)


def encode_strings(values) -> list[str]:
	return [_hex(value) for value in values]


def digest(outputs: list) -> str:
	canonical = json.dumps(outputs, sort_keys=True, separators=(",", ":"))
	return hashlib.sha256(canonical.encode()).hexdigest()[:16]
