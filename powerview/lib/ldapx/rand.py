import random
from collections.abc import Callable
from typing import Protocol

Swap = Callable[[int, int], None]


class Source(Protocol):
	def intn(self, n: int) -> int: ...

	def float64(self) -> float: ...

	def shuffle(self, n: int, swap: Swap) -> None: ...


class SystemSource:
	def __init__(self):
		self._random = random.SystemRandom()

	def intn(self, n: int) -> int:
		if n <= 0:
			raise ValueError("invalid argument to intn")
		return self._random.randrange(n)

	def float64(self) -> float:
		return self._random.random()

	def shuffle(self, n: int, swap: Swap) -> None:
		for i in range(n - 1, 0, -1):
			swap(i, self._random.randrange(i + 1))


_source: Source = SystemSource()


def use(source: Source) -> Source:
	"""Replace the process-wide random source and return the previous one, which the caller must restore."""
	global _source
	previous, _source = _source, source
	return previous


def intn(n: int) -> int:
	return _source.intn(n)


def float64() -> float:
	return _source.float64()


def shuffle(n: int, swap: Swap) -> None:
	_source.shuffle(n, swap)
