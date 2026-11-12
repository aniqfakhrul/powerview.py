import random
from contextlib import contextmanager

from powerview.lib.ldapx import rand


class SeededSource:
	def __init__(self, seed: int):
		self._random = random.Random(seed)

	def intn(self, n: int) -> int:
		return self._random.randrange(n)

	def float64(self) -> float:
		return self._random.random()

	def shuffle(self, n: int, swap) -> None:
		for i in range(n - 1, 0, -1):
			swap(i, self._random.randrange(i + 1))


@contextmanager
def seeded(seed: int):
	previous = rand.use(SeededSource(seed))
	try:
		yield
	finally:
		rand.use(previous)
