import unittest

from powerview.lib.ldapx import UPSTREAM_REVISION
from powerview.lib.ldapx.middlewares.attrentries import Attribute
from powerview.lib.ldapx.obfuscator import Obfuscator
from powerview.lib.ldapx.parser.filter import filter_to_query, query_to_filter
from tools.ldapx.support import (
	GoRand,
	digest,
	encode_filter,
	encode_strings,
	go_rand,
	parity_fixture,
)


def run_case(fixture: dict, kind: str, chain: str, input_index: int, options_index: int, seed: int) -> list:
	options = fixture["option_sets"][options_index]
	samples = fixture["samples"]
	with go_rand(seed):
		if kind == "filter":
			obfuscator = Obfuscator(filter_chain=chain, options=options)
			query = fixture["filters"][input_index]
			return [encode_filter(obfuscator.filter(query_to_filter(query))) for _ in range(samples)]
		if kind in ("basedn", "basedn_safe"):
			obfuscator = Obfuscator(basedn_chain=chain, options=options)
			execute = obfuscator.basedn if kind == "basedn" else obfuscator.basedn_safe
			dn = fixture["dns"][input_index]
			return [to_hex(execute(dn)) for _ in range(samples)]
		if kind == "attrlist":
			obfuscator = Obfuscator(attrlist_chain=chain, options=options)
			attrs = fixture["attr_lists"][input_index]
			return [encode_strings(obfuscator.attrlist(attrs)) for _ in range(samples)]
		obfuscator = Obfuscator(attrentries_chain=chain, options=options)
		entries = [Attribute(name, ["v"]) for name in fixture["entries"]]
		return [encode_strings(entry.name for entry in obfuscator.attrentries(entries)) for _ in range(samples)]


def to_hex(value: str) -> str:
	return encode_strings([value])[0]


class UpstreamParityTests(unittest.TestCase):
	@classmethod
	def setUpClass(cls):
		cls.fixture = parity_fixture()

	def test_fixture_matches_pinned_revision(self):
		self.assertEqual(self.fixture["revision"], UPSTREAM_REVISION)

	def test_go_random_source_port(self):
		for vector in self.fixture["random"]:
			source = GoRand(vector["seed"])
			self.assertEqual([source.int63() for _ in vector["int63"]], vector["int63"])
			self.assertEqual([[n, source.intn(n)] for n, _ in vector["intn"]], vector["intn"])
			self.assertEqual([source.float64() for _ in vector["float64"]], vector["float64"])
			permutation = list(range(len(vector["shuffle"])))

			def swap(i, j):
				permutation[i], permutation[j] = permutation[j], permutation[i]

			source.shuffle(len(permutation), swap)
			self.assertEqual(permutation, vector["shuffle"])

	def test_filter_rendering_matches_upstream(self):
		for query, expected in zip(self.fixture["filters"], self.fixture["renders"]):
			self.assertEqual(to_hex(filter_to_query(query_to_filter(query))), expected)

	def test_seeded_chains_are_bit_identical_to_upstream(self):
		failures = []
		for kind, chain, input_index, options_index, seed, expected in self.fixture["cases"]:
			actual = digest(run_case(self.fixture, kind, chain, input_index, options_index, seed))
			if actual != expected:
				failures.append((kind, chain, input_index, options_index, seed))
		self.assertEqual(failures[:20], [], "%d of %d cases diverge from upstream" % (len(failures), len(self.fixture["cases"])))


if __name__ == "__main__":
	unittest.main()
