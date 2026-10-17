import argparse
import json
import random
import re
import statistics
import subprocess
import sys
from collections import Counter
from contextlib import nullcontext
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from powerview.lib.ldapx import (  # noqa: E402
	ATTRLIST_CODES,
	BASEDN_CODES,
	FILTER_CODES,
	ChainError,
	Obfuscator,
)
from powerview.lib.ldapx.gostd import from_bytes  # noqa: E402
from powerview.lib.ldapx.middlewares.attrentries import Attribute  # noqa: E402
from powerview.lib.ldapx.parser.filter import (  # noqa: E402
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
	SubstringFilter,
	filter_to_query,
	query_to_filter,
)
from tools.ldapx.support import encode_filter, encode_strings, go_rand, parity_fixture  # noqa: E402

MAP_ORDER_CODES = {"filter": "T", "attrlist": "g"}
RUNE_REBUILDING_CODES = "CsIEUWK"
BASEDN_OPTIONS = {"BDNGuid": "00112233445566778899aabbccddeeff", "BDNSid": "S-1-5-21-1-2-3-512"}
FILTER_OPTIONS = {"FiltObjCategoryRootDN": "DC=wonka,DC=lab"}
_ASSERTIONS = {"equality": FilterEqualityMatch, "greater_or_equal": FilterGreaterOrEqual, "less_or_equal": FilterLessOrEqual, "approx": FilterApproxMatch}


class Oracle:
	def __init__(self, path: str):
		self._process = subprocess.Popen([path], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

	def run(self, **request) -> list:
		self._process.stdin.write(json.dumps(request) + "\n")
		self._process.stdin.flush()
		response = json.loads(self._process.stdout.readline())
		if "error" in response:
			raise RuntimeError(response["error"])
		return response["outputs"]


def unhex(value: str) -> str:
	return from_bytes(bytes.fromhex(value))


def decode_filter(node: dict):
	kind = node["type"]
	if kind in ("and", "or"):
		return (FilterAnd if kind == "and" else FilterOr)([decode_filter(sub) for sub in node["filters"]])
	if kind == "not":
		return FilterNot(decode_filter(node["filter"]))
	if kind in _ASSERTIONS:
		return _ASSERTIONS[kind](unhex(node["attribute"]), unhex(node["value"]))
	if kind == "present":
		return FilterPresent(unhex(node["attribute"]))
	if kind == "substring":
		return FilterSubstring(unhex(node["attribute"]), [SubstringFilter(*map(unhex, part)) for part in node["substrings"]])
	return FilterExtensibleMatch(unhex(node["rule"]), unhex(node["attribute"]), unhex(node["value"]), node["dn"])


def python_outputs(kind: str, chain: str, value, options: dict, seed: int | None, samples: int) -> list:
	with go_rand(seed) if seed is not None else nullcontext():
		if kind == "filter":
			obfuscator = Obfuscator(filter_chain=chain, options=options)
			return [encode_filter(obfuscator.filter(query_to_filter(value))) for _ in range(samples)]
		if kind == "basedn":
			obfuscator = Obfuscator(basedn_chain=chain, options=options)
			return [encode_strings([obfuscator.basedn(value)])[0] for _ in range(samples)]
		if kind == "attrlist":
			obfuscator = Obfuscator(attrlist_chain=chain, options=options)
			return [encode_strings(obfuscator.attrlist(value)) for _ in range(samples)]
		obfuscator = Obfuscator(attrentries_chain=chain, options=options)
		return [encode_strings(entry.name for entry in obfuscator.attrentries([Attribute(name, ["v"]) for name in value])) for _ in range(samples)]


def has_invalid_utf8(query: str) -> bool:
	return any(0xDC80 <= ord(char) <= 0xDCFF for char in filter_to_query(query_to_filter(query)))


def random_chain(rng: random.Random, codes: str, length: int) -> str:
	return "".join(rng.choice(codes) for _ in range(rng.randint(1, length)))


def exact_section(oracle: Oracle, fixture: dict, seeds: int, samples: int, rng: random.Random) -> int:
	filter_codes = "".join(code for code in FILTER_CODES if code != MAP_ORDER_CODES["filter"])
	attrlist_codes = "".join(code for code in ATTRLIST_CODES if code != MAP_ORDER_CODES["attrlist"])
	binary = [query for query in fixture["filters"] if has_invalid_utf8(query)]
	plans = []
	for seed in range(seeds):
		chain = random_chain(rng, filter_codes, 6)
		query = rng.choice(fixture["filters"])
		if query in binary and any(code in chain for code in RUNE_REBUILDING_CODES):
			chain = "".join(code for code in chain if code not in RUNE_REBUILDING_CODES) or "Z"
		plans.append(("filter", chain, query, FILTER_OPTIONS, seed))
		basedn_chain = random_chain(rng, "".join(c for c in BASEDN_CODES if c not in "UI"), 4)
		try:
			Obfuscator(basedn_chain=basedn_chain, options=BASEDN_OPTIONS)
		except ChainError:
			basedn_chain = "CX"
		plans.append(("basedn", basedn_chain, rng.choice(fixture["dns"]), BASEDN_OPTIONS, seed))
		plans.append(("attrlist", random_chain(rng, attrlist_codes, 5), rng.choice(fixture["attr_lists"]), {}, seed))
		plans.append(("attrentries", random_chain(rng, "OCR", 4), fixture["entries"], {}, seed))

	mismatches = Counter()
	examples = []
	for kind, chain, value, options, seed in plans:
		request = {"kind": kind, "chain": chain, "options": options, "seed": seed, "n": samples}
		request["attrs" if kind in ("attrlist", "attrentries") else "input"] = value
		expected = oracle.run(**request)
		actual = python_outputs(kind, chain, value, options, seed, samples)
		if expected != actual:
			mismatches[kind] += 1
			examples.append((kind, chain, value, seed))
	total = Counter(kind for kind, *_ in plans)
	print("== Exact seeded parity (random chains, %d seeds, %d samples each)" % (seeds, samples))
	for kind in ("filter", "basedn", "attrlist", "attrentries"):
		print("  %-12s %5d/%-5d identical" % (kind, total[kind] - mismatches[kind], total[kind]))
	for example in examples[:5]:
		print("  mismatch:", example)
	return sum(mismatches.values())


def lead_zeros(text: str) -> float:
	runs = re.findall(r"(?<=[=\-])(0*)(?=[1-9][0-9]*)", text)
	return statistics.mean(len(run) for run in runs) if runs else 0.0


def double_negations(text: str) -> float:
	leaves = re.findall(r"\(([^()!&|]+)\)", text)
	return text.count("(!(!") / max(1, len(leaves))


def case_flip(original: str, text: str) -> float | None:
	if original.lower() != text.lower():
		return None
	letters = [(a, b) for a, b in zip(original, text) if a.isalpha()]
	return 100 * sum(a != b for a, b in letters) / max(1, len(letters))


METRICS = [
	("C", "filter", "(&(objectClass=group)(cn=Domain Admins))", "letters case-flipped %", lambda q, t: case_flip(q, t)),
	("Z", "filter", "(&(samAccountType=805306368)(userAccountControl=512))", "zeros per number", lambda q, t: lead_zeros(t)),
	("Z", "filter", "(objectSid=S-1-5-21-1275038127-4001443720-2863730958-512)", "zeros per SID part", lambda q, t: lead_zeros(t)),
	("D", "filter", "(&(objectClass=user)(cn=x)(sn=y))", "(!(! per leaf", lambda q, t: double_negations(t)),
	("B", "filter", "(cn=x)", "boolean wrappers", lambda q, t: t.count("(&") + t.count("(|")),
	("X", "filter", "(memberOf=CN=Domain Admins,CN=Users,DC=wonka,DC=lab)", "hex escapes", lambda q, t: t.count("\\\\")),
	("S", "filter", "(memberOf=CN=Domain Admins,CN=Users,DC=wonka,DC=lab)", "spaces added", lambda q, t: t.count(" ") - q.count(" ")),
	("G", "filter", "(cn=x)", "garbage siblings", lambda q, t: t.count("(") - 2),
	("s", "filter", "(cn=Administrator)", "% split", lambda q, t: 100 * ("*" in t)),
	("t", "filter", "(whenCreated>=20240101000000.0Z)", "chars added", lambda q, t: len(t) - len(q)),
	("n", "filter", "(aNR==admin)", "chars added", lambda q, t: len(t) - len(q) - 1),
	("P", "filter", "(userAccountControl:1.2.840.113556.1.4.803:=2)", "% dn toggled", lambda q, t: 100 * (":dn:" in t)),
	("O", "filter", "(cn=x)", "attribute length", lambda q, t: len(t.split("=")[0])),
	("R", "filter", "(&(cn=a)(sn=b)(name=c))", "% reordered", lambda q, t: 100 * (not t.startswith("(&(cn=a)"))),
	("T", "filter", "(objectClass=*)", "length", lambda q, t: len(t)),
	("T", "filter", "(objectClass=*)", "% typo tautology", lambda q, t: 100 * (t.startswith("(!(") and t.count("(") == 2)),
	("U", "filter", "(cn=Domain Admins)", "code points added", lambda q, t: len(t) - len(q)),
	("W", "filter", "(cn=Domain Admins)", "% spaces replaced", lambda q, t: 100 * (" " not in t)),
	("K", "filter", "(cn=Administrator)", "% chars folded", lambda q, t: 100 * sum(ord(c) > 127 for c in t) / 13),
]


def statistical_section(oracle: Oracle, samples: int, rng: random.Random) -> None:
	print("\n== Statistical parity (upstream seeded streams vs the port's production RNG, %d samples per side)" % samples)
	print("  %-4s %-26s %10s %10s %8s" % ("code", "metric", "upstream", "port", "delta"))
	for code, kind, query, name, metric in METRICS:
		go_values, py_values = [], []
		for _ in range(samples // 50):
			for node in oracle.run(kind=kind, chain=code, input=query, options=FILTER_OPTIONS, seed=rng.getrandbits(62), n=50):
				value = metric(query, filter_to_query(decode_filter(node)))
				if value is not None:
					go_values.append(value)
			for node in python_outputs(kind, code, query, FILTER_OPTIONS, None, 50):
				value = metric(query, filter_to_query(decode_filter(node)))
				if value is not None:
					py_values.append(value)
		go_mean, py_mean = statistics.mean(go_values), statistics.mean(py_values)
		delta = (py_mean - go_mean) / go_mean * 100 if go_mean else py_mean
		print("  %-4s %-26s %10.3f %10.3f %7.1f%%" % (code, name, go_mean, py_mean, delta))

	print("\n== attrlist g (GarbageExisting) member distribution")
	go_counts, py_counts = Counter(), Counter()
	for _ in range(samples // 50):
		for output in oracle.run(kind="attrlist", chain="g", attrs=["cn"], seed=rng.getrandbits(62), n=50):
			go_counts[len(output)] += 1
		for output in python_outputs("attrlist", "g", ["cn"], {}, None, 50):
			py_counts[len(output)] += 1
	print("  list length histogram upstream=%s port=%s" % (dict(sorted(go_counts.items())), dict(sorted(py_counts.items()))))


def main() -> int:
	parser = argparse.ArgumentParser(description="Compare powerview's ldapx port against upstream ldapx")
	parser.add_argument("--oracle", default="/tmp/pv-ldapx-oracle", help="path to the built tools/ldapx/cmd/oracle binary")
	parser.add_argument("--seeds", type=int, default=500)
	parser.add_argument("--samples", type=int, default=2000)
	parser.add_argument("--rng-seed", type=int, default=1337)
	args = parser.parse_args()
	rng = random.Random(args.rng_seed)
	oracle = Oracle(args.oracle)
	mismatches = exact_section(oracle, parity_fixture(), args.seeds, 4, rng)
	statistical_section(oracle, args.samples, rng)
	return 1 if mismatches else 0


if __name__ == "__main__":
	sys.exit(main())
