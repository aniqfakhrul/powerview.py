import argparse
import json
import unittest

from ldap3.operation.search import parse_filter
from pyasn1.codec.ber import encoder

from powerview.lib.ldapx import (
	ChainError,
	Obfuscator,
	OptionError,
	Options,
	parse_option,
	rand,
)
from powerview.lib.ldapx.gostd import (
	atoi,
	equal_fold,
	from_bytes,
	parse_float,
	parse_uint,
	to_bytes,
)
from powerview.lib.ldapx.parser.asn1 import filter_to_asn1
from powerview.lib.ldapx.parser.filter import (
	FilterEqualityMatch,
	FilterSubstring,
	FilterSyntaxError,
	filter_to_ldap_string,
	filter_to_query,
	query_to_filter,
)
from powerview.utils.obfuscation import (
	DEFAULT_CHAINS,
	ObfuscationError,
	ObfuscationSettings,
	operations_argument,
	option_argument,
)
from tools.ldapx.support import go_rand

INVALID_UTF8 = from_bytes(b"\xe9t\xe9")


class ParserTests(unittest.TestCase):
	def test_escaped_bytes_decode_as_utf8(self):
		self.assertEqual(query_to_filter(r"(cn=caf\c3\a9)"), FilterEqualityMatch("cn", "café"))

	def test_invalid_utf8_bytes_round_trip_losslessly(self):
		parsed = query_to_filter(r"(cn=\e9t\e9)")
		self.assertEqual(to_bytes(parsed.assertion_value), b"\xe9t\xe9")
		self.assertEqual(filter_to_ldap_string(parsed), r"(cn=\e9t\e9)")

	def test_syntax_errors_follow_upstream(self):
		for query in ("", "cn=x", r"(cn=\zz)", r"(cn=\a)", "(cn)"):
			with self.subTest(query=query), self.assertRaises(FilterSyntaxError):
				query_to_filter(query)

	def test_ldap_string_is_valid_rfc4515_for_ldap3(self):
		self.assertEqual(filter_to_ldap_string(query_to_filter(r"(cn=a\2a\28b\29\5c)")), r"(cn=a\2a\28b\29\5c)")
		with go_rand(9):
			obfuscated = Obfuscator("CZNDRGxsP").filter(query_to_filter("(&(cn=a*b)(uid=x)(member=CN=a,DC=b))"))
		parse_filter(filter_to_ldap_string(obfuscated), None, True, True, None, False)

	def test_empty_substring_renders_like_upstream(self):
		self.assertEqual(filter_to_query(FilterSubstring("cn", [])), "(cn=)")


class ScriptedSource:
	def __init__(self, values):
		self._values = iter(values)

	def intn(self, n):
		return next(self._values)

	def float64(self):
		return 0.0

	def shuffle(self, n, swap):
		pass


class EncodingTests(unittest.TestCase):
	def test_empty_substring_tautology_encodes_like_upstream(self):
		previous = rand.use(ScriptedSource([5, 0, 1, 1, 1]))
		try:
			tautology = Obfuscator("T").filter(query_to_filter("(objectClass=*)"))
		finally:
			rand.use(previous)
		substring = tautology.filters[1]
		attribute = to_bytes(substring.attribute_desc)
		self.assertEqual(substring.substrings, [])
		self.assertEqual(encoder.encode(filter_to_asn1(substring)), bytes([0xA4, len(attribute) + 4, 0x04, len(attribute)]) + attribute + b"\x30\x00")

	def test_empty_extensible_value_is_omitted_like_upstream(self):
		self.assertEqual(encoder.encode(filter_to_asn1(query_to_filter("(cn:=)"))).hex(), "a9048202636e")


class GoSemanticsTests(unittest.TestCase):
	def test_equal_fold_uses_unicode_simple_folding(self):
		self.assertTrue(equal_fold("Kelvin", "\u212aELVIN"))
		self.assertTrue(equal_fold("\u017f", "S"))
		self.assertFalse(equal_fold("\u0131", "I"))
		self.assertFalse(equal_fold("\u0130", "i"))

	def test_parse_float_follows_strconv(self):
		accepted = {"0.7": 0.7, "1.": 1.0, "+.5": 0.5, "0x1.8p1": 3.0, "0_0.0": 0.0, "1_000.5": 1000.5, "1e-400": 0.0, "-Infinity": float("-inf")}
		for value, expected in accepted.items():
			with self.subTest(value=value):
				self.assertEqual(parse_float(value), expected)
		for value in ("1e309", "+NaN", "-nan", "0x10", "infinit", "1__0", "_1", " 1", "0b1", ""):
			with self.subTest(value=value):
				self.assertIsNone(parse_float(value))

	def test_integer_parsing_is_bounded_like_strconv(self):
		self.assertIsNone(atoi("9" * 5000))
		self.assertEqual(atoi("0" * 5000 + "42"), 42)
		self.assertIsNone(atoi("9223372036854775808"))
		self.assertEqual(atoi("-9223372036854775808"), -(1 << 63))
		self.assertIsNone(parse_uint("4294967296", 32))


class BinarySafetyTests(unittest.TestCase):
	def test_rune_rebuilding_middlewares_preserve_invalid_bytes(self):
		for chain in "CsIEUWK":
			with self.subTest(chain=chain), go_rand(4):
				options = {"FiltCaseProb": "1", "FiltSubstringSplitProb": "1", "FiltIgnorableUnicodeProb": "1", "FiltSortKeyFoldProb": "1"}
				rendered = to_bytes(filter_to_ldap_string(Obfuscator(chain, options=options).filter(FilterEqualityMatch("cn", INVALID_UTF8))))
				self.assertNotIn("\ufffd".encode(), rendered)
				self.assertIn(b"\\e9", rendered)

	def test_hex_encoding_escapes_the_original_byte(self):
		with go_rand(1):
			dn = Obfuscator(basedn_chain="X", options={"BDNHexValueProb": "1"}).basedn("CN=" + INVALID_UTF8)
		self.assertEqual(dn, "CN=\\e9\\74\\e9")


class ValidationTests(unittest.TestCase):
	def test_unknown_codes_are_rejected_like_upstream(self):
		with self.assertRaisesRegex(ChainError, 'unrecognized middleware code\\(s\\): "Q", "q"'):
			Obfuscator("qCQ")

	def test_basedn_chain_rules(self):
		cases = {
			"UC": 'middleware "U" \\(GUIDFormat\\) must be the only one',
			"XW": 'cannot be preceded by "X" \\(HexValue\\)',
			"CWW": "cannot appear more than once",
			"I": "requires the BDNSid option",
		}
		for chain, message in cases.items():
			with self.subTest(chain=chain), self.assertRaisesRegex(ChainError, message):
				Obfuscator(basedn_chain=chain, options={"BDNGuid": "00"})
		Obfuscator(basedn_chain="CWX")

	def test_object_category_form_requires_root_dn(self):
		with self.assertRaisesRegex(ChainError, "FiltObjCategoryRootDN"):
			Obfuscator("F")
		Obfuscator("F", options={"FiltObjCategoryRootDN": "DC=wonka,DC=lab"})

	def test_options_follow_upstream_parsing(self):
		self.assertEqual(parse_option("FiltCaseProb=0.9"), ("FiltCaseProb", "0.9"))
		for assignment in ("Nope=1", "FiltCaseProb", "FiltGarbageMaxElems=0", "FiltBitwiseDecompositionMaxBits=1", "FiltGarbageMaxSize=abc"):
			with self.subTest(assignment=assignment), self.assertRaises(OptionError):
				parse_option(assignment)
		options = Options({"FiltCaseProb": "garbage", "FiltOIDAttributeIncludePrefix": "1"})
		self.assertEqual(options.get_float("FiltCaseProb"), 0.7)
		self.assertFalse(options.get_bool("FiltOIDAttributeIncludePrefix"))
		self.assertEqual(options.get_int("BDNGuid"), 0)


class SettingsTests(unittest.TestCase):
	def args(self, **values):
		defaults = {"obfuscate": False, "obfuscate_basedn": None, "obfuscate_attrlist": None, "obfuscate_attrentries": None, "obfuscate_option": None, "obfuscate_ops": None}
		return argparse.Namespace(**{**defaults, **values})

	def test_disabled_by_default(self):
		self.assertIsNone(ObfuscationSettings.from_args(self.args()))

	def test_flag_alone_uses_powerview_defaults(self):
		settings = ObfuscationSettings.from_args(self.args(obfuscate=True))
		self.assertEqual((settings.filter, settings.basedn, settings.attrlist, settings.attrentries), tuple(DEFAULT_CHAINS.values()))
		self.assertEqual(settings.operations, ("search",))

	def test_explicit_chains_override_defaults(self):
		settings = ObfuscationSettings.from_args(self.args(obfuscate="CZ", obfuscate_attrlist=""))
		self.assertEqual((settings.filter, settings.basedn, settings.attrlist), ("CZ", "CX", ""))

	def test_single_chain_flag_enables_only_that_chain(self):
		settings = ObfuscationSettings.from_args(self.args(obfuscate_basedn="WCX"))
		self.assertEqual((settings.filter, settings.basedn, settings.attrlist), ("", "WCX", ""))

	def test_settings_leave_args_json_serializable(self):
		args = self.args(obfuscate="CZ", obfuscate_option=[("FiltCaseProb", "1")], obfuscate_ops=("search", "modify"))
		ObfuscationSettings.from_args(args)
		json.dumps(vars(args))

	def test_invalid_settings_raise(self):
		with self.assertRaises(ObfuscationError):
			ObfuscationSettings.from_args(self.args(obfuscate="CZQ"))

	def test_argument_types(self):
		self.assertEqual(operations_argument("search, modify,search"), ("search", "modify"))
		self.assertEqual(option_argument("AttrsCaseProb=1"), ("AttrsCaseProb", "1"))
		for value in ("search,bind", ""):
			with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
				operations_argument(value)
		with self.assertRaises(argparse.ArgumentTypeError):
			option_argument("Unknown=1")


if __name__ == "__main__":
	unittest.main()
