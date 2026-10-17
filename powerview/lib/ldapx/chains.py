from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Generic, TypeVar

from powerview.lib.ldapx.middlewares import attrentries, attrlist, basedn
from powerview.lib.ldapx.middlewares.attrentries import AttrEntriesMiddleware
from powerview.lib.ldapx.middlewares.attrlist import AttrListMiddleware
from powerview.lib.ldapx.middlewares.basedn import BaseDNMiddleware
from powerview.lib.ldapx.middlewares.filter import obfuscation as filters
from powerview.lib.ldapx.middlewares.filter.helpers import FilterMiddleware
from powerview.lib.ldapx.options import Options
from powerview.lib.ldapx.parser.attributes import AttrEntries
from powerview.lib.ldapx.parser.filter import Filter

FILTER_CODES = {
	"O": "OIDAttribute",
	"C": "Case",
	"X": "HexValue",
	"S": "Spacing",
	"T": "ReplaceTautologies",
	"t": "TimestampGarbage",
	"B": "AddBool",
	"D": "DblNegBool",
	"M": "DeMorganBool",
	"R": "ReorderBool",
	"b": "ExactBitwiseBreakout",
	"d": "BitwiseDecomposition",
	"I": "EqInclusion",
	"E": "EqExclusion",
	"G": "Garbage",
	"A": "EqApproxMatch",
	"x": "EqExtensible",
	"Z": "PrependZeros",
	"s": "SubstringSplit",
	"N": "NamesToANR",
	"n": "ANRGarbageSubstring",
	"P": "DNAttributesNoise",
	"L": "TransitiveEval",
	"F": "ObjectCategoryForm",
	"U": "IgnorableUnicode",
	"W": "AltSpace",
	"K": "SortKeyFold",
}

BASEDN_CODES = {
	"O": "OIDAttribute",
	"C": "Case",
	"X": "HexValue",
	"S": "Spacing",
	"Q": "DoubleQuotes",
	"U": "GUIDFormat",
	"I": "SIDFormat",
	"W": "WKGUIDFormat",
	"N": "IgnorableUnicode",
	"A": "AltSpace",
	"K": "SortKeyFold",
}

ATTRLIST_CODES = {
	"O": "OIDAttribute",
	"C": "Case",
	"D": "Duplicate",
	"G": "GarbageNonExisting",
	"g": "GarbageExisting",
	"W": "ReplaceWithWildcard",
	"w": "AddWildcard",
	"p": "AddPlus",
	"E": "ReplaceWithEmpty",
	"R": "ReorderList",
	"r": "Range",
}

ATTRENTRIES_CODES = {
	"O": "OIDAttribute",
	"C": "Case",
	"R": "ReorderList",
}

# Upstream's mixed-case "msds-additionalsamaccountName" never matches a lowercased name; kept for parity.
ANR_SET = (
	"name", "displayname", "samaccountname",
	"givenname", "legacyexchangedn", "sn", "proxyaddresses",
	"physicaldeliveryofficename", "msds-additionalsamaccountName",
	"msds-phoneticcompanyname", "msds-phoneticdepartment",
	"msds-phoneticdisplayname", "msds-phoneticfirstname",
	"msds-phoneticlastname",
)

EXCLUSIVE_BASEDN_CODES = {"U": "GUIDFormat", "I": "SIDFormat"}
WKGUID_PREDECESSORS = frozenset({"C"})
REQUIRED_BASEDN_OPTIONS = {"U": "BDNGuid", "I": "BDNSid"}

T = TypeVar("T")
Steps = tuple[tuple[str, Callable[[T], T]], ...]


class ChainError(ValueError):
	pass


# Upstream accepts the *OIDAttributeIncludePrefix options but always adds the oID. prefix.
def _filter_factories(o: Options) -> dict[str, Callable[[], FilterMiddleware]]:
	return {
		"OIDAttribute": lambda: filters.oid_attribute(o.get_int("FiltOIDAttributeMaxSpaces"), o.get_int("FiltOIDAttributeMaxZeros")),
		"Case": lambda: filters.rand_case(o.get_float("FiltCaseProb")),
		"HexValue": lambda: filters.rand_hex_value(o.get_float("FiltHexValueProb")),
		"Spacing": lambda: filters.rand_spacing(o.get_int("FiltSpacingMaxSpaces")),
		"ReplaceTautologies": filters.replace_tautologies,
		"TimestampGarbage": lambda: filters.rand_timestamp_suffix(
			o.get_int("FiltTimestampGarbageMaxChars"),
			o.get_str("FiltGarbageCharset"),
			o.get_bool("FiltTimestampGarbageUseComma"),
		),
		"AddBool": lambda: filters.rand_add_bool(o.get_int("FiltAddBoolMaxDepth"), o.get_float("FiltAddBoolProb")),
		"DblNegBool": lambda: filters.rand_dbl_neg_bool(o.get_int("FiltDblNegBoolMaxDepth"), o.get_float("FiltDblNegBoolProb")),
		"DeMorganBool": filters.de_morgan_bool,
		"ReorderBool": filters.rand_bool_reorder,
		"ExactBitwiseBreakout": filters.exact_bitwise_breakout,
		"BitwiseDecomposition": lambda: filters.bitwise_decompose(o.get_int("FiltBitwiseDecompositionMaxBits")),
		"EqInclusion": filters.equality_by_inclusion,
		"EqExclusion": filters.equality_by_exclusion,
		"Garbage": lambda: filters.rand_garbage(
			o.get_int("FiltGarbageMaxElems"),
			o.get_int("FiltGarbageMaxSize"),
			o.get_str("FiltGarbageCharset"),
		),
		"EqApproxMatch": filters.equality_to_approx_match,
		"EqExtensible": lambda: filters.equality_to_extensible(o.get_bool("FiltEqExtensibleAppendDN")),
		"PrependZeros": lambda: filters.rand_prepend_zeros(o.get_int("FiltPrependZerosMaxElems")),
		"SubstringSplit": lambda: filters.rand_substring_split(o.get_float("FiltSubstringSplitProb")),
		"NamesToANR": lambda: filters.anr_attribute(ANR_SET),
		"ANRGarbageSubstring": lambda: filters.anr_substring_garbage(o.get_int("FiltANRSubstringMaxElems"), o.get_str("FiltGarbageCharset")),
		"DNAttributesNoise": lambda: filters.rand_dn_attributes_noise(o.get_float("FiltDNAttrNoiseProb")),
		"TransitiveEval": filters.transitive_eval,
		"ObjectCategoryForm": lambda: filters.object_category_form(o.get_str("FiltObjCategoryRootDN")),
		"IgnorableUnicode": lambda: filters.rand_ignorable_unicode(o.get_float("FiltIgnorableUnicodeProb"), o.get_str("FiltIgnorableUnicodeMode")),
		"AltSpace": lambda: filters.rand_alt_space(o.get_float("FiltAltSpaceProb"), o.get_bool("FiltAltSpaceIncludeVisible")),
		"SortKeyFold": lambda: filters.rand_sort_key_fold(o.get_float("FiltSortKeyFoldProb"), o.get_str("FiltSortKeyFoldClasses")),
	}


def _basedn_factories(o: Options) -> dict[str, Callable[[], BaseDNMiddleware]]:
	return {
		"OIDAttribute": lambda: basedn.oid_attribute(o.get_int("BDNOIDAttributeMaxSpaces"), o.get_int("BDNOIDAttributeMaxZeros")),
		"Case": lambda: basedn.rand_case(o.get_float("BDNCaseProb")),
		"HexValue": lambda: basedn.rand_hex_value(o.get_float("BDNHexValueProb")),
		"Spacing": lambda: basedn.rand_spacing(o.get_int("BDNSpacingMaxElems")),
		"DoubleQuotes": basedn.double_quotes,
		"GUIDFormat": lambda: basedn.guid_format(o.get_str("BDNGuid"), o.get_str("BDNMatch")),
		"SIDFormat": lambda: basedn.sid_format(o.get_str("BDNSid"), o.get_str("BDNMatch")),
		"WKGUIDFormat": basedn.wkguid_format,
		"IgnorableUnicode": lambda: basedn.rand_ignorable_unicode(o.get_float("BDNIgnorableUnicodeProb"), o.get_str("BDNIgnorableUnicodeMode")),
		"AltSpace": lambda: basedn.rand_alt_space(o.get_float("BDNAltSpaceProb"), o.get_bool("BDNAltSpaceIncludeVisible")),
		"SortKeyFold": lambda: basedn.rand_sort_key_fold(o.get_float("BDNSortKeyFoldProb"), o.get_str("BDNSortKeyFoldClasses")),
	}


def _attrlist_factories(o: Options) -> dict[str, Callable[[], AttrListMiddleware]]:
	return {
		"OIDAttribute": lambda: attrlist.oid_attribute(o.get_int("AttrsOIDAttributeMaxSpaces"), o.get_int("AttrsOIDAttributeMaxZeros")),
		"Case": lambda: attrlist.rand_case(o.get_float("AttrsCaseProb")),
		"Duplicate": lambda: attrlist.duplicate(o.get_float("AttrsDuplicateProb")),
		"GarbageNonExisting": lambda: attrlist.garbage_non_existing(
			o.get_int("AttrsGarbageNonExistingMaxElems"),
			o.get_int("AttrsGarbageNonExistingMaxSize"),
			o.get_str("AttrsGarbageCharset"),
		),
		"GarbageExisting": lambda: attrlist.garbage_existing(o.get_int("AttrsGarbageExistingMaxElems")),
		"ReplaceWithWildcard": attrlist.replace_with_wildcard,
		"AddWildcard": attrlist.add_wildcard,
		"AddPlus": attrlist.add_plus,
		"ReplaceWithEmpty": attrlist.replace_with_empty,
		"ReorderList": attrlist.reorder_list,
		"Range": lambda: attrlist.range_option(o.get_str("AttrsRangeOption")),
	}


def _attrentries_factories(o: Options) -> dict[str, Callable[[], AttrEntriesMiddleware]]:
	return {
		"OIDAttribute": lambda: attrentries.oid_attribute(o.get_int("AttrEntriesOIDAttributeMaxSpaces"), o.get_int("AttrEntriesOIDAttributeMaxZeros")),
		"Case": lambda: attrentries.rand_case(o.get_float("AttrEntriesCaseProb")),
		"ReorderList": attrentries.reorder_list,
	}


@dataclass(frozen=True)
class Chain(Generic[T]):
	code: str
	steps: Steps[T]

	@property
	def names(self) -> tuple[str, ...]:
		return tuple(name for name, _ in self.steps)

	def execute(self, value: T) -> T:
		for _, middleware in self.steps:
			value = middleware(value)
		return value


@dataclass(frozen=True)
class BaseDNChain(Chain[str]):
	def execute(self, value: str, allow_reference_forms: bool = True) -> str:
		for name, middleware in self.steps:
			if not allow_reference_forms and name in basedn.REFERENCE_ONLY_FORMS:
				continue
			value = basedn.apply_to_dn_part(middleware)(value)
		return value


def _quoted(codes: Iterable[str]) -> str:
	return ", ".join('"%s"' % code for code in sorted(codes))


def validate_codes(chain: str, codes: dict[str, str]) -> None:
	unknown = [code for code in chain if code not in codes]
	if unknown:
		raise ChainError("unrecognized middleware code(s): %s" % _quoted(unknown))


def validate_basedn_chain(chain: str, options: Options) -> None:
	validate_codes(chain, BASEDN_CODES)
	for index, code in enumerate(chain):
		if code in EXCLUSIVE_BASEDN_CODES and len(chain) > 1:
			raise ChainError('middleware "%s" (%s) must be the only one in the basedn chain' % (code, EXCLUSIVE_BASEDN_CODES[code]))
		if code == "W" and index > 0:
			for previous in chain[:index]:
				if previous == code:
					raise ChainError('middleware "W" (WKGUIDFormat) cannot appear more than once in the basedn chain')
				if previous not in WKGUID_PREDECESSORS:
					raise ChainError(
						'middleware "W" (WKGUIDFormat) cannot be preceded by "%s" (%s) in the basedn chain - place it after "W" instead'
						% (previous, BASEDN_CODES[previous])
					)
		option = REQUIRED_BASEDN_OPTIONS.get(code)
		if option and not options.get_str(option):
			raise ChainError('middleware "%s" (%s) requires the %s option to be set' % (code, BASEDN_CODES[code], option))


def validate_filter_chain(chain: str, options: Options) -> None:
	validate_codes(chain, FILTER_CODES)
	if "F" in chain and not options.get_str("FiltObjCategoryRootDN"):
		raise ChainError('middleware "F" (ObjectCategoryForm) requires the FiltObjCategoryRootDN option to be set')


def _build(chain: str, codes: dict[str, str], factories: dict[str, Callable[[], Callable[[T], T]]]) -> Steps[T]:
	return tuple((codes[code], factories[codes[code]]()) for code in chain)


def build_filter_chain(chain: str, options: Options) -> Chain[Filter]:
	validate_filter_chain(chain, options)
	return Chain(chain, _build(chain, FILTER_CODES, _filter_factories(options)))


def build_basedn_chain(chain: str, options: Options) -> BaseDNChain:
	validate_basedn_chain(chain, options)
	return BaseDNChain(chain, _build(chain, BASEDN_CODES, _basedn_factories(options)))


def build_attrlist_chain(chain: str, options: Options) -> Chain[list[str]]:
	validate_codes(chain, ATTRLIST_CODES)
	return Chain(chain, _build(chain, ATTRLIST_CODES, _attrlist_factories(options)))


def build_attrentries_chain(chain: str, options: Options) -> Chain[AttrEntries]:
	validate_codes(chain, ATTRENTRIES_CODES)
	return Chain(chain, _build(chain, ATTRENTRIES_CODES, _attrentries_factories(options)))
