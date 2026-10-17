from collections.abc import Mapping

from powerview.lib.ldapx.gostd import atoi, parse_float, to_lower

DEFAULT_OPTIONS = {
	"BDNCaseProb": "0.7",
	"BDNHexValueProb": "0.7",
	"BDNOIDAttributeMaxSpaces": "4",
	"BDNOIDAttributeMaxZeros": "4",
	"BDNOIDAttributeIncludePrefix": "true",
	"BDNSpacingMaxElems": "4",
	"BDNGuid": "",
	"BDNSid": "",
	"BDNMatch": "",
	"BDNIgnorableUnicodeProb": "0.3",
	"BDNIgnorableUnicodeMode": "invisible,marks",
	"BDNAltSpaceProb": "1",
	"BDNAltSpaceIncludeVisible": "false",
	"BDNSortKeyFoldProb": "0.5",
	"BDNSortKeyFoldClasses": "all",
	"FiltSpacingMaxSpaces": "4",
	"FiltTimestampGarbageUseComma": "false",
	"FiltTimestampGarbageMaxChars": "6",
	"FiltAddBoolMaxDepth": "4",
	"FiltAddBoolProb": "1",
	"FiltDblNegBoolMaxDepth": "1",
	"FiltDblNegBoolProb": "1",
	"FiltANRSubstringMaxElems": "4",
	"FiltSubstringSplitProb": "0.7",
	"FiltPrependZerosMaxElems": "4",
	"FiltGarbageMaxElems": "4",
	"FiltGarbageMaxSize": "6",
	"FiltGarbageCharset": "abcdefghijklmnopqrsutwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"FiltCaseProb": "0.7",
	"FiltHexValueProb": "0.7",
	"FiltEqExtensibleAppendDN": "false",
	"FiltBitwiseDecompositionMaxBits": "32",
	"FiltOIDAttributeMaxSpaces": "4",
	"FiltOIDAttributeMaxZeros": "4",
	"FiltOIDAttributeIncludePrefix": "true",
	"FiltDNAttrNoiseProb": "0.8",
	"FiltObjCategoryRootDN": "",
	"FiltIgnorableUnicodeProb": "0.3",
	"FiltIgnorableUnicodeMode": "invisible,marks",
	"FiltAltSpaceProb": "1",
	"FiltAltSpaceIncludeVisible": "false",
	"FiltSortKeyFoldProb": "0.5",
	"FiltSortKeyFoldClasses": "all",
	"AttrsDuplicateProb": "0.7",
	"AttrsCaseProb": "0.7",
	"AttrsGarbageCharset": "abcdefghijklmnopqrsutwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
	"AttrsGarbageExistingMaxElems": "4",
	"AttrsGarbageNonExistingMaxElems": "4",
	"AttrsGarbageNonExistingMaxSize": "6",
	"AttrsOIDAttributeMaxSpaces": "4",
	"AttrsOIDAttributeMaxZeros": "4",
	"AttrsOIDAttributeIncludePrefix": "true",
	"AttrsRangeOption": "0-*",
	"AttrEntriesCaseProb": "0.7",
	"AttrEntriesOIDAttributeMaxSpaces": "4",
	"AttrEntriesOIDAttributeMaxZeros": "4",
	"AttrEntriesOIDAttributeIncludePrefix": "true",
}

POSITIVE_INT_OPTIONS = {
	"BDNSpacingMaxElems": 1,
	"FiltSpacingMaxSpaces": 1,
	"FiltTimestampGarbageMaxChars": 1,
	"FiltGarbageMaxElems": 1,
	"FiltGarbageMaxSize": 1,
	"FiltANRSubstringMaxElems": 1,
	"FiltPrependZerosMaxElems": 1,
	"FiltAddBoolMaxDepth": 1,
	"FiltDblNegBoolMaxDepth": 1,
	"FiltBitwiseDecompositionMaxBits": 2,
	"AttrsGarbageExistingMaxElems": 1,
	"AttrsGarbageNonExistingMaxElems": 1,
	"AttrsGarbageNonExistingMaxSize": 1,
}


class OptionError(ValueError):
	pass


def validate_option(key: str, value: str) -> None:
	if key not in DEFAULT_OPTIONS:
		raise OptionError("unknown option %r" % key)
	minimum = POSITIVE_INT_OPTIONS.get(key)
	if minimum is None:
		return
	number = atoi(value)
	if number is None:
		raise OptionError("option %r must be an integer >= %d, got %r" % (key, minimum, value))
	if number < minimum:
		raise OptionError("option %r must be an integer >= %d, got %d" % (key, minimum, number))


def parse_option(assignment: str) -> tuple[str, str]:
	key, separator, value = assignment.partition("=")
	if not separator:
		raise OptionError("invalid option format: %s" % assignment)
	validate_option(key, value)
	return key, value


class Options:
	def __init__(self, overrides: Mapping[str, str] | None = None):
		self._values = {}
		for key, value in (overrides or {}).items():
			validate_option(key, value)
			self._values[key] = value

	def __contains__(self, key: str) -> bool:
		return key in self._values

	def overrides(self) -> dict[str, str]:
		return dict(self._values)

	def get_str(self, key: str) -> str:
		return self._values.get(key, DEFAULT_OPTIONS[key])

	def get_int(self, key: str) -> int:
		value = atoi(self._values[key]) if key in self._values else None
		if value is None:
			value = atoi(DEFAULT_OPTIONS[key])
		return value if value is not None else 0

	def get_float(self, key: str) -> float:
		value = parse_float(self._values[key]) if key in self._values else None
		if value is None:
			value = parse_float(DEFAULT_OPTIONS[key])
		return value if value is not None else 0.0

	def get_bool(self, key: str) -> bool:
		return to_lower(self.get_str(key)) == "true"
