from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from powerview.lib.ldapx.gostd import from_bytes, to_bytes, trim_space


class FilterSyntaxError(ValueError):
	pass


class Filter:
	__slots__ = ()


@dataclass(slots=True)
class FilterAnd(Filter):
	filters: list[Filter] = field(default_factory=list)


@dataclass(slots=True)
class FilterOr(Filter):
	filters: list[Filter] = field(default_factory=list)


@dataclass(slots=True)
class FilterNot(Filter):
	filter: Filter


@dataclass(slots=True)
class FilterEqualityMatch(Filter):
	attribute_desc: str
	assertion_value: str


@dataclass(slots=True)
class FilterPresent(Filter):
	attribute_desc: str


@dataclass(frozen=True, slots=True)
class SubstringFilter:
	initial: str = ""
	any: str = ""
	final: str = ""


@dataclass(slots=True)
class FilterSubstring(Filter):
	attribute_desc: str
	substrings: list[SubstringFilter] = field(default_factory=list)


@dataclass(slots=True)
class FilterGreaterOrEqual(Filter):
	attribute_desc: str
	assertion_value: str


@dataclass(slots=True)
class FilterLessOrEqual(Filter):
	attribute_desc: str
	assertion_value: str


@dataclass(slots=True)
class FilterApproxMatch(Filter):
	attribute_desc: str
	assertion_value: str


@dataclass(slots=True)
class FilterExtensibleMatch(Filter):
	matching_rule: str = ""
	attribute_desc: str = ""
	match_value: str = ""
	dn_attributes: bool = False


ASSERTIONS = (FilterEqualityMatch, FilterGreaterOrEqual, FilterLessOrEqual, FilterApproxMatch)


def get_attr_name(f: Filter) -> str | None:
	if isinstance(f, (FilterAnd, FilterOr, FilterNot)):
		return None
	return f.attribute_desc


def query_to_filter(query: str) -> Filter:
	query = trim_space(query)
	if not query:
		raise FilterSyntaxError("empty query string")
	if query[0] != "(" or query[-1] != ")":
		raise FilterSyntaxError("invalid query format")
	if query[1] == "&":
		return FilterAnd(_parse_sub_filters(query[2:-1]))
	if query[1] == "|":
		return FilterOr(_parse_sub_filters(query[2:-1]))
	if query[1] == "!":
		if len(query) < 4:
			raise FilterSyntaxError("invalid NOT filter")
		return FilterNot(query_to_filter(query[2:-1]))
	return _parse_simple_filter(query)


def _parse_sub_filters(query: str) -> list[Filter]:
	filters = []
	current = ""
	depth = 0
	for char in query:
		if char == "(":
			depth += 1
		elif char == ")":
			depth -= 1
		current += char
		if depth == 0:
			filters.append(query_to_filter(current))
			current = ""
	return filters


def _decode_escaped(value: str) -> str:
	buffer = bytearray()
	index = 0
	while index < len(value):
		char = value[index]
		if char != "\\":
			buffer += to_bytes(char)
			index += 1
			continue
		pair = value[index + 1:index + 3]
		if len(pair) < 2:
			raise FilterSyntaxError("missing characters for escape in filter")
		if not all(c in "0123456789abcdefABCDEF" for c in pair):
			raise FilterSyntaxError("invalid characters for escape in filter")
		buffer.append(int(pair, 16))
		index += 3
	return from_bytes(bytes(buffer))


_OPERATORS = (
	(":dn:=", FilterExtensibleMatch, True, False),
	(":dn:", FilterExtensibleMatch, True, True),
	(":=", FilterExtensibleMatch, False, False),
	(":", FilterExtensibleMatch, False, True),
	("=", FilterEqualityMatch, False, False),
	(">=", FilterGreaterOrEqual, False, False),
	("<=", FilterLessOrEqual, False, False),
	("~=", FilterApproxMatch, False, False),
)


def _match_operator(remaining: str):
	for token, kind, dn_attributes, reads_rule in _OPERATORS:
		if remaining.startswith(token):
			return len(token), kind, dn_attributes, reads_rule
	return None


def _parse_simple_filter(query: str) -> Filter:
	query = trim_space(query)
	if len(query) < 3 or query[0] != "(" or query[-1] != ")":
		raise FilterSyntaxError("invalid simple filter format")

	attribute, rule, condition = [], [], []
	kind, dn_attributes, target = None, False, attribute
	pos = 1
	while pos < len(query):
		remaining = query[pos:]
		if remaining[0] == ")":
			break
		if target is attribute:
			operator = _match_operator(remaining)
			if operator:
				width, kind, is_dn, reads_rule = operator
				dn_attributes = dn_attributes or is_dn
				target = rule if reads_rule else condition
				pos += width
				continue
		elif target is rule and remaining.startswith(":="):
			target = condition
			pos += 2
			continue
		target.append(remaining[0])
		pos += 1

	if pos == len(query):
		raise FilterSyntaxError("unexpected end of filter")
	if kind is None:
		raise FilterSyntaxError("error parsing filter")

	raw_condition = "".join(condition)
	value = _decode_escaped(raw_condition)
	attribute_desc = "".join(attribute)
	if kind is FilterExtensibleMatch:
		return FilterExtensibleMatch("".join(rule), attribute_desc, value, dn_attributes)
	if kind is not FilterEqualityMatch:
		return kind(attribute_desc, value)
	if raw_condition == "*":
		return FilterPresent(attribute_desc)
	if "*" in raw_condition:
		return FilterSubstring(attribute_desc, _parse_substrings(raw_condition))
	return FilterEqualityMatch(attribute_desc, value)


def _parse_substrings(raw_condition: str) -> list[SubstringFilter]:
	parts = raw_condition.split("*")
	substrings = []
	for index, part in enumerate(parts):
		if not part:
			continue
		value = _decode_escaped(part)
		if index == 0:
			substrings.append(SubstringFilter(initial=value))
		elif index == len(parts) - 1:
			substrings.append(SubstringFilter(final=value))
		else:
			substrings.append(SubstringFilter(any=value))
	return substrings


def ldap_escape(value: str) -> str:
	return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def rfc4515_escape(value: str) -> str:
	escaped = []
	for byte in to_bytes(value):
		if byte in b"*()\\\x00" or byte >= 0x80:
			escaped.append("\\%02x" % byte)
		else:
			escaped.append(chr(byte))
	return "".join(escaped)


def filter_to_query(f: Filter) -> str:
	return _render(f, ldap_escape, strict=False)


def filter_to_ldap_string(f: Filter) -> str:
	return _render(f, rfc4515_escape, strict=True)


def _render(f: Filter, escape: Callable[[str], str], strict: bool) -> str:
	if isinstance(f, FilterAnd):
		return "(&" + "".join(_render(sub, escape, strict) for sub in f.filters) + ")"
	if isinstance(f, FilterOr):
		return "(|" + "".join(_render(sub, escape, strict) for sub in f.filters) + ")"
	if isinstance(f, FilterNot):
		return "(!" + _render(f.filter, escape, strict) + ")"
	if isinstance(f, FilterEqualityMatch):
		return "(%s=%s)" % (escape(f.attribute_desc), escape(f.assertion_value))
	if isinstance(f, FilterSubstring):
		return "(%s=%s)" % (escape(f.attribute_desc), _render_substrings(f.substrings, escape))
	if isinstance(f, FilterGreaterOrEqual):
		return "(%s>=%s)" % (escape(f.attribute_desc), escape(f.assertion_value))
	if isinstance(f, FilterLessOrEqual):
		return "(%s<=%s)" % (escape(f.attribute_desc), escape(f.assertion_value))
	if isinstance(f, FilterPresent):
		return "(%s=*)" % escape(f.attribute_desc)
	if isinstance(f, FilterApproxMatch):
		return "(%s~=%s)" % (escape(f.attribute_desc), escape(f.assertion_value))
	if isinstance(f, FilterExtensibleMatch):
		parts = []
		if f.attribute_desc:
			parts.append(escape(f.attribute_desc))
		if f.dn_attributes:
			parts.append("dn")
		if f.matching_rule:
			parts.append(escape(f.matching_rule))
		if f.match_value or strict:
			parts.append("=" + escape(f.match_value))
		return "(%s)" % ":".join(parts)
	raise TypeError("unsupported filter type: %s" % type(f).__name__)


def _render_substrings(substrings: list[SubstringFilter], escape: Callable[[str], str]) -> str:
	parts = []
	for part in substrings:
		if part.initial:
			parts.append(escape(part.initial))
		elif part.any:
			parts.append(escape(part.any))
		elif part.final:
			parts.append(escape(part.final))
	if parts:
		if not substrings[0].initial:
			parts[0] = "*" + parts[0]
		if not substrings[-1].final:
			parts[-1] += "*"
	return "*".join(parts)
