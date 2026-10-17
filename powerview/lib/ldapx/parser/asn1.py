from ldap3.protocol import rfc4511
from pyasn1.type.constraint import ConstraintsIntersection
from pyasn1.type.namedtype import DefaultedNamedType, NamedTypes, OptionalNamedType

from powerview.lib.ldapx.gostd import from_bytes, to_bytes
from powerview.lib.ldapx.parser.filter import (
	Filter,
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
)

_ASSERTIONS = {
	"equalityMatch": (FilterEqualityMatch, rfc4511.EqualityMatch),
	"greaterOrEqual": (FilterGreaterOrEqual, rfc4511.GreaterOrEqual),
	"lessOrEqual": (FilterLessOrEqual, rfc4511.LessOrEqual),
	"approxMatch": (FilterApproxMatch, rfc4511.ApproxMatch),
}
_ASSERTION_NAMES = {ast_type: (name, asn1_type) for name, (ast_type, asn1_type) in _ASSERTIONS.items()}
_SUBSTRING_PARTS = (("initial", rfc4511.Initial), ("any", rfc4511.Any), ("final", rfc4511.Final))


# Upstream's FilterToPacket emits empty substring lists and omits an empty matchValue.
class Substrings(rfc4511.Substrings):
	subtypeSpec = ConstraintsIntersection()


class ExtensibleMatch(rfc4511.ExtensibleMatch):
	componentType = NamedTypes(
		OptionalNamedType("matchingRule", rfc4511.MatchingRule()),
		OptionalNamedType("type", rfc4511.Type()),
		OptionalNamedType("matchValue", rfc4511.MatchValue()),
		DefaultedNamedType("dnAttributes", rfc4511.DnAttributes()),
	)


def text(component) -> str:
	return from_bytes(bytes(component))


def _present(component, name: str) -> bool:
	value = component[name]
	return value is not None and value.isValue


def filter_from_asn1(node: rfc4511.Filter) -> Filter:
	name = node.getName()
	value = node.getComponent()
	if name == "and":
		return FilterAnd([filter_from_asn1(child) for child in value])
	if name == "or":
		return FilterOr([filter_from_asn1(child) for child in value])
	if name == "notFilter":
		return FilterNot(filter_from_asn1(value["innerNotFilter"]))
	if name in _ASSERTIONS:
		return _ASSERTIONS[name][0](text(value["attributeDesc"]), text(value["assertionValue"]))
	if name == "present":
		return FilterPresent(text(value))
	if name == "substringFilter":
		substrings = [SubstringFilter(**{part.getName(): text(part.getComponent())}) for part in value["substrings"]]
		return FilterSubstring(text(value["type"]), substrings)
	if name == "extensibleMatch":
		return FilterExtensibleMatch(
			matching_rule=text(value["matchingRule"]) if _present(value, "matchingRule") else "",
			attribute_desc=text(value["type"]) if _present(value, "type") else "",
			match_value=text(value["matchValue"]) if _present(value, "matchValue") else "",
			dn_attributes=bool(value["dnAttributes"]) if _present(value, "dnAttributes") else False,
		)
	raise ValueError("unsupported filter type: %s" % name)


def filter_to_asn1(f: Filter) -> rfc4511.Filter:
	node = rfc4511.Filter()
	if isinstance(f, (FilterAnd, FilterOr)):
		children = rfc4511.And() if isinstance(f, FilterAnd) else rfc4511.Or()
		for index, child in enumerate(f.filters):
			children.setComponentByPosition(index, filter_to_asn1(child))
		node.setComponentByName("and" if isinstance(f, FilterAnd) else "or", children, verifyConstraints=False)
	elif isinstance(f, FilterNot):
		inner = rfc4511.Not()
		inner["innerNotFilter"] = filter_to_asn1(f.filter)
		node.setComponentByName("notFilter", inner, verifyConstraints=False)
	elif type(f) in _ASSERTION_NAMES:
		name, asn1_type = _ASSERTION_NAMES[type(f)]
		assertion = asn1_type()
		assertion["attributeDesc"] = rfc4511.AttributeDescription(to_bytes(f.attribute_desc))
		assertion["assertionValue"] = rfc4511.AssertionValue(to_bytes(f.assertion_value))
		node[name] = assertion
	elif isinstance(f, FilterPresent):
		node["present"] = rfc4511.Present(to_bytes(f.attribute_desc))
	elif isinstance(f, FilterSubstring):
		node.setComponentByName("substringFilter", _substring_to_asn1(f), verifyConstraints=False)
	elif isinstance(f, FilterExtensibleMatch):
		node.setComponentByName("extensibleMatch", _extensible_to_asn1(f), verifyConstraints=False)
	else:
		raise TypeError("unsupported filter type: %s" % type(f).__name__)
	return node


def _substring_to_asn1(f: FilterSubstring) -> rfc4511.SubstringFilter:
	parts = Substrings()
	for substring in f.substrings:
		for name, asn1_type in _SUBSTRING_PARTS:
			value = getattr(substring, name)
			if value:
				part = rfc4511.Substring()
				part[name] = asn1_type(to_bytes(value))
				parts.setComponentByPosition(len(parts), part)
	node = rfc4511.SubstringFilter()
	node["type"] = rfc4511.AttributeDescription(to_bytes(f.attribute_desc))
	node.setComponentByName("substrings", parts, verifyConstraints=False)
	return node


def _extensible_to_asn1(f: FilterExtensibleMatch) -> rfc4511.ExtensibleMatch:
	node = ExtensibleMatch()
	if f.matching_rule:
		node["matchingRule"] = rfc4511.MatchingRule(to_bytes(f.matching_rule))
	if f.attribute_desc:
		node["type"] = rfc4511.Type(to_bytes(f.attribute_desc))
	if f.match_value:
		node["matchValue"] = rfc4511.MatchValue(to_bytes(f.match_value))
	if f.dn_attributes:
		node["dnAttributes"] = rfc4511.DnAttributes(True)
	return node
