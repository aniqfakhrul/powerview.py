from dataclasses import replace

from powerview.lib.ldapx import rand
from powerview.lib.ldapx.gostd import (
	atoi,
	byte_len,
	byte_slice,
	equal_fold,
	parse_uint,
	to_lower,
	wrap_int64,
)
from powerview.lib.ldapx.middlewares.filter._object_categories import (
	OBJECT_CATEGORY_CLASSES,
)
from powerview.lib.ldapx.middlewares.filter.helpers import (
	FilterMiddleware,
	add_anr_spacing,
	add_dn_spacing,
	add_sid_spacing,
	get_next_sid,
	get_next_string,
	get_previous_sid,
	get_previous_string,
	leaf_applier,
	prepend_zeros_to_number,
	prepend_zeros_to_sid,
	randomly_hex_encode_dn_string,
	replace_timestamp,
	split_slice,
)
from powerview.lib.ldapx.middlewares.helpers._tables import (
	ALT_SPACE_RUNES,
	VISIBLE_ALT_SPACE_RUNES,
)
from powerview.lib.ldapx.middlewares.helpers.strings import (
	generate_garbage_string,
	obfuscate_oid_name,
	randomly_change_case_string,
)
from powerview.lib.ldapx.middlewares.helpers.unicode import (
	FoldSubstituter,
	ignorable_mode_runes,
	insert_runes,
	substitute_spaces,
	transform_dn_values,
)
from powerview.lib.ldapx.parser._schema import (
	ATTR_FORMATS,
	BITWISE_ATTRS,
	NUMBER_FORMATS,
	TokenFormat,
)
from powerview.lib.ldapx.parser.attributes import token_format
from powerview.lib.ldapx.parser.filter import (
	ASSERTIONS,
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
	get_attr_name,
)

BITWISE_AND = "1.2.840.113556.1.4.803"
BITWISE_OR = "1.2.840.113556.1.4.804"
TRANSITIVE_EVAL = "1.2.840.113556.1.4.1941"

TRANSITIVE_LINK_ATTRS = ("memberof", "member", "manager", "directreports", "msds-membertransitive", "msds-memberoftransitive")
GREEDY_ATTR_PRESENCES = (
	"objectclass", "distinguishedname", "name", "objectguid",
	"objectcategory", "whencreated", "whenchanged", "usncreated", "usnchanged",
)
_ATTRIBUTE_LEAVES = ASSERTIONS + (FilterSubstring, FilterPresent, FilterExtensibleMatch)


def oid_attribute(max_spaces: int, max_zeros: int) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, _ATTRIBUTE_LEAVES):
			f.attribute_desc = obfuscate_oid_name(f.attribute_desc, max_spaces, max_zeros)
		return f

	return leaf_applier(middleware)


def anr_attribute(anr_set: tuple[str, ...]) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, ASSERTIONS) and to_lower(f.attribute_desc) in anr_set:
			f.attribute_desc = "aNR"
			f.assertion_value = "=" + f.assertion_value
		return f

	return leaf_applier(middleware)


def anr_substring_garbage(max_chars: int, charset: str) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if max_chars <= 0:
			return f
		if isinstance(f, FilterEqualityMatch) and f.attribute_desc == "aNR":
			garbage = generate_garbage_string(1 + rand.intn(max_chars), charset)
			return FilterSubstring("aNR", [SubstringFilter(initial=f.assertion_value), SubstringFilter(final=garbage)])
		return f

	return leaf_applier(middleware)


def generate_garbage_filter(attribute: str, garbage_size: int, charset: str) -> Filter:
	def garbage() -> str:
		return generate_garbage_string(garbage_size, charset)

	def name() -> str:
		return attribute if attribute else garbage()

	def equality() -> Filter:
		attr = name()
		return FilterEqualityMatch(attr, garbage())

	def approx() -> Filter:
		attr = name()
		return FilterApproxMatch(attr, garbage())

	def substring() -> Filter:
		attr = name()
		substrings = []
		pattern = rand.intn(4)
		if pattern == 0:
			substrings.append(SubstringFilter(initial=garbage()))
		elif pattern == 1:
			substrings.append(SubstringFilter(final=garbage()))
		elif pattern == 2:
			substrings.append(SubstringFilter(initial=garbage()))
			substrings.append(SubstringFilter(final=garbage()))
		else:
			substrings.append(SubstringFilter(initial=garbage()))
			for _ in range(rand.intn(3)):
				substrings.append(SubstringFilter(any=garbage()))
			if rand.intn(2) == 0:
				substrings.append(SubstringFilter(final=garbage()))
		return FilterSubstring(attr, substrings)

	def less_or_equal() -> Filter:
		attr = name()
		return FilterLessOrEqual(attr, garbage())

	def greater_or_equal() -> Filter:
		attr = name()
		return FilterGreaterOrEqual(attr, garbage())

	def extensible() -> Filter:
		attr = name()
		rule = garbage()
		return FilterExtensibleMatch(rule, attr, garbage())

	generators = (equality, approx, substring, less_or_equal, greater_or_equal, extensible)
	return generators[rand.intn(len(generators))]()


def rand_garbage(max_garbage: int, garbage_size: int, charset: str) -> FilterMiddleware:
	def wrap(f: Filter) -> Filter:
		count = 1 + rand.intn(max_garbage)
		return FilterOr([f] + [generate_garbage_filter("", garbage_size, charset) for _ in range(count)])

	def apply(f: Filter) -> Filter:
		if max_garbage <= 0:
			return f
		if isinstance(f, FilterAnd):
			return FilterAnd([apply(sub) for sub in f.filters])
		if isinstance(f, FilterOr):
			return FilterOr([apply(sub) for sub in f.filters])
		return wrap(f)

	return apply


def _neighbours(f: FilterEqualityMatch) -> tuple[str, str] | None:
	kind = token_format(f.attribute_desc)
	if kind is None:
		return None
	if kind == TokenFormat.SID:
		if f.assertion_value.count("-") <= 2:
			return None
		return get_previous_sid(f.assertion_value), get_next_sid(f.assertion_value)
	if kind in NUMBER_FORMATS:
		value = atoi(f.assertion_value)
		if value is None:
			# Upstream still builds the range with empty bounds when the value is not an integer.
			return "", ""
		return str(wrap_int64(value - 1)), str(wrap_int64(value + 1))
	if kind == TokenFormat.STRING_UNICODE:
		return get_previous_string(f.assertion_value), get_next_string(f.assertion_value)
	return None


def equality_by_inclusion() -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if not isinstance(f, FilterEqualityMatch):
			return f
		bounds = _neighbours(f)
		if bounds is None:
			return f
		lower, upper = bounds
		attr = f.attribute_desc
		return FilterAnd([
			FilterGreaterOrEqual(attr, lower),
			FilterLessOrEqual(attr, upper),
			FilterNot(FilterEqualityMatch(attr, lower)),
			FilterNot(FilterEqualityMatch(attr, upper)),
		])

	return leaf_applier(middleware)


def equality_by_exclusion() -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if not isinstance(f, FilterEqualityMatch):
			return f
		bounds = _neighbours(f)
		if bounds is None:
			return f
		lower, upper = bounds
		attr = f.attribute_desc
		return FilterAnd([
			FilterPresent(attr),
			FilterNot(FilterLessOrEqual(attr, lower)),
			FilterNot(FilterGreaterOrEqual(attr, upper)),
		])

	return leaf_applier(middleware)


def exact_bitwise_breakout() -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if not isinstance(f, FilterEqualityMatch) or token_format(f.attribute_desc) not in NUMBER_FORMATS:
			return f
		value = parse_uint(f.assertion_value, 32)
		if value is None:
			return f
		return FilterAnd([
			FilterExtensibleMatch(BITWISE_AND, f.attribute_desc, f.assertion_value),
			FilterNot(FilterExtensibleMatch(BITWISE_OR, f.attribute_desc, str(~value & 0xFFFFFFFF))),
		])

	return leaf_applier(middleware)


def bitwise_decompose(max_bits: int) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if not isinstance(f, FilterExtensibleMatch):
			return f
		value = parse_uint(f.match_value, 32)
		if value is None:
			return f
		filters = []
		bits_found = 0
		remaining = value
		for bit in range(31):
			if bits_found >= max_bits - 1:
				break
			if value & (1 << bit):
				filters.append(FilterExtensibleMatch(f.matching_rule, f.attribute_desc, str(1 << bit)))
				remaining &= ~(1 << bit)
				bits_found += 1
		if remaining:
			filters.append(FilterExtensibleMatch(f.matching_rule, f.attribute_desc, str(remaining)))
		if len(filters) > 1:
			if f.matching_rule == BITWISE_AND:
				return FilterAnd(filters)
			if f.matching_rule == BITWISE_OR:
				return FilterOr(filters)
		elif len(filters) == 1:
			return filters[0]
		return f

	return leaf_applier(middleware)


def rand_add_bool(max_depth: int, prob: float) -> FilterMiddleware:
	def apply(f: Filter) -> Filter:
		if max_depth <= 0:
			return f
		result = f
		for _ in range(rand.intn(max_depth) + 1):
			if rand.float64() < prob:
				result = FilterAnd([result]) if rand.intn(2) == 0 else FilterOr([result])
		return result

	return apply


def rand_dbl_neg_bool(max_depth: int, prob: float) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if max_depth <= 0:
			return f
		result = f
		for _ in range(rand.intn(max_depth) + 1):
			if rand.float64() < prob:
				result = FilterNot(FilterNot(result))
		return result

	return leaf_applier(middleware)


def de_morgan_bool() -> FilterMiddleware:
	def apply(f: Filter) -> Filter:
		if isinstance(f, FilterAnd):
			return FilterNot(FilterOr([FilterNot(apply(sub)) for sub in f.filters]))
		if isinstance(f, FilterOr):
			return FilterNot(FilterAnd([FilterNot(apply(sub)) for sub in f.filters]))
		if isinstance(f, FilterNot):
			return FilterNot(apply(f.filter))
		return f

	return apply


def rand_bool_reorder() -> FilterMiddleware:
	def shuffled(filters: list[Filter]) -> list[Filter]:
		items = list(filters)
		for i in range(len(items) - 1, 0, -1):
			j = rand.intn(i + 1)
			items[i], items[j] = items[j], items[i]
		return [apply(sub) for sub in items]

	def apply(f: Filter) -> Filter:
		if isinstance(f, FilterAnd):
			return FilterAnd(shuffled(f.filters))
		if isinstance(f, FilterOr):
			return FilterOr(shuffled(f.filters))
		if isinstance(f, FilterNot):
			return FilterNot(apply(f.filter))
		return f

	return apply


def _string_value_transform(transform) -> FilterMiddleware:
	def obfuscate(attribute: str, value: str) -> str:
		if not value:
			return value
		kind = token_format(attribute)
		if kind == TokenFormat.STRING_UNICODE:
			return transform(value)
		if kind == TokenFormat.DN_STRING:
			return transform_dn_values(value, transform)
		return value

	def middleware(f: Filter) -> Filter:
		if isinstance(f, ASSERTIONS):
			f.assertion_value = obfuscate(f.attribute_desc, f.assertion_value)
		elif isinstance(f, FilterSubstring):
			for index, part in enumerate(f.substrings):
				initial = obfuscate(f.attribute_desc, part.initial)
				any_ = obfuscate(f.attribute_desc, part.any)
				final = obfuscate(f.attribute_desc, part.final)
				f.substrings[index] = SubstringFilter(initial, any_, final)
		return f

	return leaf_applier(middleware)


def rand_ignorable_unicode(prob: float, mode: str) -> FilterMiddleware:
	pool = ignorable_mode_runes(mode)
	return _string_value_transform(lambda value: insert_runes(value, pool, prob))


def rand_alt_space(prob: float, include_visible: bool) -> FilterMiddleware:
	pool = ALT_SPACE_RUNES + VISIBLE_ALT_SPACE_RUNES if include_visible else ALT_SPACE_RUNES
	return _string_value_transform(lambda value: substitute_spaces(value, pool, prob))


def rand_sort_key_fold(prob: float, classes: str) -> FilterMiddleware:
	substituter = FoldSubstituter(classes)
	return _string_value_transform(lambda value: substituter.apply(value, prob))


def rand_case(prob: float) -> FilterMiddleware:
	def obfuscate(attribute: str, value: str) -> tuple[str, str]:
		if token_format(attribute) == TokenFormat.SID and not value.startswith("S-"):
			return attribute, value
		return randomly_change_case_string(attribute, prob), randomly_change_case_string(value, prob)

	def middleware(f: Filter) -> Filter:
		if isinstance(f, ASSERTIONS):
			f.attribute_desc, f.assertion_value = obfuscate(f.attribute_desc, f.assertion_value)
		elif isinstance(f, FilterSubstring):
			f.attribute_desc = randomly_change_case_string(f.attribute_desc, prob)
			for index, part in enumerate(f.substrings):
				initial = randomly_change_case_string(part.initial, prob) if part.initial else part.initial
				any_ = randomly_change_case_string(part.any, prob) if part.any else part.any
				final = randomly_change_case_string(part.final, prob) if part.final else part.final
				f.substrings[index] = SubstringFilter(initial, any_, final)
		elif isinstance(f, FilterPresent):
			# Upstream case-randomizes a dummy "S-" value here, which consumes random draws.
			f.attribute_desc, _ = obfuscate(f.attribute_desc, "S-")
		elif isinstance(f, FilterExtensibleMatch):
			f.attribute_desc, f.match_value = obfuscate(f.attribute_desc, f.match_value)
		return f

	return leaf_applier(middleware)


def equality_to_approx_match() -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterEqualityMatch):
			return FilterApproxMatch(f.attribute_desc, f.assertion_value)
		return f

	return leaf_applier(middleware)


def object_category_form(root_dn: str) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if not isinstance(f, FilterEqualityMatch) or not equal_fold(f.attribute_desc, "objectCategory"):
			return f
		if "=" in f.assertion_value:
			return f
		cn = OBJECT_CATEGORY_CLASSES.get(to_lower(f.assertion_value))
		if cn is None:
			return f
		return FilterEqualityMatch(f.attribute_desc, "CN=%s,CN=Schema,CN=Configuration,%s" % (cn, root_dn))

	return leaf_applier(middleware)


def rand_hex_value(prob: float) -> FilterMiddleware:
	def encode(attribute: str, value: str) -> str:
		if token_format(attribute) == TokenFormat.DN_STRING:
			return randomly_hex_encode_dn_string(value, prob)
		return value

	def middleware(f: Filter) -> Filter:
		if isinstance(f, (FilterEqualityMatch, FilterApproxMatch)):
			return type(f)(f.attribute_desc, encode(f.attribute_desc, f.assertion_value))
		return f

	return leaf_applier(middleware)


def rand_timestamp_suffix(max_chars: int, charset: str, use_comma: bool) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, ASSERTIONS):
			return type(f)(f.attribute_desc, replace_timestamp(f.assertion_value, max_chars, charset, use_comma))
		if isinstance(f, FilterExtensibleMatch):
			value = replace_timestamp(f.match_value, max_chars, charset, use_comma)
			return FilterExtensibleMatch(f.matching_rule, f.attribute_desc, value, f.dn_attributes)
		return f

	return leaf_applier(middleware)


def rand_prepend_zeros(max_zeros: int) -> FilterMiddleware:
	def prepend(attribute: str, value: str) -> str:
		kind = token_format(attribute)
		if kind in NUMBER_FORMATS:
			return prepend_zeros_to_number(value, max_zeros)
		if kind == TokenFormat.SID:
			return prepend_zeros_to_sid(value, max_zeros)
		return value

	def middleware(f: Filter) -> Filter:
		if isinstance(f, ASSERTIONS):
			return type(f)(f.attribute_desc, prepend(f.attribute_desc, f.assertion_value))
		if isinstance(f, FilterExtensibleMatch):
			value = prepend(f.attribute_desc, f.match_value)
			return FilterExtensibleMatch(f.matching_rule, f.attribute_desc, value, f.dn_attributes)
		return f

	return leaf_applier(middleware)


def rand_spacing(max_spaces: int) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterSubstring):
			if f.attribute_desc == "aNR":
				for index, part in enumerate(f.substrings):
					initial = add_anr_spacing(part.initial, max_spaces) if part.initial else part.initial
					final = add_anr_spacing(part.final, max_spaces) if part.final else part.final
					f.substrings[index] = replace(part, initial=initial, final=final)
			return f
		if not isinstance(f, ASSERTIONS):
			return f
		kind = token_format(f.attribute_desc)
		if kind is None:
			return f
		value = f.assertion_value
		dn_allowed = isinstance(f, (FilterEqualityMatch, FilterApproxMatch))
		if to_lower(f.attribute_desc) == "anr":
			f.assertion_value = add_anr_spacing(value, max_spaces)
		elif dn_allowed and kind == TokenFormat.DN_STRING:
			f.assertion_value = add_dn_spacing(value, max_spaces)
		elif kind == TokenFormat.SID:
			f.assertion_value = add_sid_spacing(value, max_spaces)
		return f

	return leaf_applier(middleware)


def rand_substring_split(prob: float) -> FilterMiddleware:
	def split_equality(f: FilterEqualityMatch) -> Filter:
		if rand.float64() < prob and token_format(f.attribute_desc) == TokenFormat.STRING_UNICODE:
			chars = f.assertion_value
			split_point = rand.intn(len(chars) + 1)
			substrings = []
			if split_point > 0:
				substrings.append(SubstringFilter(initial=chars[:split_point]))
			if split_point < len(chars):
				substrings.append(SubstringFilter(final=chars[split_point:]))
			return FilterSubstring(f.attribute_desc, substrings)
		return f

	def split_substring(f: FilterSubstring) -> Filter:
		if not (rand.float64() < prob and f.substrings):
			return f
		index = rand.intn(len(f.substrings))
		sub = f.substrings[index]
		before, after = split_slice(f.substrings, index)
		if sub.initial:
			point = rand.intn(byte_len(sub.initial))
			suffix = byte_slice(sub.initial, point)
			f.substrings = before + [replace(sub, initial=byte_slice(sub.initial, 0, point)), SubstringFilter(any=suffix)] + after
		elif byte_len(sub.any) > 1:
			point = rand.intn(byte_len(sub.any) - 1) + 1
			suffix = byte_slice(sub.any, point)
			f.substrings = before + [replace(sub, any=byte_slice(sub.any, 0, point)), SubstringFilter(any=suffix)] + after
		elif sub.final:
			point = rand.intn(byte_len(sub.final)) + 1
			prefix = byte_slice(sub.final, 0, point)
			f.substrings = before + [SubstringFilter(any=prefix), replace(sub, final=byte_slice(sub.final, point))] + after
		return f

	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterEqualityMatch):
			return split_equality(f)
		if isinstance(f, FilterSubstring):
			return split_substring(f)
		return f

	return leaf_applier(middleware)


def equality_to_extensible(dn: bool) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterEqualityMatch):
			return FilterExtensibleMatch("", f.attribute_desc, f.assertion_value, dn)
		return f

	return leaf_applier(middleware)


def _generate_typo(attribute: str) -> str:
	chars = list(attribute)
	index = rand.intn(len(chars))
	base = "a" if rand.intn(2) == 0 else "A"
	chars[index] = chr(rand.intn(26) + ord(base))
	return "".join(chars)


def replace_tautologies() -> FilterMiddleware:
	existing_attrs = tuple(ATTR_FORMATS)

	def basic(f: Filter) -> Filter:
		return FilterOr([FilterNot(f), f])

	def random_other_attr(f: Filter) -> str:
		current = get_attr_name(f) or ""
		attr = ""
		while attr == "" or attr == current:
			attr = existing_attrs[rand.intn(len(existing_attrs))]
		return attr

	def random_letter() -> str:
		return chr(rand.intn(26) + ord("a"))

	def bitwise_and(_: Filter) -> Filter:
		attr = BITWISE_ATTRS[rand.intn(len(BITWISE_ATTRS))]
		return FilterOr([FilterExtensibleMatch(BITWISE_AND, attr, "0"), FilterNot(FilterPresent(attr))])

	def bitwise_or(_: Filter) -> Filter:
		attr = BITWISE_ATTRS[rand.intn(len(BITWISE_ATTRS))]
		return FilterOr([
			FilterExtensibleMatch(BITWISE_OR, attr, "4294967295"),
			FilterNot(FilterPresent(attr)),
			FilterEqualityMatch(attr, "0"),
		])

	def typo(_: Filter) -> Filter:
		while True:
			candidate = _generate_typo(existing_attrs[rand.intn(len(existing_attrs))])
			if to_lower(candidate) not in ATTR_FORMATS:
				return FilterNot(FilterPresent(candidate))

	def presence(f: Filter) -> Filter:
		return basic(FilterPresent(random_other_attr(f)))

	def equality(f: Filter) -> Filter:
		attr = random_other_attr(f)
		return basic(FilterEqualityMatch(attr, random_letter()))

	def substring(f: Filter) -> Filter:
		attr = random_other_attr(f)
		substrings = []
		if rand.intn(2) == 0:
			substrings.append(SubstringFilter(initial=random_letter()))
		if rand.intn(2) == 0:
			substrings.append(SubstringFilter(any=random_letter()))
		if rand.intn(2) == 0:
			substrings.append(SubstringFilter(final=random_letter()))
		return basic(FilterSubstring(attr, substrings))

	def bitwise(_: Filter) -> Filter:
		attr = BITWISE_ATTRS[rand.intn(len(BITWISE_ATTRS))]
		rule = BITWISE_OR if rand.intn(2) == 0 else BITWISE_AND
		return basic(FilterExtensibleMatch(rule, attr, str(rand.intn(4294967296))))

	tautologies = (bitwise_and, bitwise_or, typo, presence, equality, substring, bitwise)

	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterPresent) and to_lower(f.attribute_desc) in GREEDY_ATTR_PRESENCES:
			return tautologies[rand.intn(len(tautologies))](f)
		return f

	return leaf_applier(middleware)


def rand_dn_attributes_noise(prob: float) -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterExtensibleMatch) and rand.float64() < prob:
			f.dn_attributes = not f.dn_attributes
		return f

	return leaf_applier(middleware)


def transitive_eval() -> FilterMiddleware:
	def middleware(f: Filter) -> Filter:
		if isinstance(f, FilterEqualityMatch) and to_lower(f.attribute_desc) in TRANSITIVE_LINK_ATTRS:
			return FilterExtensibleMatch(TRANSITIVE_EVAL, f.attribute_desc, f.assertion_value)
		return f

	return leaf_applier(middleware)
