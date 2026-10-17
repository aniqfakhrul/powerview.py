import hashlib
import logging
import threading
import weakref
from collections import OrderedDict
from collections.abc import Iterable, MutableMapping
from typing import TypeVar

from ldap3 import Connection
from ldap3.protocol.rfc2696 import RealSearchControlValue
from ldap3.protocol.rfc4511 import (
	LDAPDN,
	AssertionValue,
	AttributeDescription,
	AttributeList,
	AttributeSelection,
	AttributeValueAssertion,
	Changes,
	Control,
	DelRequest,
	NewSuperior,
	ProtocolOp,
	RelativeLDAPDN,
	Selector,
)
from ldap3.protocol.rfc4511 import Attribute as Asn1Attribute
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error

from powerview.lib.ldapx.gostd import to_bytes
from powerview.lib.ldapx.middlewares.attrlist import strip_completed_range_option
from powerview.lib.ldapx.obfuscator import Obfuscator
from powerview.lib.ldapx.parser.asn1 import filter_from_asn1, filter_to_asn1, text
from powerview.lib.ldapx.parser.attributes import Attribute
from powerview.lib.ldapx.parser.filter import FilterEqualityMatch, filter_to_query

OPERATIONS = ("search", "modify", "add", "delete", "modifydn", "compare")
DEFAULT_OPERATIONS = ("search",)
PAGED_RESULTS_OID = "1.2.840.113556.1.4.319"
TRACKED_SEARCHES = 1024

_MESSAGE_OPERATIONS = {
	"searchRequest": "search",
	"modifyRequest": "modify",
	"addRequest": "add",
	"delRequest": "delete",
	"modDNRequest": "modifydn",
	"compareRequest": "compare",
}
_RESPONSE_DECODERS = ("decode_response", "decode_response_fast")
_STRATEGY_ATTRIBUTE = "_powerview_ldapx"

T = TypeVar("T")


def normalize_operations(operations: Iterable[str]) -> frozenset[str]:
	normalized = frozenset(operations)
	unknown = sorted(normalized.difference(OPERATIONS))
	if unknown:
		raise ValueError("unknown operation(s) %s, expected a subset of: %s" % (", ".join(unknown), ", ".join(OPERATIONS)))
	return normalized


def _printable(value: str) -> str:
	return to_bytes(value).decode("utf-8", "backslashreplace")


def _debug_search(label: str, base: str, query: str, attributes: list[str]) -> None:
	if logging.getLogger().isEnabledFor(logging.DEBUG):
		logging.debug("[ldapx] %s Search base='%s' filter=%s attributes=%s", label, _printable(base), _printable(query), [_printable(a) for a in attributes])


def _paged_cookie(controls) -> bytes:
	for control in controls or ():
		if isinstance(control, Control):
			oid = str(control["controlType"])
			value = control["controlValue"]
			value = bytes(value) if value is not None and value.hasValue() else b""
		elif isinstance(control, (tuple, list)) and len(control) == 3:
			oid, _, value = control
			value = bytes(value or b"")
		else:
			continue
		if oid != PAGED_RESULTS_OID or not value:
			continue
		try:
			decoded, _ = decoder.decode(value, asn1Spec=RealSearchControlValue())
		except PyAsn1Error:
			logging.debug("[ldapx] Malformed paged results control value - skipping tracking for this control")
			continue
		cookie = bytes(decoded["cookie"])
		if cookie:
			return cookie
	return b""


def _message_controls(ldap_message):
	controls = ldap_message["controls"]
	return controls if controls is not None and controls.isValue else None


class Interceptor:
	def __init__(self, strategy, obfuscator: Obfuscator, operations: Iterable[str] = DEFAULT_OPERATIONS):
		self._strategy = strategy
		self._lock = threading.Lock()
		self._tracked = OrderedDict()
		self._referrals = weakref.WeakSet()
		self.obfuscator = obfuscator
		self.operations = normalize_operations(operations)
		self._originals = {"sending": strategy.sending, "create_referral_connection": strategy.create_referral_connection}
		self._originals.update({name: getattr(strategy, name) for name in _RESPONSE_DECODERS if hasattr(strategy, name)})
		strategy.sending = self._sending
		strategy.create_referral_connection = self._create_referral_connection
		for name in _RESPONSE_DECODERS:
			if name in self._originals:
				setattr(strategy, name, self._range_stripping(self._originals[name]))

	def configure(self, obfuscator: Obfuscator, operations: Iterable[str] = DEFAULT_OPERATIONS) -> None:
		operations = normalize_operations(operations)
		with self._lock:
			self.obfuscator = obfuscator
			self.operations = operations
			self._tracked.clear()
		for referral in list(self._referrals):
			attach(referral, obfuscator, operations)

	def restore(self) -> None:
		for referral in list(self._referrals):
			detach(referral)
		for name, original in self._originals.items():
			setattr(self._strategy, name, original)

	def _sending(self, ldap_message):
		protocol_op = ldap_message["protocolOp"]
		message_type = protocol_op.getName()
		operation = _MESSAGE_OPERATIONS.get(message_type)
		if operation in self.operations:
			request = getattr(self, "_" + operation)(protocol_op.getComponent(), _message_controls(ldap_message))
			ldap_message["protocolOp"] = ProtocolOp().setComponentByName(message_type, request)
		return self._originals["sending"](ldap_message)

	def _create_referral_connection(self, referrals):
		selected_referral, referral_connection, cachekey = self._originals["create_referral_connection"](referrals)
		if referral_connection is not None:
			attach(referral_connection, self.obfuscator, self.operations)
			self._referrals.add(referral_connection)
		return selected_referral, referral_connection, cachekey

	def _range_stripping(self, decode):
		def decode_response(message):
			response = decode(message)
			if (
				self.obfuscator.strips_ranges
				and response.get("type") == "searchResEntry"
				and not hasattr(self._strategy, "_auto_range_searching")
			):
				for key in ("raw_attributes", "attributes"):
					if response.get(key):
						response[key] = _strip_completed_ranges(response[key])
			return response

		return decode_response

	def _search(self, request, controls):
		key = hashlib.sha256(encoder.encode(request)).digest()
		with self._lock:
			if _paged_cookie(controls):
				tracked = self._tracked.get(key)
				if tracked is not None:
					self._tracked.move_to_end(key)
					logging.debug("[ldapx] [Paging] Search Request Forwarded")
					return tracked
				logging.debug("[ldapx] Error finding previous packet (tracking algorithm)")

			base = text(request["baseObject"])
			search_filter = filter_from_asn1(request["filter"])
			attributes = [text(attribute) for attribute in request["attributes"]]
			query = filter_to_query(search_filter)
			_debug_search("Intercepted", base, query, attributes)

			new_filter = self.obfuscator.filter(search_filter)
			new_attributes = self.obfuscator.attrlist(attributes)
			new_base = self.obfuscator.basedn(base)
			new_query = filter_to_query(new_filter)

			replacements = {}
			if new_base != base:
				replacements["baseObject"] = LDAPDN(to_bytes(new_base))
			if new_query != query:
				replacements["filter"] = filter_to_asn1(new_filter)
			if new_attributes != attributes:
				replacements["attributes"] = _attribute_selection(new_attributes)
			request = _replace_components(request, **replacements)
			_debug_search("Changed", new_base, new_query, new_attributes)

			self._tracked[key] = request
			self._tracked.move_to_end(key)
			while len(self._tracked) > TRACKED_SEARCHES:
				self._tracked.popitem(last=False)
			return request

	def _modify(self, request, controls):
		target = self.obfuscator.basedn(text(request["object"]))
		changes = Changes()
		for index, change in enumerate(request["changes"]):
			changes.setComponentByPosition(index, self._modify_change(change), verifyConstraints=False)
		logging.debug("[ldapx] Changed Modify target='%s'", _printable(target))
		return _replace_components(request, object=LDAPDN(to_bytes(target)), changes=changes)

	def _modify_change(self, change):
		modification = change["modification"]
		name = text(modification["type"])
		values = list(modification["vals"])
		if not values:
			return change
		entries = self.obfuscator.attrentries([Attribute(name, values)])
		if len(entries) != 1 or entries[0].name == name:
			return change
		return _replace_components(change, modification=_replace_components(modification, type=AttributeDescription(to_bytes(entries[0].name))))

	def _add(self, request, controls):
		entry = self.obfuscator.basedn_safe(text(request["entry"]))
		replacements = {"entry": LDAPDN(to_bytes(entry))}
		entries = _merge_attributes(request["attributes"])
		valued = [attribute for attribute in entries if attribute.values]
		changed = self.obfuscator.attrentries(valued)
		if [(e.name, e.values) for e in changed] != [(e.name, e.values) for e in valued]:
			replacements["attributes"] = _attribute_list(changed + [attribute for attribute in entries if not attribute.values])
		logging.debug("[ldapx] Changed Add entry='%s' attributes=%s", _printable(entry), [_printable(e.name) for e in changed])
		return _replace_components(request, **replacements)

	def _delete(self, request, controls):
		target = self.obfuscator.basedn(text(request))
		logging.debug("[ldapx] Changed Delete target='%s'", _printable(target))
		return DelRequest(to_bytes(target))

	def _modifydn(self, request, controls):
		entry = self.obfuscator.basedn(text(request["entry"]))
		superior_value = request.getComponentByName("newSuperior", default=None, instantiate=False)
		superior = self.obfuscator.basedn(text(superior_value) if superior_value is not None else "")
		replacements = {
			"entry": LDAPDN(to_bytes(entry)),
			"newrdn": RelativeLDAPDN(to_bytes(self.obfuscator.basedn_safe(text(request["newrdn"])))),
		}
		if superior_value is not None:
			replacements["newSuperior"] = NewSuperior(to_bytes(superior))
		logging.debug("[ldapx] Changed ModifyDN entry='%s'", _printable(entry))
		return _replace_components(request, **replacements)

	def _compare(self, request, controls):
		replacements = {"entry": LDAPDN(to_bytes(self.obfuscator.basedn(text(request["entry"]))))}
		ava = request["ava"]
		result = self.obfuscator.filter(FilterEqualityMatch(text(ava["attributeDesc"]), text(ava["assertionValue"])))
		if isinstance(result, FilterEqualityMatch):
			assertion = AttributeValueAssertion()
			assertion["attributeDesc"] = AttributeDescription(to_bytes(result.attribute_desc))
			assertion["assertionValue"] = AssertionValue(to_bytes(result.assertion_value))
			replacements["ava"] = assertion
		else:
			logging.debug("[ldapx] Filter chain rewrote the assertion into a compound filter, which a Compare cannot carry - assertion left unchanged")
		return _replace_components(request, **replacements)


# pyasn1 clone() cannot copy ldap3's recursive Not filters, so requests are rebuilt sharing their untouched
# components instead of being mutated: ldap3 keeps and may resend the original request.
def _replace_components(component: T, **replacements) -> T:
	copied = type(component)()
	for named_type in component.componentType.namedTypes:
		value = replacements.get(named_type.name)
		if value is None:
			value = component.getComponentByName(named_type.name, default=None, instantiate=False)
		if value is not None:
			copied.setComponentByName(named_type.name, value, verifyConstraints=False)
	return copied


def _as_list(values) -> list:
	return list(values) if isinstance(values, (list, tuple)) else [values]


def _strip_completed_ranges(attributes: MutableMapping) -> MutableMapping:
	stripped = type(attributes)()
	for name, values in attributes.items():
		name = strip_completed_range_option(name)
		if name in stripped:
			stripped[name] = _as_list(stripped[name]) + _as_list(values)
		else:
			stripped[name] = values
	return stripped


def _attribute_selection(attributes: list[str]) -> AttributeSelection:
	selection = AttributeSelection()
	for index, attribute in enumerate(attributes):
		selection.setComponentByPosition(index, Selector(to_bytes(attribute)))
	return selection


def _merge_attributes(asn1_attributes) -> list[Attribute]:
	merged = []
	for asn1_attribute in asn1_attributes:
		name = text(asn1_attribute["type"])
		values = list(asn1_attribute["vals"])
		existing = next((entry for entry in merged if entry.name == name), None)
		if existing is None:
			merged.append(Attribute(name, values))
		else:
			existing.values.extend(values)
	return merged


def _attribute_list(entries: list[Attribute]) -> AttributeList:
	attribute_list = AttributeList()
	for index, entry in enumerate(entries):
		asn1_attribute = Asn1Attribute()
		asn1_attribute["type"] = AttributeDescription(to_bytes(entry.name))
		for position, value in enumerate(entry.values):
			asn1_attribute["vals"].setComponentByPosition(position, value)
		attribute_list.setComponentByPosition(index, asn1_attribute)
	return attribute_list


def attach(connection: Connection, obfuscator: Obfuscator | None, operations: Iterable[str] = DEFAULT_OPERATIONS) -> None:
	if obfuscator is None:
		detach(connection)
		return
	strategy = connection.strategy
	interceptor = getattr(strategy, _STRATEGY_ATTRIBUTE, None)
	if interceptor is None:
		setattr(strategy, _STRATEGY_ATTRIBUTE, Interceptor(strategy, obfuscator, operations))
	else:
		interceptor.configure(obfuscator, operations)


def detach(connection: Connection) -> None:
	strategy = getattr(connection, "strategy", None)
	interceptor = getattr(strategy, _STRATEGY_ATTRIBUTE, None)
	if interceptor is not None:
		interceptor.restore()
		delattr(strategy, _STRATEGY_ATTRIBUTE)


def interceptor_of(connection: Connection) -> Interceptor | None:
	return getattr(getattr(connection, "strategy", None), _STRATEGY_ATTRIBUTE, None)
