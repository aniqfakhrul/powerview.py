import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ldap3
from ldap3 import DEREF_ALWAYS, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
from ldap3.operation.add import add_operation
from ldap3.operation.compare import compare_operation
from ldap3.operation.delete import delete_operation
from ldap3.operation.modify import modify_operation
from ldap3.operation.modifyDn import modify_dn_operation
from ldap3.operation.search import compile_filter, parse_filter, search_operation
from ldap3.protocol.rfc2696 import paged_search_control
from pyasn1.codec.ber import encoder

from powerview.lib.adws.core.connection import Connection as ADWSConnection
from powerview.lib.ldap3.extend import CustomStandardExtendedOperations
from powerview.lib.ldapx import Obfuscator, attach, detach, interceptor_of
from powerview.lib.ldapx.parser.asn1 import filter_from_asn1, text
from powerview.lib.ldapx.parser.filter import (
	FilterEqualityMatch,
	filter_to_ldap_string,
	query_to_filter,
)
from powerview.utils.obfuscation import ObfuscationSettings, apply_to_session
from tools.ldapx.support import go_rand

QUERY = "(&(samAccountType=805306368)(|(sAMAccountName=Administrator)(cn=Administrator))(objectSid=S-1-5-21-1-2-3-500))"
BASE = "CN=Users,DC=wonka,DC=lab"
ATTRIBUTES = ["sAMAccountName", "objectSid", "memberOf"]
ALL_OPERATIONS = ("search", "modify", "add", "delete", "modifydn", "compare")


def offline_connection():
	connection = ldap3.Connection(ldap3.Server("127.0.0.1"))
	connection.listening = True
	connection.strategy._outstanding = {}
	connection.sent = []
	connection.strategy.sending = connection.sent.append
	return connection


def wire(connection):
	return connection.sent[-1]["protocolOp"].getComponent()


def search_request(query=QUERY, base=BASE, attributes=ATTRIBUTES):
	return search_operation(base, query, SUBTREE, DEREF_ALWAYS, list(attributes), 0, 0, False, True, True, None, None, False)


def paged(cookie):
	return [paged_search_control(False, 100, cookie)]


class SearchInterceptionTests(unittest.TestCase):
	def setUp(self):
		self.connection = offline_connection()
		self.obfuscator = Obfuscator("CZNDRGx", "WCX", "CRD")
		attach(self.connection, self.obfuscator)

	def search(self, request=None, controls=None):
		self.connection.send("searchRequest", request or search_request(), controls)
		return wire(self.connection)

	def test_search_on_the_wire_equals_upstream_chain_order(self):
		with go_rand(11):
			expected_filter = self.obfuscator.filter(query_to_filter(QUERY))
			expected_attributes = self.obfuscator.attrlist(ATTRIBUTES)
			expected_base = self.obfuscator.basedn(BASE)
		with go_rand(11):
			request = self.search()
		self.assertEqual(filter_from_asn1(request["filter"]), expected_filter)
		self.assertEqual([text(a) for a in request["attributes"]], expected_attributes)
		self.assertEqual(text(request["baseObject"]), expected_base)

	def test_ldap3_keeps_the_original_request_metadata(self):
		self.search()
		self.assertEqual(self.connection.request["attributes"], ATTRIBUTES)
		self.assertEqual(self.connection.request["base"], BASE)

	def test_ldap3_request_objects_are_never_mutated(self):
		attach(self.connection, Obfuscator("CZNDRG", "CX", "CRO"), ALL_OPERATIONS)
		requests = [
			("searchRequest", search_request()),
			("modifyRequest", modify_operation(BASE, {"description": [(MODIFY_REPLACE, ["x"])]}, True, None, None, False)),
			("addRequest", add_operation(BASE, {"cn": ["a"]}, True, None, None, False)),
			("modDNRequest", modify_dn_operation(BASE, "CN=b", True, "DC=x")),
			("compareRequest", compare_operation(BASE, "cn", "a", True, None, None, False)),
		]
		for message_type, request in requests:
			before = encoder.encode(request)
			self.connection.send(message_type, request)
			self.assertEqual(encoder.encode(request), before, message_type)

	def test_transformed_filter_encodes_exactly_like_ldap3(self):
		for seed in range(20):
			with go_rand(seed):
				request = self.search()
			rendered = filter_to_ldap_string(filter_from_asn1(request["filter"]))
			compiled = compile_filter(parse_filter(rendered, None, True, True, None, False).elements[0])
			self.assertEqual(encoder.encode(request["filter"]), encoder.encode(compiled))

	def test_values_survive_that_ldap3_string_parsing_would_normalize(self):
		attach(self.connection, Obfuscator("Z"))
		with go_rand(3):
			request = self.search(search_request("(userAccountControl=512)"))
		value = text(request["filter"].getComponent()["assertionValue"])
		self.assertTrue(value.startswith("0") and value.endswith("512"))

	def test_unchanged_rendering_keeps_the_original_filter(self):
		attach(self.connection, Obfuscator("s", options={"FiltSubstringSplitProb": "1"}))
		request = self.search(search_request("(cn=)"))
		self.assertEqual(filter_from_asn1(request["filter"]), FilterEqualityMatch("cn", ""))

	def test_paged_continuation_replays_the_first_transformed_request(self):
		first = encoder.encode(self.search(controls=paged(None)))
		self.assertEqual(encoder.encode(self.search(controls=paged(b"cookie"))), first)

	def test_new_search_without_cookie_is_transformed_again(self):
		with go_rand(1):
			first = encoder.encode(self.search(controls=paged(None)))
			second = encoder.encode(self.search(controls=paged(None)))
		self.assertNotEqual(second, first)

	def test_cookie_without_tracked_request_falls_back_to_a_fresh_transform(self):
		request = self.search(search_request("(cn=unseen)"), paged(b"cookie"))
		self.assertNotEqual(filter_from_asn1(request["filter"]), query_to_filter("(cn=unseen)"))

	def test_write_operations_are_untouched_unless_enabled(self):
		self.connection.send("delRequest", delete_operation(BASE))
		self.assertEqual(text(wire(self.connection)), BASE)


class WriteInterceptionTests(unittest.TestCase):
	def setUp(self):
		self.connection = offline_connection()
		attach(self.connection, Obfuscator("C", "C", "", "OCR"), ALL_OPERATIONS)

	def test_modify_obfuscates_target_and_attribute_names_but_not_values(self):
		changes = {"description": [(MODIFY_REPLACE, ["x"])], "unicodePwd": [(MODIFY_REPLACE, [b"\x00\xff"])], "info": [(MODIFY_DELETE, [])]}
		self.connection.send("modifyRequest", modify_operation(BASE, changes, True, None, None, False))
		request = wire(self.connection)
		self.assertEqual(text(request["object"]).lower(), BASE.lower())
		names = [text(change["modification"]["type"]) for change in request["changes"]]
		self.assertEqual(names[2], "info")
		self.assertTrue(all(name.lower().startswith("oid.") for name in names[:2]))
		self.assertEqual(bytes(request["changes"][1]["modification"]["vals"][0]), b"\x00\xff")

	def test_add_uses_the_safe_basedn_chain(self):
		attach(self.connection, Obfuscator("", "W", "", "R"), ("add",))
		self.connection.send("addRequest", add_operation(BASE + ",DC=x", {"objectClass": ["user"], "cn": ["a"]}, True, None, None, False))
		self.assertEqual(text(wire(self.connection)["entry"]), BASE + ",DC=x")

	def test_delete_and_modify_dn_obfuscate_dns(self):
		attach(self.connection, Obfuscator("", "W"), ("delete", "modifydn"))
		self.connection.send("delRequest", delete_operation(BASE))
		self.assertTrue(text(wire(self.connection)).startswith("<WKGUID="))
		self.connection.send("modDNRequest", modify_dn_operation("CN=a,CN=Users,DC=x", "CN=b", True, "CN=Users,DC=x"))
		request = wire(self.connection)
		self.assertEqual(text(request["newrdn"]), "CN=b")
		self.assertTrue(text(request["newSuperior"]).startswith("<WKGUID="))

	def test_compare_keeps_single_assertion_and_rejects_compound_results(self):
		self.connection.send("compareRequest", compare_operation(BASE, "cn", "Administrator", True, None, None, False))
		self.assertEqual(text(wire(self.connection)["ava"]["assertionValue"]).lower(), "administrator")
		attach(self.connection, Obfuscator("D"), ("compare",))
		self.connection.send("compareRequest", compare_operation(BASE, "cn", "Administrator", True, None, None, False))
		self.assertEqual(text(wire(self.connection)["ava"]["assertionValue"]), "Administrator")


class ResponseAndReferralTests(unittest.TestCase):
	def setUp(self):
		self.connection = offline_connection()
		self.connection.strategy.decode_response_fast = lambda message: message
		self.referred = offline_connection()
		self.connection.strategy.create_referral_connection = lambda referrals: ("referral", self.referred, "key")

	def decode(self, raw_attributes):
		entry = {"type": "searchResEntry", "raw_attributes": dict(raw_attributes), "attributes": dict(raw_attributes)}
		return self.connection.strategy.decode_response_fast(entry)

	def test_completed_ranges_are_stripped_only_when_range_is_chained(self):
		attach(self.connection, Obfuscator(attrlist_chain="r"))
		entry = self.decode({"member;range=0-*": [b"a"], "cn;range=0-10": [b"b"], "x;Range=5-*;binary": [b"c"]})
		self.assertEqual(list(entry["raw_attributes"]), ["member", "cn;range=0-10", "x;binary"])
		attach(self.connection, Obfuscator(attrlist_chain="C"))
		self.assertEqual(list(self.decode({"member;range=0-*": [b"a"]})["attributes"]), ["member;range=0-*"])

	def test_plain_and_ranged_descriptors_are_merged(self):
		attach(self.connection, Obfuscator(attrlist_chain="r"))
		entry = self.decode({"member": [b"plain"], "member;range=0-*": [b"ranged"]})
		self.assertEqual(entry["raw_attributes"], {"member": [b"plain", b"ranged"]})

	def test_referral_connections_follow_the_parent_interceptor(self):
		attach(self.connection, Obfuscator("C"), ALL_OPERATIONS)
		_, referral, _ = self.connection.strategy.create_referral_connection([])
		self.assertIs(referral, self.referred)
		self.assertEqual(interceptor_of(referral).operations, frozenset(ALL_OPERATIONS))
		replacement = Obfuscator("Z")
		attach(self.connection, replacement, ("search",))
		self.assertIs(interceptor_of(referral).obfuscator, replacement)
		detach(self.connection)
		self.assertIsNone(interceptor_of(referral))


class PagedSearchAttributeTests(unittest.TestCase):
	def test_pages_share_one_immutable_attribute_selection(self):
		operations = CustomStandardExtendedOperations.__new__(CustomStandardExtendedOperations)
		operations._connection = MagicMock()
		operations.cache_namespace = "test-session"
		operations.server = SimpleNamespace(host="dc.example.test")
		operations.no_cache = True
		operations.no_vuln_check = True
		operations.use_adws = False
		operations.raw = False
		operations.cache = MagicMock()
		attributes = ["cn"]
		with patch("powerview.lib.ldap3.extend.paged_search_generator", return_value=iter([])) as generator:
			operations.paged_search(BASE, "(cn=*)", attributes=attributes, get_operational_attributes=True)
		self.assertEqual(generator.call_args.args[5], ("cn",))
		self.assertEqual(attributes, ["cn"])


class AttachmentTests(unittest.TestCase):
	def test_attach_is_idempotent_and_detach_restores_the_strategy(self):
		connection = offline_connection()
		recorder = connection.strategy.sending
		attach(connection, Obfuscator("C"))
		interceptor = interceptor_of(connection)
		attach(connection, Obfuscator("Z"))
		self.assertIs(interceptor_of(connection), interceptor)
		detach(connection)
		self.assertIs(connection.strategy.sending, recorder)
		self.assertIsNone(interceptor_of(connection))

	def test_real_ldap3_connection_is_wrapped_before_bind(self):
		connection = ldap3.Connection(ldap3.Server("127.0.0.1"))
		apply_to_session(connection, ObfuscationSettings.defaults())
		self.assertIsNotNone(interceptor_of(connection))
		apply_to_session(connection, None)
		self.assertIsNone(interceptor_of(connection))

	def test_adws_sessions_receive_a_string_obfuscator_for_searches_only(self):
		session = ADWSConnection.__new__(ADWSConnection)
		session.obfuscator = None
		apply_to_session(session, ObfuscationSettings.defaults())
		self.assertIsNotNone(session.obfuscator)
		apply_to_session(session, ObfuscationSettings(filter="C", operations=("modify",)))
		self.assertIsNone(session.obfuscator)


if __name__ == "__main__":
	unittest.main()
