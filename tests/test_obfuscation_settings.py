import unittest
from argparse import Namespace
from types import SimpleNamespace

import ldap3
from flask import Flask

from powerview.utils.connections import CONNECTION, apply_obfuscation
from powerview.utils.obfuscation import ObfuscationSettings
from powerview.web.api.server import APIServer


class ObfuscationSettingsAPITests(unittest.TestCase):
	def setUp(self):
		self.app = Flask(__name__)
		self.connection = CONNECTION.__new__(CONNECTION)
		self.connection.obfuscation = None
		self.connection._connection_pool = SimpleNamespace(entries=lambda: [])
		self.server = ldap3.Server("127.0.0.1")
		self.session = ldap3.Connection(self.server)
		self.connection._ldap_session = self.session
		self.args = Namespace(
			obfuscate=False, obfuscate_basedn=None, obfuscate_attrlist=None,
			obfuscate_attrentries=None, obfuscate_option=None, obfuscate_ops=None,
			no_cache=False, no_vuln_check=False, use_adws=False, raw=False,
		)
		self.api = APIServer.__new__(APIServer)
		self.api.powerview = SimpleNamespace(
			conn=self.connection, args=self.args, ldap_session=self.session, ldap_server=self.server,
		)

	def configure(self, **kwargs):
		vars(self.args).update(kwargs)
		self.connection.obfuscation = ObfuscationSettings.from_args(self.args)
		apply_obfuscation(self.session, self.connection.obfuscation)
		return self.connection.obfuscation

	def get_settings(self):
		with self.app.test_request_context("/api/settings"):
			return self.api.handle_settings().get_json()

	def save_settings(self, body):
		with self.app.test_request_context("/api/set/settings", method="POST", json=body):
			response = self.api.handle_set_settings()
			if isinstance(response, tuple):
				return response[0].get_json(), response[1]
			return response.get_json(), response.status_code

	def test_specific_chain_settings_round_trip(self):
		expected = self.configure(obfuscate_basedn="W")
		state = self.get_settings()
		self.assertTrue(state["obfuscate"])
		self.assertEqual(self.save_settings(state)[1], 200)
		self.assertEqual(self.connection.obfuscation, expected)

	def test_custom_chains_options_and_operations_round_trip(self):
		expected = self.configure(
			obfuscate="CZXANDR", obfuscate_basedn="WCX", obfuscate_attrlist="CRD",
			obfuscate_attrentries="CR", obfuscate_option=[("FiltCaseProb", "0.9")],
			obfuscate_ops=("search", "modify"),
		)
		self.assertEqual(self.save_settings(self.get_settings())[1], 200)
		self.assertEqual(self.connection.obfuscation, expected)

	def test_saved_settings_restore_after_disabling(self):
		for values in ({"obfuscate_basedn": "W"}, {"obfuscate": "CZ", "obfuscate_basedn": "WCX"}):
			with self.subTest(values=values):
				expected = self.configure(**values)
				state = self.get_settings()
				self.assertEqual(self.save_settings({"obfuscate": False})[1], 200)
				self.assertIsNone(self.connection.obfuscation)
				self.assertEqual(self.save_settings(state)[1], 200)
				self.assertEqual(self.connection.obfuscation, expected)

	def test_unrelated_settings_preserve_obfuscation_and_other_settings(self):
		expected = self.configure(obfuscate_basedn="W", no_vuln_check=True)
		self.assertEqual(self.save_settings({"no_cache": True})[1], 200)
		self.assertEqual(self.connection.obfuscation, expected)
		self.assertTrue(self.args.no_vuln_check)
		self.assertTrue(self.args.no_cache)

	def test_legacy_filter_update_preserves_other_chains_and_options(self):
		expected = self.configure(obfuscate="CZ", obfuscate_basedn="WCX", obfuscate_option=[("FiltCaseProb", "0.9")])
		self.assertEqual(self.save_settings({"obfuscate": "CZXANDR"})[1], 200)
		self.assertEqual(self.connection.obfuscation.filter, "CZXANDR")
		self.assertEqual(self.connection.obfuscation.basedn, expected.basedn)
		self.assertEqual(self.connection.obfuscation.options, expected.options)

	def test_invalid_settings_leave_the_active_configuration_unchanged(self):
		expected = self.configure(obfuscate_basedn="W", no_cache=True)
		for body in ({"obfuscate": "?"}, {"obfuscate": True, "obfuscate_basedn": "XW"}):
			with self.subTest(body=body):
				self.assertEqual(self.save_settings(body)[1], 400)
				self.assertEqual(self.connection.obfuscation, expected)
				self.assertTrue(self.args.no_cache)

	def test_disabled_settings_do_not_report_stale_chains(self):
		self.configure(obfuscate="CZ", obfuscate_basedn="WCX")
		self.assertEqual(self.save_settings({"obfuscate": False})[1], 200)
		state = self.get_settings()
		self.assertFalse(state["obfuscate"])
		self.assertIsNone(state["obfuscate_basedn"])
		self.assertIsNone(ObfuscationSettings.from_args(self.args))

	def test_numeric_option_values_are_normalized_to_strings(self):
		body = {
			"obfuscate": True,
			"obfuscate_option": [["AttrsCaseProb", 0.5], ["AttrsGarbageExistingMaxElems", 2]],
		}
		self.assertEqual(self.save_settings(body)[1], 200)
		self.assertEqual(self.connection.obfuscation.options, (("AttrsCaseProb", "0.5"), ("AttrsGarbageExistingMaxElems", "2")))
		self.assertEqual(self.connection.obfuscation.obfuscator.options.get_float("AttrsCaseProb"), 0.5)

	def test_chain_only_updates_enable_just_the_requested_chain(self):
		for name, chain in (("filter", "CZ"), ("basedn", "CX"), ("attrlist", "r"), ("attrentries", "CR")):
			with self.subTest(chain=name):
				self.save_settings({"obfuscate": False})
				self.assertEqual(self.save_settings({"obfuscate_" + name: chain})[1], 200)
				self.assertEqual(self.connection.obfuscation, ObfuscationSettings(**{name: chain}))

	def test_operations_and_options_alone_require_an_enabling_flag(self):
		for body in (
			{"obfuscate_ops": ["modify"]},
			{"obfuscate_ops": "search,modify"},
			{"obfuscate_option": [["AttrsCaseProb", 0.5]]},
		):
			with self.subTest(body=body):
				response, status = self.save_settings(body)
				self.assertEqual(status, 400)
				self.assertIn("require --obfuscate or a chain flag", response["error"])
				self.assertIsNone(self.connection.obfuscation)

	def test_explicit_false_disables_obfuscation_even_with_chain_keys(self):
		self.configure(obfuscate_basedn="W")
		self.assertEqual(self.save_settings({"obfuscate": False, "obfuscate_basedn": "CX"})[1], 200)
		self.assertIsNone(self.connection.obfuscation)

	def test_comma_separated_operations_use_cli_normalization(self):
		body = {"obfuscate": True, "obfuscate_ops": " Search, Modify,search "}
		self.assertEqual(self.save_settings(body)[1], 200)
		self.assertEqual(self.connection.obfuscation.operations, ("search", "modify"))

	def test_invalid_operation_strings_return_a_clear_validation_error(self):
		expected = self.configure(obfuscate_basedn="W")
		for operations in ("search,bogus", "", ", ,"):
			with self.subTest(operations=operations):
				response, status = self.save_settings({"obfuscate_ops": operations})
				self.assertEqual(status, 400)
				self.assertIn("Invalid obfuscation settings:", response["error"])
				self.assertEqual(self.connection.obfuscation, expected)


if __name__ == "__main__":
	unittest.main()
