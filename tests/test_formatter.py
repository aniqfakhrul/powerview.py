import contextlib
import copy
import io
import json
import unittest
from argparse import Namespace

from ldap3.utils.ciDict import CaseInsensitiveDict

from powerview.utils.formatter import FORMATTER


def args(**overrides):
	base = dict(tableview="", select=None, properties=None, outfile=None, nowrap=True, count=False, json=False)
	base.update(overrides)
	return Namespace(**base)


def render(method_name, entries, **overrides):
	buffer = io.StringIO()
	with contextlib.redirect_stdout(buffer):
		getattr(FORMATTER(args(**overrides)), method_name)(entries)
	return buffer.getvalue()


def acl_entries():
	return [{"dn": "CN=t", "attributes": [
		{"ObjectDN": "CN=t", "ACEType": "ACCESS_ALLOWED_ACE", "ACEFlags": ["CONTAINER_INHERIT_ACE", "INHERITED_ACE"], "ActiveDirectoryRights": ["ReadControl", "WriteDACL"], "SecurityIdentifier": "TEST\\alice"},
		{"ObjectDN": "CN=t", "ACEType": "ACCESS_DENIED_OBJECT_ACE", "ACEFlags": [], "AccessMask": ["WriteProperty"], "ObjectAceFlags": [], "SecurityIdentifier": "TEST\\bob"},
	]}]


def object_entries():
	entries = []
	for name, groups in (("carol", ["CN=Admins"]), ("alice", ["CN=Staff", "CN=Admins"]), ("bob", [])):
		attributes = CaseInsensitiveDict()
		attributes["sAMAccountName"] = name
		attributes["memberOf"] = groups
		entries.append({"dn": f"CN={name}", "attributes": attributes})
	return entries


class FormatterTextTests(unittest.TestCase):
	def test_ace_lists_print_on_one_line(self):
		lines = render("print", acl_entries()).splitlines()
		width = len("ActiveDirectoryRights") + 5
		self.assertIn(f"{'ActiveDirectoryRights'.ljust(width)}: ReadControl, WriteDACL", lines)
		self.assertIn(f"{'ACEFlags'.ljust(width)}: CONTAINER_INHERIT_ACE, INHERITED_ACE", lines)

	def test_object_lists_print_one_item_per_aligned_line(self):
		lines = render("print", object_entries()).splitlines()
		width = len("sAMAccountName") + 5
		self.assertIn(f"{'memberOf'.ljust(width)}: CN=Staff", lines)
		self.assertIn(f"{''.ljust(width + 2)}CN=Admins", lines)

	def test_json_keeps_ace_lists(self):
		self.assertEqual(json.loads(render("print_json", acl_entries()))[0]["attributes"][0]["ActiveDirectoryRights"], ["ReadControl", "WriteDACL"])

	def test_empty_lists_are_omitted(self):
		output = render("print", acl_entries())
		self.assertEqual(output.count("ACEFlags"), 1)
		self.assertNotIn("ObjectAceFlags", output)

	def test_single_select_prints_the_ace_list_on_one_line(self):
		self.assertEqual(render("print_select", acl_entries(), select=["ActiveDirectoryRights"]).strip(), "ReadControl, WriteDACL")

	def test_where_matches_individual_list_items(self):
		entries = acl_entries()
		original = copy.deepcopy(entries)
		for condition, expected in (("ACEFlags contains inherited", ["TEST\\alice"]), ("activedirectoryrights eq writedacl", ["TEST\\alice"]), ("ACEFlags not INHERITED_ACE", ["TEST\\bob"])):
			filtered = FORMATTER(args()).alter_entries(entries, condition)
			self.assertEqual([ace["SecurityIdentifier"] for ace in filtered[0]["attributes"]], expected)
		self.assertEqual(entries, original)

	def test_where_null_selects_populated_values(self):
		filtered = FORMATTER(args()).alter_entries(object_entries(), "memberOf not null")
		self.assertEqual([entry["attributes"]["sAMAccountName"] for entry in filtered], ["carol", "alice"])

	def test_sort_orders_entries_and_puts_missing_values_last(self):
		ordered = FORMATTER(args()).sort_entries(object_entries(), "memberof")
		self.assertEqual([entry["attributes"]["sAMAccountName"] for entry in ordered], ["carol", "alice", "bob"])
		ordered = FORMATTER(args()).sort_entries(object_entries(), "samaccountname")
		self.assertEqual([entry["attributes"]["sAMAccountName"] for entry in ordered], ["alice", "bob", "carol"])

	def test_sort_with_unknown_key_keeps_the_original_order(self):
		entries = object_entries()
		with self.assertLogs(level="WARNING"):
			self.assertIs(FORMATTER(args()).sort_entries(entries, "missing"), entries)

	def test_table_headers_cover_every_ace_key(self):
		output = render("table_view", acl_entries(), tableview="csv")
		header = output.strip().splitlines()[0]
		for key in ("ActiveDirectoryRights", "AccessMask", "ObjectAceFlags"):
			self.assertIn(key, header)
		self.assertIn('"ReadControl, WriteDACL"', output)
		self.assertIn('"CN=Staff\nCN=Admins"', render("table_view", object_entries(), tableview="csv"))


if __name__ == '__main__':
	unittest.main()
