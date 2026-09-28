import unittest
from unittest.mock import MagicMock, patch

from ldap3.protocol.microsoft import security_descriptor_control

from powerview.modules.ldapattack import ACLEnum, ACCESS_MASK, SIMPLE_PERMISSIONS
from powerview.powerview import PowerView
from powerview.utils.query_cache import QueryCache
from tests import test_cache_and_dns_names


class ACLEnumerationTests(unittest.TestCase):
	def test_combined_permissions_preserve_additional_rights(self):
		enum = ACLEnum(None, [], 'DC=test')
		mask = SIMPLE_PERMISSIONS.Read.value | ACCESS_MASK.WriteDACL.value
		self.assertEqual(enum.parsePerms(mask), ['Read', 'WriteDACL'])

	def test_unsupported_ace_returns_diagnostic_without_losing_the_object(self):
		ace = MagicMock()
		ace.__getitem__.side_effect = {
			"Ace": {"Sid": MagicMock(formatCanonical=lambda: "S-1-5-18")},
			"TypeName": "ACCESS_ALLOWED_CALLBACK_ACE",
		}.__getitem__
		ace.hasFlag.return_value = False
		result = ACLEnum(None, [], "DC=test").parseACE(ace)
		self.assertEqual(result["ACEType"], "ACCESS_ALLOWED_CALLBACK_ACE")
		self.assertEqual(result["ACEFlags"], "None")

	def test_direct_principal_call_without_cli_args(self):
		view = PowerView.__new__(PowerView)
		view.root_dn = 'DC=test'
		view.get_domainobject = MagicMock(return_value=[{'attributes': {}}])
		with patch('powerview.powerview.ACLEnum') as parser:
			view.get_domainobjectacl(security_identifier='S-1-5-18', guids_map_dict={'guid': 'right'}, no_cache=True)
			self.assertTrue(parser.call_args.kwargs['no_cache'])
			parser.return_value.read_dacl.assert_called_once()

	def test_each_trustee_is_refreshed_once_per_enumeration(self):
		view = MagicMock()
		view.convertfrom_sid.return_value = 'TEST\\alice'
		enum = ACLEnum(view, [], 'DC=test', no_cache=True)
		self.assertEqual(enum.resolve_sid('sid'), 'TEST\\alice')
		self.assertEqual(enum.resolve_sid('sid'), 'TEST\\alice')
		view.convertfrom_sid.assert_called_once_with('sid', no_cache=True)



class ACLCacheTests(unittest.TestCase):
	def test_control_and_session_changes_use_separate_cache_entries(self):
		helper = test_cache_and_dns_names.PagedSearchCacheTests()
		operations = helper.make_operations()
		operations.cache = QueryCache()
		operations._connection.user = 'alice'
		with patch('powerview.lib.ldap3.extend.paged_search_generator', return_value=[]) as query:
			for flags in (5, 5, 4):
				operations.paged_search('DC=test', '(objectClass=*)', attributes=['nTSecurityDescriptor'], controls=security_descriptor_control(sdflags=flags))
			self.assertEqual(query.call_count, 2)
			operations.cache_namespace = 'another-session'
			operations.paged_search('DC=test', '(objectClass=*)', attributes=['nTSecurityDescriptor'], controls=security_descriptor_control(sdflags=4))
			self.assertEqual(query.call_count, 3)


if __name__ == '__main__':
	unittest.main()
