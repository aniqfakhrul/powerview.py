import unittest
from unittest.mock import MagicMock, patch

from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin
from powerview.modules.dacledit import DACLedit, RIGHTS_GUID
from powerview.modules.ldapattack import ACLEnum, create_empty_sd
from powerview.powerview import PowerView
from powerview.utils.ace_identity import ace_identity, dacl_fingerprint


class ExactACLRemovalTests(unittest.TestCase):
    def setUp(self):
        self.editor = DACLedit.__new__(DACLedit)
        self.editor.inheritance = False
        self.editor.target_DN = 'CN=Target,DC=example,DC=test'
        self.editor.principal_security_descriptor = create_empty_sd()
        self.editor.modify_secDesc_for_dn = MagicMock(return_value=True)
        self.dacl = self.editor.principal_security_descriptor['Dacl']

    def simple(self, mask=0x40000):
        return self.editor.create_ace(mask, 'S-1-5-11', 'allowed')

    def identity(self, index):
        return ace_identity(self.dacl.aces[index], index, dacl_fingerprint(self.dacl))

    def test_removes_only_selected_duplicate_and_preserves_order(self):
        first, second, last = self.simple(), self.simple(), self.simple(0x20000)
        self.dacl.aces = [first, second, last]
        selection = self.identity(1)
        self.assertTrue(self.editor.remove_exact(selection))
        self.assertEqual(self.dacl.aces, [first, last])
        self.assertIs(self.dacl.aces[0], first)
        self.editor.modify_secDesc_for_dn.assert_called_once()
        with self.assertRaisesRegex(ValueError, 'DACL changed'):
            self.editor.remove_exact(selection)
        self.assertEqual(self.editor.modify_secDesc_for_dn.call_count, 1)

    def test_arbitrary_mask_and_class_restricted_ace_are_exactly_removable(self):
        ace = self.editor.create_object_ace(RIGHTS_GUID.WriteMembers.value, 'S-1-5-11', 'denied')
        ace['Ace']['Mask']['Mask'] = 0x40030
        ace['Ace']['Flags'] |= 2
        ace['Ace']['InheritedObjectType'] = string_to_bin('bf967aba-0de6-11d0-a285-00aa003049e2')
        ace['AceFlags'] = 11
        self.dacl.aces = [self.simple(), ace]
        self.assertTrue(self.editor.remove_exact(self.identity(1)))
        self.assertEqual(len(self.dacl.aces), 1)

    def test_changed_dacl_or_entry_is_rejected_without_writing(self):
        self.dacl.aces = [self.simple()]
        selection = self.identity(0)
        self.dacl.aces.append(self.simple(0x20000))
        with self.assertRaisesRegex(ValueError, 'DACL changed'):
            self.editor.remove_exact(selection)
        selection = self.identity(0)
        selection['ace'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'access entry changed'):
            self.editor.remove_exact(selection)
        self.editor.modify_secDesc_for_dn.assert_not_called()

    def test_inherited_entry_is_rejected_even_with_valid_identity(self):
        ace = self.simple()
        ace['AceFlags'] = 16
        self.dacl.aces = [ace]
        with self.assertRaisesRegex(ValueError, 'Inherited'):
            self.editor.remove_exact(self.identity(0))
        self.editor.modify_secDesc_for_dn.assert_not_called()

    def test_malformed_selection_is_rejected_without_writing(self):
        self.dacl.aces = [self.simple()]
        valid = self.identity(0)
        for selection in (None, {}, {'index': 0}, {**valid, 'index': True}, {**valid, 'index': -1}, {**valid, 'index': '0'}, {**valid, 'ace': 'invalid'}, {**valid, 'extra': 1}, {**valid, 'index': 999}):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                self.editor.remove_exact(selection)
        self.editor.modify_secDesc_for_dn.assert_not_called()

    def test_write_failure_is_propagated(self):
        self.dacl.aces = [self.simple()]
        self.editor.modify_secDesc_for_dn.return_value = False
        self.assertIs(self.editor.remove_exact(self.identity(0)), False)

    def test_enumeration_identity_survives_binary_roundtrip_and_filtering(self):
        inherited = self.simple()
        inherited['AceFlags'] = 16
        self.dacl.aces = [inherited, self.simple(0x20000), self.simple()]
        parsed = ldaptypes.ACL(data=self.dacl.getData())
        enum = ACLEnum(None, [], 'DC=example,DC=test', include_ace_identity=True)
        enum.resolve_trustee = MagicMock(return_value=('Principal', None))
        rows = enum.parseDACL(parsed)
        self.assertNotIn('RemovalIdentity', rows[0])
        self.assertEqual(rows[2]['RemovalIdentity'], self.identity(2))
        original = enum.parseACE
        enum.parseACE = lambda ace: None if ace['Ace']['Mask']['Mask'] == 0x20000 else original(ace)
        self.assertEqual(enum.parseDACL(parsed)[1]['RemovalIdentity']['index'], 2)

    def test_acl_response_keeps_target_classes_once_per_object(self):
        self.dacl.aces = [self.simple(), self.simple(0x20000)]
        for classes in (['top', 'user', 'computer'], 'group', None):
            entry = {'dn': self.editor.target_DN, 'attributes': {
                'objectClass': classes,
                'nTSecurityDescriptor': self.editor.principal_security_descriptor.getData(),
            }}
            enum = ACLEnum(None, [entry], 'DC=example,DC=test')
            enum.resolve_trustee = MagicMock(return_value=('Principal', None))
            result = enum.read_dacl()
            self.assertEqual(result[0]['objectClass'], ['group'] if classes == 'group' else classes or [])
            self.assertEqual(len(result[0]['attributes']), 2)
            self.assertNotIn('objectClass', result[0]['attributes'][0])

    def test_api_function_reads_fresh_without_resolving_principal(self):
        view = PowerView.__new__(PowerView)
        view.ldap_server = MagicMock()
        view.ldap_session = MagicMock()
        view.root_dn = 'DC=example,DC=test'
        self.dacl.aces = [self.simple()]
        selection = self.identity(0)
        view.get_domainobject = MagicMock(return_value=[{
            'dn': self.editor.target_DN, 'attributes': {},
            'raw_attributes': {'nTSecurityDescriptor': [self.editor.principal_security_descriptor.getData()]},
        }])
        with patch.object(DACLedit, 'modify_secDesc_for_dn', return_value=True) as write:
            self.assertTrue(view.remove_domainobjectacl(self.editor.target_DN, ace=selection))
            write.assert_called_once()
        view.get_domainobject.assert_called_once()
        self.assertTrue(view.get_domainobject.call_args.kwargs['no_cache'])
        with self.assertRaises(ValueError):
            view.remove_domainobjectacl(self.editor.target_DN, 'Someone', ace=selection)
