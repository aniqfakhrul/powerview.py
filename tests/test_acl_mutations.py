import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from impacket.uuid import string_to_bin
from impacket.ldap import ldaptypes
from powerview.modules.ldapattack import ACLEnum
from powerview.modules.dacledit import DACLedit, RIGHTS_GUID, SIMPLE_PERMISSIONS
from powerview.powerview import PowerView


class ACLMutationTests(unittest.TestCase):
    def editor(self, rights='fullcontrol'):
        editor = DACLedit.__new__(DACLedit)
        editor.rights = rights
        editor.rights_guid = None
        editor.ace_type = 'allowed'
        editor.inheritance = False
        editor.principal_SID = 'S-1-5-11'
        editor.target_DN = 'CN=Target,DC=example,DC=test'
        editor.principal_security_descriptor = {'Dacl': SimpleNamespace(aces=[])}
        editor.modify_secDesc_for_dn = MagicMock(return_value=True)
        return editor

    def test_enumeration_preserves_raw_identity_and_object_metadata(self):
        editor = self.editor('resetpassword')
        editor.inheritance = True
        guid = RIGHTS_GUID.ResetPassword.value
        ace = editor.create_object_ace(guid, editor.principal_SID, 'denied')
        parsed = ldaptypes.ACE(data=ace.getData())
        enum = ACLEnum(None, [], 'DC=example,DC=test')
        enum.resolve_trustee = MagicMock(return_value=('Friendly name', None))
        result = enum.parseACE(parsed)
        self.assertEqual(result['RawSecurityIdentifier'], editor.principal_SID)
        self.assertEqual(result['SecurityIdentifier'], 'Friendly name')
        self.assertEqual(result['ACEFlagsValue'], 3)
        self.assertEqual(result['AccessMaskValue'], 256)
        self.assertEqual(result['ObjectAceFlagsValue'], 1)
        self.assertEqual(result['ObjectAceTypeGuid'], guid)

    def test_remove_returns_write_result_and_removes_all_exact_matches(self):
        for result in (True, False):
            with self.subTest(result=result):
                editor = self.editor()
                matching = editor.create_ace(SIMPLE_PERMISSIONS.FullControl.value, editor.principal_SID, 'allowed')
                different = editor.create_ace(SIMPLE_PERMISSIONS.FullControl.value, 'S-1-5-18', 'allowed')
                editor.principal_security_descriptor['Dacl'].aces = [matching, different, matching]
                editor.modify_secDesc_for_dn.return_value = result
                self.assertIs(editor.remove(), result)
                self.assertEqual(editor.principal_security_descriptor['Dacl'].aces, [different])
                editor.modify_secDesc_for_dn.assert_called_once()

    def test_remove_no_match_does_not_write(self):
        editor = self.editor()
        self.assertIs(editor.remove(), False)
        editor.modify_secDesc_for_dn.assert_not_called()

    def test_remove_preserves_inherited_and_class_restricted_entries(self):
        editor = self.editor('resetpassword')
        guid = RIGHTS_GUID.ResetPassword.value
        matching = editor.create_object_ace(guid, editor.principal_SID, 'allowed')
        inherited = editor.create_object_ace(guid, editor.principal_SID, 'allowed')
        inherited['AceFlags'] = 16
        restricted = editor.create_object_ace(guid, editor.principal_SID, 'allowed')
        restricted['Ace']['Flags'] |= 2
        restricted['Ace']['InheritedObjectType'] = string_to_bin('bf967aba-0de6-11d0-a285-00aa003049e2')
        editor.principal_security_descriptor['Dacl'].aces = [matching, inherited, restricted]
        self.assertIs(editor.remove(), True)
        self.assertEqual(editor.principal_security_descriptor['Dacl'].aces, [inherited, restricted])

    def test_remove_reads_fresh_descriptor_and_propagates_result(self):
        view = PowerView.__new__(PowerView)
        view.ldap_server = MagicMock()
        view.ldap_session = MagicMock()
        view.root_dn = 'DC=example,DC=test'
        target = {'dn': 'CN=Target,' + view.root_dn, 'attributes': {'sAMAccountName': 'Target', 'objectSid': 'S-1-5-21-1-2-3-1000'}, 'raw_attributes': {'nTSecurityDescriptor': [b'descriptor']}}
        principal = {'dn': 'CN=Principal,' + view.root_dn, 'attributes': {'sAMAccountName': 'Principal', 'objectSid': 'S-1-5-21-1-2-3-1001'}}
        for result in (True, False):
            with self.subTest(result=result), patch('powerview.powerview.DACLedit') as editor:
                view.get_domainobject = MagicMock(side_effect=[[target], [principal]])
                editor.return_value.remove.return_value = result
                self.assertIs(view.remove_domainobjectacl(target['dn'], principal['dn']), result)
                self.assertIs(view.get_domainobject.call_args_list[0].kwargs['no_cache'], True)
