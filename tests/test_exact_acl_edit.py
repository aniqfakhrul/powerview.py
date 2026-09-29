import inspect
import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from impacket.ldap import ldaptypes
from impacket.uuid import string_to_bin
from powerview.modules.dacledit import DACLedit, RIGHTS_GUID
from powerview.modules.ldapattack import create_empty_sd
from powerview.powerview import PowerView
from powerview.utils.ace_identity import ace_identity, dacl_fingerprint
from powerview.utils.parsers import powerview_arg_parse
from powerview.utils.completer import COMMANDS
from powerview.web.api.server import APIServer


class ExactACLEditTests(unittest.TestCase):
    def setUp(self):
        self.editor = DACLedit.__new__(DACLedit)
        self.editor.inheritance = False
        self.editor.target_DN = 'CN=Target,DC=example,DC=test'
        self.editor.principal_security_descriptor = create_empty_sd()
        self.editor.modify_secDesc_for_dn = MagicMock(return_value=True)
        self.dacl = self.editor.principal_security_descriptor['Dacl']
        self.dacl.aces = [self.editor.create_ace(0x20000, 'S-1-5-11', 'allowed') for _ in range(3)]

    def identity(self, index=1):
        return ace_identity(self.dacl.aces[index], index, dacl_fingerprint(self.dacl))

    def test_replaces_one_duplicate_preserving_order_and_trustee(self):
        before = [ace.getData() for ace in self.dacl.aces]
        self.assertTrue(self.editor.edit_exact(self.identity(), access_mask=0x40000, ace_type='denied', ace_flags=3))
        parsed = ldaptypes.ACL(data=self.dacl.getData())
        self.assertEqual([parsed.aces[i].getData() for i in (0, 2)], [before[0], before[2]])
        selected = parsed.aces[1]
        self.assertEqual(selected['TypeName'], 'ACCESS_DENIED_ACE')
        self.assertEqual(selected['Ace']['Mask']['Mask'], 0x40000)
        self.assertEqual(selected['AceFlags'], 3)
        self.assertEqual(selected['Ace']['Sid'].formatCanonical(), 'S-1-5-11')
        self.editor.modify_secDesc_for_dn.assert_called_once()

    def test_object_ace_preserves_guids_and_unspecified_fields(self):
        ace = self.editor.create_object_ace(RIGHTS_GUID.WriteMembers.value, 'S-1-5-11', 'denied')
        ace['Ace']['Flags'] |= 2
        ace['Ace']['InheritedObjectType'] = string_to_bin('bf967aba-0de6-11d0-a285-00aa003049e2')
        ace['AceFlags'] = 11
        self.dacl.aces[1] = ace
        object_guid = ace['Ace']['ObjectType']
        inherited_guid = ace['Ace']['InheritedObjectType']
        self.assertTrue(self.editor.edit_exact(self.identity(), ace_type='allowed'))
        selected = ldaptypes.ACL(data=self.dacl.getData()).aces[1]
        self.assertEqual(selected['TypeName'], 'ACCESS_ALLOWED_OBJECT_ACE')
        self.assertEqual(selected['Ace']['Flags'], 3)
        self.assertEqual(selected['Ace']['ObjectType'], object_guid)
        self.assertEqual(selected['Ace']['InheritedObjectType'], inherited_guid)
        self.assertEqual(selected['Ace']['Mask']['Mask'], ace['Ace']['Mask']['Mask'])
        self.assertEqual(selected['AceFlags'], 11)

    def test_rejects_stale_inherited_and_unsupported_entries(self):
        selection = self.identity()
        self.dacl.aces[0]['Ace']['Mask']['Mask'] = 1
        with self.assertRaisesRegex(ValueError, 'DACL changed'):
            self.editor.edit_exact(selection, access_mask=2)
        self.dacl.aces[1]['AceFlags'] = 16
        with self.assertRaisesRegex(ValueError, 'Inherited'):
            self.editor.edit_exact(self.identity(), access_mask=2)
        self.dacl.aces[1]['AceFlags'] = 0
        self.dacl.aces[1]['AceType'] = ldaptypes.SYSTEM_AUDIT_ACE.ACE_TYPE
        with self.assertRaisesRegex(ValueError, 'Only standard'):
            self.editor.edit_exact(self.identity(), access_mask=2)
        self.editor.modify_secDesc_for_dn.assert_not_called()

    def test_invalid_changes_do_not_write_or_mutate(self):
        before = self.dacl.getData()
        for changes in ({}, {'access_mask': -1}, {'access_mask': 2**32}, {'access_mask': True}, {'access_mask': '1'}, {'ace_type': 'audit'}, {'ace_flags': 16}, {'ace_flags': True}, {'ace_flags': -1}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.editor.edit_exact(self.identity(), **changes)
            self.assertEqual(self.dacl.getData(), before)
        self.editor.modify_secDesc_for_dn.assert_not_called()

    def test_noop_and_write_failure(self):
        self.assertTrue(self.editor.edit_exact(self.identity(), access_mask=0x20000))
        self.editor.modify_secDesc_for_dn.assert_not_called()
        self.editor.modify_secDesc_for_dn.return_value = False
        self.assertFalse(self.editor.edit_exact(self.identity(), access_mask=0x80000000))

    def test_api_reads_fresh_and_writes_once_without_principal_lookup(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.ldap_server = MagicMock()
        pv.ldap_session = MagicMock()
        pv.get_domainobject = MagicMock(return_value=[{
            'dn': self.editor.target_DN, 'attributes': {},
            'raw_attributes': {'nTSecurityDescriptor': [self.editor.principal_security_descriptor.getData()]},
        }])
        with patch.object(DACLedit, 'modify_secDesc_for_dn', return_value=True) as write:
            self.assertTrue(pv.set_domainobjectacl(self.editor.target_DN, self.identity(), access_mask=0x20))
            write.assert_called_once()
        pv.get_domainobject.assert_called_once()
        self.assertTrue(pv.get_domainobject.call_args.kwargs['no_cache'])
        self.assertEqual(pv.get_domainobject.call_args.kwargs['sd_flag'], 4)

    def test_cli_and_alias_parse_exact_selection_and_optional_changes(self):
        selection = self.identity()
        for command in ('Set-DomainObjectAcl', 'Set-ObjectAcl'):
            args = powerview_arg_parse([command, '-TargetIdentity', 'Target', '-ACEIndex', '1', '-ACEFingerprint', selection['ace'], '-DACLFingerprint', selection['dacl'], '-AccessMask', '0x40000', '-ACEFlags', '3', '-ACEType', 'denied'])
            self.assertEqual(args.access_mask, 0x40000)
            self.assertEqual(args.ace_flags, 3)
            self.assertEqual(args.ace_index, 1)
            self.assertEqual(args.ace_fingerprint, selection['ace'])
            self.assertIn('-ACEIndex', COMMANDS[command])
        args = powerview_arg_parse(['Get-DomainObjectAcl', '-Identity', 'Target', '-IncludeACEIdentity'])
        self.assertTrue(args.include_ace_identity)

    def test_cli_enumeration_passes_identity_opt_in(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.get_domainobject = MagicMock(return_value=[{'attributes': {}}])
        args = powerview_arg_parse(['Get-DomainObjectAcl', '-Identity', 'Target', '-IncludeACEIdentity'])
        with patch('powerview.powerview.ACLEnum') as parser:
            pv.get_domainobjectacl(args=args, guids_map_dict={'guid': 'right'})
            self.assertTrue(parser.call_args.kwargs['include_ace_identity'])

    def test_http_route_binds_to_real_signature_and_propagates_outcome(self):
        pv = SimpleNamespace(flatName='EXAMPLE', args=Namespace(web_auth=None, username='tester', ldap_address='dc.example.test', stack_trace=False))
        server = APIServer(pv)
        params = {'targetidentity': self.editor.target_DN, 'ace': self.identity(), 'access_mask': 0x20, 'ace_type': 'denied', 'ace_flags': 3}
        with server.app.test_client() as client:
            for result in (True, False):
                pv.set_domainobjectacl = MagicMock(return_value=result)
                response = client.post('/api/set/domainobjectacl', json=params)
                self.assertEqual(response.status_code, 200)
                self.assertIs(response.get_json(), result)
                inspect.signature(PowerView.set_domainobjectacl).bind(pv, **pv.set_domainobjectacl.call_args.kwargs)
                pv.set_domainobjectacl.assert_called_once_with(**params)
            pv.set_domainobjectacl.side_effect = ValueError('The DACL changed.')
            response = client.post('/api/set/domainobjectacl', json=params)
            self.assertEqual(response.status_code, 400)
