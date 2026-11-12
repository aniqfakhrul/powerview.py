import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ldap3
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.data.DNWithBinary import DNWithBinary

from powerview.powerview import PowerView


class ShadowCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.certificate = X509Certificate2(subject='QA', keySize=2048)

    def write_key(self, object_classes, sam='QA'):
        dn = 'CN=QA,CN=Computers,DC=example,DC=test'
        existing = b'existing-key-preserved-verbatim'
        entry = {
            'dn': dn,
            'attributes': {'objectClass': object_classes, 'sAMAccountName': sam},
            'raw_attributes': {'msDS-KeyCredentialLink': [existing]},
        }
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.ldap_session = SimpleNamespace(modify=MagicMock(), result={'result': 0})
        pv.get_domainobject = MagicMock(return_value=[entry])
        with patch('powerview.modules.shadowcred.X509Certificate2', return_value=self.certificate):
            result = pv.set_shadowcredential(identity=sam, export='NONE')
        self.assertEqual(result[0]['attributes']['TargetDN'], dn)
        self.assertIn('objectClass', pv.get_domainobject.call_args.kwargs['properties'])
        self.assertTrue(pv.get_domainobject.call_args.kwargs['no_cache'])
        pv.ldap_session.modify.assert_called_once()
        target, changes = pv.ldap_session.modify.call_args.args
        self.assertEqual(target, dn)
        operation, values = changes['msDS-KeyCredentialLink']
        self.assertEqual(operation, ldap3.MODIFY_REPLACE)
        self.assertEqual(values[:-1], [existing])
        blob = DNWithBinary.fromRawDNWithBinary(values[-1]).BinaryData
        fields = {}
        offset = 4
        while offset < len(blob):
            size, identifier = struct.unpack_from('<HB', blob, offset)
            offset += 3
            fields[identifier] = blob[offset:offset + size]
            offset += size
        self.assertEqual(offset, len(blob))
        return fields

    def test_computers_use_computer_metadata_without_last_logon(self):
        for classes in [
            ['top', 'person', 'organizationalPerson', 'user', 'computer'],
            ['top', 'COMPUTER'],
            'computer',
        ]:
            with self.subTest(object_classes=classes):
                fields = self.write_key(classes)
                self.assertEqual(fields[7], b'\x01\x02')
                self.assertNotIn(8, fields)

    def test_users_preserve_user_metadata_even_with_dollar_suffix(self):
        fields = self.write_key(['top', 'person', 'user'], sam='QA$')
        self.assertEqual(fields[7], b'\x01\x00')
        self.assertIn(8, fields)

    def test_missing_classes_preserve_default_metadata(self):
        fields = self.write_key(None)
        self.assertEqual(fields[7], b'\x01\x00')
        self.assertIn(8, fields)


if __name__ == '__main__':
    unittest.main()
