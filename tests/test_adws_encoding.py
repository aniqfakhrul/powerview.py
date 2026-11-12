import io
import unittest
import xml.etree.ElementTree as ET
import base64
from ldap3 import MODIFY_ADD, MODIFY_REPLACE

from powerview.lib.adws.encoder.records.datatypes import MultiByteInt31, Utf8String
from powerview.lib.adws.operation.add import add_operation
from powerview.lib.adws.operation.search import search_operation
from powerview.lib.adws.operation.modify import modify_operation
from powerview.lib.adws.templates import NAMESPACES


class BinaryEncodingTests(unittest.TestCase):
    def test_multibyte_integer_roundtrips_and_serialization_is_repeatable(self):
        for value in (0, 127, 128, 16384, 0x7fffffff):
            with self.subTest(value=value):
                number = MultiByteInt31(value)
                encoded = number.to_bytes()
                self.assertEqual(number.value, value)
                self.assertEqual(number.to_bytes(), encoded)
                self.assertEqual(MultiByteInt31.parse(io.BytesIO(encoded)).value, value)

    def test_utf8_lengths_roundtrip_above_one_byte(self):
        for value in ('abc', 'x' * 128, 'é' * 100, 'x' * 16384):
            with self.subTest(length=len(value)):
                stream = io.BytesIO(Utf8String(value).to_bytes() + b'!')
                self.assertEqual(Utf8String.parse(stream).value, value)
                self.assertEqual(stream.read(), b'!')

    def test_truncated_utf8_payload_is_rejected(self):
        with self.assertRaises((ValueError, EOFError)):
            Utf8String.parse(io.BytesIO(b'\x03a'))

    def test_search_xml_preserves_ldap_metacharacters(self):
        base = 'OU=Research & Development,DC=example,DC=test'
        search_filter = '(&(objectClass=user)(description=Alice < Bob & Carol))'
        root = ET.fromstring(search_operation('dc.example.test', base, search_filter, 'SUBTREE', ['name']))
        self.assertIn(base, [node.text for node in root.iter()])
        self.assertIn(search_filter, [node.text for node in root.iter()])

    def test_add_splits_escaped_rdn_at_the_actual_parent(self):
        dn = r'CN=Last\, First,OU=People,DC=example,DC=test'
        root = ET.fromstring(add_operation('dc.example.test', dn, {'objectClass': ['person']}))
        values = [node.text for node in root.iter() if node.tag.endswith('value')]
        self.assertIn(r'CN=Last\, First', values)
        self.assertIn('OU=People,DC=example,DC=test', values)

    def test_modify_emits_each_change_once_and_preserves_binary_values(self):
        binary = b'\x00\xff\x80data'
        changes = {'description': [(MODIFY_ADD, ['Research & Development'])],
                   'displayName': [(MODIFY_REPLACE, ['Example'])],
                   'userCertificate': [(MODIFY_REPLACE, [binary])]}
        root = ET.fromstring(modify_operation('dc.example.test', 'CN=Example,DC=example,DC=test', changes, auto_encode=False))
        edits = root.findall('.//{http://schemas.microsoft.com/2006/11/IdentityManagement/DirectoryAccess}Change')
        self.assertEqual(len(edits), 3)
        values = root.findall('.//{http://schemas.microsoft.com/2008/1/ActiveDirectory}value')
        self.assertEqual(values[0].text, 'Research & Development')
        self.assertEqual(values[1].text, 'Example')
        self.assertEqual(base64.b64decode(values[2].text), binary)
        self.assertEqual(values[2].get('{http://www.w3.org/2001/XMLSchema-instance}type'), 'xsd:base64Binary')
