import unittest
from unittest.mock import patch

from ldap3.operation.search import compile_filter, parse_filter

from powerview.lib.ldap3.filters import restore_filter_escape_decoding
from powerview.utils.helpers import escape_filter_chars_except_asterisk, expand_identity_values, is_dn, parse_identity_list


def assertion_bytes(search_filter):
    restore_filter_escape_decoding()
    node = parse_filter(search_filter, None, True, True, None, False)
    return bytes(compile_filter(node.elements[0])['equalityMatch']['assertionValue'])


class EscapedDNTests(unittest.TestCase):
    def test_dn_detection_accepts_raw_and_filter_escaped_spellings(self):
        for dn in (r'CN=Doe\, Jane,OU=Sales\, EMEA,DC=example,DC=test', 'cn=svc,dc=corp,dc=local',
                   r'CN=Jos\C3\A9,DC=test', 'CN=Plain (EMEA),OU=Sales,DC=example,DC=test', 'DC=example,DC=test'):
            with self.subTest(dn=dn):
                self.assertTrue(is_dn(dn))
                self.assertTrue(is_dn(escape_filter_chars_except_asterisk(dn)))
        for value in ('alice', 'alice,bob', 'alice,dc=corp', 'S-1-5-21-1-2-3-500', 'a=b', 'CN=x', 'CN=x,O=org', '', None):
            with self.subTest(value=value):
                self.assertFalse(is_dn(value))

    def test_escaped_identity_reaches_the_server_as_the_original_value(self):
        for raw in (r'CN=Doe\, Jane,OU=Sales,DC=example,DC=test', 'Sales (EMEA)', r'back\slash'):
            with self.subTest(raw=raw):
                identity = parse_identity_list(raw)
                self.assertEqual(assertion_bytes(f'(distinguishedName={identity})'), raw.encode())


    def test_cli_keeps_each_raw_dn_as_one_identity(self):
        for dn in (r'CN=Doe\, Jane,OU=Sales\, EMEA,DC=example,DC=test',
                   r'cn=Doe\, Jane,dc=example,dc=test',
                   r'CN=Shelf\5c20Items,DC=example,DC=test'):
            with self.subTest(dn=dn):
                self.assertEqual(expand_identity_values(dn), [dn])
                self.assertEqual(parse_identity_list(dn), escape_filter_chars_except_asterisk(dn))
        self.assertEqual(parse_identity_list('alice,bob'), ['alice', 'bob'])

    def test_identity_file_preserves_dns_and_expands_name_lists(self):
        dn = r'CN=Doe\, Jane,DC=example,DC=test'
        with patch('powerview.utils.helpers.read_file', return_value=f'{dn}\nalice,bob\n'):
            self.assertEqual(expand_identity_values('@names.txt'), [dn, 'alice', 'bob'])
