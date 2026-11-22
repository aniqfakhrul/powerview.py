import unittest
from unittest.mock import patch

from powerview.utils.helpers import escape_filter_chars_except_asterisk, expand_identity_values, parse_identity_list


class EscapedDNTests(unittest.TestCase):
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
