import unittest
from unittest.mock import patch

from ldap3 import OFFLINE_AD_2012_R2, Server

from powerview.utils.completer import Completer


class PropertyCompletionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = Server('test', get_info=OFFLINE_AD_2012_R2).schema

    def setUp(self):
        self.completer = Completer(lambda: self.schema)

    def complete(self, line, cursor=None):
        cursor = len(line) if cursor is None else cursor
        start = max(line.rfind(delimiter, 0, cursor) for delimiter in ' \t\n;') + 1
        with (
            patch('powerview.utils.completer.readline.get_line_buffer', return_value=line),
            patch('powerview.utils.completer.readline.get_begidx', return_value=start),
            patch('powerview.utils.completer.readline.get_endidx', return_value=cursor),
        ):
            results = []
            for state in range(5000):
                result = self.completer.complete(line[start:cursor], state)
                if result is None:
                    return results
                results.append(result)
        self.fail('Completion did not terminate')

    def test_case_insensitive_command_flag_and_attribute(self):
        self.assertEqual(self.complete('gEt-DoMaInUsEr -pRoPeRtIeS SAMACCOUNTN'), ['sAMAccountName'])

    def test_comma_list_preserves_previous_spelling(self):
        self.assertEqual(self.complete('Get-DomainUser -Properties NAME,SAMACCOUNTN'), ['NAME,sAMAccountName'])

    def test_excludes_previously_selected_attributes_case_insensitively(self):
        self.assertEqual(self.complete('Get-DomainUser -Properties SAMACCOUNTNAME,samaccountn'), [])

    def test_empty_value_offers_attributes_not_flags(self):
        results = self.complete('Get-DomainUser -Properties ')
        self.assertIn('sAMAccountName', results)
        self.assertIn('*', results)
        self.assertNotIn('-Identity ', results)

    def test_directory_commands_offer_attributes_from_other_classes(self):
        for command in ('Get-DomainUser', 'Get-DomainComputer', 'Get-DomainGroup', 'Get-DomainOU'):
            self.assertIn('operatingSystem', self.complete(f'{command} -Properties OPER'))
            self.assertIn('dNSHostName', self.complete(f'{command} -Properties dnsh'))

    def test_generic_object_alias_uses_all_attributes(self):
        self.assertIn('operatingSystem', self.complete('Get-ADObject -Properties OPER'))

    def test_binary_and_constructed_attributes_are_included(self):
        self.assertIn('userCertificate', self.complete('Get-DomainUser -Properties userCert'))
        self.assertIn('tokenGroups', self.complete('Get-DomainUser -Properties tokenG'))

    def test_unclosed_quotes(self):
        for quote in ('"', "'"):
            self.assertEqual(self.complete('Get-DomainUser -Properties ' + quote + 'name,samaccountn'), [quote + 'name,sAMAccountName'])

    def test_middle_of_value_preserves_suffix(self):
        line = 'Get-DomainUser -Properties samAccountName,description -Identity alice'
        cursor = line.index('AccountName')
        self.assertEqual(self.complete(line, cursor), ['sAM'])

    def test_flags_after_value_and_duplicate_flags_are_case_insensitive(self):
        results = self.complete('Get-DomainUser -properties name -')
        self.assertIn('-Identity ', results)
        self.assertNotIn('-Properties ', results)

    def test_missing_schema(self):
        self.completer = Completer()
        self.assertEqual(self.complete('Get-DomainUser -Properties sam'), [])

    def test_localuser_offers_select_without_properties(self):
        results = self.complete('Get-LocalUser -')
        self.assertIn('-Select ', results)
        self.assertNotIn('-Properties ', results)
        self.assertEqual(self.complete('Get-LocalUser -Properties sam'), [])

    def test_schema_provider_is_read_again_after_switch(self):
        schema = [None]
        self.completer = Completer(lambda: schema[0])
        self.assertEqual(self.complete('Get-DomainUser -Properties samAccountN'), [])
        schema[0] = self.schema
        self.assertEqual(self.complete('Get-DomainUser -Properties samAccountN'), ['sAMAccountName'])


if __name__ == '__main__':
    unittest.main()
