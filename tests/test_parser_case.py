import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from powerview.utils.parsers import powerview_arg_parse


class CaseInsensitiveParserTests(unittest.TestCase):
    def parse(self, *tokens):
        args = powerview_arg_parse(list(tokens))
        self.assertIsNotNone(args)
        return args

    def test_property_flags_preserve_explicit_identity(self):
        for flag in ('-properties', '-PROPERTIES', '-pRoPeRtIeS'):
            with self.subTest(flag=flag):
                args = self.parse('Get-DomainComputer', flag, 'name,dNSHostName', '-Identity', 'PC01')
                self.assertEqual(args.properties, ['name', 'dNSHostName'])
                self.assertEqual(args.identity, 'PC01')

    def test_lowercase_select_is_not_a_positional_identity(self):
        args = self.parse('Get-LocalUser', '-computer', 'HOST', '-select', 'userName,userRID')
        self.assertEqual(args.computer, 'HOST')
        self.assertEqual(args.select, ['userName', 'userRID'])
        self.assertIsNone(args.identity)

    def test_mixed_case_command_and_alias(self):
        for command in ('gEt-DoMaInObJeCt', 'gEt-AdObJeCt'):
            args = self.parse(command, '-properties', 'name', '-identity', 'Alice')
            self.assertEqual(args.properties, ['name'])
            self.assertEqual(args.identity, 'Alice')

    def test_required_flags_are_recognized_before_validation(self):
        args = self.parse('enable-plugin', '-name', 'ExamplePlugin')
        self.assertEqual(args.name, 'ExamplePlugin')

    def test_values_containing_flag_names_are_unchanged(self):
        value = '(&(description=Literal -properties Value)(name=Get-DomainUser))'
        args = self.parse('Get-DomainUser', '-ldapfilter', value, '-properties', 'name')
        self.assertEqual(args.ldapfilter, value)

    def test_equals_syntax_preserves_value_case(self):
        args = self.parse('Get-DomainComputer', '-properties=dNSHostName', '-identity=PC01')
        self.assertEqual(args.properties, ['dNSHostName'])
        self.assertEqual(args.identity, 'PC01')

    def test_optional_flag_value_and_switches(self):
        args = self.parse('Get-DomainComputer', '-tableview', '-properties', 'name', '-nocache')
        self.assertEqual(args.tableview, 'default')
        self.assertEqual(args.properties, ['name'])
        self.assertTrue(args.no_cache)

    def test_positional_shorthand_combines_with_lowercase_flags(self):
        args = self.parse('Get-DomainComputer', 'PC01', '-properties', 'name')
        self.assertEqual(args.identity, 'PC01')
        self.assertEqual(args.properties, ['name'])

    def test_plugin_flags_use_registered_parser_options(self):
        registry = SimpleNamespace(commands={'Get-TestEntry': {'args': ['-Label']}})
        with patch('powerview.utils.parsers._plugin_registry', registry):
            args = self.parse('get-testentry', '-label', 'CaseSensitive')
        self.assertEqual(args.label, 'CaseSensitive')

    def test_unknown_flags_are_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            args = powerview_arg_parse(['Get-DomainComputer', '-unknown', 'name'])
        self.assertIsNone(args)

    def test_input_tokens_are_not_modified(self):
        tokens = ['Get-DomainComputer', '-properties', 'name']
        original = tokens.copy()
        self.assertIsNotNone(powerview_arg_parse(tokens))
        self.assertEqual(tokens, original)


if __name__ == '__main__':
    unittest.main()
