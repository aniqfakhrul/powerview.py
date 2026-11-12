import unittest
from argparse import Namespace
from unittest.mock import DEFAULT, patch

import ldap3
import powerview


class CLIFailureTests(unittest.TestCase):
    def invoke(self, *, parsed=True, error=None, connection_error=None, mutation=False):
        dependencies = {name: DEFAULT for name in ('arg_parse', 'LOG', 'CONNECTION', 'PowerView', 'Completer',
                                                    'PluginRegistry', 'load_plugins', 'powerview_arg_parse')}
        with patch.multiple(powerview, **dependencies) as mocks, patch('powerview.utils.parsers.set_plugin_registry'):
            mocks['arg_parse'].return_value = Namespace(domain='example.test', username='tester', debug=False,
                query='Clear-Cache' if mutation else 'Get-DomainUser', json=False, mcp=False,
                ldap_address='dc.example.test', stack_trace=False)
            if connection_error:
                mocks['CONNECTION'].side_effect = connection_error
            conn = mocks['CONNECTION'].return_value
            shell = mocks['PowerView'].return_value
            shell.domain = 'example.test'
            shell.plugin_registry.get_before_hooks.return_value = []
            shell.plugin_registry.get_after_hooks.return_value = []
            shell.get_domainuser.side_effect = error
            shell.clear_cache.return_value = False
            mocks['powerview_arg_parse'].return_value = Namespace(
                module='Clear-Cache' if mutation else 'Get-DomainUser', server=None, json=False, tableview='', outfile=None
            ) if parsed else None
            with self.assertRaises(SystemExit) as result:
                powerview.main()
            self.assertEqual(result.exception.code, 1)
            if not connection_error:
                conn.close.assert_called_once_with()

    def test_invalid_command_fails_one_shot(self):
        self.invoke(parsed=False)

    def test_query_exception_fails_one_shot(self):
        for error in (ValueError('bad query'), ldap3.core.exceptions.LDAPAttributeError('invalid attribute')):
            with self.subTest(error=type(error).__name__):
                self.invoke(error=error)

    def test_initial_connection_failure_exits_unsuccessfully(self):
        self.invoke(connection_error=ldap3.core.exceptions.LDAPSocketOpenError('unreachable'))

    def test_unsuccessful_action_fails_one_shot(self):
        self.invoke(mutation=True)
