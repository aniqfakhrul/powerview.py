import io
import inspect
import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import Mock, patch

from powerview.modules.sccm import SCCM
from powerview.modules.smbclient import SMBClient
from powerview.powerview import PowerView
from powerview.utils.history import get_shell_history
from powerview.utils.parsers import PowerViewParser


class MiscRegressionTests(unittest.TestCase):
    def test_cross_domain_lookup_uses_the_core_query_contract_and_requested_properties(self):
        pv = PowerView.__new__(PowerView)
        pv.args = Namespace()
        pv.get_domaintrust = Mock(return_value=[{'attributes': {'name': 'other.test'}}])
        pv.get_domain_connection = Mock()
        result = [{'attributes': {'name': 'Alice'}}]
        def query(**kwargs):
            inspect.signature(PowerView.get_domainobject).bind(None, **kwargs)
            self.assertEqual(kwargs['properties'], ['name'])
            return result
        with patch('powerview.powerview.PowerView', return_value=SimpleNamespace(get_domainobject=query)):
            self.assertEqual(pv.get_object_across_domains('Alice', properties=['name']), result)

    def test_sccm_probe_uses_a_timeout_and_keeps_status_methods_callable(self):
        probe = SCCM('server.example.test')
        with patch('powerview.modules.sccm.socket.socket') as factory:
            sock = factory.return_value.__enter__.return_value
            sock.recv.return_value = b'HTTP/1.1 200 OK\r\n'
            probe.check_datalib_endpoint()
            self.assertTrue(probe.http_enabled())
            self.assertTrue(probe.http_anonymous_enabled())
            sock.settimeout.assert_called_once_with(5)
            factory.return_value.__exit__.assert_called_once()
            sock.recv.return_value = b'HTTP/1.1 401 Unauthorized\r\n'
            probe.check_datalib_endpoint()
            self.assertFalse(probe.http_anonymous_enabled())

    def test_sccm_enrichment_handles_multiple_results_and_applies_resolved_ip(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.nameserver = '192.0.2.1'
        pv.use_system_nameserver = False
        pv.ldap_session = SimpleNamespace(extend=SimpleNamespace(standard=SimpleNamespace(paged_search=Mock(return_value=[
            {'attributes': {'dNSHostName': 'one.example.test'}},
            {'attributes': {'dNSHostName': 'two.example.test'}},
        ]))))
        with patch('powerview.powerview.SCCM') as factory, patch('powerview.powerview.host2ip', return_value='192.0.2.2'):
            factory.return_value.http_enabled.side_effect = [False, True, True, True]
            entries = pv.get_domainsccm(args=Namespace(check_datalib=True, ldapfilter=None))
            self.assertEqual(len(entries), 2)
            self.assertTrue(all(entry['attributes']['DatalibEndpoint'] for entry in entries))
            self.assertIn(unittest.mock.call('192.0.2.2'), factory.call_args_list)

    def test_history_includes_the_oldest_item_and_handles_empty_history(self):
        history = ['first', 'second', 'history']
        with patch('powerview.utils.history.readline') as readline:
            readline.get_current_history_length.return_value = len(history)
            readline.get_history_item.side_effect = lambda index: history[index - 1]
            self.assertEqual(get_shell_history(10, False), ['second', 'first'])
            self.assertEqual(get_shell_history(0, False), [])
            readline.get_current_history_length.return_value = 0
            self.assertEqual(get_shell_history(10, False), [])

    def test_core_execute_forwards_the_parsed_namespace_with_filter_switches(self):
        pv = PowerView.__new__(PowerView)
        pv.plugin_registry = None
        seen = []
        pv.get_domainuser = lambda args=None: seen.append(args) or []
        args = Namespace(module='Get-DomainUser', spn=True)
        pv.execute(args)
        self.assertIs(seen[0], args)

    def test_parser_errors_return_a_failure_exit_code(self):
        with patch('sys.stderr', new=io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                PowerViewParser().parse_args(['--invalid'])
        self.assertEqual(error.exception.code, 2)

    def test_smb_acl_removal_accepts_explicit_allow_or_deny_filters(self):
        client = SMBClient(Mock())
        with (patch('powerview.modules.smbclient.transport.SMBTransport'),
              patch('powerview.modules.smbclient.srvs.hNetrpGetFileSecurity', return_value=b'sd'),
              patch('powerview.modules.smbclient.srvs.hNetrpSetFileSecurity', return_value={'ErrorCode': 0}),
              patch('powerview.modules.smbclient.AccessControl.remove_ace', return_value=(b'new', 1)) as remove):
            for ace_type, number in [('allow', 0), ('deny', 1)]:
                self.assertTrue(client.remove_file_security('share', 'file', 'S-1-5-11', ace_type=ace_type))
                self.assertEqual(remove.call_args.args[-1], number)
