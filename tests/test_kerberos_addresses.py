import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from powerview.utils.connections import CONNECTION
from powerview.utils.parsers import arg_parse
from powerview.lib.adws.core.connection import Connection as ADWSConnection


class KerberosAddressTests(unittest.TestCase):
    def test_ip_target_does_not_replace_the_kdc_ip_with_the_service_hostname(self):
        with patch('sys.argv', ['powerview', 'example.test/alice@192.0.2.1', '-k', '--no-pass', '-q', 'Get-Domain']):
            args = arg_parse()
        connection = CONNECTION(args)
        self.addCleanup(connection.close)
        connection.get_alt_server_info = MagicMock(return_value={'dnsHostName': ['dc.example.test']})
        connection.init_ldap_kerberos = MagicMock(side_effect=RuntimeError('reached bind'))
        with self.assertRaisesRegex(RuntimeError, 'reached bind'):
            connection.init_ldap_session()
        self.assertEqual(connection.init_ldap_kerberos.call_args.args[0], 'dc.example.test')
        self.assertEqual(connection.init_ldap_kerberos.call_args.args[-1], '192.0.2.1')

    def test_ldap_connects_to_the_ip_and_authenticates_to_the_hostname(self):
        connection = CONNECTION.__new__(CONNECTION)
        connection.args = SimpleNamespace(ldap_timeout=5)
        connection.use_gc_ldaps = False
        connection.use_ldaps = True
        connection.port = 636
        connection.ldap_address = '192.0.2.1'
        connection.TGT = {'KDC_REP': b'tgt', 'oldSessionKey': b'old', 'sessionKey': b'new'}
        connection.TGS = {'KDC_REP': b'tgs', 'oldSessionKey': b'old', 'sessionKey': b'new'}
        connection._new_ldap3_connection = MagicMock()
        connection._set_session_security_state = MagicMock()
        server = SimpleNamespace(ssl=True)
        with patch.dict('os.environ', {}, clear=True), patch('impacket.krb5.ccache.CCache') as cache, patch('powerview.utils.connections.ldap3.Server', return_value=server) as factory:
            cache.return_value.getCredential.return_value = None
            connection.init_ldap_kerberos('dc.example.test', tls=object(), domain='example.test', username='alice')
        self.assertEqual(factory.call_args.kwargs['host'], '192.0.2.1')
        self.assertEqual(connection._new_ldap3_connection.call_args.kwargs['sasl_credentials'], ('dc.example.test',))

    def test_adws_connects_to_the_ip_and_negotiates_for_the_hostname(self):
        server = SimpleNamespace(host='dc.example.test', port=9389, resource='Enumeration')
        with patch('powerview.lib.adws.core.connection.socket.socket') as sock, patch('powerview.lib.adws.core.connection.NNS') as nns, patch('powerview.lib.adws.core.connection.NMFConnection'):
            connection = ADWSConnection(server, 'alice', '', 'example.test', '', '', connect_address='192.0.2.1')
            connection.connect()
            sock.return_value.connect.assert_called_once_with(('192.0.2.1', 9389))
            self.assertEqual(nns.call_args.kwargs['fqdn'], 'dc.example.test')
