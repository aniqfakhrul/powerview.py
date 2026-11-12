import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from powerview.web.api.server import APIServer


class WebRegressionTests(unittest.TestCase):
    def server(self):
        args = Namespace(web_auth=None, username='tester', ldap_address='dc.example.test', stack_trace=False,
                         no_cache=False, no_vuln_check=True, password='secret', target='domain/user:secret@host',
                         hashes='secret-hash', lmhash='lm-secret', nthash='nt-secret', auth_aes_key='aes-secret',
                         pfx='sensitive.pfx', query='Set-DomainUserPassword -AccountPassword secret')
        return APIServer(SimpleNamespace(flatName='EXAMPLE', args=args, conn=SimpleNamespace(obfuscation=None)))

    def test_settings_do_not_expose_authentication_or_command_secrets(self):
        server = self.server()
        with server.app.test_client() as client:
            response = client.get('/api/settings')
            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertNotIn('secret', response.get_data(as_text=True))
            self.assertEqual(data['no_vuln_check'], True)

    def test_generic_operation_rejects_malformed_argument_objects(self):
        server = self.server()
        method = server.powerview.get_domainuser = Mock(return_value=[])
        with server.app.test_client() as client:
            for body in ([], ['unexpected'], 'unexpected', {'args': []}, {'args': 'unexpected'}):
                with self.subTest(body=body):
                    self.assertEqual(client.post('/api/get/domainuser', json=body).status_code, 400)
        method.assert_not_called()

    def test_web_paths_follow_the_cli_log_handler(self):
        server = self.server()
        pv = server.powerview
        pv.log_handler = SimpleNamespace(logs_folder='/tmp/pv-logs', file_name='run.log', history_file='/tmp/pv-history')
        server = APIServer(pv)
        self.assertEqual(server.log_file_path, '/tmp/pv-logs/run.log')
        self.assertEqual(server.history_file_path, '/tmp/pv-history')

    def test_log_pages_do_not_overlap_at_the_oldest_partial_page(self):
        server = self.server()
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test.log'
            path.write_text(''.join(f'[2026-01-01 00:00:00] root INFO message-{i}\n' for i in range(15)))
            server.log_file_path = str(path)
            with server.app.test_client() as client:
                pages = [client.get(f'/api/logs?page={page}&limit=10').get_json()['logs'] for page in (1, 2, 3)]
                self.assertEqual([len(page) for page in pages], [10, 5, 0])
                for query in ('page=0', 'limit=0', 'page=-1', 'limit=wrong'):
                    self.assertEqual(client.get('/api/logs?' + query).status_code, 400)
