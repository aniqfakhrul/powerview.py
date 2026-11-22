import io
import tempfile
import threading
import unittest
from argparse import ArgumentTypeError, Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from powerview.utils.parsers import Helper
from powerview.web.api.server import APIServer


class WebRegressionTests(unittest.TestCase):
    def server(self, web_auth=None):
        args = Namespace(web_auth=web_auth, username='tester', ldap_address='dc.example.test', stack_trace=False,
                         no_cache=False, no_vuln_check=True, password='secret', target='domain/user:secret@host',
                         hashes='secret-hash', lmhash='lm-secret', nthash='nt-secret', auth_aes_key='aes-secret',
                         pfx='sensitive.pfx', query='Set-DomainUserPassword -AccountPassword secret')
        return APIServer(SimpleNamespace(flatName='EXAMPLE', args=args, conn=SimpleNamespace(obfuscation=None)))

    def test_requested_authentication_fails_closed(self):
        for value in ('', ':', 'viewer:', ':password', 'viewer'):
            with self.subTest(value=value), self.assertRaises(ArgumentTypeError):
                Helper.parse_web_auth(value)
        for config in ({}, {'web_auth_user': 'viewer', 'web_auth_password': ''}):
            with self.assertRaises(ValueError):
                self.server(config)
        client = self.server(Helper.parse_web_auth('viewer:one:two')).app.test_client()
        for path in ('/explorer', '/api/settings'):
            self.assertEqual(client.get(path).status_code, 401)
            self.assertEqual(client.get(path, auth=('viewer', 'one:two')).status_code, 200)

    def test_control_routes_require_same_origin_browser_posts(self):
        server = self.server()
        server.powerview.clear_cache = Mock(return_value=True)
        server.powerview.conn.close = Mock(return_value=True)
        server.powerview.conn.reset_connection = Mock(return_value=True)
        client = server.app.test_client()
        for path, method in (
            ('/api/clear-cache', server.powerview.clear_cache),
            ('/api/ldap/close', server.powerview.conn.close),
            ('/api/ldap/rebind', server.powerview.conn.reset_connection),
        ):
            with self.subTest(path=path):
                self.assertEqual(client.get(path).status_code, 405)
                self.assertEqual(client.head(path).status_code, 405)
                for headers in ({'Origin': 'https://other.example'}, {'Origin': 'null'},
                                {'Sec-Fetch-Site': 'cross-site'}, {'Sec-Fetch-Site': 'same-site'}):
                    self.assertEqual(client.post(path, headers=headers).status_code, 403)
                method.assert_not_called()
                for headers in ({}, {'Origin': 'http://localhost'}, {'Sec-Fetch-Site': 'same-origin'}):
                    self.assertEqual(client.post(path, headers=headers).status_code, 200)
                self.assertEqual(method.call_count, 3)

    def test_legacy_redirects_preserve_query_as_data(self):
        client = self.server().app.test_client()
        query = 'dn=CN%3DJos%C3%A9&tag=one&tag=two&empty=&_anchor=value&endpoint=test'
        for path, destination in (('/', '/pv/explorer'), ('/dashboard', '/pv/')):
            response = client.get(path + '?' + query, environ_overrides={'SCRIPT_NAME': '/pv'})
            self.assertEqual(response.status_code, 302)
            self.assertEqual(response.headers['Location'], destination + '?' + query)

    def test_status_tracks_the_bound_listener(self):
        server = self.server()
        with patch('powerview.web.api.server.make_server', side_effect=SystemExit(1)):
            server.start()
            self.assertFalse(server.get_status())
        stop = threading.Event()
        listener = Mock(port=5555)
        listener.serve_forever.side_effect = lambda: stop.wait(timeout=5)
        with patch('powerview.web.api.server.make_server', return_value=listener):
            server.start()
            try:
                self.assertTrue(server.get_status())
                self.assertEqual(server.port, 5555)
            finally:
                stop.set()
                server.api_server_thread.join(timeout=5)
        self.assertFalse(server.get_status())
        listener.server_close.assert_called_once()

    def test_uploads_use_private_staging_and_clean_up_failures(self):
        server = self.server()
        server.powerview.conn.init_smb_session = Mock()
        client = server.app.test_client()
        form = {'computer': 'files', 'share': 'docs', 'path': 'incoming'}
        self.assertEqual(client.post('/api/smb/put', data=form).status_code, 400)
        response = client.post('/api/smb/put', data={**form, 'file': (io.BytesIO(b''), 'dir/report.txt')})
        self.assertEqual(response.status_code, 400)
        server.powerview.conn.init_smb_session.assert_not_called()

        staged = []
        def inspect_file(share, remote, local):
            self.assertEqual((share, remote), ('docs', r'incoming\report.txt'))
            path = Path(local)
            self.assertEqual(path.read_bytes(), b'example')
            self.assertNotEqual(path.name, 'report.txt')
            staged.append(path)
            if len(staged) == 2:
                raise OSError('Write failed')

        with patch('powerview.web.api.server.SMBClient.put', side_effect=inspect_file):
            for expected in (200, 500):
                response = client.post('/api/smb/put', data={**form, 'file': (io.BytesIO(b'example'), 'report.txt')})
                self.assertEqual(response.status_code, expected)
                self.assertFalse(staged[-1].parent.exists())
        self.assertNotEqual(*staged)

    def test_account_actions_reject_non_object_bodies(self):
        server = self.server()
        action = server.powerview.unlock_adaccount = Mock()
        for body in ([], ['value'], 'value'):
            response = server.app.test_client().post('/api/account/unlock', json=body)
            self.assertEqual(response.status_code, 400)
            self.assertIn('error', response.get_json())
        action.assert_not_called()

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
