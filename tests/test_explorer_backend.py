"""Explorer integration checks without a live directory or write operations."""
import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock

from powerview.powerview import PowerView
from powerview.web.api.server import APIServer


class ExplorerBackendTests(unittest.TestCase):
    def test_move_preserves_escaped_and_multivalued_rdn(self):
        destination = 'OU=People,DC=example,DC=test'
        for rdn in (r'CN=Last\, First', 'CN=Alice+UID=123', 'CN=Alice'):
            with self.subTest(rdn=rdn):
                dn = f'{rdn},CN=Users,DC=example,DC=test'
                pv = PowerView.__new__(PowerView)
                pv.root_dn = 'DC=example,DC=test'
                pv.args = Namespace()
                pv.get_domainobject = MagicMock(side_effect=[
                    [{'attributes': {'distinguishedName': dn}}],
                    [{'attributes': {'distinguishedName': destination}}],
                ])
                pv.ldap_session = SimpleNamespace(modify_dn=MagicMock(return_value=True))
                self.assertTrue(pv.set_domainobjectdn(dn, destination))
                pv.ldap_session.modify_dn.assert_called_once_with(dn, rdn, new_superior=destination)

    def make_server(self, auth=None):
        return APIServer(SimpleNamespace(
            flatName='EXAMPLE', args=Namespace(web_auth=auth, username='tester', ldap_address='dc.example.test'),
        ))

    def test_pages_assets_and_prefix(self):
        server = self.make_server()
        with server.app.test_client() as client:
            for path in ['/', '/dashboard', '/graph', '/users', '/computers', '/groups', '/dns', '/ca', '/ou', '/gpo', '/smb', '/utils']:
                response = client.get(path)
                self.assertEqual(response.status_code, 200, path)
            html = client.get('/').get_data(as_text=True)
            self.assertIn('id="explorer"', html)
            self.assertNotIn('UI foundation', html)
            for path in ['css/pages/explorer.css', 'js/pages/explorer.js', 'images/icons.svg']:
                with client.get('/static/' + path) as response:
                    self.assertEqual(response.status_code, 200)
            html = client.get('/', environ_overrides={'SCRIPT_NAME': '/pv'}).get_data(as_text=True)
            self.assertIn('data-api-root="/pv/api/"', html)
            self.assertIn('/pv/static/js/pages/explorer.js', html)

    def test_explorer_retains_basic_auth(self):
        import base64
        server = self.make_server({'web_auth_user': 'tester', 'web_auth_password': 'test-only'})
        with server.app.test_client() as client:
            self.assertEqual(client.get('/').status_code, 401)
            token = base64.b64encode(b'tester:test-only').decode()
            self.assertEqual(client.get('/', headers={'Authorization': 'Basic ' + token}).status_code, 200)


if __name__ == '__main__':
    unittest.main()
