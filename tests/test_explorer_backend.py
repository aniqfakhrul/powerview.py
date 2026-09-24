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
                self.assertIn('id="connection-status"', response.get_data(as_text=True), path)
            html = client.get('/').get_data(as_text=True)
            self.assertIn('id="explorer"', html)
            self.assertNotIn('UI foundation', html)
            for path in ['css/pages/explorer.css', 'js/pages/explorer.js', 'images/icons.svg']:
                with client.get('/static/' + path) as response:
                    self.assertEqual(response.status_code, 200)
            html = client.get('/', environ_overrides={'SCRIPT_NAME': '/pv'}).get_data(as_text=True)
            self.assertIn('data-api-root="/pv/api/"', html)
            self.assertIn('/pv/static/js/pages/explorer.js', html)

    def test_user_search_options_reach_ldap_without_replacing_user_constraint(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.args = Namespace()
        pv.ldap_session = MagicMock()
        search = pv.ldap_session.extend.standard.paged_search
        search.return_value = []
        server = self.make_server()
        server.powerview.get_domainuser = pv.get_domainuser
        with server.app.test_client() as client:
            response = client.post('/api/get/domainuser', json={
                'properties': ['name', 'mail'], 'raw': True, 'no_vuln_check': True,
                'searchbase': 'OU=People,DC=example,DC=test', 'search_scope': 'LEVEL',
                'args': {'passnotrequired': True, 'admincount': True, 'ldapfilter': '(mail=*)'},
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        positional, keywords = search.call_args
        self.assertEqual(positional[0], 'OU=People,DC=example,DC=test')
        self.assertEqual(positional[1], '(&(samAccountType=805306368)(userAccountControl:1.2.840.113556.1.4.803:=32)(admincount=1)(mail=*))')
        self.assertEqual(keywords['search_scope'], 'LEVEL')
        self.assertEqual(set(keywords['attributes']), {'name', 'mail'})
        self.assertTrue(keywords['raw'])

    def test_explorer_retains_basic_auth(self):
        import base64
        server = self.make_server({'web_auth_user': 'tester', 'web_auth_password': 'test-only'})
        with server.app.test_client() as client:
            self.assertEqual(client.get('/').status_code, 401)
            token = base64.b64encode(b'tester:test-only').decode()
            self.assertEqual(client.get('/', headers={'Authorization': 'Basic ' + token}).status_code, 200)


if __name__ == '__main__':
    unittest.main()
