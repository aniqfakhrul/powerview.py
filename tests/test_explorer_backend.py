"""Explorer integration checks without a live directory or write operations."""
import inspect
import re
import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock

from powerview.powerview import PowerView
from powerview.web.api.server import APIServer
from powerview.web.frontend import PAGES


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
            for path in ['/', '/explorer', '/pathfinder', '/users', '/computers', '/groups', '/dns', '/ca', '/ou', '/gpo']:
                response = client.get(path)
                self.assertEqual(response.status_code, 200, path)
                self.assertIn('id="connection-status"', response.get_data(as_text=True), path)
            for path in ['/smb', '/utils']:
                self.assertEqual(client.get(path).status_code, 404, path)
            html = client.get('/').get_data(as_text=True)
            self.assertIn('id="dashboard"', html)
            self.assertNotIn('SMB browser', html)
            self.assertNotIn('Utilities', html)
            self.assertLess(html.index('href="/"'), html.index('href="/explorer"'))
            html = client.get('/explorer').get_data(as_text=True)
            self.assertIn('id="explorer"', html)
            self.assertIn('class="brand" href="/"', html)
            self.assertNotIn('UI foundation', html)
            for path in ['css/pages/explorer.css', 'js/pages/explorer.js', 'images/icons.svg']:
                with client.get('/static/' + path) as response:
                    self.assertEqual(response.status_code, 200)
            html = client.get('/explorer', environ_overrides={'SCRIPT_NAME': '/pv'}).get_data(as_text=True)
            self.assertIn('data-api-root="/pv/api/"', html)
            self.assertIn('/pv/static/js/pages/explorer.js', html)
            self.assertIn('data-explorer="/pv/explorer"', client.get('/users', environ_overrides={'SCRIPT_NAME': '/pv'}).get_data(as_text=True))

    def test_rendered_icons_exist_in_sprite(self):
        server = self.make_server()
        with server.app.test_client() as client:
            with client.get('/static/images/icons.svg') as response:
                symbols = set(re.findall(r'<symbol id="([^"]+)"', response.get_data(as_text=True)))
            for page in PAGES:
                names = set(re.findall(r'icons\.svg[^#"]*#([^"]+)"', client.get(page.path).get_data(as_text=True)))
                self.assertIn(f'{page.icon}-filled', names, page.path)
                self.assertEqual(names - symbols, set(), page.path)

    def test_dashboard_is_home_and_old_links_redirect(self):
        server = self.make_server()
        with server.app.test_client() as client:
            legacy = client.get('/dashboard?signal=users_spn', environ_overrides={'SCRIPT_NAME': '/pv'})
            self.assertEqual(legacy.status_code, 302)
            self.assertEqual(legacy.headers['Location'], '/pv/?signal=users_spn')
            deep = client.get('/?dn=CN%3DAlice%2CDC%3Dexample%2CDC%3Dtest')
            self.assertEqual(deep.status_code, 302)
            self.assertTrue(deep.headers['Location'].startswith('/explorer?dn='))
            self.assertEqual(client.get(deep.headers['Location']).status_code, 200)

    def test_pathfinder_uses_existing_acl_endpoint_with_optional_identity(self):
        server = self.make_server()
        result = [{'attributes': [{'ObjectDN': 'DC=example,DC=test', 'ACEType': 'ACCESS_ALLOWED_ACE'}]}]
        server.powerview.get_domainobjectacl = MagicMock(return_value=result)
        with server.app.test_client() as client:
            for identity in (None, 'Administrator'):
                params = {'depth': 2, 'security_identifier': 'alice', 'resolveguids': True, 'no_cache': True, 'no_vuln_check': True}
                if identity:
                    params['identity'] = identity
                response = client.post('/api/get/domainobjectacl', json=params)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json(), result)
                passed = server.powerview.get_domainobjectacl.call_args.kwargs
                inspect.signature(PowerView.get_domainobjectacl).bind(server.powerview, **passed)
                for key, value in params.items():
                    self.assertEqual(passed[key], value)
                if not identity:
                    self.assertNotIn('identity', passed)

    def test_acl_mutations_forward_exact_parameters_and_preserve_failure(self):
        server = self.make_server()
        params = {
            'targetidentity': 'CN=Target,DC=example,DC=test',
            'principalidentity': 'S-1-5-11',
            'rights': 'fullcontrol',
            'rights_guid': '00299570-246d-11d0-a768-00aa006e0529',
            'ace_type': 'denied',
            'inheritance': True,
        }
        with server.app.test_client() as client:
            for action in ('add', 'remove'):
                method = MagicMock()
                setattr(server.powerview, f'{action}_domainobjectacl', method)
                for result in (True, False, None):
                    with self.subTest(action=action, result=result):
                        method.return_value = result
                        response = client.post(f'/api/{action}/domainobjectacl', json=params)
                        self.assertEqual(response.status_code, 200)
                        self.assertEqual(response.get_json(), result)
                        passed = method.call_args.kwargs
                        inspect.signature(getattr(PowerView, f'{action}_domainobjectacl')).bind(server.powerview, **passed)
                        self.assertEqual(passed, params)

    def test_exact_acl_api_preserves_selection_and_reports_stale_errors(self):
        server = self.make_server()
        server.powerview.args.stack_trace = False
        selection = {'index': 3, 'ace': 'a' * 64, 'dacl': 'b' * 64}
        params = {'targetidentity': 'CN=Target,DC=example,DC=test', 'ace': selection}
        method = MagicMock(return_value=True)
        server.powerview.remove_domainobjectacl = method
        with server.app.test_client() as client:
            response = client.post('/api/remove/domainobjectacl', json=params)
            self.assertIs(response.get_json(), True)
            method.assert_called_once_with(**params)
            inspect.signature(PowerView.remove_domainobjectacl).bind(server.powerview, **method.call_args.kwargs)
            method.side_effect = ValueError('The DACL changed. Refresh Security and select the entry again.')
            response = client.post('/api/remove/domainobjectacl', json=params)
            self.assertEqual(response.status_code, 400)
            self.assertIn('DACL changed', response.get_json()['error'])

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

    def test_object_suggestions_reach_ldap_with_a_size_limit(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.args = Namespace()
        pv.ldap_session = MagicMock()
        search = pv.ldap_session.extend.standard.paged_search
        search.return_value = []
        server = self.make_server()
        server.powerview.get_domainobject = pv.get_domainobject
        with server.app.test_client() as client:
            response = client.post('/api/get/domainobject', json={
                'properties': ['name'], 'ldap_filter': '(|(name=al*)(sAMAccountName=al*))', 'size_limit': 21, 'raw': True, 'no_vuln_check': True,
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        positional, keywords = search.call_args
        self.assertEqual(positional[1], '(&(objectClass=*)(|(name=al*)(sAMAccountName=al*)))')
        self.assertEqual(keywords['size_limit'], 21)

    def test_computer_presets_reach_ldap(self):
        filters = {
            'enabled': '(!(userAccountControl:1.2.840.113556.1.4.803:=2))',
            'disabled': '(userAccountControl:1.2.840.113556.1.4.803:=2)',
            'workstation': '(&(operatingSystem=*)(!(operatingSystem=*Server*)))',
            'notworkstation': '(&(operatingSystem=*)(operatingSystem=*Server*))',
            'excludedcs': '(!(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            'obsolete': '(operatingSystem=*Windows XP*)',
            'spn': '(servicePrincipalName=*)',
            'unconstrained': '(userAccountControl:1.2.840.113556.1.4.803:=524288)',
            'trustedtoauth': '(msds-allowedtodelegateto=*)',
            'rbcd': '(msDS-AllowedToActOnBehalfOfOtherIdentity=*)',
            'shadowcred': '(msDS-KeyCredentialLink=*)',
            'laps': '(ms-Mcs-AdmPwd=*)',
            'pre2k': '(userAccountControl=4128)(logonCount=0)',
        }
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.args = Namespace()
        pv.ldap_session = MagicMock()
        pv._resolve_schema_feature = MagicMock(return_value=SimpleNamespace(
            presence_filter='(ms-Mcs-AdmPwd=*)', properties=['ms-Mcs-AdmPwd'],
        ))
        search = pv.ldap_session.extend.standard.paged_search
        search.return_value = []
        server = self.make_server()
        server.powerview.get_domaincomputer = pv.get_domaincomputer
        with server.app.test_client() as client:
            for option, expected in filters.items():
                with self.subTest(option=option):
                    response = client.post('/api/get/domaincomputer', json={
                        'properties': ['name'], 'raw': True, 'no_vuln_check': True,
                        'args': {option: True},
                    })
                    self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
                    positional, keywords = search.call_args
                    self.assertIn('(objectClass=computer)', positional[1])
                    self.assertIn(expected, positional[1])
                    self.assertTrue(keywords['raw'])

    def test_add_computer_api_maps_name_password_and_container(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.domain = 'example.test'
        pv.args = Namespace(debug=False)
        pv.conn = SimpleNamespace(use_ldaps=True, use_adws=False)
        pv.ldap_session = MagicMock()
        pv.ldap_session.add.return_value = True
        server = self.make_server()
        server.powerview.add_domaincomputer = pv.add_domaincomputer
        with server.app.test_client() as client:
            response = client.post('/api/add/domaincomputer', json={
                'computer_name': 'WS-NEW', 'computer_pass': 'Test-only-password!',
                'basedn': 'OU=Servers,DC=example,DC=test',
            })
        self.assertEqual(response.status_code, 200)
        self.assertIs(response.get_json(), True)
        dn, classes, attributes = pv.ldap_session.add.call_args.args
        self.assertEqual(dn, 'CN=WS-NEW,OU=Servers,DC=example,DC=test')
        self.assertEqual(classes, ['computer'])
        self.assertEqual(attributes['sAMAccountName'], 'WS-NEW$')
        self.assertEqual(attributes['dnsHostName'], 'WS-NEW.example.test')
        self.assertEqual(attributes['unicodePwd'], '"Test-only-password!"'.encode('utf-16-le'))

    def test_group_search_accepts_partial_args(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.args = Namespace()
        pv.ldap_session = MagicMock()
        search = pv.ldap_session.extend.standard.paged_search
        search.return_value = []
        server = self.make_server()
        server.powerview.get_domaingroup = pv.get_domaingroup
        with server.app.test_client() as client:
            response = client.post('/api/get/domaingroup', json={'properties': ['name'], 'raw': True, 'args': {'ldapfilter': '(name=Domain*)'}})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(search.call_args.args[1], '(&(objectCategory=group)(name=Domain*))')

    def test_group_search_with_unknown_member_returns_empty_list(self):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.args = Namespace()
        pv.ldap_session = MagicMock()
        pv.get_domainobject = MagicMock(return_value=[])
        server = self.make_server()
        server.powerview.get_domaingroup = pv.get_domaingroup
        with server.app.test_client() as client:
            response = client.post('/api/get/domaingroup', json={'properties': ['name'], 'args': {'memberidentity': 'nobody'}})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), [])
        pv.ldap_session.extend.standard.paged_search.assert_not_called()

    def test_explorer_retains_basic_auth(self):
        import base64
        server = self.make_server({'web_auth_user': 'tester', 'web_auth_password': 'test-only'})
        with server.app.test_client() as client:
            self.assertEqual(client.get('/').status_code, 401)
            token = base64.b64encode(b'tester:test-only').decode()
            self.assertEqual(client.get('/', headers={'Authorization': 'Basic ' + token}).status_code, 200)


if __name__ == '__main__':
    unittest.main()
