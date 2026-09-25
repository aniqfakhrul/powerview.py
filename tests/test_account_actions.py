import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock

from powerview.web.api.server import APIServer

DN = 'CN=Dana Whitfield,OU=Staff,DC=example,DC=test'


class AccountActionRouteTests(unittest.TestCase):
    def make_server(self, auth=None):
        powerview = SimpleNamespace(
            flatName='EXAMPLE',
            args=Namespace(web_auth=auth, username='tester', ldap_address='dc.example.test', stack_trace=False),
            unlock_adaccount=MagicMock(return_value=True),
            enable_adaccount=MagicMock(return_value=True),
            disable_adaccount=MagicMock(return_value=False),
            enable_rdp=MagicMock(return_value=True),
        )
        return APIServer(powerview), powerview

    def test_each_action_calls_only_its_account_method(self):
        server, powerview = self.make_server()
        with server.app.test_client() as client:
            for action, method in [('unlock', powerview.unlock_adaccount), ('enable', powerview.enable_adaccount)]:
                with self.subTest(action=action):
                    response = client.post(f'/api/account/{action}', json={'identity': f'  {DN} ', 'searchbase': 'DC=example,DC=test'})
                    self.assertEqual(response.status_code, 200)
                    self.assertIs(response.get_json(), True)
                    method.assert_called_once_with(identity=DN, searchbase='DC=example,DC=test')
            response = client.post('/api/account/disable', json={'identity': DN})
            self.assertIs(response.get_json(), False)
            powerview.disable_adaccount.assert_called_once_with(identity=DN)

    def test_other_methods_and_bad_input_are_rejected(self):
        server, powerview = self.make_server()
        with server.app.test_client() as client:
            self.assertEqual(client.post('/api/account/rdp', json={'identity': DN}).status_code, 404)
            self.assertEqual(client.get('/api/account/unlock').status_code, 405)
            for body in [None, {}, {'identity': ''}, {'identity': 42}]:
                with self.subTest(body=body):
                    response = client.post('/api/account/unlock', json=body) if body is not None else client.post('/api/account/unlock')
                    self.assertEqual(response.status_code, 400)
        powerview.enable_rdp.assert_not_called()
        powerview.unlock_adaccount.assert_not_called()

    def test_method_errors_return_400_with_message(self):
        server, powerview = self.make_server()
        powerview.enable_adaccount.side_effect = RuntimeError('Insufficient rights')
        with server.app.test_client() as client:
            response = client.post('/api/account/enable', json={'identity': DN})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json(), {'error': 'Insufficient rights'})

    def test_routes_require_web_auth_when_configured(self):
        server, powerview = self.make_server({'web_auth_user': 'tester', 'web_auth_password': 'test-only'})
        with server.app.test_client() as client:
            self.assertEqual(client.post('/api/account/unlock', json={'identity': DN}).status_code, 401)
        powerview.unlock_adaccount.assert_not_called()


if __name__ == '__main__':
    unittest.main()
