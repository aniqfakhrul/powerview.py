import unittest
from argparse import Namespace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from ldap3.core.exceptions import LDAPNoSuchObjectResult, LDAPOperationResult
from ldap3.utils.ciDict import CaseInsensitiveDict

from powerview.web.api.dashboard import account_summary, dashboard_section, domain_summary, inventory_summary
from powerview.web.api.server import APIServer


ROOT_DN = 'DC=example,DC=test'
NOW = datetime(2026, 9, 27, tzinfo=timezone.utc)


def entry(name, **attrs):
    return {'dn': f'CN={name},CN=Users,{ROOT_DN}', 'attributes': {'name': name, 'sAMAccountName': name, **attrs}}


def powerview():
    return SimpleNamespace(
        flatName='EXAMPLE', domain='example.test', root_dn=ROOT_DN, dc_dnshostname='dc.example.test',
        args=Namespace(web_auth=None, username='tester', ldap_address='dc.example.test'),
        ldap_session=SimpleNamespace(result={'result': 0}),
        get_domain=MagicMock(return_value=[entry('example', minPwdLength=12)]),
        get_domainuser=MagicMock(return_value=[]), get_domaincomputer=MagicMock(return_value=[]),
        get_domainobject=MagicMock(return_value=[]), get_domainca=MagicMock(return_value=[]),
    )


class DashboardTests(unittest.TestCase):
    def test_ldap_attribute_mappings_work_in_every_source(self):
        pv = powerview()
        for method, record in [
            (pv.get_domain, entry('domain', minPwdLength=12)),
            (pv.get_domainobject, entry('group', objectClass=['top', 'group'])),
            (pv.get_domainuser, entry('user', userAccountControl=512 | 4194304)),
            (pv.get_domaincomputer, entry('dc$', userAccountControl=8192)),
        ]:
            record['attributes'] = CaseInsensitiveDict(record['attributes'])
            method.return_value = [record]
        with APIServer(pv).app.test_client() as client:
            results = {}
            for section in ['domain', 'inventory', 'users', 'computers']:
                response = client.get(f'/api/dashboard/{section}')
                self.assertEqual(response.status_code, 200, response.get_json())
                results[section] = response.get_json()
        self.assertEqual(results['domain']['policy']['minPwdLength'], 12)
        self.assertEqual(results['inventory']['counts']['groups'], 1)
        self.assertEqual(results['users']['findings']['users_preauth']['count'], 1)
        self.assertEqual(results['computers']['counts']['controllers'], 1)

    def test_enabled_signals_and_unknown_account_state(self):
        pv = powerview()
        pv.get_domainuser.return_value = [
            entry('review', userAccountControl=512 | 4194304 | 32 | 65536, adminCount=1, servicePrincipalName=['HTTP/app', 'HTTP/other'], lastLogonTimestamp=NOW - timedelta(days=91)),
            entry('disabled', userAccountControl=2 | 4194304 | 32 | 65536, adminCount=1, servicePrincipalName=['HTTP/disabled']),
            entry('unknown', servicePrincipalName=['HTTP/unknown']),
            entry('krbtgt', userAccountControl=512, servicePrincipalName=['kadmin/changepw']),
            entry('boundary', userAccountControl='512', lastLogonTimestamp=NOW - timedelta(days=90)),
        ]
        result = account_summary(pv, 'users', NOW)
        self.assertEqual(result['counts']['total'], 5)
        self.assertEqual(result['counts']['enabled'], 3)
        self.assertEqual(result['counts']['disabled'], 1)
        self.assertEqual(result['counts']['unknown'], 1)
        self.assertEqual(result['counts']['missing_logon'], 1)
        for finding in result['findings'].values():
            self.assertEqual(finding['count'], 1)
            self.assertEqual(finding['objects'][0]['name'], 'review')
        self.assertIn('(+1 more)', result['findings']['users_spn']['objects'][0]['evidence'])

    def test_samples_are_bounded_but_counts_are_not(self):
        pv = powerview()
        pv.get_domainuser.return_value = [entry(str(index), userAccountControl=4194304) for index in range(125)]
        result = account_summary(pv, 'users', NOW)
        finding = result['findings']['users_preauth']
        self.assertEqual(finding['count'], 125)
        self.assertEqual(len(finding['objects']), 100)
        self.assertEqual(result['findings']['users_stale']['count'], 0)

    def test_computers_exclude_controllers_from_unconstrained_signal(self):
        pv = powerview()
        old = int(((NOW - timedelta(days=100)) - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 10000000)
        pv.get_domaincomputer.return_value = [
            entry('dc$', userAccountControl=8192 | 524288, operatingSystem='Windows Server', dNSHostName='dc.example.test'),
            entry('rodc$', userAccountControl=67108864 | 524288),
            entry('app$', userAccountControl=[4096 | 524288 | 32], operatingSystem='Windows Server', lastLogonTimestamp=str(old), **{'msDS-AllowedToDelegateTo': ['HTTP/service']}),
            entry('disabled$', userAccountControl=4096 | 524288 | 2),
        ]
        result = account_summary(pv, 'computers', NOW)
        self.assertEqual(result['counts']['controllers'], 2)
        for finding in result['findings'].values():
            self.assertEqual(finding['count'], 1)
            self.assertEqual(finding['objects'][0]['name'], 'app$')
        self.assertEqual(sum(item['count'] for item in result['systems']), 4)
        self.assertEqual(result['controllers'][0]['host'], 'dc.example.test')

    def test_domain_intervals_missing_values_and_zero_are_distinct(self):
        pv = powerview()
        pv.get_domain.return_value = [entry('domain', minPwdLength=[0], maxPwdAge=-36288000000000, minPwdAge=timedelta(0), lockoutDuration=timedelta(minutes=-30), pwdProperties=17)]
        result = domain_summary(pv)['policy']
        self.assertEqual(result['minPwdLength'], 0)
        self.assertEqual(result['maxPwdAge'], 42 * 86400)
        self.assertEqual(result['minPwdAge'], 0)
        self.assertEqual(result['lockoutDuration'], 1800)
        self.assertIsNone(result['lockoutThreshold'])
        pv.get_domain.assert_called_once()
        self.assertEqual(pv.get_domain.call_args.kwargs['search_scope'], 'BASE')

    def test_inventory_and_case_insensitive_attributes(self):
        pv = powerview()
        pv.get_domainobject.return_value = [
            entry('group', objectClass=['top', 'group']), entry('ou', objectClass='organizationalUnit'),
            entry('gpo', objectClass=['top', 'groupPolicyContainer']),
            entry('partner', OBJECTCLASS=['trustedDomain'], TRUSTDIRECTION=[3], trustPartner='partner.test', trustAttributes=8),
        ]
        pv.get_domainca.return_value = [
            entry('CA-One', certificateTemplates=['User', 'WebServer']),
            entry('CA-Two', CERTIFICATETEMPLATES='user'),
        ]
        result = inventory_summary(pv)
        self.assertEqual(result['counts'], {'groups': 1, 'ous': 1, 'gpos': 1, 'trusts': 1, 'cas': 2, 'published_templates': 2})
        self.assertEqual(result['trusts'][0]['direction'], 3)
        self.assertIsNone(result['ca_error'])
        self.assertEqual(pv.get_domainca.call_args.kwargs['check_all'], False)
        self.assertEqual(pv.get_domainca.call_args.kwargs['properties'], ['name', 'dNSHostName', 'certificateTemplates'])

    def test_authority_failures_do_not_hide_inventory(self):
        pv = powerview()
        pv.get_domainobject.return_value = [entry('group', objectClass=['top', 'group'])]
        pv.get_domainca.side_effect = LDAPNoSuchObjectResult()
        result = inventory_summary(pv)
        self.assertEqual((result['counts']['cas'], result['counts']['published_templates'], result['ca_error']), (0, 0, None))
        pv.get_domainca.side_effect = LDAPOperationResult(description='insufficientAccessRights')
        result = inventory_summary(pv)
        self.assertEqual(result['counts']['groups'], 1)
        self.assertIsNone(result['counts']['cas'])
        self.assertIsNone(result['counts']['published_templates'])
        self.assertTrue(result['ca_error'])

    def test_reads_use_the_cache_by_default(self):
        pv = powerview()
        for section in ['domain', 'inventory', 'users', 'computers']:
            result = dashboard_section(pv, section)
            self.assertEqual(result['root_dn'], ROOT_DN)
            self.assertEqual(result['sample_limit'], 100)
            self.assertIn('collected_at', result)
        for method in [pv.get_domain, pv.get_domainobject, pv.get_domainca, pv.get_domainuser, pv.get_domaincomputer]:
            kwargs = method.call_args.kwargs
            self.assertIs(kwargs['no_cache'], False)
            for option in ['raw', 'no_vuln_check']:
                self.assertIs(kwargs[option], True)
            self.assertNotIn('*', kwargs['properties'])
            self.assertFalse(set(prop.lower() for prop in kwargs['properties']) & {'unicodepwd', 'ms-mcs-admpwd', 'mslaps-password', 'msds-managedpassword'})

    def test_refresh_bypasses_the_cache(self):
        pv = powerview()
        dashboard_section(pv, 'users', fresh=True)
        self.assertIs(pv.get_domainuser.call_args.kwargs['no_cache'], True)

    def test_inactivity_threshold_is_configurable_and_validated(self):
        pv = powerview()
        pv.get_domainuser.return_value = [entry('idle', userAccountControl=512, lastLogonTimestamp=NOW - timedelta(days=45))]
        self.assertEqual(account_summary(pv, 'users', NOW, days=30)['findings']['users_stale']['count'], 1)
        self.assertEqual(account_summary(pv, 'users', NOW, days=60)['findings']['users_stale']['count'], 0)
        self.assertEqual(account_summary(pv, 'users', NOW, days=60)['inactive_days'], 60)
        with self.assertRaises(ValueError):
            dashboard_section(pv, 'users', days=45)

    def test_route_passes_refresh_and_threshold(self):
        pv = powerview()
        with APIServer(pv).app.test_client() as client:
            self.assertEqual(client.get('/api/dashboard/users?fresh=1&days=180').get_json()['inactive_days'], 180)
            self.assertIs(pv.get_domainuser.call_args.kwargs['no_cache'], True)
            self.assertEqual(client.get('/api/dashboard/users?days=45').status_code, 400)
            self.assertEqual(client.get('/api/dashboard/users?days=soon').status_code, 400)

    def test_never_intervals_are_reported_explicitly(self):
        pv = powerview()
        pv.get_domain.return_value = [entry('domain', maxPwdAge=timedelta.max, lockoutDuration=-9223372036854775808, minPwdAge=timedelta(days=1))]
        policy = domain_summary(pv)['policy']
        self.assertEqual(policy['maxPwdAge'], 'never')
        self.assertEqual(policy['lockoutDuration'], 'never')
        self.assertEqual(policy['minPwdAge'], 86400)

    def test_api_failures_are_not_reported_as_zero_and_routes_are_restricted(self):
        pv = powerview()
        server = APIServer(pv)
        with server.app.test_client() as client:
            self.assertEqual(client.get('/api/dashboard/anything').status_code, 404)
            self.assertEqual(client.post('/api/dashboard/users').status_code, 405)
            self.assertEqual(client.get('/api/dashboard/users').get_json()['counts']['total'], 0)
            pv.get_domainuser.return_value = None
            self.assertEqual(client.get('/api/dashboard/users').status_code, 400)
            pv.get_domainuser.return_value = []
            pv.ldap_session.result = {'result': 4, 'description': 'left over from another request'}
            self.assertEqual(client.get('/api/dashboard/users').status_code, 200)
            pv.get_domainuser.side_effect = RuntimeError('Access denied')
            self.assertEqual(client.get('/api/dashboard/users').get_json()['error'], 'Access denied')

    def test_auth_and_prefixed_dashboard(self):
        pv = powerview()
        pv.args.web_auth = {'web_auth_user': 'tester', 'web_auth_password': 'test-only'}
        with APIServer(pv).app.test_client() as client:
            self.assertEqual(client.get('/api/dashboard/users').status_code, 401)
        pv.get_domainuser.assert_not_called()
        pv.args.web_auth = None
        with APIServer(pv).app.test_client() as client:
            html = client.get('/', environ_overrides={'SCRIPT_NAME': '/pv'}).get_data(as_text=True)
            self.assertIn('data-api-root="/pv/api/"', html)
            self.assertIn('/pv/static/js/pages/dashboard.js', html)
            self.assertNotIn('Coming next', html)

    def test_domain_change_during_a_source_read_discards_result(self):
        pv = powerview()

        def change_domain(**kwargs):
            pv.root_dn = 'DC=other,DC=test'
            return []

        pv.get_domainuser.side_effect = change_domain
        with self.assertRaisesRegex(ValueError, 'domain changed'):
            dashboard_section(pv, 'users')


if __name__ == '__main__':
    unittest.main()
