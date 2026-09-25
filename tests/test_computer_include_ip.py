"""IncludeIP joins returned computer hostnames to AD DNS records, without network I/O."""
import unittest
from argparse import Namespace
from copy import deepcopy
from unittest.mock import MagicMock

from powerview.powerview import PowerView


def computer(hostname, key='dNSHostName'):
    return {'attributes': {key: hostname, 'name': 'WS01'}}


def dns_record(name, address):
    return {'attributes': {'name': name, 'Address': address}}


class ComputerIncludeIPTests(unittest.TestCase):
    def make_powerview(self, entries, records_by_zone):
        pv = PowerView.__new__(PowerView)
        pv.root_dn = 'DC=example,DC=test'
        pv.args = Namespace(stack_trace=False)
        pv.ldap_session = MagicMock()
        pv.ldap_session.extend.standard.paged_search.return_value = deepcopy(entries)
        pv.get_domaindnszone = MagicMock(return_value=[
            {'attributes': {'name': zone}} for zone in records_by_zone
        ])
        pv.get_domaindnsrecord = MagicMock(side_effect=lambda **kwargs: records_by_zone[kwargs['zonename']])
        return pv

    def test_identity_forms_enrich_the_returned_hostname(self):
        for identity in ['WS01', 'WS01$', 'WS01.example.test',
                         'CN=WS01,OU=Computers,DC=example,DC=test', 'S-1-5-21-1-2-3-1000']:
            with self.subTest(identity=identity):
                pv = self.make_powerview([computer('WS01.example.test')], {
                    'example.test': [dns_record('WS01', '192.0.2.1')],
                })
                entries = pv.get_domaincomputer(args=Namespace(identity=identity, include_ip=True), no_cache=True)
                self.assertEqual(entries[0]['attributes']['IPAddress'], '192.0.2.1')
                pv.get_domaindnsrecord.assert_called_once_with(zonename='example.test', record_type='A', no_cache=True)
                pv.get_domaindnszone.assert_called_once_with(no_cache=True)

    def test_plain_cached_dicts_casing_and_list_values(self):
        for key in ['dNSHostName', 'dnsHostName', 'DNSHOSTNAME']:
            with self.subTest(key=key):
                pv = self.make_powerview([computer(['WS01.EXAMPLE.TEST.'], key)], {
                    'example.test': [{'attributes': {'NAME': ['ws01'], 'ADDRESS': ['192.0.2.1']}}],
                })
                result = pv.get_domaincomputer(include_ip=True, properties=['name'])
                self.assertEqual(result[0]['attributes']['IPAddress'], '192.0.2.1')
                attributes = pv.ldap_session.extend.standard.paged_search.call_args.kwargs['attributes']
                self.assertIn('dnshostname', [name.lower() for name in attributes])

    def test_full_names_isolate_zones_and_keep_nested_labels(self):
        pv = self.make_powerview([computer('WS01.example.test'), computer('WS01.other.test'),
                                 computer('WS01.branch.example.test'), computer('WS01.unknown.test')], {
            'example.test': [dns_record('WS01', '192.0.2.1'), dns_record('WS01.branch', '192.0.2.3')],
            'other.test': [dns_record('WS01', '192.0.2.2')],
        })
        result = pv.get_domaincomputer(include_ip=True)
        self.assertEqual([entry['attributes'].get('IPAddress') for entry in result],
                         ['192.0.2.1', '192.0.2.2', '192.0.2.3', None])
        self.assertEqual(pv.get_domaindnsrecord.call_count, 2)

    def test_child_zone_and_apex_and_multiple_addresses(self):
        pv = self.make_powerview([computer('WS01.branch.example.test'), computer('branch.example.test')], {
            'example.test': [dns_record('WS01.branch', '192.0.2.99')],
            'branch.example.test': [dns_record('WS01', '192.0.2.1'), dns_record('WS01', '192.0.2.1'),
                                    dns_record('WS01', '192.0.2.2'), dns_record('@', '192.0.2.3')],
        })
        result = pv.get_domaincomputer(include_ip=True)
        self.assertEqual(result[0]['attributes']['IPAddress'], ['192.0.2.1', '192.0.2.2'])
        self.assertEqual(result[1]['attributes']['IPAddress'], '192.0.2.3')
        pv.get_domaindnsrecord.assert_called_once_with(zonename='branch.example.test', record_type='A', no_cache=False)

    def test_no_flag_or_no_hostname_does_not_query_dns(self):
        for entries, enabled in [([computer('WS01.example.test')], False), ([computer([])], True), ([], True)]:
            with self.subTest(entries=entries, enabled=enabled):
                pv = self.make_powerview(entries, {})
                pv.get_domaincomputer(include_ip=enabled)
                pv.get_domaindnszone.assert_not_called()
                pv.get_domaindnsrecord.assert_not_called()

    def test_dns_failure_preserves_computers_and_other_zones(self):
        pv = self.make_powerview([computer('WS01.example.test'), computer('WS01.other.test')], {
            'example.test': [], 'other.test': [],
        })
        def lookup(**kwargs):
            if kwargs['zonename'] == 'example.test':
                raise RuntimeError('DNS partition unavailable')
            return [dns_record('WS01', '192.0.2.2')]
        pv.get_domaindnsrecord.side_effect = lookup
        result = pv.get_domaincomputer(include_ip=True)
        self.assertNotIn('IPAddress', result[0]['attributes'])
        self.assertEqual(result[1]['attributes']['IPAddress'], '192.0.2.2')
        pv.get_domaindnszone.side_effect = RuntimeError('No DNS access')
        self.assertEqual(len(pv.get_domaincomputer(include_ip=True)), 2)
        pv.args.stack_trace = True
        with self.assertRaisesRegex(RuntimeError, 'No DNS access'):
            pv.get_domaincomputer(include_ip=True)


if __name__ == '__main__':
    unittest.main()
