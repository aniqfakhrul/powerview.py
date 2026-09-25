import socket
import unittest
from unittest.mock import MagicMock, patch

import ldap3

from powerview.lib.dns import DNS_RECORD, DNS_RPC_RECORD_A, DNS_UTIL
from powerview.powerview import PowerView

NODE = 'DC=web01,DC=example.test,CN=MicrosoftDNS,DC=DomainDnsZones,DC=example,DC=test'


def a_record(address, serial=10):
	return DNS_UTIL.new_record(1, serial, address).getData()


def aaaa_record():
	record = DNS_RECORD()
	record['Type'] = 28
	record['Serial'] = 10
	record['TtlSeconds'] = 180
	record['Rank'] = 240
	record['Data'] = socket.inet_pton(socket.AF_INET6, '2001:db8::1')
	return record.getData()


def address(raw):
	return DNS_RPC_RECORD_A(DNS_RECORD(raw)['Data']).formatCanonical()


class SetDnsRecordTests(unittest.TestCase):
	def run_set(self, stored, found=(NODE,), name='web01', **kwargs):
		powerview = PowerView.__new__(PowerView)
		powerview.domain = 'example.test'
		powerview.nameserver = None
		powerview.dc_ip = '192.0.2.1'
		powerview.get_domaindnsrecord = MagicMock(return_value=[{'attributes': {'distinguishedName': dn, 'name': 'web01'}} for dn in found])
		powerview.get_domainobject = MagicMock(return_value=[{'attributes': {'distinguishedName': NODE}, 'raw_attributes': {'dnsRecord': list(stored)}}])
		powerview.ldap_session = MagicMock()
		powerview.ldap_session.modify.return_value = True
		with patch.object(DNS_UTIL, 'get_next_serial', return_value=42):
			result = powerview.set_domaindnsrecord(name, '10.0.0.99', zonename='example.test', **kwargs)
		return result, powerview

	def written(self, powerview):
		dn, changes = powerview.ldap_session.modify.call_args.args
		self.assertEqual(dn, NODE)
		operation, records = changes['dnsRecord'][0]
		self.assertEqual(operation, ldap3.MODIFY_REPLACE)
		return records

	def test_reads_node_fresh_by_dn(self):
		result, powerview = self.run_set([a_record('10.0.0.1')])
		self.assertTrue(result)
		powerview.get_domaindnsrecord.assert_called_once_with(identity='web01', zonename='example.test', properties=['distinguishedName', 'name'], no_cache=True)
		kwargs = powerview.get_domainobject.call_args.kwargs
		self.assertEqual((kwargs['identity'], kwargs['searchbase'], kwargs['search_scope'], kwargs['no_cache'], kwargs['raw']), (NODE, NODE, ldap3.BASE, True, True))
		self.assertEqual([address(raw) for raw in self.written(powerview)], ['10.0.0.99'])

	def test_changes_only_the_matching_a_record_and_keeps_the_rest(self):
		stored = [a_record('10.0.0.1'), aaaa_record(), a_record('10.0.0.2')]
		result, powerview = self.run_set(stored, oldaddress='10.0.0.2')
		self.assertTrue(result)
		records = self.written(powerview)
		self.assertEqual(records[:2], stored[:2])
		self.assertEqual(address(records[2]), '10.0.0.99')
		self.assertEqual(DNS_RECORD(records[2])['Serial'], 42)

	def test_distinguished_name_is_used_without_a_name_lookup(self):
		result, powerview = self.run_set([a_record('10.0.0.1')], name=NODE, oldaddress='10.0.0.1')
		self.assertTrue(result)
		powerview.get_domaindnsrecord.assert_not_called()
		self.assertEqual(powerview.get_domainobject.call_args.kwargs['identity'], NODE)

	def test_several_a_records_need_an_old_address(self):
		result, powerview = self.run_set([a_record('10.0.0.1'), a_record('10.0.0.2')])
		self.assertFalse(result)
		powerview.ldap_session.modify.assert_not_called()

	def test_unknown_old_address_changes_nothing(self):
		result, powerview = self.run_set([a_record('10.0.0.1')], oldaddress='10.0.0.7')
		self.assertFalse(result)
		powerview.ldap_session.modify.assert_not_called()

	def test_name_matching_several_nodes_changes_nothing(self):
		result, powerview = self.run_set([a_record('10.0.0.1')], found=(NODE, NODE.replace('DomainDnsZones', 'ForestDnsZones')))
		self.assertFalse(result)
		powerview.get_domainobject.assert_not_called()
		powerview.ldap_session.modify.assert_not_called()

	def test_node_without_a_record_changes_nothing(self):
		result, powerview = self.run_set([aaaa_record()])
		self.assertFalse(result)
		powerview.ldap_session.modify.assert_not_called()


if __name__ == '__main__':
	unittest.main()
