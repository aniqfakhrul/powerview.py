import unittest
from argparse import Namespace
from unittest.mock import patch

from powerview.utils import connections
from powerview.utils.parsers import arg_parse


class StopConstruction(Exception):
	pass


class KeepaliveTests(unittest.TestCase):
	def ldap_keepalive(self, args, **kwargs):
		with patch.object(connections, 'ConnectionPool') as pool, patch.object(connections, 'SMBConnectionPool', side_effect=StopConstruction):
			with self.assertRaises(StopConstruction):
				connections.CONNECTION(args, **kwargs)
		return pool.call_args.kwargs['keepalive_interval']

	def test_interactive_sessions_keep_alive_every_300_seconds_by_default(self):
		with patch('sys.argv', ['powerview', 'example.test/alice:secret@10.0.0.1']):
			self.assertEqual(arg_parse().keepalive_interval, 300)

	def test_pool_uses_the_interval_and_zero_disables_it(self):
		self.assertEqual(self.ldap_keepalive(Namespace(keepalive_interval=300, query=None)), 300)
		self.assertEqual(self.ldap_keepalive(Namespace(keepalive_interval=0, query=None)), 0)

	def test_one_shot_queries_and_child_connections_skip_keepalive(self):
		self.assertEqual(self.ldap_keepalive(Namespace(keepalive_interval=300, query='Get-Domain')), 0)
		self.assertEqual(self.ldap_keepalive(Namespace(keepalive_interval=300, query=None), _is_child=True), 0)


if __name__ == '__main__':
	unittest.main()
