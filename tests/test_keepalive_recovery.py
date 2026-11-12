import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ldap3

from powerview.lib.adws.core.connection import Connection as AdwsConnection
from powerview.lib.adws import ENUMERATION
from powerview.utils.connections import CONNECTION, ConnectionPool
from powerview.utils.session import session_lock


class KeepaliveRecoveryTests(unittest.TestCase):
    def make_connection(self, session=None):
        conn = CONNECTION.__new__(CONNECTION)
        conn.args = Namespace(stack_trace=False)
        conn._connection_pool = ConnectionPool(keepalive_interval=0, cleanup_interval=0)
        conn._smb_pool = SimpleNamespace(shutdown=MagicMock())
        conn.get_domain = MagicMock(return_value='example.test')
        if session is None:
            session = ldap3.Connection(ldap3.Server('dc.example.test'))
            session.bound = True
            session.closed = False
            session.search = MagicMock(return_value=True)
            session.send = MagicMock(return_value=1)
            session.strategy.close = MagicMock()
        conn.ldap_server = session.server
        conn.ldap_session = session
        self.addCleanup(conn.close)
        return conn

    def test_adws_keepalive_uses_a_real_rootdse_request(self):
        session = AdwsConnection.__new__(AdwsConnection)
        session.server = SimpleNamespace()
        session.closed = False
        session.bound = True
        session.resource = ENUMERATION
        session.nmf = SimpleNamespace(_sock=MagicMock())
        session.nmf._sock.gettimeout.return_value = None
        session.search = MagicMock(return_value=True)
        session.unbind = MagicMock()
        conn = self.make_connection(session)
        self.assertTrue(conn.keep_alive())
        session.search.assert_called_once_with(search_base='', search_filter='(objectClass=*)',
                                               search_scope=ldap3.BASE, attributes=['currentTime'])
        self.assertEqual([call.args for call in session.nmf._sock.settimeout.call_args_list], [(5,), (None,)])

    def test_adws_probe_timeout_is_restored_after_failure(self):
        session = AdwsConnection.__new__(AdwsConnection)
        session.server = SimpleNamespace()
        session.closed = False
        session.bound = True
        session.resource = ENUMERATION
        session.nmf = SimpleNamespace(_sock=MagicMock())
        session.nmf._sock.gettimeout.return_value = 2
        session.search = MagicMock(side_effect=TimeoutError('probe timed out'))
        session.unbind = MagicMock()
        conn = self.make_connection(session)
        conn.add_domain_connection('example.test')
        conn._connection_pool._perform_keepalive()
        self.assertEqual([call.args for call in session.nmf._sock.settimeout.call_args_list], [(2,), (2,)])
        self.assertFalse(getattr(conn, '_closing', False))
        self.assertTrue(session_lock(conn).interrupted)

    def test_failed_primary_probe_recovers_and_resumes_keepalive(self):
        conn = self.make_connection()
        original = conn.ldap_session
        conn.add_domain_connection('example.test')
        original.send.side_effect = ConnectionResetError('transport lost')
        conn._connection_pool._perform_keepalive()
        self.assertFalse(getattr(conn, '_closing', False))
        self.assertIs(conn._ldap_session, original)
        self.assertFalse(conn._connection_pool._shutdown_event.is_set())
        self.assertTrue(session_lock(conn).interrupted)
        replacement = ldap3.Connection(original.server)
        replacement.bound = True
        replacement.closed = False
        replacement.search = MagicMock(return_value=True)
        replacement.send = MagicMock(return_value=2)
        conn.init_ldap_session = MagicMock(return_value=(original.server, replacement))
        self.assertIs(conn.ldap_session, replacement)
        self.assertFalse(session_lock(conn).interrupted)
        self.assertIs(conn._connection_pool._pool['example.test'].connection, conn)
        conn._connection_pool._perform_keepalive()
        replacement.send.assert_called_once()

    def test_dead_child_is_still_closed(self):
        conn = self.make_connection()
        conn.add_domain_connection('example.test')
        child = SimpleNamespace(is_connection_alive=lambda: True, keep_alive=lambda: False, close=MagicMock())
        conn._connection_pool.add_connection(child, 'child.test')
        conn._connection_pool._perform_keepalive()
        child.close.assert_called_once()
        self.assertNotIn('child.test', conn._connection_pool.get_all_domains())
        self.assertFalse(getattr(conn, '_closing', False))

    def test_primary_removal_and_eviction_do_not_close_it(self):
        for operation in ('remove', 'replace', 'evict', 'shutdown'):
            with self.subTest(operation=operation):
                conn = self.make_connection()
                original = conn.ldap_session
                conn.add_domain_connection('example.test')
                child = SimpleNamespace(is_connection_alive=lambda: True, close=MagicMock())
                if operation == 'remove':
                    conn._connection_pool.remove_connection('example.test')
                elif operation == 'replace':
                    conn._connection_pool.add_connection(child, 'example.test')
                elif operation == 'evict':
                    conn._connection_pool.max_connections = 1
                    conn._connection_pool.add_connection(child, 'child.test')
                else:
                    conn._connection_pool.shutdown()
                self.assertFalse(getattr(conn, '_closing', False))
                self.assertIs(conn._ldap_session, original)
                original.strategy.close.assert_not_called()

    def test_health_checks_preserve_primary_for_recovery(self):
        for operation in ('health_check', '_cleanup_expired_connections'):
            with self.subTest(operation=operation):
                conn = self.make_connection()
                conn.add_domain_connection('example.test')
                conn.ldap_session.search.return_value = False
                getattr(conn._connection_pool, operation)()
                self.assertFalse(getattr(conn, '_closing', False))
                self.assertTrue(session_lock(conn).interrupted)
                self.assertFalse(conn._connection_pool._shutdown_event.is_set())

    def test_late_failure_does_not_remove_recovered_registration(self):
        conn = self.make_connection()
        conn.add_domain_connection('example.test')
        original = conn._connection_pool._pool['example.test']
        original.is_healthy = False
        conn.add_domain_connection('example.test')
        conn._connection_pool.remove_connection('example.test', expected=original)
        self.assertIs(conn._connection_pool._pool['example.test'].connection, conn)
        self.assertFalse(getattr(conn, '_closing', False))

    def test_replacing_unhealthy_registration_does_not_close_same_child(self):
        pool = ConnectionPool(cleanup_interval=0, keepalive_interval=0)
        self.addCleanup(pool.shutdown)
        child = SimpleNamespace(is_connection_alive=lambda: True, close=MagicMock())
        pool.add_connection(child, 'child.test')
        previous = pool._pool['child.test']
        previous.is_healthy = False
        pool.add_connection(child, 'child.test')
        pool.remove_connection('child.test', expected=previous)
        child.close.assert_not_called()
        self.assertTrue(pool._pool['child.test'].is_healthy)


if __name__ == '__main__':
    unittest.main()
