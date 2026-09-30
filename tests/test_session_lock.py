import asyncio
import json
import threading
import unittest
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from powerview.powerview import PowerView
from powerview.utils.connections import CONNECTION, ConnectionPool, ConnectionPoolEntry
from powerview.utils.session import session_lock
from powerview.web.api.server import APIServer


class SessionLockTests(unittest.TestCase):
    def make_server(self):
        conn = CONNECTION.__new__(CONNECTION)
        conn.args = Namespace(stack_trace=False)
        conn.ldap_session = SimpleNamespace(bound=True, search=MagicMock(return_value=True))
        conn.ldap_server = SimpleNamespace(info=SimpleNamespace(other={'defaultNamingContext': ['DC=example,DC=test']}, to_json=lambda: '{}'))
        conn._connection_pool = SimpleNamespace(shutdown=lambda: None)
        for name, value in [('domain', 'example.test'), ('username', 'tester'), ('proto', 'LDAPS'), ('ldap_address', 'dc.example.test'), ('nameserver', 'dc.example.test')]:
            setattr(conn, name, value)
        conn.use_system_ns = False
        pv = SimpleNamespace(conn=conn, flatName='EXAMPLE', args=Namespace(web_auth=None, username='tester', ldap_address='dc.example.test', stack_trace=False))
        return APIServer(pv), pv, conn

    def request(self, server, path):
        with server.app.test_client() as client:
            response = client.get(path)
            return response.status_code, response.get_json()

    def test_api_serializes_generator_consumption_and_status_queries(self):
        server, pv, conn = self.make_server()
        entered, release, status_started = threading.Event(), threading.Event(), threading.Event()

        def records():
            entered.set()
            self.assertTrue(release.wait(2))
            yield {'attributes': {'name': 'first'}}

        pv.get_domainobject = records

        def status():
            status_started.set()
            return self.request(server, '/api/connectioninfo')

        with ThreadPoolExecutor(max_workers=3) as executor:
            query = executor.submit(self.request, server, '/api/get/domainobject')
            self.assertTrue(entered.wait(1))
            check = executor.submit(status)
            try:
                self.assertTrue(status_started.wait(1))
                self.assertFalse(check.done())
                conn.ldap_session.search.assert_not_called()
                self.assertEqual(executor.submit(self.request, server, '/health').result(1)[0], 200)
            finally:
                release.set()
            self.assertEqual(query.result(2), (200, [{'attributes': {'name': 'first'}}]))
            self.assertEqual(check.result(2)[1]['status'], 'OK')
        conn.ldap_session.search.assert_called_once()

    def test_api_and_cli_share_lock_and_release_after_error(self):
        server, pv, conn = self.make_server()
        called = threading.Event()

        def fail():
            called.set()
            raise ValueError('expected failure')

        pv.get_domainobject = fail
        with ThreadPoolExecutor(max_workers=1) as executor:
            with session_lock(pv):
                request = executor.submit(self.request, server, '/api/get/domainobject')
                self.assertFalse(called.wait(0.05))
            self.assertEqual(request.result(2)[0], 400)
            self.assertTrue(executor.submit(lambda: self.acquire_and_release(conn)).result(1))

    def test_smb_stream_releases_session_after_setup(self):
        server, pv, conn = self.make_server()
        entered, release = threading.Event(), threading.Event()
        setup_locked = []

        def connect(host):
            with ThreadPoolExecutor(max_workers=1) as executor:
                setup_locked.append(not executor.submit(self.acquire_and_release, conn).result(1))
            return object()

        def listing(share, path):
            entered.set()
            release.wait(3)
            return []

        conn.init_smb_session = connect
        pv.get_domainobject = lambda: [{'attributes': {'name': 'test'}}]
        with patch('powerview.web.api.server.SMBClient') as client:
            client.return_value.ls.side_effect = listing
            with ThreadPoolExecutor(max_workers=2) as executor:
                stream = executor.submit(self.request, server, '/api/smb/search-stream?computer=dc.example.test&share=data')
                try:
                    self.assertTrue(entered.wait(2))
                    self.assertEqual(executor.submit(self.request, server, '/api/get/domainobject').result(1)[0], 200)
                    self.assertEqual(executor.submit(self.request, server, '/api/connectioninfo').result(1)[1]['status'], 'OK')
                finally:
                    release.set()
                self.assertEqual(stream.result(2)[0], 200)
        self.assertEqual(setup_locked, [True])

    def test_pool_logs_connection_creation_failure(self):
        pool = ConnectionPool(cleanup_interval=0, keepalive_interval=0)
        try:
            with self.assertLogs(level='WARNING') as logs:
                with self.assertRaisesRegex(ConnectionError, 'unavailable'):
                    pool.get_connection('example.test', MagicMock(side_effect=ConnectionError('unavailable')))
            self.assertIn('Failed to create connection for domain example.test: unavailable', logs.output[0])
        finally:
            pool.shutdown()

    def acquire_and_release(self, owner):
        lock = session_lock(owner)
        acquired = lock.acquire(timeout=0.5)
        if acquired:
            lock.release()
        return acquired

    def test_shared_connection_wrappers_and_rebind_keep_same_lock(self):
        _, pv, conn = self.make_server()
        other = CONNECTION.__new__(CONNECTION)
        other.ldap_session = conn.ldap_session
        self.assertIs(session_lock(pv), session_lock(conn))
        self.assertIs(session_lock(other), session_lock(conn.ldap_session))
        original = session_lock(conn)
        conn.ldap_session = SimpleNamespace(bound=True)
        self.assertIs(session_lock(conn), original)
        self.assertIs(session_lock(conn.ldap_session), original)

    def test_execute_holds_lock_until_generator_is_consumed(self):
        conn = SimpleNamespace()
        pv = PowerView.__new__(PowerView)
        pv.conn = conn
        pv.plugin_registry = None
        def records():
            with ThreadPoolExecutor(max_workers=1) as executor:
                self.assertFalse(executor.submit(lambda: self.acquire_and_release(conn)).result(1))
            yield {'attributes': {'name': 'test'}}
        pv.get_domainobject = records
        self.assertEqual(pv.execute(Namespace(module='Get-DomainObject')), [{'attributes': {'name': 'test'}}])

    def test_busy_connection_skips_pool_probes_without_marking_dead(self):
        _, pv, conn = self.make_server()
        pool = ConnectionPool(cleanup_interval=0, keepalive_interval=0)
        entry = ConnectionPoolEntry(conn, 'example.test')
        pool._pool['example.test'] = entry
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                with session_lock(pv):
                    self.assertTrue(executor.submit(entry.is_alive).result(1))
                    executor.submit(pool._perform_keepalive).result(1)
                    executor.submit(pool._cleanup_expired_connections).result(1)
            self.assertTrue(entry.is_healthy)
            conn.ldap_session.search.assert_not_called()
        finally:
            pool._pool.clear()
            pool.shutdown()

    def test_pool_closes_outside_registry_lock_and_does_not_close_same_connection(self):
        pool = ConnectionPool(cleanup_interval=0, keepalive_interval=0)
        conn = SimpleNamespace(is_connection_alive=lambda: True, close=MagicMock())
        pool.add_connection(conn, 'example.test')
        pool.add_connection(conn, 'example.test')
        conn.close.assert_not_called()
        observed = []
        def close():
            with ThreadPoolExecutor(max_workers=1) as executor:
                observed.append(executor.submit(pool.get_all_domains).result(1))
        conn.close.side_effect = close
        pool.remove_connection('example.test')
        conn.close.assert_called_once()
        self.assertEqual(observed, [[]])
        pool.shutdown()

    def test_rebind_and_close_wait_for_active_operation(self):
        for operation in ['reset_connection', 'close']:
            with self.subTest(operation=operation):
                _, pv, conn = self.make_server()
                conn.ldap_session.rebind = MagicMock(return_value=True)
                conn.ldap_session.unbind = MagicMock()
                session = conn.ldap_session
                with ThreadPoolExecutor(max_workers=1) as executor:
                    with session_lock(pv):
                        future = executor.submit(getattr(conn, operation))
                        self.assertFalse(future.done())
                        session.rebind.assert_not_called()
                        session.unbind.assert_not_called()
                    future.result(2)
                if operation == 'close':
                    session.unbind.assert_called_once()
                else:
                    session.rebind.assert_called_once()

    def test_mcp_tool_shares_the_session_lock(self):
        from fastmcp import FastMCP
        from powerview.mcp.src.tools import setup_tools

        _, pv, conn = self.make_server()
        called = threading.Event()
        pv.get_domain = MagicMock(side_effect=lambda **kwargs: (called.set() or [{'attributes': {'name': 'example.test'}}]))
        mcp = FastMCP('Session test')
        setup_tools(mcp, pv)

        async def invoke():
            tool = await mcp.get_tool('get_domain')
            return await tool.run({})

        with ThreadPoolExecutor(max_workers=1) as executor:
            with session_lock(conn):
                future = executor.submit(asyncio.run, invoke())
                self.assertFalse(called.wait(0.05))
            result = future.result(3)
        payload = json.loads(result.content[0].text)
        self.assertEqual(payload['data'], [{'attributes': {'name': 'example.test'}}])


if __name__ == '__main__':
    unittest.main()
