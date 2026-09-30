import asyncio
import json
import threading
import unittest
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from ldap3 import Connection, Server, OFFLINE_AD_2012_R2

from powerview.powerview import PowerView
from powerview.utils.connections import CONNECTION, ConnectionPool, ConnectionPoolEntry
from powerview.utils.session import session_lock, recover_interrupted_session
from powerview.utils.shell import get_prompt
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
        session = conn.ldap_session
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
                session.search.assert_not_called()
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

    def test_powerview_refreshes_replaced_session_and_extensions(self):
        _, _, conn = self.make_server()
        views = []
        for _ in range(2):
            view = PowerView.__new__(PowerView)
            view.conn = conn
            view.ldap_session = conn.ldap_session
            view.ldap_server = conn.ldap_server
            view._initialize_attributes_from_connection = MagicMock()
            views.append(view)
        replacement = SimpleNamespace(bound=True)
        conn.ldap_session = replacement
        conn.ldap_server = object()
        for view in views:
            self.assertIs(view.ldap_session, replacement)
            self.assertIs(view.ldap_server, conn.ldap_server)
            view._initialize_attributes_from_connection.assert_called_once()

    def test_fresh_reset_skips_rebind_and_replaces_interrupted_session(self):
        _, _, conn = self.make_server()
        old = conn.ldap_session
        old.rebind = MagicMock()
        old.unbind = MagicMock()
        old.close = MagicMock()
        replacement = SimpleNamespace(bound=True, search=MagicMock(return_value=True))
        conn.init_ldap_session = MagicMock(return_value=(conn.ldap_server, replacement))
        self.assertTrue(conn.reset_connection(fresh=True))
        old.rebind.assert_not_called()
        old.unbind.assert_not_called()
        old.close.assert_called_once()
        self.assertIs(conn.ldap_session, replacement)

    def test_replacement_session_reinstalls_custom_paging_and_cache(self):
        _, _, conn = self.make_server()
        conn.ldap_server = Server('dc.example.test', get_info=OFFLINE_AD_2012_R2)
        conn.ldap_session = Connection(conn.ldap_server)
        conn.who_am_i = MagicMock(return_value='EXAMPLE\\tester')
        view = PowerView.__new__(PowerView)
        view.conn = conn
        view.args = Namespace(obfuscate=False, no_cache=False, no_vuln_check=True, use_adws=False, raw=False)
        view.ldap_server = conn.ldap_server
        view.ldap_session = conn.ldap_session
        view._initialize_attributes_from_connection()
        original = view.custom_paged_search.standard
        query = ('DC=example,DC=test', '(objectClass=domain)')
        rows = [{'type': 'searchResEntry', 'attributes': {'name': 'example'}}]
        with patch('powerview.lib.ldap3.extend.paged_search_generator', return_value=iter(rows)):
            original.paged_search(*query)
        conn.ldap_session = Connection(conn.ldap_server)
        self.assertIs(view.ldap_session, conn.ldap_session)
        operations = view.custom_paged_search.standard
        self.assertIs(operations._connection, conn.ldap_session)
        self.assertIs(conn.ldap_session.extend.standard.paged_search.__self__, operations)
        self.assertEqual(operations.cache_namespace, original.cache_namespace)
        self.assertIs(operations.cache, original.cache)
        self.assertTrue(operations.no_vuln_check)
        with patch('powerview.lib.ldap3.extend.paged_search_generator') as search:
            self.assertTrue(operations.paged_search(*query)[0]['from_cache'])
            search.assert_not_called()

    def test_foreign_operation_marks_only_its_own_connection(self):
        _, _, primary = self.make_server()
        _, _, foreign = self.make_server()
        with self.assertRaises(KeyboardInterrupt) as raised:
            with session_lock(primary):
                with session_lock(foreign.ldap_session):
                    raise KeyboardInterrupt()
        self.assertTrue(session_lock(foreign).interrupted)
        self.assertFalse(session_lock(primary).interrupted)
        self.assertIs(raised.exception.session_lock, session_lock(foreign))

    def test_interrupted_relay_never_unbinds_or_reauthenticates(self):
        _, _, conn = self.make_server()
        session = conn.ldap_session
        session.unbind = MagicMock()
        conn._relayed_session = True
        conn.init_ldap_session = MagicMock()
        session_lock(conn).interrupted = True
        self.assertFalse(conn.reset_connection(fresh=True))
        self.assertFalse(conn.is_connection_alive())
        with self.assertRaisesRegex(ConnectionError, 'relay again'):
            _ = conn.ldap_session
        conn.init_ldap_session.assert_not_called()
        session.unbind.assert_not_called()

    def test_second_interrupt_defers_recovery_until_next_access(self):
        _, _, conn = self.make_server()
        lock = session_lock(conn)
        lock.interrupted = True
        replacement = SimpleNamespace(bound=True, search=MagicMock(return_value=True))
        conn.init_ldap_session = MagicMock(side_effect=[KeyboardInterrupt(), (conn.ldap_server, replacement)])
        error = KeyboardInterrupt()
        error.session_lock = lock
        self.assertFalse(recover_interrupted_session(error))
        self.assertTrue(lock.interrupted)
        self.assertFalse(lock.recovering)
        self.assertFalse(conn.is_connection_alive())
        self.assertIs(conn.ldap_session, replacement)
        self.assertFalse(lock.interrupted)

    def test_raw_search_marks_the_foreign_connection(self):
        class InterruptedSession:
            def search(self):
                raise KeyboardInterrupt()

        _, _, primary = self.make_server()
        _, _, foreign = self.make_server()
        foreign.ldap_session = InterruptedSession()
        with self.assertRaises(KeyboardInterrupt) as raised:
            with session_lock(primary):
                foreign.ldap_session.search()
        self.assertIs(raised.exception.session_lock.owner, foreign)
        self.assertFalse(session_lock(primary).interrupted)

    def test_flagged_connection_status_and_pool_checks_do_not_recover(self):
        server, _, conn = self.make_server()
        conn.reset_connection = MagicMock()
        session_lock(conn).interrupted = True
        pool = ConnectionPool(cleanup_interval=0, keepalive_interval=0)
        pool._pool['example.test'] = ConnectionPoolEntry(conn, 'example.test')
        try:
            self.assertEqual(self.request(server, '/api/connectioninfo')[1]['status'], 'KO')
            pool._perform_keepalive()
            pool._cleanup_expired_connections()
            self.assertEqual(pool.get_all_domains(), ['example.test'])
            conn.reset_connection.assert_not_called()
        finally:
            pool.shutdown()

    def test_prompt_never_retries_interrupted_recovery(self):
        _, pv, conn = self.make_server()
        pv.whoami = 'EXAMPLE\\tester'
        conn.who_am_i = MagicMock(side_effect=KeyboardInterrupt())
        session_lock(conn).interrupted = True
        for _ in range(3):
            self.assertIn('EXAMPLE\\tester', get_prompt(pv, args=Namespace(no_admin_check=True)))
        conn.who_am_i.assert_not_called()

    def test_fresh_reset_closes_ldap_transport_without_unbind(self):
        _, _, conn = self.make_server()
        original = Connection(Server('dc.example.test'))
        conn.ldap_session = original
        original.strategy.close = MagicMock()
        original.unbind = MagicMock(side_effect=RuntimeError('must not send'))
        replacement = SimpleNamespace(bound=True, search=MagicMock(return_value=True))
        conn.init_ldap_session = MagicMock(return_value=(conn.ldap_server, replacement))
        self.assertTrue(conn.reset_connection(fresh=True))
        original.strategy.close.assert_called_once()
        original.unbind.assert_not_called()

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
