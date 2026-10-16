import io
import socket
import struct
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

from Cryptodome.Cipher import ARC4
from impacket import ntlm
from ldap3.core.exceptions import LDAPSignatureVerificationFailedError, LDAPSocketReceiveError, LDAPSocketSendError

from powerview.lib.adws.core.connection import Connection
from powerview.lib.adws import ACCOUNT_MANAGEMENT, ENUMERATION
from powerview.lib.adws.nns import NNS
from powerview.utils.session import share_session_lock, session_lock


class FragmentedSocket:
    def __init__(self, data, chunk_size=2):
        self.data = io.BytesIO(data)
        self.chunk_size = chunk_size

    def recv(self, size):
        return self.data.read(min(size, self.chunk_size))


class ADWSTransportTests(unittest.TestCase):
    flags = 0xe2888235
    key = b'K' * 16

    def connection(self, **kwargs):
        return Connection(SimpleNamespace(host='dc.test', port=9389, resource='Enumeration'),
                          'alice', 'secret', 'example.test', '', '', **kwargs)

    def receiver(self, frames):
        receiver = NNS.__new__(NNS)
        receiver._sock = FragmentedSocket(frames)
        receiver._auth_type = 'ntlm'
        receiver._flags = self.flags
        receiver._sequence = 0
        receiver._server_signing_key = ntlm.SIGNKEY(self.flags, self.key, 'Server')
        receiver._server_sealing_handle = ARC4.new(ntlm.SEALKEY(self.flags, self.key, 'Server')).encrypt
        return receiver

    def frames(self, messages):
        handle = ARC4.new(ntlm.SEALKEY(self.flags, self.key, 'Server')).encrypt
        output = bytearray()
        for sequence, message in enumerate(messages):
            encrypted, signature = ntlm.SEAL(self.flags, ntlm.SIGNKEY(self.flags, self.key, 'Server'), None,
                                              message, message, sequence, handle)
            frame = signature.getData() + encrypted
            output.extend(struct.pack('<I', len(frame)) + frame)
        return bytes(output)

    def test_fragmented_headers_and_consecutive_frames(self):
        messages = (b'first response', b'second response')
        receiver = self.receiver(self.frames(messages))
        for message in messages:
            self.assertEqual(receiver._recv(), message)

    def test_eof_in_header_or_payload_raises(self):
        frame = self.frames([b'response'])
        for truncated in (b'', frame[:2], frame[:-1]):
            with self.subTest(length=len(truncated)), self.assertRaises(ConnectionError):
                self.receiver(truncated)._recv()

    def test_tampered_signature_and_ciphertext_are_rejected(self):
        frame = self.frames([b'response'])
        for offset in (8, -1):
            damaged = bytearray(frame)
            damaged[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(LDAPSignatureVerificationFailedError):
                self.receiver(bytes(damaged))._recv()

    def test_envelope_can_span_multiple_sealed_frames(self):
        receiver = self.receiver(self.frames([b'\x06\x08part', b'ial!']))
        self.assertEqual(receiver.recv(), b'\x06\x08partial!')

    def test_handshake_reads_fragmented_payload(self):
        receiver = self.receiver(b'\x16\x01\x00\x00\x05token')
        self.assertEqual(receiver._recv_handshake()['payload'], b'token')

    def test_connect_sets_timeout_before_connecting(self):
        connection = self.connection(receive_timeout=7)
        with patch('powerview.lib.adws.core.connection.socket.socket') as transport, \
                patch.object(connection, '_create_NNS_from_auth'), \
                patch('powerview.lib.adws.core.connection.NMFConnection'):
            connection.connect()
        self.assertEqual(transport.return_value.method_calls[:2],
                         [call.settimeout(7), call.connect(('dc.test', 9389))])
        self.assertIs(connection.socket, transport.return_value)
        connection.unbind()

    def test_unbind_interrupts_a_blocked_socket_read(self):
        client, peer = socket.socketpair()
        entered, finished = threading.Event(), threading.Event()
        connection = self.connection()
        connection.socket = client
        connection.nmf = SimpleNamespace(_sock=client)
        connection.bound, connection.closed = True, False

        def read():
            entered.set()
            try:
                client.recv(1)
            except OSError:
                pass
            finally:
                finished.set()

        worker = threading.Thread(target=read, daemon=True)
        worker.start()
        try:
            self.assertTrue(entered.wait(1))
            connection.unbind()
            self.assertTrue(finished.wait(1))
            self.assertIsNone(connection.socket)
            self.assertIsNone(connection.nmf)
            self.assertFalse(connection.bound)
            self.assertTrue(connection.closed)
        finally:
            client.close()
            peer.close()
            worker.join(1)

    def test_endpoint_reconnect_preserves_transport_failures(self):
        connection = self.connection()
        with patch('powerview.lib.adws.core.connection.socket.socket') as transport:
            transport.return_value.connect.side_effect = TimeoutError('Proxy stalled')
            with self.assertRaises(TimeoutError):
                connection.reconnect('Resource')
        transport.return_value.close.assert_called_once()
        self.assertTrue(connection.closed)
        self.assertFalse(connection.bound)

    def bound_connection(self, error):
        client, peer = socket.socketpair()
        self.addCleanup(client.close)
        self.addCleanup(peer.close)

        def recv():
            raise error

        connection = self.connection()
        connection.socket = client
        connection.nmf = SimpleNamespace(_sock=client, send=lambda request: None, recv=recv)
        connection.bound, connection.closed = True, False
        connection.resource = ENUMERATION
        return connection

    def assertTornDown(self, connection):
        self.assertIsNone(connection.socket)
        self.assertIsNone(connection.nmf)
        self.assertFalse(connection.bound)
        self.assertFalse(connection.is_connection_alive())

    def test_timeout_tears_down_the_session_so_a_late_reply_is_never_read(self):
        connection = self.bound_connection(TimeoutError('timed out'))
        with self.assertRaises(LDAPSocketReceiveError) as raised:
            connection.send_and_recv('<request/>')
        self.assertIsInstance(raised.exception.__cause__, TimeoutError)
        self.assertTornDown(connection)
        with self.assertRaises(LDAPSocketSendError):
            connection.send_and_recv('<next request/>')

    def test_signature_failure_tears_down_the_session_and_keeps_its_error(self):
        connection = self.bound_connection(LDAPSignatureVerificationFailedError('tampered'))
        with self.assertRaises(LDAPSignatureVerificationFailedError):
            connection.send_and_recv('<request/>')
        self.assertTornDown(connection)

    def test_decode_failure_keeps_the_synchronized_session(self):
        connection = self.bound_connection(ValueError('unknown record'))
        with self.assertRaises(ValueError):
            connection.send_and_recv('<request/>')
        self.assertTrue(connection.bound)
        self.assertTrue(connection.is_connection_alive())

    def test_keepalive_failure_is_not_masked_by_restoring_the_timeout(self):
        connection = self.bound_connection(TimeoutError('timed out'))
        connection.socket.settimeout(30)
        with patch.object(connection, 'search', side_effect=lambda **_: connection.send_and_recv('<probe/>')), \
                self.assertRaises(LDAPSocketReceiveError):
            connection.keep_alive()
        self.assertTornDown(connection)

    def test_password_operations_share_the_session_lock(self):
        connection = self.connection()
        connection.resource = ACCOUNT_MANAGEMENT
        owner = SimpleNamespace()
        share_session_lock(owner, connection)

        def send(request):
            self.assertTrue(session_lock(owner)._is_owned())
            return '<response/>'

        with patch.object(connection, 'send_and_recv', side_effect=send), \
                patch('powerview.lib.adws.core.connection.password_response_to_dict', return_value={}):
            self.assertTrue(connection.set_password('CN=alice,DC=example,DC=test', 'new'))
            self.assertTrue(connection.change_password('CN=alice,DC=example,DC=test', 'old', 'new'))
