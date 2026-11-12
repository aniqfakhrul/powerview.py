import io
import struct
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ldap3
from ldap3.operation.abandon import abandon_operation
from ldap3.protocol.rfc4511 import LDAPMessage
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import KG_USAGE_ACCEPTOR_SEAL
from pyasn1.codec.ber.encoder import encode

from powerview.lib.krb5.gss import CfxContext, GSSError
from powerview.lib.ldap3.sasl import SaslSocket, install_ldap_protection


def server_frame(message, sequence=0):
    header = struct.pack('>2sBBHHQ', b'\x05\x04', 7, 255, 0, 0, sequence)
    sealed = _enctype_table[18].encrypt(Key(18, b'K' * 32), KG_USAGE_ACCEPTOR_SEAL,
                                      message + header, None)
    token = header + sealed
    return struct.pack('>I', len(token)) + token


class FragmentedSocket:
    def __init__(self, data, fragment=2):
        self.stream = io.BytesIO(data)
        self.fragment = fragment
        self.closed = False

    def recv(self, size):
        return self.stream.read(min(size, self.fragment))

    def close(self):
        self.closed = True

    def shutdown(self, how):
        pass


class SaslTransportTests(unittest.TestCase):
    def session(self, transport):
        session = ldap3.Connection(ldap3.Server('offline.invalid'), authentication=ldap3.SASL,
                                   sasl_mechanism=ldap3.KERBEROS, session_security=ldap3.ENCRYPT)
        session.socket = transport
        session.closed = False
        session.bound = True
        context = CfxContext(Key(18, b'K' * 32), 0, 0, True)
        install_ldap_protection(session, context, 1024)
        return session

    def test_protection_is_independent_of_ldap3_platform_backend(self):
        import ldap3.strategy.base as base
        for windows_backend in (False, True):
            with self.subTest(windows_backend=windows_backend):
                transport = MagicMock()
                session = self.session(transport)
                session.krb_ctx.wrap = MagicMock(wraps=session.krb_ctx.wrap)
                native = SimpleNamespace(authGSSClientWrap=MagicMock(), authGSSClientResponse=MagicMock())
                message = LDAPMessage()
                message['messageID'] = 1
                message['protocolOp']['abandonRequest'] = abandon_operation(1)
                with patch.object(base, 'posix_gssapi_unavailable', windows_backend), \
                     patch.dict('sys.modules', {'winkerberos': native}):
                    session.strategy.sending(message)
                session.krb_ctx.wrap.assert_called_once()
                native.authGSSClientWrap.assert_not_called()
                frame = transport.sendall.call_args.args[0]
                self.assertEqual(int.from_bytes(frame[:4], 'big'), len(frame) - 4)

    def test_fragmented_and_consecutive_frames_preserve_partial_reads(self):
        session = self.session(FragmentedSocket(server_frame(b'hello') + server_frame(b'world', 1)))
        self.assertEqual(session.socket.recv(0), b'')
        self.assertEqual(session.socket.recv(2), b'he')
        self.assertEqual(session.socket.recv(20), b'llo')
        self.assertEqual(session.socket.recv(20), b'world')

    def test_receiving_is_independent_of_ldap3_platform_backend(self):
        import ldap3.strategy.sync as sync
        message = LDAPMessage()
        message['messageID'] = 1
        message['protocolOp']['abandonRequest'] = abandon_operation(1)
        encoded = encode(message)
        for windows_backend in (False, True):
            with self.subTest(windows_backend=windows_backend):
                session = self.session(FragmentedSocket(server_frame(encoded)))
                native = SimpleNamespace(authGSSClientUnwrap=MagicMock())
                with patch.object(sync, 'posix_gssapi_unavailable', windows_backend), \
                     patch.dict('sys.modules', {'winkerberos': native}):
                    self.assertEqual(session.strategy.receiving(), [encoded])
                native.authGSSClientUnwrap.assert_not_called()

    def test_integrity_errors_and_incomplete_frames_close_the_session(self):
        frame = server_frame(b'reply')
        changed = frame[:-1] + bytes([frame[-1] ^ 1])
        for data, exception in ((changed, GSSError), (frame[:2], ConnectionError),
                                (frame[:-1], ConnectionError), (b'\x00' * 4, GSSError)):
            with self.subTest(length=len(data)):
                raw = FragmentedSocket(data)
                session = self.session(raw)
                with self.assertRaises(exception):
                    session.socket.recv(100)
                self.assertTrue(raw.closed)
                self.assertFalse(session.bound)
                self.assertTrue(session.closed)

    def test_outgoing_messages_are_split_to_the_wrap_limit(self):
        raw = MagicMock()
        session = self.session(raw)
        maximum = session.krb_ctx.get_wrap_size_limit(1024 - 4)
        session.socket.sendall(b'x' * (maximum * 2 + 1))
        frames = [call.args[0] for call in raw.sendall.call_args_list]
        self.assertEqual(len(frames), 3)
        self.assertTrue(all(len(frame) <= 1024 for frame in frames))

    def test_sasl_rebinding_requires_a_fresh_transport(self):
        session = self.session(MagicMock())
        session.sasl_in_progress = True
        with self.assertRaisesRegex(GSSError, 'fresh connection'):
            session.socket.sendall(b'new bind')
        self.assertFalse(session.bound)


if __name__ == '__main__':
    unittest.main()
