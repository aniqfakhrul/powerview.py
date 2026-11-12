import os
import unittest
from datetime import datetime, timezone

from pyasn1.codec.der import encoder
from pyasn1.type.univ import noValue

from impacket.krb5 import constants
from impacket.krb5.asn1 import AP_REP, EncAPRepPart
from impacket.krb5.crypto import Key, _enctype_table
from impacket.krb5.gssapi import GSSAPI_RC4, KG_USAGE_ACCEPTOR_SEAL
from impacket.krb5.types import KerberosTime

from powerview.lib.krb5 import gss
from powerview.lib.krb5.gss import CfxContext, GSSError, Rc4Context, accept_ap_rep, frame_token, unframe_token

AES256 = constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value
RC4 = constants.EncryptionTypes.rc4_hmac.value


def acceptor_cfx_token(key, message, sequence, rotation=28, extra_count=0, acceptor_subkey=True):
    flags = CfxContext.SENT_BY_ACCEPTOR | CfxContext.SEALED | (CfxContext.ACCEPTOR_SUBKEY if acceptor_subkey else 0)
    header = lambda rrc: CfxContext.HEADER.pack(CfxContext.TOKEN_ID, flags, 0xff, extra_count, rrc, sequence)
    sealed = _enctype_table[key.enctype].encrypt(key, KG_USAGE_ACCEPTOR_SEAL, message + b'\xff' * extra_count + header(0), None)
    rrc = rotation % len(sealed)
    return header(rotation) + (sealed[-rrc:] + sealed[:-rrc] if rrc else sealed)


class AcceptorRc4(Rc4Context):
    INITIATOR_DIRECTION, ACCEPTOR_DIRECTION = Rc4Context.ACCEPTOR_DIRECTION, Rc4Context.INITIATOR_DIRECTION


class TokenFramingTests(unittest.TestCase):
    def test_round_trips_short_and_long_lengths(self):
        for size in (0, 100, 200, 70000):
            inner = os.urandom(size)
            self.assertEqual(unframe_token(frame_token(inner)), inner)

    def test_rejects_truncated_or_foreign_tokens(self):
        token = frame_token(b'payload')
        for bad in (b'', token[:-1], b'\x30' + token[1:]):
            with self.assertRaises(GSSError):
                unframe_token(bad)

    def test_rejects_trailing_and_noncanonical_length_encodings(self):
        token = frame_token(b'payload')
        body = token[2:]
        malformed = (token + b'trailing', b'\x60\x80' + body + b'\x00\x00',
                     b'\x60\x81' + bytes([len(body)]) + body,
                     b'\x60\x82\x00' + bytes([len(body)]) + body,
                     b'\x60\x82\x01')
        for bad in malformed:
            with self.subTest(token=bad), self.assertRaises(GSSError):
                unframe_token(bad)


class CfxContextTests(unittest.TestCase):
    key = Key(AES256, b'K' * 32)

    def test_wrap_matches_rfc4121_layout(self):
        token = CfxContext(self.key, 7, 0, acceptor_subkey=True).wrap(b'hello').message
        token_id, flags, filler, extra_count, rotation, sequence = CfxContext.HEADER.unpack(token[:16])
        self.assertEqual((token_id, flags, filler, extra_count, rotation, sequence), (b'\x05\x04', 0x06, 0xff, 0, 28, 7))

    def test_unwraps_acceptor_tokens_in_sequence(self):
        context = CfxContext(self.key, 0, 41, acceptor_subkey=True)
        self.assertEqual(context.unwrap(acceptor_cfx_token(self.key, b'first', 41)).message, b'first')
        self.assertEqual(context.unwrap(acceptor_cfx_token(self.key, b'second', 42, rotation=0, extra_count=5)).message, b'second')

    def test_rejects_tampered_replayed_and_reflected_tokens(self):
        token = acceptor_cfx_token(self.key, b'message', 0)
        context = CfxContext(self.key, 0, 0, acceptor_subkey=True)
        with self.assertRaisesRegex(GSSError, 'Integrity'):
            context.unwrap(token[:-1] + bytes([token[-1] ^ 1]))
        context.unwrap(token)
        with self.assertRaisesRegex(GSSError, 'Out of sequence'):
            context.unwrap(token)
        with self.assertRaisesRegex(GSSError, 'flags'):
            context.unwrap(CfxContext(self.key, 1, 0, acceptor_subkey=True).wrap(b'mine').message)

    def test_wrap_size_limit_accounts_for_overhead(self):
        context = CfxContext(self.key, 0, 0)
        self.assertEqual(len(context.wrap(b'x' * context.get_wrap_size_limit(1000)).message), 1000)


class Rc4ContextTests(unittest.TestCase):
    key = Key(RC4, b'R' * 16)

    def test_impacket_reads_our_tokens(self):
        message = os.urandom(300)
        plain, _ = GSSAPI_RC4().GSS_Unwrap_LDAP(self.key, Rc4Context(self.key, 0, 0).wrap(message).message, 0)
        self.assertEqual(plain, message)

    def test_unwraps_acceptor_tokens_and_checks_sequence(self):
        context = Rc4Context(self.key, 0, 3)
        acceptor = AcceptorRc4(self.key, 3, 0)
        self.assertEqual(context.unwrap(acceptor.wrap(b'reply').message).message, b'reply')
        with self.assertRaisesRegex(GSSError, 'Out of sequence'):
            context.unwrap(AcceptorRc4(self.key, 9, 0).wrap(b'reply').message)

    def test_rejects_tampered_and_reflected_tokens(self):
        token = AcceptorRc4(self.key, 0, 0).wrap(b'reply').message
        with self.assertRaisesRegex(GSSError, 'Integrity'):
            Rc4Context(self.key, 0, 0).unwrap(token[:-2] + bytes([token[-2] ^ 1]) + token[-1:])
        with self.assertRaisesRegex(GSSError, 'acceptor'):
            Rc4Context(self.key, 0, 0).unwrap(Rc4Context(self.key, 0, 0).wrap(b'mine').message)


class AcceptApRepTests(unittest.TestCase):
    session_key = Key(AES256, b'S' * 32)
    cipher = _enctype_table[AES256]
    authenticator_time = datetime(2026, 10, 18, 12, 34, 56, 123456, tzinfo=timezone.utc)

    def ap_rep(self, subkey=None, sequence=None, authenticator_time=None):
        timestamp = authenticator_time or self.authenticator_time
        enc_part = EncAPRepPart()
        enc_part['ctime'] = KerberosTime.to_asn1(timestamp)
        enc_part['cusec'] = timestamp.microsecond
        if subkey is not None:
            enc_part['subkey'] = noValue
            enc_part['subkey']['keytype'] = subkey.enctype
            enc_part['subkey']['keyvalue'] = subkey.contents
        if sequence is not None:
            enc_part['seq-number'] = sequence
        ap_rep = AP_REP()
        ap_rep['pvno'] = 5
        ap_rep['msg-type'] = constants.ApplicationTagNumbers.AP_REP.value
        ap_rep['enc-part'] = noValue
        ap_rep['enc-part']['etype'] = AES256
        ap_rep['enc-part']['cipher'] = self.cipher.encrypt(self.session_key, gss.AP_REP_KEY_USAGE, encoder.encode(enc_part), None)
        return frame_token(gss.KRB5_AP_REP + encoder.encode(ap_rep))

    def test_uses_acceptor_subkey_and_sequence(self):
        subkey = Key(AES256, b'A' * 32)
        context = accept_ap_rep(self.ap_rep(subkey, 1234), self.cipher, self.session_key, self.authenticator_time)
        self.assertIsInstance(context, CfxContext)
        self.assertEqual(context.unwrap(acceptor_cfx_token(subkey, b'ok', 1234)).message, b'ok')

    def test_falls_back_to_session_key_without_subkey(self):
        context = accept_ap_rep(self.ap_rep(), self.cipher, self.session_key, self.authenticator_time)
        self.assertEqual(context.unwrap(acceptor_cfx_token(self.session_key, b'ok', 0, acceptor_subkey=False)).message, b'ok')

    def test_rejects_ap_rep_under_the_wrong_key(self):
        with self.assertRaisesRegex(GSSError, 'integrity'):
            accept_ap_rep(self.ap_rep(), self.cipher, Key(AES256, b'X' * 32), self.authenticator_time)

    def test_rejects_unexpected_token_ids(self):
        with self.assertRaisesRegex(GSSError, 'AP-REP'):
            accept_ap_rep(frame_token(b'\x01\x00' + b'\x00' * 8), self.cipher, self.session_key, self.authenticator_time)

    def test_rejects_a_reply_for_a_different_authenticator(self):
        for timestamp in (self.authenticator_time.replace(second=57),
                          self.authenticator_time.replace(microsecond=123457)):
            with self.subTest(timestamp=timestamp), self.assertRaisesRegex(GSSError, 'authenticator'):
                accept_ap_rep(self.ap_rep(authenticator_time=timestamp), self.cipher, self.session_key,
                              self.authenticator_time)


if __name__ == '__main__':
    unittest.main()
