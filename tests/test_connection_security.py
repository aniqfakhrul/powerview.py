import datetime
import hashlib
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import ldap3
from ldap3.core.exceptions import LDAPInvalidCredentialsResult, LDAPStrongerAuthRequiredResult

from powerview.utils.connections import CONNECTION, ConnectionSetupError, tls_channel_binding_token
from powerview.utils.parsers import arg_parse

TARGET = 'example.test/alice:secret@10.0.0.1'
CB_ERROR = 'AcceptSecurityContext error, data 80090346, v65f4'


def parse(*flags):
    with patch('sys.argv', ['powerview', TARGET, *flags]):
        return arg_parse()


def make_conn(use_ssl=True, **overrides):
    conn = CONNECTION.__new__(CONNECTION)
    conn.args = SimpleNamespace(ldap_timeout=30)
    conn.use_ldaps = use_ssl
    conn.use_ldap = not use_ssl
    conn.use_gc = False
    conn.use_gc_ldaps = False
    conn.port = None
    conn.hashes = None
    conn.no_pass = False
    conn.auth_method = ldap3.NTLM
    conn.channel_binding = True
    conn.sign_and_seal = True
    conn.channel_binding_supported = True
    conn.sign_and_seal_supported = True
    conn.channel_binding_active = False
    conn.sign_and_seal_active = False
    for key, value in overrides.items():
        setattr(conn, key, value)
    return conn


class ParserTests(unittest.TestCase):
    def test_channel_binding_and_sign_and_seal_are_on_by_default(self):
        args = parse()
        self.assertTrue(args.channel_binding)
        self.assertTrue(args.sign_and_seal)

    def test_no_flags_opt_out(self):
        args = parse('--no-channel-binding', '--no-sign-and-seal')
        self.assertFalse(args.channel_binding)
        self.assertFalse(args.sign_and_seal)

    def test_opt_outs_combine_with_auth_types(self):
        args = parse('--use-simple-auth', '--no-channel-binding', '--no-sign-and-seal')
        self.assertTrue(args.use_simple_auth)
        self.assertFalse(args.channel_binding)


class SecurityKwargsTests(unittest.TestCase):
    def test_ntlm_gets_channel_binding_over_tls_and_sealing_over_plain_ldap(self):
        conn = make_conn()
        self.assertEqual(conn._security_kwargs(True, ldap3.NTLM), {'channel_binding': ldap3.TLS_CHANNEL_BINDING})
        self.assertEqual(conn._security_kwargs(False, ldap3.NTLM), {'session_security': ldap3.ENCRYPT})

    def test_kerberos_gets_sealing_only_on_plain_ldap(self):
        conn = make_conn()
        self.assertEqual(conn._security_kwargs(True, ldap3.SASL, ldap3.KERBEROS), {})
        self.assertEqual(conn._security_kwargs(False, ldap3.SASL, ldap3.KERBEROS), {'session_security': ldap3.ENCRYPT})

    def test_simple_and_certificate_binds_get_nothing(self):
        conn = make_conn()
        for use_ssl in (True, False):
            self.assertEqual(conn._security_kwargs(use_ssl, ldap3.SIMPLE), {})
            self.assertEqual(conn._security_kwargs(use_ssl, ldap3.SASL, ldap3.EXTERNAL), {})

    def test_opt_outs_and_overrides(self):
        conn = make_conn(channel_binding=False, sign_and_seal=False)
        self.assertEqual(conn._security_kwargs(True, ldap3.NTLM), {})
        self.assertEqual(conn._security_kwargs(False, ldap3.NTLM), {})
        conn = make_conn()
        self.assertEqual(conn._security_kwargs(True, ldap3.NTLM, channel_binding=False), {})
        self.assertEqual(conn._security_kwargs(False, ldap3.NTLM, sign_and_seal=False), {})

    def test_unsupported_ldap3_disables_both(self):
        conn = make_conn(channel_binding_supported=False, sign_and_seal_supported=False)
        self.assertEqual(conn._security_kwargs(True, ldap3.NTLM), {})
        self.assertEqual(conn._security_kwargs(False, ldap3.NTLM), {})

    def test_bare_instances_default_to_secure(self):
        conn = CONNECTION.__new__(CONNECTION)
        conn.channel_binding_supported = True
        conn.sign_and_seal_supported = True
        self.assertIn('channel_binding', conn._security_kwargs(True, ldap3.NTLM))


class ChannelBindingTokenTests(unittest.TestCase):
    def make_cert(self, algorithm):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'dc.example.test')])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
                .sign(key, getattr(hashes, algorithm)()))
        return cert.public_bytes(serialization.Encoding.DER)

    def expected(self, der, hash_name):
        application_data = b'tls-server-end-point:' + hashlib.new(hash_name, der).digest()
        return hashlib.md5(b'\x00' * 16 + len(application_data).to_bytes(4, 'little') + application_data).digest()

    def test_uses_the_certificate_signature_hash(self):
        der = self.make_cert('SHA384')
        self.assertEqual(tls_channel_binding_token(der), self.expected(der, 'sha384'))

    def test_sha256_certificate(self):
        der = self.make_cert('SHA256')
        self.assertEqual(tls_channel_binding_token(der), self.expected(der, 'sha256'))

    def test_md5_and_sha1_certificates_are_upgraded_to_sha256(self):
        # cryptography no longer signs with SHA-1
        from cryptography.hazmat.primitives import hashes
        der = self.make_cert('SHA256')
        for algorithm in (hashes.SHA1(), hashes.MD5()):
            with patch('cryptography.x509.load_der_x509_certificate', return_value=SimpleNamespace(signature_hash_algorithm=algorithm)):
                self.assertEqual(tls_channel_binding_token(der), self.expected(der, 'sha256'))


class LdapsTlsTests(unittest.TestCase):
    def make_session_conn(self):
        conn = make_conn()
        conn.use_kerberos = False
        conn.do_certificate = False
        conn.relay = False
        conn.use_adws = False
        conn.username, conn.password, conn.lmhash, conn.nthash = 'alice', 'secret', '', ''
        conn.domain, conn.targetDomain, conn.kdcHost = 'example.test', None, None
        conn.ldap_address, conn.auth_aes_key = '10.0.0.1', None
        return conn

    def bound(self):
        server = MagicMock()
        server.info.other = {'defaultNamingContext': ['DC=example,DC=test']}
        return server, MagicMock()

    def test_first_attempt_negotiates_modern_tls(self):
        tls = CONNECTION._ldaps_tls()
        self.assertEqual(tls.version, ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(tls.validate, ssl.CERT_NONE)
        self.assertEqual(tls.ciphers, 'ALL:@SECLEVEL=0')

    def test_legacy_retry_is_tls10(self):
        tls = CONNECTION._ldaps_tls(legacy=True)
        self.assertEqual(tls.version, ssl.PROTOCOL_TLSv1)
        self.assertEqual(tls.ciphers, 'ALL:@SECLEVEL=0')

    def test_ntlm_and_simple_servers_use_the_given_tls(self):
        tls = CONNECTION._ldaps_tls()
        for auth_method in (ldap3.NTLM, ldap3.SIMPLE):
            with self.subTest(auth_method=auth_method):
                server = MagicMock(ssl=True)
                with patch.object(ldap3, 'Server', return_value=server) as server_type, \
                        patch.object(ldap3, 'Connection', side_effect=lambda s, **kw: FakeSession(kw)):
                    make_conn().init_ldap_connection('dc.example.test', tls, 'example.test', 'alice', 'secret', auth_method=auth_method)
                self.assertIs(server_type.call_args.kwargs['tls'], tls)

    def test_anonymous_server_uses_the_given_tls(self):
        tls = CONNECTION._ldaps_tls()
        conn = make_conn()
        with patch.object(ldap3, 'Server') as server_type, patch.object(ldap3, 'Connection') as connection_type:
            connection_type.return_value.bind.return_value = False
            with self.assertRaises(ConnectionSetupError):
                conn.init_ldap_anonymous('dc.example.test', tls)
        self.assertIs(server_type.call_args.kwargs['tls'], tls)

    def test_tls_handshake_failure_retries_with_legacy_tls10(self):
        conn = self.make_session_conn()
        conn.init_ldap_connection = MagicMock(side_effect=[ldap3.core.exceptions.LDAPSocketOpenError('handshake failed'), self.bound()])
        conn.init_ldap_session()
        first, retry = (call.args[1] for call in conn.init_ldap_connection.call_args_list)
        self.assertEqual(first.version, ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(retry.version, ssl.PROTOCOL_TLSv1)

    def test_falls_back_to_plain_ldap_when_both_tls_attempts_fail(self):
        conn = self.make_session_conn()
        failure = ldap3.core.exceptions.LDAPSocketOpenError('handshake failed')
        conn.init_ldap_connection = MagicMock(side_effect=[failure, failure, self.bound()])
        conn.init_ldap_session()
        self.assertIsNone(conn.init_ldap_connection.call_args_list[2].args[1])
        self.assertTrue(conn.use_ldap)
        self.assertFalse(conn.use_ldaps)


class FakeSession:
    def __init__(self, kwargs, error=None):
        self.kwargs = kwargs
        self.error = error
        self.session_security = kwargs.get('session_security')
        self.channel_binding = kwargs.get('channel_binding')
        self.result = {'message': CB_ERROR if error is LDAPInvalidCredentialsResult else '', 'description': 'error'}

    def bind(self):
        if self.error is LDAPInvalidCredentialsResult:
            raise LDAPInvalidCredentialsResult(result=49, description='invalidCredentials', message=CB_ERROR)
        if self.error is not None:
            raise self.error()
        return True


class InitLdapConnectionTests(unittest.TestCase):
    def bind(self, conn, errors, auth_method=ldap3.NTLM):
        calls = []
        errors = list(errors)

        def connection(server, **kwargs):
            calls.append(kwargs)
            return FakeSession(kwargs, errors.pop(0) if errors else None)

        server = MagicMock(ssl=conn.use_ldaps)
        with patch.object(ldap3, 'Server', return_value=server), patch.object(ldap3, 'Connection', side_effect=connection):
            conn.init_ldap_connection('dc.example.test', MagicMock() if conn.use_ldaps else None, 'example.test', 'alice', 'secret', auth_method=auth_method)
        return calls

    def test_ldaps_ntlm_sends_channel_binding(self):
        conn = make_conn()
        calls = self.bind(conn, [None])
        self.assertEqual(calls[0]['channel_binding'], ldap3.TLS_CHANNEL_BINDING)
        self.assertTrue(conn.channel_binding_active)
        self.assertFalse(conn.sign_and_seal_active)

    def test_ldap_ntlm_seals(self):
        conn = make_conn(use_ssl=False)
        calls = self.bind(conn, [None])
        self.assertEqual(calls[0]['session_security'], ldap3.ENCRYPT)
        self.assertNotIn('channel_binding', calls[0])
        self.assertTrue(conn.sign_and_seal_active)

    def test_rejected_channel_binding_token_retries_without_it(self):
        conn = make_conn()
        with self.assertLogs(level='WARNING'):
            calls = self.bind(conn, [LDAPInvalidCredentialsResult, None])
        self.assertIn('channel_binding', calls[0])
        self.assertNotIn('channel_binding', calls[1])
        self.assertFalse(conn.channel_binding_active)

    def test_token_rejected_on_enforcing_dc_does_not_blame_the_opt_out_flag(self):
        conn = make_conn()
        with self.assertLogs(level='WARNING'), self.assertRaises(ConnectionSetupError) as raised:
            self.bind(conn, [LDAPInvalidCredentialsResult, LDAPInvalidCredentialsResult])
        self.assertIn('rejected the channel binding token', str(raised.exception))
        self.assertNotIn('--no-channel-binding', str(raised.exception))

    def test_enforced_channel_binding_with_opt_out_explains_the_fix(self):
        conn = make_conn(channel_binding=False)
        with self.assertRaisesRegex(ConnectionSetupError, '--no-channel-binding'):
            self.bind(conn, [LDAPInvalidCredentialsResult])

    def test_enforced_signing_with_opt_out_explains_the_fix(self):
        conn = make_conn(use_ssl=False, sign_and_seal=False)
        with self.assertRaisesRegex(ConnectionSetupError, '--no-sign-and-seal'):
            self.bind(conn, [LDAPStrongerAuthRequiredResult])

    def test_simple_bind_on_signing_enforced_ldap(self):
        conn = make_conn(use_ssl=False)
        with self.assertLogs(level='WARNING'), self.assertRaisesRegex(ConnectionSetupError, 'SIMPLE'):
            self.bind(conn, [LDAPStrongerAuthRequiredResult], auth_method=ldap3.SIMPLE)


class KerberosFallbackTests(unittest.TestCase):
    def fallback(self, conn, use_ssl, side_effect):
        conn.impacket_ldap3_kerberos_login = MagicMock(side_effect=side_effect)
        result = conn._impacket_kerberos_fallback(MagicMock(), 'dc.example.test', 'alice', 'secret', 'example.test', '', '', '', None, use_ssl)
        return result, [c.kwargs['channel_binding'] for c in conn.impacket_ldap3_kerberos_login.call_args_list]

    def test_sends_channel_binding_over_tls(self):
        result, calls = self.fallback(make_conn(), True, [True])
        self.assertTrue(result)
        self.assertEqual(calls, [True])

    def test_rejected_token_retries_without_channel_binding(self):
        error = LDAPInvalidCredentialsResult(result=49, description='invalidCredentials', message=CB_ERROR)
        with self.assertLogs(level='WARNING'):
            result, calls = self.fallback(make_conn(), True, [error, False])
        self.assertFalse(result)
        self.assertEqual(calls, [True, False])

    def test_token_rejected_twice_reports_rejection(self):
        error = LDAPInvalidCredentialsResult(result=49, description='invalidCredentials', message=CB_ERROR)
        with self.assertLogs(level='WARNING'), self.assertRaisesRegex(ConnectionSetupError, 'rejected the channel binding token'):
            self.fallback(make_conn(), True, [error, error])

    def test_opt_out_on_enforcing_dc_explains_the_fix(self):
        error = LDAPInvalidCredentialsResult(result=49, description='invalidCredentials', message=CB_ERROR)
        with self.assertRaisesRegex(ConnectionSetupError, '--no-channel-binding'):
            self.fallback(make_conn(channel_binding=False), True, [error])

    def test_signing_enforced_on_plain_ldap(self):
        with self.assertRaisesRegex(ConnectionSetupError, 'cannot sign and seal'):
            self.fallback(make_conn(use_ssl=False), False, [LDAPStrongerAuthRequiredResult()])

    def test_warns_when_session_is_left_unsealed(self):
        with self.assertLogs(level='WARNING') as logs:
            self.fallback(make_conn(use_ssl=False), False, [False])
        self.assertIn('not encrypted', '\n'.join(logs.output))


class KerberosChannelBindingChecksumTests(unittest.TestCase):
    def test_authenticator_checksum_carries_the_channel_binding_token(self):
        from impacket.krb5 import constants
        from impacket.krb5.asn1 import AP_REQ, Authenticator, TGS_REP, seq_set
        from impacket.krb5.crypto import Key, _enctype_table
        from impacket.krb5.types import Principal
        from pyasn1.codec.der import decoder, encoder
        from powerview.lib.krb5.kerberosv5 import getKerberosType1

        cipher = _enctype_table[constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value]
        session_key = Key(cipher.enctype, b'K' * 32)
        tgs = TGS_REP()
        tgs['pvno'] = 5
        tgs['msg-type'] = int(constants.ApplicationTagNumbers.TGS_REP.value)
        tgs['crealm'] = 'EXAMPLE.TEST'
        seq_set(tgs, 'cname', Principal('alice', type=constants.PrincipalNameType.NT_PRINCIPAL.value).components_to_asn1)
        ticket = tgs['ticket']
        ticket['tkt-vno'] = 5
        ticket['realm'] = 'EXAMPLE.TEST'
        seq_set(ticket, 'sname', Principal('ldap/dc.example.test', type=constants.PrincipalNameType.NT_SRV_INST.value).components_to_asn1)
        ticket['enc-part']['etype'] = cipher.enctype
        ticket['enc-part']['cipher'] = b'opaque'
        tgs['enc-part']['etype'] = cipher.enctype
        tgs['enc-part']['cipher'] = b'opaque'

        token = b'\xab' * 16
        _, _, blob = getKerberosType1('alice', '', 'EXAMPLE.TEST', '', '', TGS={'KDC_REP': encoder.encode(tgs), 'cipher': cipher, 'sessionKey': session_key},
                                      targetName='dc.example.test', useCache=False, dce_style=False, targetService='ldap',
                                      mutual_auth=False, channel_binding_value=token)

        from impacket.spnego import SPNEGO_NegTokenInit
        ap_req = decoder.decode(SPNEGO_NegTokenInit(blob)['MechToken'], asn1Spec=AP_REQ())[0]
        plain = cipher.decrypt(session_key, 11, bytes(ap_req['authenticator']['cipher']))
        checksum = bytes(decoder.decode(plain, asn1Spec=Authenticator())[0]['cksum']['checksum'])
        self.assertEqual(checksum[4:20], token)
        self.assertEqual(int.from_bytes(checksum[20:24], 'little'), 0)


if __name__ == '__main__':
    unittest.main()
