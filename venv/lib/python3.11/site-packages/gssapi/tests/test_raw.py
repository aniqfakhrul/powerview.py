import copy
import ctypes
import ctypes.util
import os
import socket
import sys
import unittest

import gssapi.raw as gb
import gssapi.raw.misc as gbmisc
import k5test.unit as ktu
import k5test as kt

from collections.abc import Set


TARGET_SERVICE_NAME = b'host'
FQDN = (
    'localhost' if sys.platform == 'darwin' else socket.getfqdn()
).encode('utf-8')
SERVICE_PRINCIPAL = TARGET_SERVICE_NAME + b'/' + FQDN

if sys.platform == 'darwin':
    TARGET_SERVICE_NAME += b"@" + FQDN


class _GSSAPIKerberosTestCase(kt.KerberosTestCase):
    @classmethod
    def setUpClass(cls):
        super(_GSSAPIKerberosTestCase, cls).setUpClass()
        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")

        cls.realm.kinit(svc_princ, flags=['-k'])

        cls._init_env()

        cls.USER_PRINC = cls.realm.user_princ.split('@')[0].encode("UTF-8")
        cls.ADMIN_PRINC = cls.realm.admin_princ.split('@')[0].encode("UTF-8")
        cls.KRB5_LIB_PATH = os.environ.get("GSSAPI_KRB5_MAIN_LIB", None)

    @classmethod
    def _init_env(cls):
        cls._saved_env = copy.deepcopy(os.environ)
        for k, v in cls.realm.env.items():
            os.environ[k] = v

    @classmethod
    def _restore_env(cls):
        for k in copy.deepcopy(os.environ):
            if k in cls._saved_env:
                os.environ[k] = cls._saved_env[k]
            else:
                del os.environ[k]

        cls._saved_env = None

    @classmethod
    def tearDownClass(cls):
        super(_GSSAPIKerberosTestCase, cls).tearDownClass()
        cls._restore_env()


class TestBaseUtilities(_GSSAPIKerberosTestCase):
    def setUp(self):
        self.realm.kinit(SERVICE_PRINCIPAL.decode("UTF-8"), flags=['-k'])

    def test_indicate_mechs(self):
        mechs = gb.indicate_mechs()
        self.assertIsInstance(mechs, set)
        self.assertIn(gb.MechType.kerberos, mechs)

    def test_import_name(self):
        imported_name = gb.import_name(TARGET_SERVICE_NAME)
        self.assertIsInstance(imported_name, gb.Name)

        gb.release_name(imported_name)

    def test_canonicalize_export_name(self):
        imported_name = gb.import_name(self.ADMIN_PRINC,
                                       gb.NameType.kerberos_principal)

        canonicalized_name = gb.canonicalize_name(imported_name,
                                                  gb.MechType.kerberos)
        self.assertIsInstance(canonicalized_name, gb.Name)

        exported_name = gb.export_name(canonicalized_name)
        self.assertIsInstance(exported_name, bytes)
        self.assertGreater(len(exported_name), 0)

    def test_duplicate_name(self):
        orig_name = gb.import_name(TARGET_SERVICE_NAME)
        new_name = gb.duplicate_name(orig_name)
        self.assertIsNotNone(new_name)
        self.assertTrue(gb.compare_name(orig_name, new_name))

    def test_display_name(self):
        imported_name = gb.import_name(TARGET_SERVICE_NAME,
                                       gb.NameType.hostbased_service)
        displ_resp = gb.display_name(imported_name)
        self.assertIsNotNone(displ_resp)

        displayed_name, out_type = displ_resp
        self.assertIsInstance(displayed_name, bytes)
        self.assertEqual(displayed_name, TARGET_SERVICE_NAME)
        self.assertEqual(out_type, gb.NameType.hostbased_service)

    # NB(directxman12): we don't test display_name_ext because the krb5 mech
    # doesn't actually implement it

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_provider_test(['mit'], 'Heimdal does not implemented for krb5')
    def test_inquire_name_not_mech_name(self):
        base_name = gb.import_name(TARGET_SERVICE_NAME,
                                   gb.NameType.hostbased_service)

        inquire_res = gb.inquire_name(base_name)
        self.assertIsNotNone(inquire_res)
        self.assertFalse(inquire_res.is_mech_name)
        self.assertIsNone(inquire_res.mech)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_provider_test(['mit'], 'Heimdal does not implemented for krb5')
    def test_inquire_name_mech_name(self):
        base_name = gb.import_name(TARGET_SERVICE_NAME,
                                   gb.NameType.hostbased_service)
        mech_name = gb.canonicalize_name(base_name, gb.MechType.kerberos)

        inquire_res = gb.inquire_name(mech_name)
        self.assertIsNotNone(inquire_res)
        self.assertTrue(inquire_res.is_mech_name)
        self.assertIsInstance(inquire_res.mech, gb.OID)
        self.assertEqual(inquire_res.mech, gb.MechType.kerberos)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.gssapi_extension_test('rfc6680_comp_oid',
                               'RFC 6680 (COMPOSITE_EXPORT OID)')
    def test_import_export_name_composite_no_attrs(self):
        base_name = gb.import_name(TARGET_SERVICE_NAME,
                                   gb.NameType.hostbased_service)
        canon_name = gb.canonicalize_name(base_name,
                                          gb.MechType.kerberos)

        exported_name = gb.export_name_composite(canon_name)
        self.assertIsInstance(exported_name, bytes)

        imported_name = gb.import_name(exported_name,
                                       gb.NameType.composite_export)
        self.assertIsInstance(imported_name, gb.Name)

    # NB(directxman12): the greet_client plugin only allows for one value

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_plugin_test('authdata', 'greet_client')
    def test_inquire_name_with_attrs(self):
        base_name = gb.import_name(TARGET_SERVICE_NAME,
                                   gb.NameType.hostbased_service)
        canon_name = gb.canonicalize_name(base_name, gb.MechType.kerberos)
        gb.set_name_attribute(canon_name, b'urn:greet:greeting',
                              [b'some greeting'])

        inquire_res = gb.inquire_name(canon_name)
        self.assertIsInstance(inquire_res.attrs, list)
        self.assertEqual(inquire_res.attrs, [b"urn:greet:greeting"])

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_plugin_test('authdata', 'greet_client')
    def test_basic_get_set_delete_name_attributes_no_auth(self):
        base_name = gb.import_name(TARGET_SERVICE_NAME,
                                   gb.NameType.hostbased_service)
        canon_name = gb.canonicalize_name(base_name, gb.MechType.kerberos)

        gb.set_name_attribute(canon_name, b'urn:greet:greeting',
                              [b'some other val'], complete=True)

        get_res = gb.get_name_attribute(canon_name, b'urn:greet:greeting')
        self.assertIsNotNone(get_res)
        self.assertIsInstance(get_res.values, list)
        self.assertEqual(get_res.values, [b"some other val"])
        self.assertIsInstance(get_res.display_values, list)
        self.assertEqual(get_res.display_values, get_res.values)
        self.assertTrue(get_res.complete)
        self.assertFalse(get_res.authenticated)

        gb.delete_name_attribute(canon_name, b'urn:greet:greeting')

        # NB(directxman12): the code below currently segfaults due to the way
        # that krb5 and the krb5 greet plugin is written
        # gb.get_name_attribute.should_raise(
        #     gb.exceptions.OperationUnavailableError, canon_name,
        #     'urn:greet:greeting')

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_plugin_test('authdata', 'greet_client')
    def test_import_export_name_composite(self):
        base_name = gb.import_name(TARGET_SERVICE_NAME,
                                   gb.NameType.hostbased_service)
        canon_name = gb.canonicalize_name(base_name, gb.MechType.kerberos)
        gb.set_name_attribute(canon_name, b'urn:greet:greeting', [b'some val'])

        exported_name = gb.export_name_composite(canon_name)
        self.assertIsInstance(exported_name, bytes)

        # TODO(directxman12): when you just import a token as composite,
        # appears as this name whose text is all garbled, since it contains
        # all of the attributes, etc, but doesn't properly have the attributes.
        # Once it's canonicalized, the attributes reappear.  However, if you
        # just import it as normal export, the attributes appear directly.
        # It is thus unclear as to what is going on

        # imported_name_raw = gb.import_name(exported_name,
        #                                    gb.NameType.composite_export)
        # imported_name = gb.canonicalize_name(imported_name_r,
        #                                      gb.MechType.kerberos)

        imported_name = gb.import_name(exported_name, gb.NameType.export)
        self.assertIsInstance(imported_name, gb.Name)

        get_res = gb.get_name_attribute(imported_name, b'urn:greet:greeting')
        self.assertEqual(get_res.values, [b"some val"])

    def test_compare_name(self):
        service_name1 = gb.import_name(TARGET_SERVICE_NAME)
        service_name2 = gb.import_name(TARGET_SERVICE_NAME)
        init_name = gb.import_name(self.ADMIN_PRINC,
                                   gb.NameType.kerberos_principal)

        self.assertTrue(gb.compare_name(service_name1, service_name2))
        self.assertTrue(gb.compare_name(service_name2, service_name1))
        self.assertFalse(gb.compare_name(service_name1, init_name))

        gb.release_name(service_name1)
        gb.release_name(service_name2)
        gb.release_name(init_name)

    def test_display_status(self):
        status_resp = gbmisc._display_status(0, False)
        self.assertIsNotNone(status_resp)

        status, ctx, cont = status_resp
        self.assertIsInstance(status, bytes)
        self.assertGreater(len(status), 0)
        self.assertIsInstance(ctx, int)
        self.assertIsInstance(cont, bool)
        self.assertFalse(cont)

    def test_acquire_creds(self):
        name = gb.import_name(SERVICE_PRINCIPAL,
                              gb.NameType.kerberos_principal)
        cred_resp = gb.acquire_cred(name)
        self.assertIsNotNone(cred_resp)

        creds, actual_mechs, ttl = cred_resp
        self.assertIsInstance(creds, gb.Creds)
        self.assertIn(gb.MechType.kerberos, actual_mechs)
        if sys.platform != 'darwin':
            self.assertIsInstance(ttl, int)

        gb.release_name(name)
        gb.release_cred(creds)

    @ktu.gssapi_extension_test('cred_imp_exp', 'credentials import-export')
    def test_cred_import_export(self):
        creds = gb.acquire_cred(None).creds
        token = gb.export_cred(creds)
        imported_creds = gb.import_cred(token)

        inquire_orig = gb.inquire_cred(creds, name=True)
        inquire_imp = gb.inquire_cred(imported_creds, name=True)
        self.assertTrue(gb.compare_name(inquire_orig.name, inquire_imp.name))

    def test_context_time(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token1,
                                            acceptor_creds=server_creds)
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=client_ctx,
                                           input_token=server_tok)
        ctx = client_resp2[0]

        ttl = gb.context_time(ctx)
        self.assertIsInstance(ttl, int)
        self.assertGreater(ttl, 0)

    def test_inquire_context(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token1,
                                            acceptor_creds=server_creds)
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=client_ctx,
                                           input_token=server_tok)
        ctx = client_resp2[0]

        inq_resp = gb.inquire_context(ctx)
        self.assertIsNotNone(inq_resp)

        src_name, target_name, ttl, mech_type, flags, local_est, is_open = \
            inq_resp
        self.assertIsInstance(src_name, gb.Name)
        self.assertIsInstance(target_name, gb.Name)
        self.assertIsInstance(ttl, int)
        self.assertEqual(mech_type, gb.MechType.kerberos)
        self.assertIsInstance(flags, Set)
        self.assertGreater(len(flags), 0)
        self.assertIsInstance(local_est, bool)
        self.assertTrue(local_est)
        self.assertIsInstance(is_open, bool)
        self.assertTrue(is_open)

    # NB(directxman12): We don't test `process_context_token` because
    #                   there is no clear non-deprecated way to test it

    @ktu.gssapi_extension_test('s4u', 'S4U')
    def test_add_cred_impersonate_name(self):
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)

        password = self.realm.password('user')
        self.realm.kinit(self.realm.user_princ, password=password,
                         flags=["-f"])
        name = gb.import_name(b"user", gb.NameType.kerberos_principal)
        client_creds = gb.acquire_cred(name, usage="initiate").creds
        cctx_res = gb.init_sec_context(
            server_name, creds=client_creds,
            flags=gb.RequirementFlag.delegate_to_peer)

        self.realm.kinit(SERVICE_PRINCIPAL.decode("utf-8"), flags=["-k"])
        server_creds = gb.acquire_cred(server_name, usage="both").creds
        sctx_res = gb.accept_sec_context(cctx_res.token, server_creds)
        self.assertTrue(gb.inquire_context(sctx_res.context).complete)

        input_creds = gb.Creds()
        imp_resp = gb.add_cred_impersonate_name(input_creds,
                                                sctx_res.delegated_creds,
                                                server_name,
                                                gb.MechType.kerberos)
        self.assertIsNotNone(imp_resp)
        self.assertIsInstance(imp_resp, gb.AddCredResult)
        self.assertIsInstance(imp_resp.creds, gb.Creds)
        self.assertIn(gb.MechType.kerberos, imp_resp.mechs)
        self.assertIsInstance(imp_resp.init_lifetime, int)
        self.assertGreater(imp_resp.init_lifetime, 0)
        self.assertIsInstance(imp_resp.accept_lifetime, int)
        self.assertEqual(imp_resp.accept_lifetime, 0)

    @ktu.gssapi_extension_test('s4u', 'S4U')
    def test_acquire_creds_impersonate_name(self):
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)

        password = self.realm.password('user')
        self.realm.kinit(self.realm.user_princ, password=password,
                         flags=["-f"])
        name = gb.import_name(b'user', gb.NameType.kerberos_principal)
        client_creds = gb.acquire_cred(name, usage="initiate").creds
        cctx_res = gb.init_sec_context(
            server_name, creds=client_creds,
            flags=gb.RequirementFlag.delegate_to_peer)

        self.realm.kinit(SERVICE_PRINCIPAL.decode("utf-8"), flags=["-k"])
        server_creds = gb.acquire_cred(server_name, usage='both').creds
        sctx_res = gb.accept_sec_context(cctx_res.token, server_creds)
        self.assertTrue(gb.inquire_context(sctx_res.context).complete)

        imp_resp = gb.acquire_cred_impersonate_name(sctx_res.delegated_creds,
                                                    server_name)
        self.assertIsInstance(imp_resp, gb.AcquireCredResult)
        self.assertIsInstance(imp_resp.creds, gb.Creds)
        self.assertIn(gb.MechType.kerberos, imp_resp.mechs)
        self.assertIsInstance(imp_resp.lifetime, int)
        self.assertGreater(imp_resp.lifetime, 0)

    @ktu.gssapi_extension_test('s4u', 'S4U')
    @ktu.krb_minversion_test('1.11',
                             'returning delegated S4U2Proxy credentials',
                             provider='mit')
    def test_always_get_delegated_creds(self):
        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")
        self.realm.kinit(svc_princ, flags=['-k', '-f'])

        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)

        client_token = gb.init_sec_context(target_name).token

        # if our acceptor creds have a usage of both, we get
        # s4u2proxy delegated credentials
        server_creds = gb.acquire_cred(None, usage='both').creds
        server_ctx_resp = gb.accept_sec_context(client_token,
                                                acceptor_creds=server_creds)
        self.assertIsNotNone(server_ctx_resp)
        self.assertIsInstance(server_ctx_resp.delegated_creds, gb.Creds)

    @ktu.gssapi_extension_test('rfc5588', 'RFC 5588')
    def test_store_cred_acquire_cred(self):
        # we need to acquire a forwardable ticket
        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")
        self.realm.kinit(svc_princ, flags=['-k', '-f'])

        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)

        client_creds = gb.acquire_cred(None, usage='initiate').creds
        client_ctx_resp = gb.init_sec_context(
            target_name, creds=client_creds,
            flags=gb.RequirementFlag.delegate_to_peer)

        client_token = client_ctx_resp[3]

        server_creds = gb.acquire_cred(None, usage='accept').creds
        server_ctx_resp = gb.accept_sec_context(client_token,
                                                acceptor_creds=server_creds)

        deleg_creds = server_ctx_resp.delegated_creds
        self.assertIsNotNone(deleg_creds)

        store_res = gb.store_cred(deleg_creds, usage='initiate',
                                  mech=gb.MechType.kerberos,
                                  set_default=True, overwrite=True)
        self.assertIsNotNone(store_res)

        if self.realm.provider.lower() != 'heimdal':
            # Heimdal does not return this info as expected
            self.assertEqual(store_res.usage, "initiate")
            self.assertIn(gb.MechType.kerberos, store_res.mechs)

        deleg_name = gb.inquire_cred(deleg_creds).name
        acq_resp = gb.acquire_cred(deleg_name, usage='initiate')
        self.assertIsNotNone(acq_resp)

    @ktu.gssapi_extension_test('cred_store', 'credentials store')
    def test_store_cred_into_acquire_cred(self):
        CCACHE = 'FILE:{tmpdir}/other_ccache'.format(tmpdir=self.realm.tmpdir)
        KT = '{tmpdir}/other_keytab'.format(tmpdir=self.realm.tmpdir)
        store = {b'ccache': CCACHE.encode('UTF-8'),
                 b'keytab': KT.encode('UTF-8')}

        princ_name = 'service/cs@' + self.realm.realm
        self.realm.addprinc(princ_name)
        self.realm.extract_keytab(princ_name, KT)
        self.realm.kinit(princ_name, None, ['-k', '-t', KT])

        initial_creds = gb.acquire_cred(None, usage='initiate').creds

        # NB(sross): overwrite because the ccache doesn't exist yet
        expected_usage = 'initiate'
        store_kwargs = {}
        if self.realm.provider.lower() == 'heimdal':
            expected_usage = 'both'
            store_kwargs['mech'] = gb.MechType.kerberos
            store_kwargs['usage'] = 'initiate'

        store_res = gb.store_cred_into(store, initial_creds, overwrite=True,
                                       **store_kwargs)
        self.assertIsNotNone(store_res.mechs)
        self.assertEqual(store_res.usage, expected_usage)

        name = gb.import_name(princ_name.encode('UTF-8'))
        retrieve_res = gb.acquire_cred_from(store, name)

        self.assertIsNotNone(retrieve_res)
        self.assertIsNotNone(retrieve_res.creds)
        self.assertIsInstance(retrieve_res.creds, gb.Creds)
        self.assertIn(gb.MechType.kerberos, retrieve_res.mechs)
        self.assertIsInstance(retrieve_res.lifetime, int)

    def test_add_cred(self):
        if sys.platform == 'darwin':
            self.skipTest('macOS fails to find the credential')

        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        client_ctx_resp = gb.init_sec_context(target_name)
        client_token = client_ctx_resp[3]
        del client_ctx_resp  # free all the things (except the token)!

        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name, usage='both')[0]
        server_ctx_resp = gb.accept_sec_context(client_token,
                                                acceptor_creds=server_creds)

        input_creds = gb.Creds()
        imp_resp = gb.add_cred(input_creds,
                               server_ctx_resp[1],
                               gb.MechType.kerberos)
        self.assertIsNotNone(imp_resp)

        new_creds, actual_mechs, output_init_ttl, output_accept_ttl = imp_resp
        self.assertIsInstance(new_creds, gb.Creds)
        self.assertIn(gb.MechType.kerberos, actual_mechs)
        self.assertIsInstance(output_init_ttl, int)
        self.assertIsInstance(output_accept_ttl, int)

    # NB(sross): we skip testing add_cred with mutate for the same reasons
    #            that testing add_cred in the high-level API is skipped

    def test_inquire_creds(self):
        name = gb.import_name(SERVICE_PRINCIPAL,
                              gb.NameType.kerberos_principal)
        cred = gb.acquire_cred(name).creds

        inq_resp = gb.inquire_cred(cred)
        self.assertIsNotNone(inq_resp)
        self.assertIsInstance(inq_resp.name, gb.Name)

        if self.realm.provider.lower() == 'heimdal':
            name = gb.import_name(self.realm.host_princ.encode('utf-8'),
                                  gb.NameType.kerberos_principal)

        self.assertTrue(gb.compare_name(name, inq_resp.name))

        if sys.platform == 'darwin':
            self.assertEqual(inq_resp.usage, "accept")
        else:
            self.assertIsInstance(inq_resp.lifetime, int)
            self.assertEqual(inq_resp.usage, "both")

        self.assertIn(gb.MechType.kerberos, inq_resp.mechs)

    def test_create_oid_from_bytes(self):
        kerberos_bytes = gb.MechType.kerberos.__bytes__()
        new_oid = gb.OID(elements=kerberos_bytes)

        self.assertEqual(new_oid, gb.MechType.kerberos)

        del new_oid  # make sure we can dealloc

    def test_error_dispatch(self):
        err_code1 = gb.ParameterReadError.CALLING_CODE
        err_code2 = gb.BadNameError.ROUTINE_CODE

        err = gb.GSSError(err_code1 | err_code2, 0)
        self.assertIsInstance(err, gb.NameReadError)
        self.assertEqual(err.maj_code, err_code1 | err_code2)

    def test_inquire_names_for_mech(self):
        res = gb.inquire_names_for_mech(gb.MechType.kerberos)
        self.assertIsNotNone(res)
        self.assertIn(gb.NameType.kerberos_principal, res)

    def test_inquire_mechs_for_name(self):
        name = gb.import_name(self.USER_PRINC,
                              gb.NameType.kerberos_principal)

        res = gb.inquire_mechs_for_name(name)
        self.assertIsNotNone(res)
        self.assertIn(gb.MechType.kerberos, res)

    @ktu.gssapi_extension_test('password', 'Password')
    def test_acquire_cred_with_password(self):
        password = self.realm.password('user')
        self.realm.kinit(self.realm.user_princ, password=password)

        name = gb.import_name(b'user', gb.NameType.kerberos_principal)

        imp_resp = gb.acquire_cred_with_password(name,
                                                 password.encode('UTF-8'))
        self.assertIsNotNone(imp_resp)

        imp_creds, actual_mechs, output_ttl = imp_resp
        self.assertIsNotNone(imp_creds)
        self.assertIsInstance(imp_creds, gb.Creds)
        if sys.platform == 'darwin':
            self.assertIn(gb.OID.from_int_seq('1.3.6.1.5.2.5'), actual_mechs)
        else:
            self.assertIn(gb.MechType.kerberos, actual_mechs)
            self.assertIsInstance(output_ttl, int)

    @ktu.gssapi_extension_test('password_add', 'Password (add)')
    def test_add_cred_with_password(self):
        password = self.realm.password('user')
        self.realm.kinit(self.realm.user_princ, password=password)

        name = gb.import_name(b'user', gb.NameType.kerberos_principal)

        input_creds = gb.Creds()
        imp_resp = gb.add_cred_with_password(input_creds, name,
                                             gb.MechType.kerberos,
                                             password.encode('UTF-8'))
        self.assertIsNotNone(imp_resp)

        new_creds, actual_mechs, output_init_ttl, output_accept_ttl = imp_resp
        self.assertIsInstance(new_creds, gb.Creds)
        self.assertIn(gb.MechType.kerberos, actual_mechs)
        self.assertIsInstance(output_init_ttl, int)
        self.assertIsInstance(output_accept_ttl, int)

    @ktu.gssapi_extension_test('rfc5587', 'RFC 5587')
    def test_rfc5587(self):
        if sys.platform == "darwin":
            self.skipTest("too many edge cases on macOS")

        mechs = gb.indicate_mechs_by_attrs(None, None, None)
        self.assertIsInstance(mechs, set)
        self.assertGreater(len(mechs), 0)

        # We're validating RFC 5587 here: by iterating over all mechanisms,
        # we can query their attributes and build a mapping of attr->{mechs}.
        # To test indicate_mechs_by_attrs, we can use this mapping and
        # ensure that, when the attribute is placed in a slot, we get the
        # expected result (e.g., attr in have --> mechs are present).
        attrs_dict = {}
        known_attrs_dict = {}

        for mech in mechs:
            self.assertIsInstance(mech, gb.OID)

            inquire_out = gb.inquire_attrs_for_mech(mech)
            mech_attrs = inquire_out.mech_attrs
            known_mech_attrs = inquire_out.known_mech_attrs

            self.assertIsInstance(mech_attrs, set)
            self.assertIsInstance(known_mech_attrs, set)

            # Verify that we get data for every available
            # attribute. Testing the contents of a few known
            # attributes is done in test_display_mech_attr().
            for mech_attr in mech_attrs:
                self.assertIsInstance(mech_attr, gb.OID)

                display_out = gb.display_mech_attr(mech_attr)
                self.assertIsInstance(display_out.name, bytes)
                self.assertIsInstance(display_out.short_desc, bytes)
                self.assertIsInstance(display_out.long_desc, bytes)

                if mech_attr not in attrs_dict:
                    attrs_dict[mech_attr] = set()
                attrs_dict[mech_attr].add(mech)

            for mech_attr in known_mech_attrs:
                self.assertIsInstance(mech_attr, gb.OID)

                display_out = gb.display_mech_attr(mech_attr)
                self.assertIsInstance(display_out.name, bytes)
                self.assertIsInstance(display_out.short_desc, bytes)
                self.assertIsInstance(display_out.long_desc, bytes)

                if mech_attr not in known_attrs_dict:
                    known_attrs_dict[mech_attr] = set()
                known_attrs_dict[mech_attr].add(mech)

        for attr, expected_mechs in attrs_dict.items():
            attrs = set([attr])

            mechs = gb.indicate_mechs_by_attrs(attrs, None, None)
            self.assertGreater(len(mechs), 0)
            self.assertEqual(mechs, expected_mechs)

            mechs = gb.indicate_mechs_by_attrs(None, attrs, None)
            for expected_mech in expected_mechs:
                self.assertNotIn(expected_mech, mechs)

        if self.realm.provider.lower() != 'heimdal':
            # Heimdal doesn't fully implement gss_indicate_mechs_by_attrs
            for attr, expected_mechs in known_attrs_dict.items():
                attrs = set([attr])

                mechs = gb.indicate_mechs_by_attrs(None, None, attrs)
                self.assertGreater(len(mechs), 0)
                self.assertEqual(mechs, expected_mechs)

    @ktu.gssapi_extension_test('rfc5587', 'RFC 5587')
    def test_display_mech_attr(self):
        test_attrs = [
            # oid, name, short_desc, long_desc
            # Taken from krb5/src/tests/gssapi/t_saslname
            [gb.OID.from_int_seq("1.3.6.1.5.5.13.24"),
                b"GSS_C_MA_CBINDINGS", b"channel-bindings",
                b"Mechanism supports channel bindings."],
            [gb.OID.from_int_seq("1.3.6.1.5.5.13.1"),
                b"GSS_C_MA_MECH_CONCRETE", b"concrete-mech",
                b"Mechanism is neither a pseudo-mechanism nor a composite "
                b"mechanism."]
        ]

        if self.realm.provider.lower() == 'heimdal':
            test_attrs[0][3] = b""
            test_attrs[1][3] = b"Indicates that a mech is neither a " \
                b"pseudo-mechanism nor a composite mechanism"

        for attr in test_attrs:
            display_out = gb.display_mech_attr(attr[0])
            self.assertEqual(display_out.name, attr[1])
            self.assertEqual(display_out.short_desc, attr[2])
            self.assertEqual(display_out.long_desc, attr[3])

    @ktu.gssapi_extension_test('rfc5801', 'SASL Names')
    def test_sasl_names(self):
        mechs = gb.indicate_mechs()

        for mech in mechs:
            out = gb.inquire_saslname_for_mech(mech)

            out_smn = out.sasl_mech_name
            if out_smn:
                self.assertIsInstance(out_smn, bytes)
                self.assertGreater(len(out_smn), 0)

            out_mn = out.mech_name
            self.assertIsInstance(out_mn, bytes)

            out_md = out.mech_description
            self.assertIsInstance(out_md, bytes)

            # Heimdal fails with Unknown mech-code on sanon
            if not (self.realm.provider.lower() == 'heimdal' and
                    mech.dotted_form == '1.3.6.1.4.1.5322.26.1.110'):
                cmp_mech = gb.inquire_mech_for_saslname(out_smn)
                self.assertIsNotNone(cmp_mech)

                # For some reason macOS sometimes returns this for mechs
                if not (sys.platform == 'darwin' and
                        cmp_mech.dotted_form == '1.2.752.43.14.2'):
                    self.assertEqual(cmp_mech, mech)

    @ktu.gssapi_extension_test('rfc4178', 'Negotiation Mechanism')
    def test_set_neg_mechs(self):
        all_mechs = gb.indicate_mechs()
        spnego_mech = gb.OID.from_int_seq("1.3.6.1.5.5.2")
        krb5_mech = gb.OID.from_int_seq("1.2.840.113554.1.2.2")
        ntlm_mech = gb.OID.from_int_seq("1.3.6.1.4.1.311.2.2.10")

        server_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)

        username = gb.import_name(name=b"user",
                                  name_type=gb.NameType.user)
        krb5_client_creds = gb.acquire_cred(
                                None, usage='initiate',
                                mechs=[krb5_mech, spnego_mech]).creds
        try:
            ntlm_client_creds = gb.acquire_cred_with_password(
                                name=username,
                                password=b'password',
                                mechs=[ntlm_mech, spnego_mech]).creds
        except gb.GSSError:
            self.skipTest('You do not have the GSSAPI gss-ntlmssp mech '
                          'installed')

        server_creds = gb.acquire_cred(server_name, usage='accept',
                                       mechs=all_mechs).creds

        neg_resp = gb.set_neg_mechs(server_creds, [ntlm_mech])
        self.assertIsNone(neg_resp)

        client_ctx_resp = gb.init_sec_context(server_name,
                                              creds=ntlm_client_creds,
                                              mech=spnego_mech)
        client_token = client_ctx_resp.token

        server_ctx_resp = gb.accept_sec_context(client_token,
                                                acceptor_creds=server_creds)
        self.assertIsNotNone(server_ctx_resp)

        client_ctx_resp = gb.init_sec_context(server_name,
                                              creds=krb5_client_creds,
                                              mech=spnego_mech)
        client_token = client_ctx_resp.token

        self.assertRaises(gb.GSSError, gb.accept_sec_context, client_token,
                          acceptor_creds=server_creds)

        neg_resp = gb.set_neg_mechs(server_creds, [krb5_mech])
        self.assertIsNone(neg_resp)

        client_ctx_resp = gb.init_sec_context(server_name,
                                              creds=krb5_client_creds,
                                              mech=spnego_mech)
        client_token = client_ctx_resp.token

        server_ctx_resp = gb.accept_sec_context(client_token,
                                                acceptor_creds=server_creds)
        self.assertIsNotNone(server_ctx_resp)

        client_ctx_resp = gb.init_sec_context(server_name,
                                              creds=ntlm_client_creds,
                                              mech=spnego_mech)
        client_token = client_ctx_resp.token

        self.assertRaises(gb.GSSError, gb.accept_sec_context, client_token,
                          acceptor_creds=server_creds)

    @ktu.gssapi_extension_test('ggf', 'Global Grid Forum')
    @ktu.gssapi_extension_test('s4u', 'S4U')
    @ktu.krb_minversion_test('1.16',
                             'querying impersonator name of krb5 GSS '
                             'Credential using the '
                             'GSS_KRB5_GET_CRED_IMPERSONATOR OID',
                             provider='mit')
    def test_inquire_cred_by_oid_impersonator(self):
        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")
        self.realm.kinit(svc_princ, flags=['-k', '-f'])

        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)

        client_token = gb.init_sec_context(target_name).token

        # if our acceptor creds have a usage of both, we get
        # s4u2proxy delegated credentials
        server_creds = gb.acquire_cred(None, usage='both').creds
        server_ctx_resp = gb.accept_sec_context(client_token,
                                                acceptor_creds=server_creds)

        self.assertIsNotNone(server_ctx_resp)
        self.assertIsNotNone(server_ctx_resp.delegated_creds)
        self.assertIsInstance(server_ctx_resp.delegated_creds, gb.Creds)

        # GSS_KRB5_GET_CRED_IMPERSONATOR
        oid = gb.OID.from_int_seq("1.2.840.113554.1.2.2.5.14")
        info = gb.inquire_cred_by_oid(server_ctx_resp.delegated_creds, oid)

        self.assertIsInstance(info, list)
        self.assertGreater(len(info), 0)
        self.assertIsInstance(info[0], bytes)
        self.assertEqual(info[0], b"%s@%s" % (
            SERVICE_PRINCIPAL, self.realm.realm.encode('utf-8')))

    @ktu.gssapi_extension_test('ggf', 'Global Grid Forum')
    def test_inquire_sec_context_by_oid(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp1 = gb.init_sec_context(target_name)

        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(ctx_resp1[3],
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=ctx_resp1[0],
                                           input_token=server_tok)
        client_ctx = client_resp2[0]

        # GSS_C_INQ_SSPI_SESSION_KEY
        session_key_oid = gb.OID.from_int_seq("1.2.840.113554.1.2.2.5.5")

        client_key = gb.inquire_sec_context_by_oid(client_ctx, session_key_oid)
        server_key = gb.inquire_sec_context_by_oid(server_ctx, session_key_oid)

        self.assertIsInstance(client_key, list)
        self.assertGreater(len(client_key), 0)
        self.assertIsInstance(server_key, list)
        self.assertGreater(len(server_key), 0)
        self.assertCountEqual(client_key, server_key)

    @ktu.gssapi_extension_test('ggf', 'Global Grid Forum')
    def test_inquire_sec_context_by_oid_should_raise_error(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp1 = gb.init_sec_context(target_name)

        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(ctx_resp1[3],
                                            acceptor_creds=server_creds)

        client_resp2 = gb.init_sec_context(target_name,
                                           context=ctx_resp1[0],
                                           input_token=server_resp[3])
        client_ctx = client_resp2[0]

        invalid_oid = gb.OID.from_int_seq("1.2.3.4.5.6.7.8.9")
        self.assertRaises(gb.GSSError, gb.inquire_sec_context_by_oid,
                          client_ctx, invalid_oid)

    @ktu.gssapi_extension_test('ggf', 'Global Grid Forum')
    @ktu.gssapi_extension_test('password', 'Add Credential with Password')
    def test_set_sec_context_option(self):
        if sys.platform == 'darwin':
            self.skipTest("macOS NTLM does not implement this OID")

        ntlm_mech = gb.OID.from_int_seq("1.3.6.1.4.1.311.2.2.10")
        username = gb.import_name(name=b"user",
                                  name_type=gb.NameType.user)
        try:
            cred = gb.acquire_cred_with_password(name=username,
                                                 password=b"password",
                                                 mechs=[ntlm_mech])
        except gb.GSSError:
            self.skipTest('You do not have the GSSAPI gss-ntlmssp mech '
                          'installed')

        server = gb.import_name(name=b"server",
                                name_type=gb.NameType.hostbased_service)
        orig_context = gb.init_sec_context(server, creds=cred.creds,
                                           mech=ntlm_mech)[0]

        # GSS_NTLMSSP_RESET_CRYPTO_OID_STRING
        reset_mech = gb.OID.from_int_seq("1.3.6.1.4.1.7165.655.1.3")
        out_context = gb.set_sec_context_option(reset_mech,
                                                context=orig_context,
                                                value=b"\x00" * 4)
        self.assertIsInstance(out_context, gb.SecurityContext)

    @ktu.gssapi_extension_test('ggf', 'Global Grid Forum')
    @ktu.gssapi_extension_test('password', 'Add Credential with Password')
    def test_set_sec_context_option_fail(self):
        ntlm_mech = gb.OID.from_int_seq("1.3.6.1.4.1.311.2.2.10")
        username = gb.import_name(name=b"user",
                                  name_type=gb.NameType.user)
        try:
            cred = gb.acquire_cred_with_password(name=username,
                                                 password=b"password",
                                                 mechs=[ntlm_mech])
        except gb.GSSError:
            self.skipTest('You do not have the GSSAPI gss-ntlmssp mech '
                          'installed')

        server = gb.import_name(name=b"server",
                                name_type=gb.NameType.hostbased_service)
        context = gb.init_sec_context(server, creds=cred.creds,
                                      mech=ntlm_mech)[0]

        # GSS_NTLMSSP_RESET_CRYPTO_OID_STRING
        reset_mech = gb.OID.from_int_seq("1.3.6.1.4.1.7165.655.1.3")

        # will raise a GSSError if no data was passed in
        self.assertRaises(gb.GSSError, gb.set_sec_context_option, reset_mech,
                          context)

    @ktu.gssapi_extension_test('set_cred_opt', 'Kitten Set Credential Option')
    @ktu.krb_minversion_test('1.14',
                             'GSS_KRB5_CRED_NO_CI_FLAGS_X was added in MIT '
                             'krb5 1.14', provider='mit')
    def test_set_cred_option(self):
        name = gb.import_name(SERVICE_PRINCIPAL,
                              gb.NameType.kerberos_principal)
        # GSS_KRB5_CRED_NO_CI_FLAGS_X
        no_ci_flags_x = gb.OID.from_int_seq("1.2.752.43.13.29")
        orig_cred = gb.acquire_cred(name).creds

        # nothing much we can test here apart from it doesn't fail and the
        # id of the return cred is the same as the input one
        output_cred = gb.set_cred_option(no_ci_flags_x, creds=orig_cred)
        self.assertIsInstance(output_cred, gb.Creds)

    @ktu.gssapi_extension_test('set_cred_opt', 'Kitten Set Credential Option')
    def test_set_cred_option_should_raise_error(self):
        name = gb.import_name(SERVICE_PRINCIPAL,
                              gb.NameType.kerberos_principal)
        orig_cred = gb.acquire_cred(name).creds

        # this is a fake OID and shouldn't work at all
        invalid_oid = gb.OID.from_int_seq("1.2.3.4.5.6.7.8.9")
        self.assertRaises(gb.GSSError, gb.set_cred_option, invalid_oid,
                          orig_cred, b"\x00")

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    @ktu.krb_provider_test(['mit'], 'Cannot revert ccache on Heimdal')
    # https://github.com/heimdal/heimdal/issues/803
    def test_krb5_ccache_name(self):
        provider = self.realm.provider.lower()

        new_ccache = os.path.join(self.realm.tmpdir, 'ccache-new')
        new_env = self.realm.env.copy()
        new_env['KRB5CCNAME'] = new_ccache
        self.realm.kinit(self.realm.user_princ,
                         password=self.realm.password('user'),
                         env=new_env)

        old_ccache = gb.krb5_ccache_name(new_ccache.encode('utf-8'))
        try:
            if provider == 'heimdal':
                # Heimdal never returns the old name - see above link
                self.assertTrue(old_ccache is None)
            else:
                self.assertEqual(old_ccache.decode('utf-8'), self.realm.ccache)

            cred_resp = gb.acquire_cred(usage='initiate').creds

            princ_name = gb.inquire_cred(cred_resp, name=True).name
            name = gb.display_name(princ_name, name_type=False).name
            self.assertEqual(name, self.realm.user_princ.encode('utf-8'))

            if provider != 'heimdal':
                changed_ccache = gb.krb5_ccache_name(old_ccache)
                self.assertEqual(changed_ccache.decode('utf-8'), new_ccache)

        finally:
            # Ensure original behaviour is back for other tests
            gb.krb5_ccache_name(None)

        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        client_resp = gb.init_sec_context(target_name, creds=cred_resp)
        client_ctx = client_resp[0]
        client_token = client_resp[3]

        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token,
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_token = server_resp[3]

        gb.init_sec_context(target_name, context=client_ctx,
                            input_token=server_token)
        initiator = gb.inquire_context(server_ctx,
                                       initiator_name=True).initiator_name
        initiator_name = gb.display_name(initiator, name_type=False).name

        self.assertEqual(initiator_name, self.realm.user_princ.encode('utf-8'))

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    def test_krb5_export_lucid_sec_context(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token1,
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=client_ctx,
                                           input_token=server_tok)
        ctx = client_resp2[0]

        self.assertRaises(gb.GSSError, gb.krb5_export_lucid_sec_context,
                          ctx, 0)

        initiator_info = gb.krb5_export_lucid_sec_context(ctx, 1)
        self.assertTrue(isinstance(initiator_info, gb.Krb5LucidContextV1))
        self.assertEqual(initiator_info.version, 1)
        self.assertTrue(initiator_info.is_initiator)
        self.assertTrue(isinstance(initiator_info.endtime, int))
        self.assertTrue(isinstance(initiator_info.send_seq, int))
        self.assertTrue(isinstance(initiator_info.recv_seq, int))
        self.assertEqual(initiator_info.protocol, 1)
        self.assertEqual(initiator_info.rfc1964_kd, None)
        self.assertTrue(isinstance(initiator_info.cfx_kd, gb.CfxKeyData))
        self.assertTrue(isinstance(initiator_info.cfx_kd.ctx_key_type, int))
        self.assertTrue(isinstance(initiator_info.cfx_kd.ctx_key, bytes))
        self.assertTrue(isinstance(initiator_info.cfx_kd.acceptor_subkey_type,
                                   int))
        self.assertTrue(isinstance(initiator_info.cfx_kd.acceptor_subkey,
                                   bytes))

        acceptor_info = gb.krb5_export_lucid_sec_context(server_ctx, 1)
        self.assertTrue(isinstance(acceptor_info, gb.Krb5LucidContextV1))
        self.assertEqual(acceptor_info.version, 1)
        self.assertFalse(acceptor_info.is_initiator)
        self.assertTrue(isinstance(acceptor_info.endtime, int))
        self.assertTrue(isinstance(acceptor_info.send_seq, int))
        self.assertTrue(isinstance(acceptor_info.recv_seq, int))
        self.assertEqual(acceptor_info.protocol, 1)
        self.assertEqual(acceptor_info.rfc1964_kd, None)
        self.assertTrue(isinstance(acceptor_info.cfx_kd, gb.CfxKeyData))
        self.assertTrue(isinstance(acceptor_info.cfx_kd.ctx_key_type, int))
        self.assertTrue(isinstance(acceptor_info.cfx_kd.ctx_key, bytes))
        self.assertTrue(isinstance(acceptor_info.cfx_kd.acceptor_subkey_type,
                                   int))
        self.assertTrue(isinstance(acceptor_info.cfx_kd.acceptor_subkey,
                                   bytes))

        self.assertEqual(initiator_info.endtime, acceptor_info.endtime)
        self.assertEqual(initiator_info.send_seq, acceptor_info.recv_seq)
        self.assertEqual(initiator_info.recv_seq, acceptor_info.send_seq)
        self.assertEqual(initiator_info.cfx_kd.ctx_key_type,
                         acceptor_info.cfx_kd.ctx_key_type)
        self.assertEqual(initiator_info.cfx_kd.ctx_key,
                         acceptor_info.cfx_kd.ctx_key)
        self.assertEqual(initiator_info.cfx_kd.acceptor_subkey_type,
                         acceptor_info.cfx_kd.acceptor_subkey_type)
        self.assertEqual(initiator_info.cfx_kd.acceptor_subkey,
                         acceptor_info.cfx_kd.acceptor_subkey)

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    def test_krb5_extract_authtime_from_sec_context(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token1,
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=client_ctx,
                                           input_token=server_tok)
        ctx = client_resp2[0]

        if self.realm.provider.lower() == 'heimdal':
            # Heimdal doesn't store the ticket info on the initiator
            client_authtime = server_authtime = \
                gb.krb5_extract_authtime_from_sec_context(server_ctx)
            self.assertRaises(gb.GSSError,
                              gb.krb5_extract_authtime_from_sec_context,
                              client_ctx)
        else:
            client_authtime = gb.krb5_extract_authtime_from_sec_context(ctx)
            server_authtime = gb.krb5_extract_authtime_from_sec_context(
                server_ctx)

        self.assertTrue(isinstance(client_authtime, int))
        self.assertTrue(isinstance(server_authtime, int))
        self.assertEqual(client_authtime, server_authtime)

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    def test_krb5_extract_authz_data_from_sec_context(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        client_token = gb.init_sec_context(target_name)[3]

        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_ctx = gb.accept_sec_context(client_token,
                                           acceptor_creds=server_creds)[0]

        # KRB5_AUTHDATA_IF_RELEVANT = 1
        authz_data = gb.krb5_extract_authz_data_from_sec_context(server_ctx, 1)
        self.assertTrue(isinstance(authz_data, bytes))

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    def test_krb5_import_cred(self):
        # Ensuring we match the krb5 library to the GSSAPI library is a thorny
        # problem.  Avoid it by requiring test suite users to explicitly
        # enable this test.
        if not self.KRB5_LIB_PATH:
            self.skipTest("Env var GSSAPI_KRB5_MAIN_LIB not defined")

        creds = gb.Creds()

        # Should fail if only creds are specified
        self.assertRaises(ValueError, gb.krb5_import_cred, creds)

        new_ccache = os.path.join(self.realm.tmpdir, 'ccache-new')
        new_env = self.realm.env.copy()
        new_env['KRB5CCNAME'] = new_ccache
        self.realm.kinit(self.realm.user_princ,
                         password=self.realm.password('user'),
                         env=new_env)

        krb5 = ctypes.CDLL(self.KRB5_LIB_PATH)
        krb5_ctx = ctypes.c_void_p()
        krb5.krb5_init_context(ctypes.byref(krb5_ctx))
        try:
            ccache_ptr = ctypes.c_void_p()
            err = krb5.krb5_cc_resolve(krb5_ctx, new_ccache.encode('utf-8'),
                                       ctypes.byref(ccache_ptr))
            self.assertEqual(err, 0)

            try:
                gb.krb5_import_cred(creds, cache=ccache_ptr.value)

                # Creds will be invalid once the cc is closed so do this now
                target_name = gb.import_name(TARGET_SERVICE_NAME,
                                             gb.NameType.hostbased_service)
                client_resp = gb.init_sec_context(target_name, creds=creds)

            finally:
                krb5.krb5_cc_close(krb5_ctx, ccache_ptr)
        finally:
            krb5.krb5_free_context(krb5_ctx)

        client_ctx = client_resp[0]
        client_token = client_resp[3]

        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token,
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_token = server_resp[3]

        gb.init_sec_context(target_name, context=client_ctx,
                            input_token=server_token)
        initiator = gb.inquire_context(server_ctx,
                                       initiator_name=True).initiator_name
        initiator_name = gb.display_name(initiator, name_type=False).name

        self.assertEqual(initiator_name, self.realm.user_princ.encode('utf-8'))

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    def test_krb5_get_tkt_flags(self):
        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(target_name)

        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name)[0]
        server_resp = gb.accept_sec_context(client_token1,
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=client_ctx,
                                           input_token=server_tok)
        client_ctx = client_resp2[0]

        if self.realm.provider.lower() == 'heimdal':
            # Heimdal doesn't store the ticket info on the initiator
            client_flags = server_flags = gb.krb5_get_tkt_flags(server_ctx)
            self.assertRaises(gb.GSSError, gb.krb5_get_tkt_flags, client_ctx)
        else:
            client_flags = gb.krb5_get_tkt_flags(client_ctx)
            server_flags = gb.krb5_get_tkt_flags(server_ctx)

        self.assertTrue(isinstance(client_flags, int))
        self.assertTrue(isinstance(server_flags, int))
        self.assertEqual(client_flags, server_flags)

    @ktu.gssapi_extension_test('krb5', 'Kerberos Extensions')
    @ktu.krb_provider_test(['mit'], 'Cannot revert ccache on Heimdal')
    # https://github.com/heimdal/heimdal/issues/803
    def test_krb5_set_allowable_enctypes(self):
        krb5_mech = gb.OID.from_int_seq("1.2.840.113554.1.2.2")
        AES_128 = 0x11
        AES_256 = 0x12

        new_ccache = os.path.join(self.realm.tmpdir, 'ccache-new')
        new_env = self.realm.env.copy()
        new_env['KRB5CCNAME'] = new_ccache
        self.realm.kinit(self.realm.user_princ,
                         password=self.realm.password('user'),
                         env=new_env)

        gb.krb5_ccache_name(new_ccache.encode('utf-8'))
        try:
            creds = gb.acquire_cred(usage='initiate',
                                    mechs=[krb5_mech]).creds
        finally:
            gb.krb5_ccache_name(None)

        gb.krb5_set_allowable_enctypes(creds, [AES_128])

        target_name = gb.import_name(TARGET_SERVICE_NAME,
                                     gb.NameType.hostbased_service)
        server_name = gb.import_name(SERVICE_PRINCIPAL,
                                     gb.NameType.kerberos_principal)
        server_creds = gb.acquire_cred(server_name, usage='accept',
                                       mechs=[krb5_mech])[0]

        if self.realm.provider.lower() != 'heimdal':
            # Will fail because the client only offers AES128
            # Only seems to work on MIT and not Heimdal
            ctx_resp = gb.init_sec_context(target_name, creds=creds)
            client_token1 = ctx_resp[3]
            client_ctx = ctx_resp[0]
            gb.krb5_set_allowable_enctypes(server_creds, [AES_256])
            self.assertRaises(gb.GSSError, gb.accept_sec_context,
                              client_token1, acceptor_creds=server_creds)

            gb.krb5_set_allowable_enctypes(server_creds, [AES_128, AES_256])

        ctx_resp = gb.init_sec_context(target_name, creds=creds)
        client_token1 = ctx_resp[3]
        client_ctx = ctx_resp[0]

        server_resp = gb.accept_sec_context(client_token1,
                                            acceptor_creds=server_creds)
        server_ctx = server_resp[0]
        server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(target_name,
                                           context=client_ctx,
                                           input_token=server_tok)
        ctx = client_resp2[0]

        initiator_info = gb.krb5_export_lucid_sec_context(ctx, 1)
        acceptor_info = gb.krb5_export_lucid_sec_context(server_ctx, 1)
        self.assertEqual(AES_128, initiator_info.cfx_kd.ctx_key_type)
        self.assertEqual(initiator_info.cfx_kd.ctx_key_type,
                         initiator_info.cfx_kd.acceptor_subkey_type)
        self.assertEqual(acceptor_info.cfx_kd.ctx_key_type,
                         acceptor_info.cfx_kd.acceptor_subkey_type)


class TestIntEnumFlagSet(unittest.TestCase):
    def test_create_from_int(self):
        int_val = (gb.RequirementFlag.integrity |
                   gb.RequirementFlag.confidentiality)
        fset = gb.IntEnumFlagSet(gb.RequirementFlag, int_val)

        self.assertEqual(int(fset), int_val)

    def test_create_from_other_set(self):
        int_val = (gb.RequirementFlag.integrity |
                   gb.RequirementFlag.confidentiality)
        fset1 = gb.IntEnumFlagSet(gb.RequirementFlag, int_val)
        fset2 = gb.IntEnumFlagSet(gb.RequirementFlag, fset1)

        self.assertEqual(fset1, fset2)

    def test_create_from_list(self):
        lst = [gb.RequirementFlag.integrity,
               gb.RequirementFlag.confidentiality]
        fset = gb.IntEnumFlagSet(gb.RequirementFlag, lst)

        self.assertCountEqual(list(fset), lst)

    def test_create_empty(self):
        fset = gb.IntEnumFlagSet(gb.RequirementFlag)
        self.assertEqual(len(fset), 0)

    def _create_fset(self):
        lst = [gb.RequirementFlag.integrity,
               gb.RequirementFlag.confidentiality]
        return gb.IntEnumFlagSet(gb.RequirementFlag, lst)

    def test_contains(self):
        fset = self._create_fset()
        self.assertIn(gb.RequirementFlag.integrity, fset)
        self.assertNotIn(gb.RequirementFlag.protection_ready, fset)

    def test_len(self):
        self.assertEqual(len(self._create_fset()), 2)

    def test_add(self):
        fset = self._create_fset()
        self.assertEqual(len(fset), 2)

        fset.add(gb.RequirementFlag.protection_ready)
        self.assertEqual(len(fset), 3)
        self.assertIn(gb.RequirementFlag.protection_ready, fset)

    def test_discard(self):
        fset = self._create_fset()
        self.assertEqual(len(fset), 2)

        fset.discard(gb.RequirementFlag.protection_ready)
        self.assertEqual(len(fset), 2)

        fset.discard(gb.RequirementFlag.integrity)
        self.assertEqual(len(fset), 1)
        self.assertNotIn(gb.RequirementFlag.integrity, fset)

    def test_and_enum(self):
        fset = self._create_fset()
        self.assertTrue(fset & gb.RequirementFlag.integrity)
        self.assertFalse(fset & gb.RequirementFlag.protection_ready)

    def test_and_int(self):
        fset = self._create_fset()
        int_val = int(gb.RequirementFlag.integrity)

        self.assertEqual(fset & int_val, int_val)

    def test_and_set(self):
        fset1 = self._create_fset()
        fset2 = self._create_fset()
        fset3 = self._create_fset()

        fset1.add(gb.RequirementFlag.protection_ready)
        fset2.add(gb.RequirementFlag.out_of_sequence_detection)

        self.assertEqual(fset1 & fset2, fset3)

    def test_or_enum(self):
        fset1 = self._create_fset()
        fset2 = fset1 | gb.RequirementFlag.protection_ready

        self.assertLess(fset1, fset2)
        self.assertIn(gb.RequirementFlag.protection_ready, fset2)

    def test_or_int(self):
        fset = self._create_fset()
        int_val = int(gb.RequirementFlag.integrity)

        self.assertEqual(fset | int_val, int(fset))

    def test_or_set(self):
        fset1 = self._create_fset()
        fset2 = self._create_fset()
        fset3 = self._create_fset()

        fset1.add(gb.RequirementFlag.protection_ready)
        fset2.add(gb.RequirementFlag.out_of_sequence_detection)
        fset3.add(gb.RequirementFlag.protection_ready)
        fset3.add(gb.RequirementFlag.out_of_sequence_detection)

        self.assertEqual(fset1 | fset2, fset3)

    def test_xor_enum(self):
        fset1 = self._create_fset()

        fset2 = fset1 ^ gb.RequirementFlag.protection_ready
        fset3 = fset1 ^ gb.RequirementFlag.integrity

        self.assertEqual(len(fset2), 3)
        self.assertIn(gb.RequirementFlag.protection_ready, fset2)
        self.assertEqual(len(fset3), 1)
        self.assertNotIn(gb.RequirementFlag.integrity, fset3)

    def test_xor_int(self):
        fset = self._create_fset()

        self.assertEqual(fset ^ int(gb.RequirementFlag.protection_ready),
                         int(fset) ^ gb.RequirementFlag.protection_ready)

        self.assertEqual(fset ^ int(gb.RequirementFlag.integrity),
                         int(fset) ^ gb.RequirementFlag.integrity)

    def test_xor_set(self):
        fset1 = self._create_fset()
        fset2 = self._create_fset()

        fset1.add(gb.RequirementFlag.protection_ready)
        fset2.add(gb.RequirementFlag.out_of_sequence_detection)

        fset3 = fset1 ^ fset2
        self.assertEqual(len(fset3), 2)
        self.assertNotIn(gb.RequirementFlag.integrity, fset3)
        self.assertNotIn(gb.RequirementFlag.confidentiality, fset3)
        self.assertIn(gb.RequirementFlag.protection_ready, fset3)
        self.assertIn(gb.RequirementFlag.out_of_sequence_detection, fset3)


class TestInitContext(_GSSAPIKerberosTestCase):
    def setUp(self):
        self.target_name = gb.import_name(TARGET_SERVICE_NAME,
                                          gb.NameType.hostbased_service)

    def tearDown(self):
        gb.release_name(self.target_name)

    def test_basic_init_default_ctx(self):
        ctx_resp = gb.init_sec_context(self.target_name)
        self.assertIsNotNone(ctx_resp)

        (ctx, out_mech_type,
         out_req_flags, out_token, out_ttl, cont_needed) = ctx_resp
        self.assertIsInstance(ctx, gb.SecurityContext)
        self.assertEqual(out_mech_type, gb.MechType.kerberos)
        self.assertIsInstance(out_req_flags, Set)
        if sys.platform != 'darwin':
            self.assertGreaterEqual(len(out_req_flags), 2)
        self.assertGreater(len(out_token), 0)
        self.assertGreater(out_ttl, 0)
        self.assertIsInstance(cont_needed, bool)

        gb.delete_sec_context(ctx)


class TestAcceptContext(_GSSAPIKerberosTestCase):

    def setUp(self):
        self.target_name = gb.import_name(TARGET_SERVICE_NAME,
                                          gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(self.target_name)

        self.client_token = ctx_resp[3]
        self.client_ctx = ctx_resp[0]
        self.assertIsNotNone(self.client_ctx)

        self.server_name = gb.import_name(SERVICE_PRINCIPAL,
                                          gb.NameType.kerberos_principal)
        self.server_creds = gb.acquire_cred(self.server_name)[0]

        self.server_ctx = None

    def tearDown(self):
        gb.release_name(self.target_name)
        gb.release_name(self.server_name)
        gb.release_cred(self.server_creds)
        gb.delete_sec_context(self.client_ctx)

        if self.server_ctx is not None:
            gb.delete_sec_context(self.server_ctx)

    def test_basic_accept_context_no_acceptor_creds(self):
        server_resp = gb.accept_sec_context(self.client_token)
        self.assertIsNotNone(server_resp)

        (self.server_ctx, name, mech_type, out_token,
         out_req_flags, out_ttl, delegated_cred, cont_needed) = server_resp
        self.assertIsInstance(self.server_ctx, gb.SecurityContext)
        self.assertIsInstance(name, gb.Name)
        self.assertEqual(mech_type, gb.MechType.kerberos)
        self.assertGreater(len(out_token), 0)
        self.assertIsInstance(out_req_flags, Set)
        self.assertGreaterEqual(len(out_req_flags), 2)
        self.assertGreater(out_ttl, 0)
        self.assertIsInstance(cont_needed, bool)

        if delegated_cred is not None:
            self.assertIsInstance(delegated_cred, gb.Creds)

    def test_basic_accept_context(self):
        server_resp = gb.accept_sec_context(self.client_token,
                                            acceptor_creds=self.server_creds)
        self.assertIsNotNone(server_resp)

        (self.server_ctx, name, mech_type, out_token,
         out_req_flags, out_ttl, delegated_cred, cont_needed) = server_resp
        self.assertIsInstance(self.server_ctx, gb.SecurityContext)
        self.assertIsInstance(name, gb.Name)
        self.assertEqual(mech_type, gb.MechType.kerberos)
        self.assertGreater(len(out_token), 0)
        self.assertIsInstance(out_req_flags, Set)
        self.assertGreaterEqual(len(out_req_flags), 2)
        self.assertGreater(out_ttl, 0)
        self.assertIsInstance(cont_needed, bool)

        if delegated_cred is not None:
            self.assertIsInstance(delegated_cred, gb.Creds)

    def test_channel_bindings(self):
        bdgs = gb.ChannelBindings(application_data=b'abcxyz',
                                  initiator_address_type=gb.AddressType.ip,
                                  initiator_address=b'127.0.0.1',
                                  acceptor_address_type=gb.AddressType.ip,
                                  acceptor_address=b'127.0.0.1')
        self.target_name = gb.import_name(TARGET_SERVICE_NAME,
                                          gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(self.target_name,
                                       channel_bindings=bdgs)

        self.client_token = ctx_resp[3]
        self.client_ctx = ctx_resp[0]
        self.assertIsNotNone(self.client_ctx)

        self.server_name = gb.import_name(SERVICE_PRINCIPAL,
                                          gb.NameType.kerberos_principal)
        self.server_creds = gb.acquire_cred(self.server_name)[0]

        server_resp = gb.accept_sec_context(self.client_token,
                                            acceptor_creds=self.server_creds,
                                            channel_bindings=bdgs)
        self.assertIsNotNone(server_resp)
        self.server_ctx = server_resp.context

    def test_bad_channel_binding_raises_error(self):
        if sys.platform == 'darwin':
            self.skipTest('macOS does not raise error with validation')

        bdgs = gb.ChannelBindings(application_data=b'abcxyz',
                                  initiator_address_type=gb.AddressType.ip,
                                  initiator_address=b'127.0.0.1',
                                  acceptor_address_type=gb.AddressType.ip,
                                  acceptor_address=b'127.0.0.1')
        self.target_name = gb.import_name(TARGET_SERVICE_NAME,
                                          gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(self.target_name,
                                       channel_bindings=bdgs)

        self.client_token = ctx_resp[3]
        self.client_ctx = ctx_resp[0]
        self.assertIsNotNone(self.client_ctx)

        self.server_name = gb.import_name(SERVICE_PRINCIPAL,
                                          gb.NameType.kerberos_principal)
        self.server_creds = gb.acquire_cred(self.server_name)[0]

        bdgs.acceptor_address = b'127.0.1.0'
        self.assertRaises(gb.GSSError, gb.accept_sec_context,
                          self.client_token, acceptor_creds=self.server_creds,
                          channel_bindings=bdgs)


class TestWrapUnwrap(_GSSAPIKerberosTestCase):
    def setUp(self):
        self.target_name = gb.import_name(TARGET_SERVICE_NAME,
                                          gb.NameType.hostbased_service)
        ctx_resp = gb.init_sec_context(self.target_name)

        self.client_token1 = ctx_resp[3]
        self.client_ctx = ctx_resp[0]
        self.server_name = gb.import_name(SERVICE_PRINCIPAL,
                                          gb.NameType.kerberos_principal)
        self.server_creds = gb.acquire_cred(self.server_name)[0]
        server_resp = gb.accept_sec_context(self.client_token1,
                                            acceptor_creds=self.server_creds)
        self.server_ctx = server_resp[0]
        self.server_tok = server_resp[3]

        client_resp2 = gb.init_sec_context(self.target_name,
                                           context=self.client_ctx,
                                           input_token=self.server_tok)
        self.client_token2 = client_resp2[3]
        self.client_ctx = client_resp2[0]

    def tearDown(self):
        gb.release_name(self.target_name)
        gb.release_name(self.server_name)
        gb.release_cred(self.server_creds)
        gb.delete_sec_context(self.client_ctx)
        gb.delete_sec_context(self.server_ctx)

    def test_import_export_sec_context(self):
        tok = gb.export_sec_context(self.client_ctx)
        self.assertIsInstance(tok, bytes)
        self.assertGreater(len(tok), 0)

        imported_ctx = gb.import_sec_context(tok)
        self.assertIsInstance(imported_ctx, gb.SecurityContext)

        self.client_ctx = imported_ctx  # ensure that it gets deleted

    def test_get_mic(self):
        mic_token = gb.get_mic(self.client_ctx, b"some message")
        self.assertIsInstance(mic_token, bytes)
        self.assertGreater(len(mic_token), 0)

    def test_basic_verify_mic(self):
        mic_token = gb.get_mic(self.client_ctx, b"some message")

        qop_used = gb.verify_mic(self.server_ctx, b"some message", mic_token)
        self.assertIsInstance(qop_used, int)

        # test a bad MIC
        self.assertRaises(gb.GSSError, gb.verify_mic, self.server_ctx,
                          b"some other message", b"some invalid mic")

    def test_wrap_size_limit(self):
        with_conf = gb.wrap_size_limit(self.client_ctx, 100)
        without_conf = gb.wrap_size_limit(self.client_ctx, 100,
                                          confidential=False)
        self.assertIsInstance(with_conf, int)
        self.assertIsInstance(without_conf, int)
        self.assertLess(without_conf, 100)
        self.assertLess(with_conf, 100)

    def test_basic_wrap_unwrap(self):
        wrapped_message, conf = gb.wrap(self.client_ctx, b"test message")
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertIsInstance(wrapped_message, bytes)
        self.assertGreater(len(wrapped_message), len("test message"))

        unwrapped_message, conf, qop = gb.unwrap(self.server_ctx,
                                                 wrapped_message)
        self.assertIsInstance(unwrapped_message, bytes)
        self.assertEqual(unwrapped_message, b'test message')

        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertIsInstance(qop, int)
        self.assertGreaterEqual(qop, 0)

    @ktu.gssapi_extension_test('dce', 'DCE (IOV/AEAD)')
    def test_basic_iov_wrap_unwrap_prealloc(self):
        init_data = b'some encrypted data'
        init_other_data = b'some other encrypted data'
        init_signed_info = b'some sig data'
        init_message = gb.IOV((gb.IOVBufferType.sign_only, init_signed_info),
                              init_data, init_other_data, auto_alloc=False)
        self.assertFalse(init_message[0].allocate)
        self.assertFalse(init_message[4].allocate)
        self.assertFalse(init_message[5].allocate)

        conf = gb.wrap_iov_length(self.client_ctx, init_message)
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertGreaterEqual(len(init_message[0]), 1)
        self.assertGreaterEqual(len(init_message[5]), 1)

        conf = gb.wrap_iov(self.client_ctx, init_message)
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)

        # make sure we didn't strings used
        self.assertEqual(init_data, b'some encrypted data')
        self.assertEqual(init_other_data, b'some other encrypted data')
        self.assertEqual(init_signed_info, b'some sig data')

        self.assertNotEqual(init_message[2].value, b'some encrypted data')
        self.assertNotEqual(init_message[3].value,
                            b'some other encrypted data')

        conf, qop = gb.unwrap_iov(self.server_ctx, init_message)
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertIsInstance(qop, int)

        self.assertEqual(init_message[1].value, init_signed_info)
        self.assertEqual(init_message[2].value, init_data)
        self.assertEqual(init_message[3].value, init_other_data)

    @ktu.gssapi_extension_test('dce', 'DCE (IOV)')
    def test_basic_iov_wrap_unwrap_autoalloc(self):
        init_data = b'some encrypted data'
        init_other_data = b'some other encrypted data'
        init_signed_info = b'some sig data'
        init_message = gb.IOV((gb.IOVBufferType.sign_only, init_signed_info),
                              init_data, init_other_data)

        conf = gb.wrap_iov(self.client_ctx, init_message)
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)

        # make sure we didn't strings used
        self.assertEqual(init_data, b'some encrypted data')
        self.assertEqual(init_other_data, b'some other encrypted data')
        self.assertEqual(init_signed_info, b'some sig data')

        self.assertNotEqual(init_message[2].value, b'some encrypted data')
        self.assertNotEqual(init_message[3].value,
                            b'some other encrypted data')

        conf, qop = gb.unwrap_iov(self.server_ctx, init_message)
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertIsInstance(qop, int)

        self.assertEqual(init_message[1].value, init_signed_info)
        self.assertEqual(init_message[2].value, init_data)
        self.assertEqual(init_message[3].value, init_other_data)

    @ktu.gssapi_extension_test('dce_aead', 'DCE (AEAD)')
    @ktu.krb_provider_test(['mit'], 'unwrapping AEAD stream')
    def test_basic_aead_wrap_unwrap(self):
        assoc_data = b'some sig data'
        wrapped_message, conf = gb.wrap_aead(self.client_ctx, b"test message",
                                             assoc_data)
        self.assertIsInstance(wrapped_message, bytes)
        self.assertGreater(len(wrapped_message), len('test message'))
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)

        unwrapped_message, conf, qop = \
            gb.unwrap_aead(self.server_ctx, wrapped_message, assoc_data)
        self.assertIsInstance(unwrapped_message, bytes)
        self.assertEqual(unwrapped_message, b'test message')
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertIsInstance(qop, int)
        self.assertGreaterEqual(qop, 0)

    @ktu.gssapi_extension_test('dce_aead', 'DCE (AEAD)')
    @ktu.krb_provider_test(['mit'], 'unwrapping AEAD stream')
    def test_basic_aead_wrap_unwrap_no_assoc(self):
        wrapped_message, conf = gb.wrap_aead(self.client_ctx, b"test message")
        self.assertIsInstance(wrapped_message, bytes)
        self.assertGreater(len(wrapped_message), len("test message"))
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)

        unwrapped_message, conf, qop = gb.unwrap_aead(self.server_ctx,
                                                      wrapped_message)
        self.assertIsInstance(unwrapped_message, bytes)
        self.assertEqual(unwrapped_message, b"test message")
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)
        self.assertIsInstance(qop, int)
        self.assertGreaterEqual(qop, 0)

    @ktu.gssapi_extension_test('dce_aead', 'DCE (AEAD)')
    @ktu.krb_provider_test(['mit'], 'unwrapping AEAD stream')
    def test_basic_aead_wrap_unwrap_bad_assoc_raises_error(self):
        assoc_data = b'some sig data'
        wrapped_message, conf = gb.wrap_aead(self.client_ctx, b"test message",
                                             assoc_data)
        self.assertIsInstance(wrapped_message, bytes)
        self.assertGreater(len(wrapped_message), len("test message"))
        self.assertIsInstance(conf, bool)
        self.assertTrue(conf)

        self.assertRaises(gb.BadMICError, gb.unwrap_aead, self.server_ctx,
                          wrapped_message, b'some other sig data')

    @ktu.gssapi_extension_test('iov_mic', 'IOV MIC')
    def test_get_mic_iov(self):
        init_message = gb.IOV(b'some data',
                              (gb.IOVBufferType.sign_only, b'some sig data'),
                              gb.IOVBufferType.mic_token, std_layout=False)

        gb.get_mic_iov(self.client_ctx, init_message)
        self.assertEqual(init_message[2].type, gb.IOVBufferType.mic_token)
        self.assertGreater(len(init_message[2].value), 0)

    @ktu.gssapi_extension_test('iov_mic', 'IOV MIC')
    def test_basic_verify_mic_iov(self):
        init_message = gb.IOV(b'some data',
                              (gb.IOVBufferType.sign_only, b'some sig data'),
                              gb.IOVBufferType.mic_token, std_layout=False)

        gb.get_mic_iov(self.client_ctx, init_message)
        self.assertEqual(init_message[2].type, gb.IOVBufferType.mic_token)
        self.assertGreater(len(init_message[2].value), 0)

        qop_used = gb.verify_mic_iov(self.server_ctx, init_message)
        self.assertIsInstance(qop_used, int)

    @ktu.gssapi_extension_test('iov_mic', 'IOV MIC')
    def test_verify_mic_iov_bad_mic_raises_error(self):
        init_message = gb.IOV(b'some data',
                              (gb.IOVBufferType.sign_only, b'some sig data'),
                              (gb.IOVBufferType.mic_token, 'abaava'),
                              std_layout=False)

        # test a bad MIC
        self.assertRaises(gb.GSSError, gb.verify_mic_iov, self.server_ctx,
                          init_message)

    @ktu.gssapi_extension_test('iov_mic', 'IOV MIC')
    def test_get_mic_iov_length(self):
        init_message = gb.IOV(b'some data',
                              (gb.IOVBufferType.sign_only, b'some sig data'),
                              gb.IOVBufferType.mic_token, std_layout=False,
                              auto_alloc=False)

        gb.get_mic_iov_length(self.client_ctx, init_message)
        self.assertEqual(init_message[2].type, gb.IOVBufferType.mic_token)
        self.assertGreater(len(init_message[2].value), 0)


TEST_OIDS = {'SPNEGO': {'bytes': b'\053\006\001\005\005\002',
                        'string': '1.3.6.1.5.5.2'},
             'KRB5': {'bytes': b'\052\206\110\206\367\022\001\002\002',
                      'string': '1.2.840.113554.1.2.2'},
             'KRB5_OLD': {'bytes': b'\053\005\001\005\002',
                          'string': '1.3.5.1.5.2'},
             'KRB5_WRONG': {'bytes': b'\052\206\110\202\367\022\001\002\002',
                            'string': '1.2.840.48018.1.2.2'},
             'IAKERB': {'bytes': b'\053\006\001\005\002\005',
                        'string': '1.3.6.1.5.2.5'}}


class TestOIDTransforms(unittest.TestCase):
    def test_decode_from_bytes(self):
        for oid in TEST_OIDS.values():
            o = gb.OID(elements=oid['bytes'])
            self.assertEqual(repr(o), f"<OID {oid['string']}>")

    def test_encode_from_string(self):
        for oid in TEST_OIDS.values():
            o = gb.OID.from_int_seq(oid['string'])
            self.assertEqual(o.__bytes__(), oid['bytes'])

    def test_encode_from_int_seq(self):
        for oid in TEST_OIDS.values():
            int_seq = oid['string'].split('.')
            o = gb.OID.from_int_seq(int_seq)
            self.assertEqual(o.__bytes__(), oid['bytes'])

    def test_comparisons(self):
        krb5 = gb.OID.from_int_seq(TEST_OIDS['KRB5']['string'])
        krb5_other = gb.OID.from_int_seq(TEST_OIDS['KRB5']['string'])
        spnego = gb.OID.from_int_seq(TEST_OIDS['SPNEGO']['string'])

        # Purpose here is to test comparisons themselves - don't simplify
        self.assertTrue(krb5 == krb5_other)
        self.assertFalse(krb5 == spnego)
        self.assertFalse(krb5 != krb5_other)
        self.assertTrue(krb5 != spnego)
