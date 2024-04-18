import copy
import os
import socket
import sys
import pickle

from parameterized import parameterized

from gssapi import creds as gsscreds
from gssapi import mechs as gssmechs
from gssapi import names as gssnames
from gssapi import sec_contexts as gssctx
from gssapi import raw as gb
from gssapi import _utils as gssutils
from gssapi import exceptions as excs
import k5test.unit as ktu
import k5test as kt


TARGET_SERVICE_NAME = b'host'
FQDN = (
    'localhost' if sys.platform == 'darwin' else socket.getfqdn()
).encode('utf-8')
SERVICE_PRINCIPAL = TARGET_SERVICE_NAME + b'/' + FQDN

# disable error deferring to catch errors immediately
gssctx.SecurityContext.__DEFER_STEP_ERRORS__ = False  # type: ignore


class _GSSAPIKerberosTestCase(kt.KerberosTestCase):
    @classmethod
    def setUpClass(cls):
        super(_GSSAPIKerberosTestCase, cls).setUpClass()
        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")

        cls.realm.kinit(svc_princ, flags=['-k'])

        cls._init_env()

        cls.USER_PRINC = cls.realm.user_princ.split('@')[0].encode("UTF-8")
        cls.ADMIN_PRINC = cls.realm.admin_princ.split('@')[0].encode("UTF-8")

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


def _perms_cycle(elem, rest, old_d):
    if elem is None:
        name_str = "with_params_"
        true_keys = [k for (k, v) in old_d.items() if v]
        if not true_keys:
            name_str += 'none'
        else:
            name_str += '_'.join(true_keys)

        return [(name_str, old_d)]
    else:
        if len(rest) > 0:
            next_elem = rest.pop()
        else:
            next_elem = None

        res = []
        for v in (True, False):
            new_d = copy.deepcopy(old_d)
            new_d[elem] = v
            res.extend(_perms_cycle(next_elem, copy.deepcopy(rest), new_d))

        return res


def exist_perms(**kwargs):
    all_elems = list(kwargs.keys())
    curr_elems = copy.deepcopy(all_elems)

    perms = _perms_cycle(curr_elems.pop(), curr_elems, {})
    res = []
    for name_str, perm in perms:
        args = dict([(k, v) for (k, v) in kwargs.items() if perm[k]])
        res.append((name_str, args))

    return parameterized.expand(res)


def true_false_perms(*all_elems_tuple):
    all_elems = list(all_elems_tuple)
    curr_elems = copy.deepcopy(all_elems)

    perms = _perms_cycle(curr_elems.pop(), curr_elems, {})
    return parameterized.expand(perms)


# NB(directxman12): MIT Kerberos completely ignores input TTLs for
#                   credentials.  I suspect this is because the TTL
#                   is actually set when kinit is called.
# NB(directxman12): the above note used to be wonderfully sarcastic
class CredsTestCase(_GSSAPIKerberosTestCase):
    def setUp(self):
        super(CredsTestCase, self).setUp()

        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")
        self.realm.kinit(svc_princ, flags=['-k'])

        self.name = gssnames.Name(SERVICE_PRINCIPAL,
                                  gb.NameType.kerberos_principal)

    @exist_perms(lifetime=30, mechs=[gb.MechType.kerberos],
                 usage='both')
    def test_acquire_by_init(self, str_name, kwargs):
        creds = gsscreds.Credentials(name=self.name, **kwargs)
        if sys.platform != 'darwin':
            self.assertIsInstance(creds.lifetime, int)
        del creds

    @exist_perms(lifetime=30, mechs=[gb.MechType.kerberos],
                 usage='both')
    def test_acquire_by_method(self, str_name, kwargs):
        cred_resp = gsscreds.Credentials.acquire(name=self.name,
                                                 **kwargs)
        self.assertIsNotNone(cred_resp)

        creds, actual_mechs, ttl = cred_resp
        self.assertIsInstance(creds, gsscreds.Credentials)
        self.assertIn(gb.MechType.kerberos, actual_mechs)
        if sys.platform != 'darwin':
            self.assertIsInstance(ttl, int)

        del creds

    @ktu.gssapi_extension_test('rfc5588', 'RFC 5588')
    def test_store_acquire(self):
        # we need to acquire a forwardable ticket
        svc_princ = SERVICE_PRINCIPAL.decode("UTF-8")
        self.realm.kinit(svc_princ, flags=['-k', '-f'])

        target_name = gssnames.Name(TARGET_SERVICE_NAME,
                                    gb.NameType.hostbased_service)

        client_creds = gsscreds.Credentials(usage='initiate')
        client_ctx = gssctx.SecurityContext(
            name=target_name, creds=client_creds,
            flags=gb.RequirementFlag.delegate_to_peer)

        client_token = client_ctx.step()

        server_creds = gsscreds.Credentials(usage='accept')
        server_ctx = gssctx.SecurityContext(creds=server_creds)
        server_ctx.step(client_token)

        deleg_creds = server_ctx.delegated_creds
        self.assertIsNotNone(deleg_creds)

        store_res = deleg_creds.store(usage='initiate', set_default=True,
                                      mech=gb.MechType.kerberos,
                                      overwrite=True)
        # While Heimdal doesn't fail it doesn't set the return values as exp.
        if self.realm.provider.lower() != 'heimdal':
            self.assertEqual(store_res.usage, "initiate")
            self.assertIn(gb.MechType.kerberos, store_res.mechs)

        reacquired_creds = gsscreds.Credentials(name=deleg_creds.name,
                                                usage='initiate')
        self.assertIsNotNone(reacquired_creds)

    @ktu.gssapi_extension_test('cred_store', 'credentials store')
    def test_store_into_acquire_from(self):
        CCACHE = 'FILE:{tmpdir}/other_ccache'.format(tmpdir=self.realm.tmpdir)
        KT = '{tmpdir}/other_keytab'.format(tmpdir=self.realm.tmpdir)
        store = {'ccache': CCACHE, 'keytab': KT}

        princ_name = 'service/cs@' + self.realm.realm
        self.realm.addprinc(princ_name)
        self.realm.extract_keytab(princ_name, KT)
        self.realm.kinit(princ_name, None, ['-k', '-t', KT])

        initial_creds = gsscreds.Credentials(name=None,
                                             usage='initiate')

        acquire_kwargs = {}
        expected_usage = 'initiate'
        if self.realm.provider.lower() == 'heimdal':
            acquire_kwargs['usage'] = 'initiate'
            acquire_kwargs['mech'] = gb.MechType.kerberos
            expected_usage = 'both'

        store_res = initial_creds.store(store, overwrite=True,
                                        **acquire_kwargs)
        self.assertIsNotNone(store_res.mechs)
        self.assertGreater(len(store_res.mechs), 0)
        self.assertEqual(store_res.usage, expected_usage)

        name = gssnames.Name(princ_name)
        retrieved_creds = gsscreds.Credentials(name=name, store=store)
        self.assertIsNotNone(retrieved_creds)

    def test_create_from_other(self):
        raw_creds = gb.acquire_cred(None, usage='accept').creds

        high_level_creds = gsscreds.Credentials(raw_creds)
        self.assertEqual(high_level_creds.usage, "accept")

    @true_false_perms('name', 'lifetime', 'usage', 'mechs')
    def test_inquire(self, str_name, kwargs):
        creds = gsscreds.Credentials(name=self.name)
        resp = creds.inquire(**kwargs)

        if kwargs['name']:
            self.assertEqual(resp.name, self.name)
        else:
            self.assertIsNone(resp.name)

        if kwargs['lifetime'] and sys.platform != 'darwin':
            self.assertIsInstance(resp.lifetime, int)
        else:
            self.assertIsNone(resp.lifetime)

        if kwargs['usage']:
            expected = "accept" if sys.platform == "darwin" else "both"
            self.assertEqual(resp.usage, expected)
        else:
            self.assertIsNone(resp.usage)

        if kwargs['mechs']:
            self.assertIn(gb.MechType.kerberos, resp.mechs)
        else:
            self.assertIsNone(resp.mechs)

    @true_false_perms('name', 'init_lifetime', 'accept_lifetime', 'usage')
    def test_inquire_by_mech(self, str_name, kwargs):
        creds = gsscreds.Credentials(name=self.name)
        resp = creds.inquire_by_mech(mech=gb.MechType.kerberos, **kwargs)

        if kwargs['name']:
            self.assertEqual(resp.name, self.name)
        else:
            self.assertIsNone(resp.name)

        if kwargs['init_lifetime']:
            self.assertIsInstance(resp.init_lifetime, int)
        else:
            self.assertIsNone(resp.init_lifetime)

        if kwargs['accept_lifetime'] and sys.platform != "darwin":
            self.assertIsInstance(resp.accept_lifetime, int)
        else:
            self.assertIsNone(resp.accept_lifetime)

        if kwargs['usage']:
            expected = "accept" if sys.platform == "darwin" else "both"
            self.assertEqual(resp.usage, expected)
        else:
            self.assertIsNone(resp.usage)

    def test_add(self):
        if sys.platform == 'darwin':
            self.skipTest("macOS Heimdal broken")

        input_creds = gsscreds.Credentials(gb.Creds())
        name = gssnames.Name(SERVICE_PRINCIPAL)
        new_creds = input_creds.add(name, gb.MechType.kerberos,
                                    usage='initiate')
        self.assertIsInstance(new_creds, gsscreds.Credentials)

    @ktu.gssapi_extension_test('cred_store', 'credentials store')
    def test_store_into_add_from(self):
        CCACHE = 'FILE:{tmpdir}/other_ccache'.format(tmpdir=self.realm.tmpdir)
        KT = '{tmpdir}/other_keytab'.format(tmpdir=self.realm.tmpdir)
        store = {'ccache': CCACHE, 'keytab': KT}

        princ_name = 'service_add_from/cs@' + self.realm.realm
        self.realm.addprinc(princ_name)
        self.realm.extract_keytab(princ_name, KT)
        self.realm.kinit(princ_name, None, ['-k', '-t', KT])

        initial_creds = gsscreds.Credentials(name=None,
                                             usage='initiate')

        store_kwargs = {}
        expected_usage = 'initiate'
        if self.realm.provider.lower() == 'heimdal':
            store_kwargs['usage'] = 'initiate'
            store_kwargs['mech'] = gb.MechType.kerberos
            expected_usage = 'both'

        store_res = initial_creds.store(store, overwrite=True, **store_kwargs)
        self.assertIsNotNone(store_res.mechs)
        self.assertGreater(len(store_res.mechs), 0)
        self.assertEqual(store_res.usage, expected_usage)

        name = gssnames.Name(princ_name)
        input_creds = gsscreds.Credentials(gb.Creds())
        retrieved_creds = input_creds.add(name, gb.MechType.kerberos,
                                          store=store)
        self.assertIsInstance(retrieved_creds, gsscreds.Credentials)

    @ktu.gssapi_extension_test('cred_imp_exp', 'credentials import-export')
    def test_export(self):
        creds = gsscreds.Credentials(name=self.name,
                                     mechs=[gb.MechType.kerberos])
        token = creds.export()
        self.assertIsInstance(token, bytes)

    @ktu.gssapi_extension_test('cred_imp_exp', 'credentials import-export')
    def test_import_by_init(self):
        creds = gsscreds.Credentials(name=self.name,
                                     mechs=[gb.MechType.kerberos])
        token = creds.export()
        imported_creds = gsscreds.Credentials(token=token)

        # lifetime seems to be None in Heimdal
        if self.realm.provider.lower() != 'heimdal':
            self.assertEqual(imported_creds.lifetime, creds.lifetime)

        self.assertEqual(imported_creds.name, creds.name)

    @ktu.gssapi_extension_test('cred_imp_exp', 'credentials import-export')
    def test_pickle_unpickle(self):
        creds = gsscreds.Credentials(name=self.name,
                                     mechs=[gb.MechType.kerberos])
        pickled_creds = pickle.dumps(creds)
        unpickled_creds = pickle.loads(pickled_creds)

        # lifetime seems to be None in Heimdal
        if self.realm.provider.lower() != 'heimdal':
            self.assertEqual(unpickled_creds.lifetime, creds.lifetime)
        self.assertEqual(unpickled_creds.name, creds.name)

    @exist_perms(lifetime=30, mechs=[gb.MechType.kerberos],
                 usage='initiate')
    @ktu.gssapi_extension_test('s4u', 'S4U')
    def test_impersonate(self, str_name, kwargs):
        server_name = gssnames.Name(SERVICE_PRINCIPAL,
                                    gb.NameType.kerberos_principal)

        password = self.realm.password("user")
        self.realm.kinit(self.realm.user_princ, password=password,
                         flags=["-f"])
        client_ctx = gssctx.SecurityContext(
            name=server_name, flags=gb.RequirementFlag.delegate_to_peer)
        client_token = client_ctx.step()

        self.realm.kinit(SERVICE_PRINCIPAL.decode("utf-8"), flags=["-k"])
        server_creds = gsscreds.Credentials(usage="both")
        server_ctx = gssctx.SecurityContext(creds=server_creds)
        server_ctx.step(client_token)
        self.assertTrue(server_ctx.complete)

        imp_creds = server_ctx.delegated_creds.impersonate(server_name,
                                                           **kwargs)
        self.assertIsInstance(imp_creds, gsscreds.Credentials)

    @ktu.gssapi_extension_test('s4u', 'S4U')
    def test_add_with_impersonate(self):
        server_name = gssnames.Name(SERVICE_PRINCIPAL,
                                    gb.NameType.kerberos_principal)

        password = self.realm.password("user")
        self.realm.kinit(self.realm.user_princ, password=password,
                         flags=["-f"])
        client_ctx = gssctx.SecurityContext(
            name=server_name, flags=gb.RequirementFlag.delegate_to_peer)
        client_token = client_ctx.step()

        self.realm.kinit(SERVICE_PRINCIPAL.decode("utf-8"), flags=["-k"])
        server_creds = gsscreds.Credentials(usage="both")
        server_ctx = gssctx.SecurityContext(creds=server_creds)
        server_ctx.step(client_token)
        self.assertTrue(server_ctx.complete)

        # use empty creds to test here
        input_creds = gsscreds.Credentials(gb.Creds())
        new_creds = input_creds.add(
            server_name, gb.MechType.kerberos,
            impersonator=server_ctx.delegated_creds, usage='initiate')
        self.assertIsInstance(new_creds, gsscreds.Credentials)


class MechsTestCase(_GSSAPIKerberosTestCase):
    def test_indicate_mechs(self):
        mechs = gssmechs.Mechanism.all_mechs()
        for mech in mechs:
            s = str(mech)
            self.assertGreater(len(s), 0)

    @ktu.gssapi_extension_test('rfc5801', 'RFC 5801: SASL Names')
    def test_sasl_properties(self):
        mechs = gssmechs.Mechanism.all_mechs()
        for mech in mechs:
            s = str(mech)
            self.assertGreater(len(s), 0)
            self.assertIsInstance(s, str)

            # Note that some mechanisms don't have SASL names or SASL
            # descriptions; in this case, GSSAPI returns empty strings.
            if mech.sasl_name:
                self.assertIsInstance(mech.sasl_name, str)

            if mech.description:
                self.assertIsInstance(mech.description, str)

            # Heimdal fails with Unknown mech-code on sanon
            if not (self.realm.provider.lower() == "heimdal" and
                    s == '1.3.6.1.4.1.5322.26.1.110'):
                cmp_mech = gssmechs.Mechanism.from_sasl_name(mech.sasl_name)

                # For some reason macOS sometimes returns this for mechs
                if not (sys.platform == 'darwin' and
                        str(cmp_mech) == '1.2.752.43.14.2'):
                    self.assertEqual(str(cmp_mech), str(mech))

    @ktu.gssapi_extension_test('rfc5587', 'RFC 5587: Mech Inquiry')
    def test_mech_inquiry(self):
        mechs = list(gssmechs.Mechanism.all_mechs())
        c = len(mechs)

        g_M_from_attrs = gssmechs.Mechanism.from_attrs

        for mech in mechs:
            attrs = mech.attrs
            known_attrs = mech.known_attrs

            for attr in attrs:
                from_desired = g_M_from_attrs(desired_attrs=[attr])
                from_except = g_M_from_attrs(except_attrs=[attr])

                from_desired = list(from_desired)
                from_except = list(from_except)

                self.assertEqual(len(from_desired) + len(from_except), c)
                self.assertIn(mech, from_desired)
                self.assertNotIn(mech, from_except)

            for attr in known_attrs:
                from_desired = g_M_from_attrs(desired_attrs=[attr])
                from_except = g_M_from_attrs(except_attrs=[attr])

                from_desired = list(from_desired)
                from_except = list(from_except)

                self.assertEqual(len(from_desired) + len(from_except), c)


class NamesTestCase(_GSSAPIKerberosTestCase):
    def test_create_from_other(self):
        raw_name = gb.import_name(SERVICE_PRINCIPAL)
        high_level_name = gssnames.Name(raw_name)

        self.assertEqual(bytes(high_level_name), SERVICE_PRINCIPAL)

    def test_create_from_name_no_type(self):
        name = gssnames.Name(SERVICE_PRINCIPAL)
        self.assertIsNotNone(name)

    def test_create_from_name_and_type(self):
        name = gssnames.Name(SERVICE_PRINCIPAL, gb.NameType.kerberos_principal)
        self.assertIsNotNone(name)
        self.assertEqual(name.name_type, gb.NameType.kerberos_principal)

    def test_create_from_token(self):
        name1 = gssnames.Name(TARGET_SERVICE_NAME,
                              gb.NameType.hostbased_service)
        exported_name = name1.canonicalize(gb.MechType.kerberos).export()
        name2 = gssnames.Name(token=exported_name)

        self.assertEqual(name2.name_type, gb.NameType.kerberos_principal)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_provider_test(['mit'], 'gss_display_name_ext as it is not '
                           'implemented for krb5')
    def test_display_as(self):
        name = gssnames.Name(TARGET_SERVICE_NAME,
                             gb.NameType.hostbased_service)
        canonical_name = name.canonicalize(gb.MechType.kerberos)

        # NB(directxman12): krb5 doesn't implement display_name_ext, so just
        # check to make sure we return the right types and a reasonable value
        krb_name = canonical_name.display_as(
            gb.NameType.hostbased_service)

        princ_str = SERVICE_PRINCIPAL.decode('utf-8') + '@'
        self.assertEqual(str(canonical_name), princ_str)
        self.assertIsInstance(krb_name, str)
        self.assertEqual(krb_name, princ_str)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_provider_test(['mit'], 'gss_canonicalize_name as it is not '
                           'implemented for krb5')
    def test_create_from_composite_token_no_attrs(self):
        name1 = gssnames.Name(TARGET_SERVICE_NAME,
                              gb.NameType.hostbased_service)
        exported_name = name1.canonicalize(
            gb.MechType.kerberos).export(composite=True)
        name2 = gssnames.Name(token=exported_name, composite=True)

        self.assertIsNotNone(name2)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_plugin_test('authdata', 'greet_client')
    def test_create_from_composite_token_with_attrs(self):
        name1 = gssnames.Name(TARGET_SERVICE_NAME,
                              gb.NameType.hostbased_service)

        canon_name = name1.canonicalize(gb.MechType.kerberos)
        canon_name.attributes['urn:greet:greeting'] = b'some val'

        exported_name = canon_name.export(composite=True)

        # TODO(directxman12): when you just import a token as composite,
        # appears as this name whose text is all garbled, since it contains
        # all of the attributes, etc, but doesn't properly have the attributes.
        # Once it's canonicalized, the attributes reappear.  However, if you
        # just import it as normal export, the attributes appear directly.
        # It is thus unclear as to what is going on
        # name2_raw = gssnames.Name(token=exported_name, composite=True)
        # name2 = name2_raw.canonicalize(gb.MechType.kerberos)

        name2 = gssnames.Name(token=exported_name)
        self.assertIsNotNone(name2)

        ugg = name2.attributes["urn:greet:greeting"]
        self.assertEqual(ugg.values, set([b"some val"]))
        self.assertTrue(ugg.complete)
        self.assertFalse(ugg.authenticated)

    def test_to_str(self):
        name = gssnames.Name(SERVICE_PRINCIPAL, gb.NameType.kerberos_principal)

        name_str = str(name)

        if sys.version_info[0] == 2:
            target_val = SERVICE_PRINCIPAL
        else:
            target_val = SERVICE_PRINCIPAL.decode(gssutils._get_encoding())

        self.assertEqual(name_str, target_val)

    def test_to_unicode(self):
        name = gssnames.Name(SERVICE_PRINCIPAL, gb.NameType.kerberos_principal)
        self.assertEqual(str(name),
                         SERVICE_PRINCIPAL.decode(gssutils._get_encoding()))

    def test_to_bytes(self):
        name = gssnames.Name(SERVICE_PRINCIPAL, gb.NameType.kerberos_principal)

        # NB(directxman12): bytes only calles __bytes__ on Python 3+
        self.assertEqual(name.__bytes__(), SERVICE_PRINCIPAL)

    def test_compare(self):
        name1 = gssnames.Name(SERVICE_PRINCIPAL)
        name2 = gssnames.Name(SERVICE_PRINCIPAL)
        name3 = gssnames.Name(TARGET_SERVICE_NAME,
                              gb.NameType.hostbased_service)

        self.assertEqual(name1, name2)
        self.assertNotEqual(name1, name3)

    def test_canoncialize_and_export(self):
        name = gssnames.Name(SERVICE_PRINCIPAL, gb.NameType.kerberos_principal)
        canonical_name = name.canonicalize(gb.MechType.kerberos)
        exported_name = canonical_name.export()

        self.assertIsInstance(exported_name, bytes)

    def test_canonicalize(self):
        name = gssnames.Name(TARGET_SERVICE_NAME,
                             gb.NameType.hostbased_service)

        canonicalized_name = name.canonicalize(gb.MechType.kerberos)
        self.assertIsInstance(canonicalized_name, gssnames.Name)

        expected = SERVICE_PRINCIPAL + b"@"
        if sys.platform == 'darwin':
            # No idea - just go with it
            expected = b"host/wellknown:org.h5l.hostbased-service@" \
                b"H5L.HOSTBASED-SERVICE"
        elif self.realm.provider.lower() == 'heimdal':
            expected += self.realm.realm.encode('utf-8')

        self.assertEqual(bytes(canonicalized_name), expected)

    def test_copy(self):
        name1 = gssnames.Name(SERVICE_PRINCIPAL)
        name2 = copy.copy(name1)

        self.assertEqual(name1, name2)

    # NB(directxman12): we don't test display_name_ext because the krb5 mech
    # doesn't actually implement it

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_provider_test(['mit'], 'Heimdal does not implemented for krb5')
    def test_is_mech_name(self):
        name = gssnames.Name(TARGET_SERVICE_NAME,
                             gb.NameType.hostbased_service)
        self.assertFalse(name.is_mech_name)

        canon_name = name.canonicalize(gb.MechType.kerberos)
        self.assertTrue(canon_name.is_mech_name)
        self.assertIsInstance(canon_name.mech, gb.OID)
        self.assertEqual(canon_name.mech, gb.MechType.kerberos)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_provider_test(['mit'], 'Heimdal does not implemented for krb5')
    def test_export_name_composite_no_attrs(self):
        name = gssnames.Name(TARGET_SERVICE_NAME,
                             gb.NameType.hostbased_service)
        canon_name = name.canonicalize(gb.MechType.kerberos)
        exported_name = canon_name.export(composite=True)

        self.assertIsInstance(exported_name, bytes)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_plugin_test('authdata', 'greet_client')
    def test_export_name_composite_with_attrs(self):
        name = gssnames.Name(TARGET_SERVICE_NAME,
                             gb.NameType.hostbased_service)
        canon_name = name.canonicalize(gb.MechType.kerberos)
        canon_name.attributes['urn:greet:greeting'] = b'some val'
        exported_name = canon_name.export(composite=True)

        self.assertIsInstance(exported_name, bytes)

    @ktu.gssapi_extension_test('rfc6680', 'RFC 6680')
    @ktu.krb_plugin_test('authdata', 'greet_client')
    def test_basic_get_set_del_name_attribute_no_auth(self):
        name = gssnames.Name(TARGET_SERVICE_NAME,
                             gb.NameType.hostbased_service)
        canon_name = name.canonicalize(gb.MechType.kerberos)

        canon_name.attributes['urn:greet:greeting'] = (b'some val', True)
        ugg = canon_name.attributes["urn:greet:greeting"]
        self.assertEqual(ugg.values, set([b"some val"]))
        self.assertTrue(ugg.complete)
        self.assertFalse(ugg.authenticated)

        del canon_name.attributes['urn:greet:greeting']

        # NB(directxman12): for some reason, the greet:greeting handler plugin
        # doesn't properly delete itself -- it just clears the value.  If we
        # try to get its value now, we segfault (due to an issue with
        # greet:greeting's delete).  Instead, just set the value again.
        canon_name.attributes['urn:greet:greeting'] = b'some other val'


class SecurityContextTestCase(_GSSAPIKerberosTestCase):
    def setUp(self):
        super(SecurityContextTestCase, self).setUp()
        gssctx.SecurityContext.__DEFER_STEP_ERRORS__ = False
        self.client_name = gssnames.Name(self.USER_PRINC)
        self.client_creds = gsscreds.Credentials(name=None,
                                                 usage='initiate')

        if sys.platform == "darwin":
            spn = TARGET_SERVICE_NAME + b"@" + FQDN
            self.target_name = gssnames.Name(spn,
                                             gb.NameType.hostbased_service)
        else:
            self.target_name = gssnames.Name(TARGET_SERVICE_NAME,
                                             gb.NameType.hostbased_service)

        self.server_name = gssnames.Name(SERVICE_PRINCIPAL)
        self.server_creds = gsscreds.Credentials(name=self.server_name,
                                                 usage='accept')

    def _create_client_ctx(self, **kwargs):
        return gssctx.SecurityContext(name=self.target_name, **kwargs)

    # NB(directxman12): we skip testing process_context_token, because there is
    #                   no concrete, non-deprecated was to obtain an "async"
    #                   token

    def test_create_from_other(self):
        raw_client_ctx, raw_server_ctx = self._create_completed_contexts()
        high_level_ctx = gssctx.SecurityContext(raw_client_ctx)

        expected = self.target_name
        if self.realm.provider.lower() == "heimdal":
            expected = gssnames.Name(self.realm.host_princ.encode('utf-8'),
                                     name_type=gb.NameType.kerberos_principal)
        self.assertEqual(high_level_ctx.target_name, expected)

    @exist_perms(lifetime=30, flags=[],
                 mech=gb.MechType.kerberos,
                 channel_bindings=None)
    def test_create_new_init(self, str_name, kwargs):
        client_ctx = gssctx.SecurityContext(name=self.target_name,
                                            creds=self.client_creds,
                                            **kwargs)
        self.assertEqual(client_ctx.usage, "initiate")

        client_ctx = self._create_client_ctx(**kwargs)
        self.assertEqual(client_ctx.usage, "initiate")

    def test_create_new_accept(self):
        server_ctx = gssctx.SecurityContext(creds=self.server_creds)
        self.assertEqual(server_ctx.usage, "accept")

    def test_init_throws_error_on_invalid_args(self):
        self.assertRaises(TypeError, gssctx.SecurityContext, usage='accept',
                          name=self.target_name)

    def _create_completed_contexts(self):
        client_ctx = self._create_client_ctx(lifetime=400)

        client_token = client_ctx.step()
        self.assertIsInstance(client_token, bytes)

        server_ctx = gssctx.SecurityContext(creds=self.server_creds)
        server_token = server_ctx.step(client_token)
        self.assertIsInstance(server_token, bytes)

        client_ctx.step(server_token)

        return (client_ctx, server_ctx)

    def test_complete_on_partially_completed(self):
        client_ctx = self._create_client_ctx()
        client_tok = client_ctx.step()
        self.assertFalse(client_ctx.complete)

        server_ctx = gssctx.SecurityContext(creds=self.server_creds)
        server_tok = server_ctx.step(client_tok)

        client_ctx.step(server_tok)
        self.assertTrue(client_ctx.complete)
        self.assertTrue(server_ctx.complete)

    def test_initiate_accept_steps(self):
        client_ctx, server_ctx = self._create_completed_contexts()

        # KDC may allow for clockskew by increasing acceptor context lifetime
        self.assertLessEqual(server_ctx.lifetime, 400 + 300)
        self.assertEqual(server_ctx.initiator_name, client_ctx.initiator_name)
        self.assertIsInstance(server_ctx.mech, gb.OID)
        self.assertIsInstance(server_ctx.actual_flags, gb.IntEnumFlagSet)
        self.assertFalse(server_ctx.locally_initiated)
        self.assertTrue(server_ctx.complete)

        self.assertLessEqual(client_ctx.lifetime, 400)

        expected = self.target_name
        if self.realm.provider.lower() == "heimdal":
            expected = gssnames.Name(self.realm.host_princ.encode('utf-8'),
                                     name_type=gb.NameType.kerberos_principal)
        self.assertEqual(client_ctx.target_name, expected)

        self.assertIsInstance(client_ctx.mech, gb.OID)
        self.assertIsInstance(client_ctx.actual_flags, gb.IntEnumFlagSet)
        self.assertTrue(client_ctx.locally_initiated)
        self.assertTrue(client_ctx.complete)

    def test_channel_bindings(self):
        bdgs = gb.ChannelBindings(application_data=b'abcxyz',
                                  initiator_address_type=gb.AddressType.ip,
                                  initiator_address=b'127.0.0.1',
                                  acceptor_address_type=gb.AddressType.ip,
                                  acceptor_address=b'127.0.0.1')
        client_ctx = self._create_client_ctx(lifetime=400,
                                             channel_bindings=bdgs)

        client_token = client_ctx.step()
        self.assertIsInstance(client_token, bytes)

        server_ctx = gssctx.SecurityContext(creds=self.server_creds,
                                            channel_bindings=bdgs)
        server_token = server_ctx.step(client_token)
        self.assertIsInstance(server_token, bytes)

        client_ctx.step(server_token)

    def test_bad_channel_bindings_raises_error(self):
        if sys.platform == "darwin":
            self.skipTest("macOS Heimdal doesn't fail as expected")

        bdgs = gb.ChannelBindings(application_data=b'abcxyz',
                                  initiator_address_type=gb.AddressType.ip,
                                  initiator_address=b'127.0.0.1',
                                  acceptor_address_type=gb.AddressType.ip,
                                  acceptor_address=b'127.0.0.1')
        client_ctx = self._create_client_ctx(lifetime=400,
                                             channel_bindings=bdgs)

        client_token = client_ctx.step()
        self.assertIsInstance(client_token, bytes)

        bdgs.acceptor_address = b'127.0.1.0'
        server_ctx = gssctx.SecurityContext(creds=self.server_creds,
                                            channel_bindings=bdgs)
        self.assertRaises(gb.BadChannelBindingsError, server_ctx.step,
                          client_token)

    def test_export_create_from_token(self):
        client_ctx, server_ctx = self._create_completed_contexts()
        token = client_ctx.export()
        self.assertIsInstance(token, bytes)

        imported_ctx = gssctx.SecurityContext(token=token)
        self.assertEqual(imported_ctx.usage, "initiate")

        expected = self.target_name
        if self.realm.provider.lower() == "heimdal":
            expected = gssnames.Name(self.realm.host_princ.encode('utf-8'),
                                     name_type=gb.NameType.kerberos_principal)

        self.assertEqual(imported_ctx.target_name, expected)

    def test_pickle_unpickle(self):
        client_ctx, server_ctx = self._create_completed_contexts()
        pickled_ctx = pickle.dumps(client_ctx)

        unpickled_ctx = pickle.loads(pickled_ctx)
        self.assertIsInstance(unpickled_ctx, gssctx.SecurityContext)
        self.assertEqual(unpickled_ctx.usage, "initiate")

        expected = self.target_name
        if self.realm.provider.lower() == "heimdal":
            expected = gssnames.Name(self.realm.host_princ.encode('utf-8'),
                                     name_type=gb.NameType.kerberos_principal)
        self.assertEqual(unpickled_ctx.target_name, expected)

    def test_encrypt_decrypt(self):
        client_ctx, server_ctx = self._create_completed_contexts()

        encrypted_msg = client_ctx.encrypt(b'test message')
        self.assertIsInstance(encrypted_msg, bytes)

        decrypted_msg = server_ctx.decrypt(encrypted_msg)
        self.assertIsInstance(decrypted_msg, bytes)
        self.assertEqual(decrypted_msg, b"test message")

    def test_encrypt_decrypt_throws_error_on_no_encryption(self):
        client_ctx, server_ctx = self._create_completed_contexts()

        wrap_res = client_ctx.wrap(b'test message', False)
        self.assertIsInstance(wrap_res, gb.WrapResult)
        self.assertFalse(wrap_res.encrypted)
        self.assertIsInstance(wrap_res.message, bytes)

        self.assertRaises(excs.EncryptionNotUsed, server_ctx.decrypt,
                          wrap_res.message)

    def test_wrap_unwrap(self):
        client_ctx, server_ctx = self._create_completed_contexts()

        wrap_res = client_ctx.wrap(b'test message', True)
        self.assertIsInstance(wrap_res, gb.WrapResult)
        self.assertTrue(wrap_res.encrypted)
        self.assertIsInstance(wrap_res.message, bytes)

        unwrap_res = server_ctx.unwrap(wrap_res.message)
        self.assertIsInstance(unwrap_res, gb.UnwrapResult)
        self.assertIsInstance(unwrap_res.message, bytes)
        self.assertEqual(unwrap_res.message, b"test message")
        self.assertTrue(unwrap_res.encrypted)

    def test_get_wrap_size_limit(self):
        client_ctx, server_ctx = self._create_completed_contexts()

        with_conf = client_ctx.get_wrap_size_limit(100)
        without_conf = client_ctx.get_wrap_size_limit(100, encrypted=True)

        self.assertIsInstance(with_conf, int)
        self.assertIsInstance(without_conf, int)
        self.assertLessEqual(with_conf, 100)
        self.assertLessEqual(without_conf, 100)

    def test_get_signature(self):
        client_ctx, server_ctx = self._create_completed_contexts()
        mic_token = client_ctx.get_signature(b'some message')

        self.assertIsInstance(mic_token, bytes)
        self.assertGreater(len(mic_token), 0)

    def test_verify_signature_raise(self):
        client_ctx, server_ctx = self._create_completed_contexts()
        mic_token = client_ctx.get_signature(b'some message')
        server_ctx.verify_signature(b'some message', mic_token)

        self.assertRaises(gb.GSSError, server_ctx.verify_signature,
                          b"other message", mic_token)

    @ktu.krb_minversion_test("1.11", "returning tokens", provider="mit")
    @ktu.krb_provider_test(["mit"], "returning tokens")
    def test_defer_step_error_on_method(self):
        gssctx.SecurityContext.__DEFER_STEP_ERRORS__ = True
        bdgs = gb.ChannelBindings(application_data=b'abcxyz')
        client_ctx = self._create_client_ctx(lifetime=400,
                                             channel_bindings=bdgs)

        client_token = client_ctx.step()
        self.assertIsInstance(client_token, bytes)

        bdgs.application_data = b'defuvw'
        server_ctx = gssctx.SecurityContext(creds=self.server_creds,
                                            channel_bindings=bdgs)
        self.assertIsInstance(server_ctx.step(client_token), bytes)
        self.assertRaises(gb.BadChannelBindingsError, server_ctx.encrypt,
                          b"test")

    @ktu.krb_minversion_test("1.11", "returning tokens", provider="mit")
    @ktu.krb_provider_test(["mit"], "returning tokens")
    def test_defer_step_error_on_complete_property_access(self):
        gssctx.SecurityContext.__DEFER_STEP_ERRORS__ = True
        bdgs = gb.ChannelBindings(application_data=b'abcxyz')
        client_ctx = self._create_client_ctx(lifetime=400,
                                             channel_bindings=bdgs)

        client_token = client_ctx.step()
        self.assertIsInstance(client_token, bytes)

        bdgs.application_data = b'defuvw'
        server_ctx = gssctx.SecurityContext(creds=self.server_creds,
                                            channel_bindings=bdgs)
        self.assertIsInstance(server_ctx.step(client_token), bytes)

        self.assertRaises(gb.BadChannelBindingsError,
                          lambda: server_ctx.complete)
