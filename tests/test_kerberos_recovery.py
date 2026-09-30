import unittest
from unittest.mock import MagicMock, patch

from powerview.utils.connections import CONNECTION


class KerberosRecoveryTests(unittest.TestCase):
    def test_reconnect_rebuilds_cache_from_saved_service_ticket(self):
        conn = CONNECTION.__new__(CONNECTION)
        conn.use_gc_ldaps = False
        conn.use_ldaps = True
        conn.port = 636
        conn._resolve_protocol = MagicMock(return_value=('LDAPS', True, 636))
        conn.TGT = {'KDC_REP': b'tgt', 'oldSessionKey': b'tgt-old', 'sessionKey': b'tgt-session'}
        conn.TGS = {'KDC_REP': b'tgs', 'oldSessionKey': b'tgs-old', 'sessionKey': b'tgs-session'}
        with (
            patch.dict('os.environ', {}, clear=True),
            patch('impacket.krb5.ccache.CCache') as cache_type,
            patch('powerview.utils.connections.ldap3.Server'),
            patch('impacket.krb5.kerberosv5.getKerberosTGT') as get_tgt,
            patch('impacket.krb5.kerberosv5.getKerberosTGS') as get_tgs,
        ):
            cache = cache_type.return_value
            cache.getCredential.side_effect = RuntimeError('cache ready')
            with self.assertRaisesRegex(RuntimeError, 'cache ready'):
                conn.init_ldap_kerberos('dc.example.test', domain='example.test', username='tester')
            cache.fromTGS.assert_called_once_with(b'tgs', b'tgs-old', b'tgs-session')
            cache.fromTGT.assert_not_called()
            get_tgt.assert_not_called()
            get_tgs.assert_not_called()
