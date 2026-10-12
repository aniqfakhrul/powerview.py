import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch, sentinel

from powerview.powerview import PowerView


class BadSuccessorTicketTests(unittest.TestCase):
    def test_ticket_material_reaches_dmsa_for_cached_and_fresh_tgts(self):
        for source in ('cached', 'ccache', 'fresh'):
            with self.subTest(source=source):
                ticket = {
                    'KDC_REP': b'tgt',
                    'cipher': sentinel.cipher,
                    'sessionKey': sentinel.session_key,
                }
                old_key = sentinel.session_key if source == 'ccache' else sentinel.old_key
                if source != 'ccache':
                    ticket['oldSessionKey'] = old_key
                pv = PowerView.__new__(PowerView)
                pv.conn = SimpleNamespace(
                    username='tester', password='password', lmhash='', nthash='',
                    auth_aes_key=None, kdcHost='dc.example.test',
                    get_domain=MagicMock(return_value='example.test'),
                    get_TGT=MagicMock(return_value=None if source == 'fresh' else ticket),
                )
                pv.get_domaindmsa = MagicMock(return_value=[])
                pv.add_domaindmsa = MagicMock(return_value=True)
                pv.get_domainuser = MagicMock(return_value=[{'attributes': {
                    'distinguishedName': 'CN=target,DC=example,DC=test',
                    'sAMAccountName': 'target', 'objectClass': ['user'],
                }}])
                pv.get_domaincomputer = MagicMock(return_value=[])
                pv.ldap_session = MagicMock()
                with (
                    patch('powerview.powerview.getKerberosTGT', return_value=(
                        b'tgt', sentinel.cipher, old_key, sentinel.session_key,
                    )) as get_tgt,
                    patch('powerview.powerview.MSA.doDMSA', return_value=(
                        b'tgs', sentinel.reply_cipher, old_key, sentinel.reply_key, [],
                    )) as do_dmsa,
                ):
                    self.assertEqual(pv.invoke_badsuccessor(
                        dmsaname='testmsa', targetidentity='target',
                        basedn='DC=example,DC=test', no_delete=True,
                    ), [])
                    do_dmsa.assert_called_once_with(
                        b'tgt', sentinel.cipher, old_key, sentinel.session_key,
                        b'', None, 'dc.example.test', 'example.test', 'testmsa$',
                    )
                    if source == 'fresh':
                        get_tgt.assert_called_once()
                    else:
                        get_tgt.assert_not_called()
