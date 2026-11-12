import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from powerview.powerview import PowerView
from powerview.utils.formatter import FORMATTER
from powerview.utils.parsers import powerview_arg_parse


class LocalUserTests(unittest.TestCase):
    def test_properties_is_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()):
            args = powerview_arg_parse(['Get-LocalUser', '-Computer', 'host', '-Properties', 'userName'])
        self.assertIsNone(args)

    def test_select_projects_complete_local_user_results(self):
        args = powerview_arg_parse(['Get-LocalUser', '-Computer', 'host', '-Select', 'userName,userRID'])
        self.assertEqual(args.select, ['userName', 'userRID'])
        self.assertFalse(hasattr(args, 'properties'))
        pv = PowerView.__new__(PowerView)
        pv.conn = SimpleNamespace()
        pv.use_kerberos = False
        user_info = {
            'UserName': 'alice', 'FullName': 'Alice Example', 'HomeDirectory': '',
            'WorkStations': '', 'AdminComment': 'Local account', 'UserAccountControl': 0,
            'PasswordLastSet': 0, 'PasswordMustChange': 0, 'LastLogon': 0,
            'LogonCount': 3, 'LocalGroups': ['Users'], 'GlobalGroups': [],
        }
        with patch('powerview.powerview.SamrObject') as samr, patch('powerview.powerview.get_time_string', return_value='Never'):
            samr.return_value.get_all_local_users.return_value = [{'RelativeId': 1001}]
            samr.return_value.get_local_user.return_value = user_info
            entries = pv.get_localuser(args.computer, args=args)
        self.assertEqual(len(entries[0]['attributes']), 13)
        self.assertEqual(entries[0]['attributes']['fullName'], 'Alice Example')
        self.assertTrue(entries[0]['attributes']['accountActive'])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            FORMATTER(args).print_select(entries)
        self.assertIn('alice', output.getvalue())
        self.assertIn('1001', output.getvalue())
        self.assertNotIn('Alice Example', output.getvalue())
        self.assertNotIn('homeDirectory', output.getvalue())


if __name__ == '__main__':
    unittest.main()
