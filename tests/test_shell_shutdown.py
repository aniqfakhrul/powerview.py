#!/usr/bin/env python3
"""Regression tests for graceful interactive-shell shutdown."""

import unittest
from argparse import Namespace
from unittest.mock import DEFAULT, patch

import powerview


class InteractiveShutdownTests(unittest.TestCase):
    def test_exit_closes_connection_before_interpreter_finalization(self):
        dependencies = {
            "arg_parse": DEFAULT,
            "LOG": DEFAULT,
            "CONNECTION": DEFAULT,
            "PowerView": DEFAULT,
            "Completer": DEFAULT,
            "PluginRegistry": DEFAULT,
            "load_plugins": DEFAULT,
            "powerview_arg_parse": DEFAULT,
            "get_prompt": DEFAULT,
        }

        with (
            patch.multiple(powerview, **dependencies) as mocks,
            patch("builtins.input", return_value="exit"),
            patch("powerview.utils.parsers.set_plugin_registry"),
        ):
            mocks["arg_parse"].return_value = Namespace(
                domain="example.test",
                username="administrator",
                ldap_address="dc.example.test",
                debug=False,
                query=None,
                json=False,
                mcp=False,
                stack_trace=False,
            )

            conn = mocks["CONNECTION"].return_value
            shell = mocks["PowerView"].return_value
            shell.ldap_session.bound = True
            shell.conn.get_domain.return_value = "example.test"
            plugin_registry = mocks["PluginRegistry"].return_value
            plugin_registry.get_before_hooks.return_value = []
            mocks["powerview_arg_parse"].return_value = Namespace(
                module="exit", server=None, json=False, tableview=""
            )

            with self.assertRaisesRegex(SystemExit, "0"):
                powerview.main()

        conn.close.assert_called_once_with()
        mocks["LOG"].return_value.save_history.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
