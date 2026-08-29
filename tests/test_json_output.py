#!/usr/bin/env python3
"""Tests for the -Json / -TableView json output modes.

Run from the repository root:

    python -m unittest tests.test_json_output -v

Note: a stale PyPI ``argparse`` backport is shipped in some site-packages
directories and shadows the stdlib when the interpreter's cwd is that
directory. It lacks ``exit_on_error``, so always run from the repo root.
"""

import base64
import contextlib
import copy
import datetime
import io
import json
import os
import tempfile
import unittest
from argparse import Namespace

import ldap3
from ldap3.utils.ciDict import CaseInsensitiveDict

from powerview.utils.formatter import FORMATTER
from powerview.utils.helpers import convert_to_json_serializable, strip_ansi
from powerview.utils.constants import JSON_CAPABLE_MODULES
from powerview.utils.parsers import Helper, powerview_arg_parse

RAW_BYTES = b"\x01\x02\xff\xfe"          # deliberately not UTF-8 decodable
ANSI_VULN = "[V1] weak thing (\033[91mHIGH\033[0m)"


def args(**overrides):
    base = dict(tableview="", select=None, properties=None, outfile=None,
                nowrap=True, count=False, json=True)
    base.update(overrides)
    return Namespace(**base)


def render(method_name, entries, **overrides):
    """Run a formatter method and return its stdout."""
    buffer = io.StringIO()
    formatter = FORMATTER(args(**overrides))
    with contextlib.redirect_stdout(buffer):
        getattr(formatter, method_name)(entries)
    return buffer.getvalue()


def render_json(method_name, entries, **overrides):
    return json.loads(render(method_name, entries, **overrides))


def entry(name, **extra):
    attributes = CaseInsensitiveDict()
    attributes["sAMAccountName"] = name
    attributes["memberOf"] = ["CN=G1", "CN=G2"]
    for key, value in extra.items():
        attributes[key] = value
    return {"dn": "CN=%s,DC=e,DC=com" % name, "attributes": attributes}


def ace(rights):
    return {"ObjectDN": "CN=t", "ActiveDirectoryRights": rights,
            "SecurityIdentifier": "S-1-5-%s" % rights}


def acl_entries():
    return [{"dn": "CN=t", "attributes": [ace("A"), ace("B"), ace("C")]}]


class SerializerTests(unittest.TestCase):
    def test_encoding_contract(self):
        out = convert_to_json_serializable({
            "blob": RAW_BYTES,
            "when": datetime.datetime(2025, 1, 3, 11, 22, 33),
            "span": datetime.timedelta(seconds=90),
        })
        self.assertEqual(base64.b64decode(out["blob"]), RAW_BYTES)
        self.assertEqual(out["when"], "2025-01-03T11:22:33")
        self.assertEqual(out["span"], "0:01:30")
        json.dumps(out)

    def test_case_insensitive_dict_becomes_object(self):
        source = CaseInsensitiveDict()
        source["Key"] = [b"a", datetime.datetime(2020, 1, 1)]
        self.assertEqual(convert_to_json_serializable(source),
                         {"Key": [base64.b64encode(b"a").decode(), "2020-01-01T00:00:00"]})

    def test_ansi_scoped_to_vulnerabilities(self):
        out = convert_to_json_serializable(
            {"vulnerabilities": [ANSI_VULN], "note": "keeps \033[91m escape"})
        self.assertEqual(out["vulnerabilities"], ["[V1] weak thing (HIGH)"])
        self.assertIn("\033[91m", out["note"])

    def test_does_not_mutate_input(self):
        source = {"a": [b"x"], "when": datetime.datetime(2020, 1, 1)}
        snapshot = copy.deepcopy(source)
        convert_to_json_serializable(source)
        self.assertEqual(source, snapshot)

    def test_strip_ansi_passthrough_for_non_strings(self):
        self.assertEqual(strip_ansi(5), 5)
        self.assertIsNone(strip_ansi(None))


class StructuredJsonTests(unittest.TestCase):
    def test_dict_entry_shape(self):
        out = render_json("print_json", [entry("alice")])
        self.assertEqual(set(out[0]), {"dn", "attributes"})
        self.assertEqual(out[0]["attributes"]["sAMAccountName"], "alice")

    def test_from_cache_is_optional_third_key(self):
        plain = render_json("print_json", [entry("alice")])[0]
        self.assertNotIn("from_cache", plain)
        cached = entry("bob")
        cached["from_cache"] = True
        self.assertTrue(render_json("print_json", [cached])[0]["from_cache"])

    def test_ldap3_entry_uses_raw_values_not_entry_to_json(self):
        """entry_to_json() would emit {"encoded": ...} and str(datetime)."""
        server = ldap3.Server("fake", get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user="cn=u,dc=e,dc=com", password="p",
                                client_strategy=ldap3.MOCK_SYNC)
        conn.strategy.add_entry("cn=alice,dc=e,dc=com", {
            "objectClass": ["person"], "sn": "alice", "revision": 1,
            "userCertificate": RAW_BYTES,
        })
        conn.bind()
        conn.search("dc=e,dc=com", "(sn=alice)", attributes=["sn", "userCertificate"])
        ldap_entry = conn.entries[0]

        legacy = json.loads(ldap_entry.entry_to_json())["attributes"]["userCertificate"]
        self.assertIn("encoded", legacy[0])          # documents what we avoid

        out = render_json("print_json", [ldap_entry])
        value = out[0]["attributes"]["userCertificate"]
        value = value[0] if isinstance(value, list) else value
        self.assertIsInstance(value, str)
        self.assertEqual(base64.b64decode(value), RAW_BYTES)
        self.assertNotIn("encoded", json.dumps(out))
        self.assertEqual(out[0]["dn"], "cn=alice,dc=e,dc=com")

    def test_acl_nesting_preserved(self):
        out = render_json("print_json", acl_entries())
        self.assertIsInstance(out[0]["attributes"], list)
        self.assertEqual(len(out[0]["attributes"]), 3)

    def test_bare_strings_and_empty_and_none(self):
        self.assertEqual(render_json("print_json", ["a", "b"]), ["a", "b"])
        self.assertEqual(render_json("print_json", []), [])
        self.assertEqual(render_json("print_json", None), [])

    def test_outfile_receives_one_document(self):
        for entries in ([entry("alice")], []):
            with tempfile.TemporaryDirectory() as tmp:
                path = os.path.join(tmp, "out.json")
                render("print_json", entries, outfile=path)
                with open(path) as handle:
                    self.assertEqual(json.load(handle),
                                     render_json("print_json", entries))

    def test_json_fallback_never_reached(self):
        def explode(obj):
            raise AssertionError("fallback reached for %r" % type(obj))
        original = FORMATTER._json_fallback
        FORMATTER._json_fallback = staticmethod(explode)
        try:
            render("print_json", [entry("alice", blob=RAW_BYTES,
                                        when=datetime.datetime(2020, 1, 1),
                                        span=datetime.timedelta(seconds=5))])
            render("print_json", acl_entries())
        finally:
            FORMATTER._json_fallback = original


class SelectionTests(unittest.TestCase):
    def test_normalize_select(self):
        self.assertIsNone(FORMATTER.normalize_select(None))
        self.assertIsNone(FORMATTER.normalize_select(""))
        self.assertEqual(FORMATTER.normalize_select(0), 0)      # not "no selection"
        self.assertEqual(FORMATTER.normalize_select(2), 2)
        self.assertEqual(FORMATTER.normalize_select("a, b"), ["a", "b"])
        self.assertEqual(FORMATTER.normalize_select(["a"]), ["a"])

    def test_int_select_limits_rows(self):
        entries = [entry(n) for n in ("alice", "bob", "carol")]
        self.assertEqual(len(render_json("print_json", entries, select=2)), 2)
        self.assertEqual(render_json("print_json", entries, select=0), [])

    def test_int_select_limits_ace_list_for_acl(self):
        out = render_json("print_json", acl_entries(), select=2)
        self.assertEqual(len(out), 1)
        self.assertEqual(len(out[0]["attributes"]), 2)

    def test_named_select_projects_inside_each_ace(self):
        out = render_json("print_json", acl_entries(), select=["ActiveDirectoryRights"])
        for projected in out[0]["attributes"]:
            self.assertEqual(list(projected), ["ActiveDirectoryRights"])

    def test_raw_string_select_is_not_iterated_per_character(self):
        for mode, kwargs in (("print_json", {}),
                             ("table_view", {"tableview": "json"})):
            out = render_json(mode, [entry("alice")],
                              select="sAMAccountName", **kwargs)
            keys = out[0]["attributes"] if mode == "print_json" else out[0]
            self.assertEqual([k.lower() for k in keys], ["samaccountname"])

    def test_selection_does_not_mutate_input(self):
        entries = acl_entries()
        snapshot = copy.deepcopy(entries)
        render("print_json", entries, select=2)
        render("print_json", entries, select=["ActiveDirectoryRights"])
        self.assertEqual(entries, snapshot)


class TableViewJsonTests(unittest.TestCase):
    def test_flat_objects(self):
        out = render_json("table_view", [entry("alice"), entry("bob")],
                          tableview="json")
        self.assertEqual(len(out), 2)
        self.assertIsInstance(out[0], dict)
        self.assertEqual(out[0]["sAMAccountName"], "alice")

    def test_empty_emits_array(self):
        self.assertEqual(render_json("table_view", [], tableview="json"), [])

    def test_empty_still_writes_outfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "empty.json")
            render("table_view", [], tableview="json", outfile=path)
            with open(path) as handle:
                self.assertEqual(json.load(handle), [])

    def test_int_select_slices_instead_of_raising(self):
        entries = [entry(n) for n in ("alice", "bob", "carol")]
        self.assertEqual(len(render_json("table_view", entries,
                                         tableview="json", select=2)), 2)
        self.assertEqual(render_json("table_view", entries,
                                     tableview="json", select=0), [])
        # the same int previously raised TypeError on every table format
        render("table_view", entries, tableview="md", select=2)

    def test_ansi_stripped_on_vulnerabilities_column_only(self):
        out = render_json("table_view",
                          [entry("alice", vulnerabilities=[ANSI_VULN],
                                 description="keeps \033[91m escape")],
                          tableview="json")
        self.assertNotIn("\033[91m", out[0]["vulnerabilities"])
        self.assertIn("\033[91m", out[0]["description"])

    def test_other_formats_unaffected(self):
        rendered = render("table_view", [entry("alice")], tableview="md")
        self.assertIn("alice", rendered)
        self.assertNotIn("{", rendered)


class ParserTests(unittest.TestCase):
    def test_json_flag_and_case_variants(self):
        for flag in ("-Json", "-json", "-JSON"):
            self.assertTrue(powerview_arg_parse(["Get-DomainUser", flag]).json, flag)
        self.assertFalse(powerview_arg_parse(["Get-DomainUser"]).json)

    def test_tableview_json_canonicalised(self):
        for value in ("json", "JSON", "Json"):
            self.assertEqual(
                powerview_arg_parse(["Get-DomainUser", "-TableView", value]).tableview,
                "json")

    def test_domainobjectowner_tableview_gets_converter(self):
        parsed = powerview_arg_parse(
            ["Get-DomainObjectOwner", "-Identity", "x", "-TableView", "JSON"])
        self.assertEqual(parsed.tableview, "json")

    def test_domaincontroller_select_returns_list(self):
        parsed = powerview_arg_parse(["Get-DomainController", "-Select", "samaccountname"])
        self.assertEqual(parsed.select, ["samaccountname"])
        self.assertEqual(powerview_arg_parse(["Get-DomainController", "-Select", "3"]).select, 3)

    def test_documented_table_formats_validate(self):
        for value in ("md", "csv", "html", "latex", "tsv", "json"):
            self.assertEqual(Helper.parse_tableview(value.upper()), value)
        self.assertEqual(Helper.parse_tableview(""), "")
        self.assertIsNone(Helper.parse_tableview(None))
        with self.assertRaises(ValueError):
            Helper.parse_tableview("bogus")

    def test_commands_without_json_support_lack_the_attribute(self):
        """The --json gate relies on hasattr() to reject these."""
        for command in (["whoami"], ["history"]):
            self.assertFalse(hasattr(powerview_arg_parse(command), "json"), command)


class HeadersRowsShapeTests(unittest.TestCase):
    """The plugin {"headers", "rows"} convention, normalised in __init__.py."""

    @staticmethod
    def normalize(result):
        headers, rows = result["headers"], result["rows"]
        return headers, rows, [{"attributes": dict(zip(headers, row))} for row in rows]

    def test_normalization_gives_row_entries(self):
        result = {"headers": ["Name", "Type"], "rows": [["a", "x"], ["b", "y"]]}
        headers, rows, entries = self.normalize(result)
        self.assertEqual(len(entries), 2)                 # -Count sees 2, not 2 dict keys
        self.assertEqual(entries[0]["attributes"]["Name"], "a")
        self.assertEqual(render_json("print_json", entries)[0]["attributes"]["Name"], "a")
        self.assertEqual(rows, result["rows"])            # originals kept for legacy render

    def test_empty_rows_still_renders_header_only_table(self):
        result = {"headers": ["Name", "Type"], "rows": []}
        headers, rows, entries = self.normalize(result)
        self.assertEqual(entries, [])
        # __init__ keeps this reachable via _header_rows_mode; print_table must
        # still emit the header row rather than nothing.
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            FORMATTER(args(json=False)).print_table(rows, headers)
        self.assertIn("Name", buffer.getvalue())

    def test_ragged_and_duplicate_headers_survive_legacy_render(self):
        rows = [["a", "x", "extra"], ["b"]]
        headers = ["Name", "Name"]
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            FORMATTER(args(json=False)).print_table(rows, headers)
        rendered = buffer.getvalue()
        self.assertIn("extra", rendered)      # trailing cell not dropped
        self.assertIn("a", rendered)


class EntrySelectionTests(unittest.TestCase):
    """Regressions for projecting an ldap3.Entry and for key casing."""

    def _entry(self):
        server = ldap3.Server("fake", get_info=ldap3.ALL)
        conn = ldap3.Connection(server, user="cn=u,dc=e,dc=com", password="p",
                                client_strategy=ldap3.MOCK_SYNC)
        conn.strategy.add_entry("cn=alice,dc=e,dc=com", {
            "objectClass": ["person"], "sn": "alice",
            "givenName": "Alice", "revision": 1,
        })
        conn.bind()
        conn.search("dc=e,dc=com", "(sn=alice)", attributes=["sn", "givenName"])
        return conn.entries[0]

    def test_named_select_projects_an_ldap3_entry(self):
        """Projecting before normalisation silently returned every attribute."""
        out = render_json("print_json", [self._entry()], select=["sn"])
        self.assertEqual(list(out[0]["attributes"]), ["sn"])

    def test_int_select_still_limits_entries(self):
        out = render_json("print_json", [self._entry(), self._entry()], select=1)
        self.assertEqual(len(out), 1)

    def test_selected_keys_keep_the_server_spelling(self):
        out = render_json("print_json", [entry("alice")], select=["samaccountname"])
        self.assertEqual(list(out[0]["attributes"]), ["sAMAccountName"])

    def test_acl_projection_keeps_ace_key_spelling(self):
        out = render_json("print_json", acl_entries(), select=["activedirectoryrights"])
        for projected in out[0]["attributes"]:
            self.assertEqual(list(projected), ["ActiveDirectoryRights"])


class JsonCapabilityTests(unittest.TestCase):
    """Only result-producing commands may request JSON."""

    # command -> the arguments its subparser marks required
    ACTION_COMMANDS = {
        "Invoke-MessageBox": ["-Computer", "host", "-Title", "t", "-Message", "m"],
        "Logoff-Session": ["-Computer", "host"],
        "Remove-NetTerminalSession": ["-Computer", "host"],
        "Restart-Computer": ["-Computer", "host"],
        "Stop-Computer": ["-Computer", "host"],
        "Stop-NetProcess": ["-Computer", "host", "-Pid", "1"],
    }
    ALIAS_ACTIONS = ["Shutdown-Computer", "Reboot-Computer", "Taskkill"]
    RESULT_COMMANDS = {
        "Get-DomainUser": [],
        "Get-DomainObjectAcl": [],
        "Get-DomainController": [],
        "Get-NetSession": ["-Computer", "host"],
        "Get-NetProcess": ["-Computer", "host"],
        "Invoke-Kerberoast": [],
    }

    @staticmethod
    def parse_capturing_stderr(argv):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            parsed = powerview_arg_parse(argv)
        return parsed, stderr.getvalue()

    def test_action_commands_are_not_in_the_allowlist(self):
        for command in list(self.ACTION_COMMANDS) + self.ALIAS_ACTIONS:
            self.assertNotIn(command.casefold(), JSON_CAPABLE_MODULES, command)

    def test_action_commands_reject_the_json_flag(self):
        """-Json must not even parse for commands that assign to `succeed`."""
        for command, required in self.ACTION_COMMANDS.items():
            parsed, stderr = self.parse_capturing_stderr([command] + required + ["-Json"])
            self.assertIsNone(parsed, command)
            # two rejection paths word this differently
            self.assertRegex(stderr.lower(), r"unrecognized arguments?:.*-json", command)

    def test_action_commands_have_no_json_attribute(self):
        """The --json gate also relies on the attribute being absent."""
        for command, required in self.ACTION_COMMANDS.items():
            parsed = powerview_arg_parse([command] + required)
            self.assertIsNotNone(parsed, command)
            self.assertFalse(hasattr(parsed, "json"), command)

    def test_tableview_json_on_an_action_command_is_gated(self):
        """The parser still accepts it; the capability gate is what rejects it."""
        parsed = powerview_arg_parse(["Stop-Computer", "-Computer", "host",
                                      "-TableView", "json"])
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.tableview, "json")
        self.assertNotIn(parsed.module.casefold(), JSON_CAPABLE_MODULES)

    def test_result_commands_are_allowed(self):
        for command, required in self.RESULT_COMMANDS.items():
            self.assertIn(command.casefold(), JSON_CAPABLE_MODULES, command)
            parsed = powerview_arg_parse([command] + required + ["-Json"])
            self.assertIsNotNone(parsed, command)
            self.assertTrue(parsed.json, command)

    def test_non_result_builtins_are_excluded(self):
        for command in ("whoami", "history", "Get-Plugin", "Dump-Schema"):
            self.assertNotIn(command.casefold(), JSON_CAPABLE_MODULES, command)

    # command -> canonical it aliases, for the result-producing aliases
    RESULT_ALIASES = {
        "Get-ADObject": "Get-DomainObject",
        "Get-ObjectAcl": "Get-DomainObjectAcl",
        "Get-ObjectOwner": "Get-DomainObjectOwner",
        "Get-CA": "Get-DomainCA",
        "Get-CATemplate": "Get-DomainCATemplate",
        "Get-DMSA": "Get-DomainDMSA",
        "Get-GMSA": "Get-DomainGMSA",
        "Get-RBCD": "Get-DomainRBCD",
        "Get-SCCM": "Get-DomainSCCM",
        "Get-WDS": "Get-DomainWDS",
        "Get-TrustKey": "Get-DomainTrustKey",
        "Get-GPOLocalGroup": "Get-DomainGPOLocalGroup",
        "Get-GPOSettings": "Get-DomainGPOSettings",
        "Find-ForeignUser": "Get-DomainForeignUser",
        "Find-ForeignGroup": "Get-DomainForeignGroupMember",
        "Invoke-DMSASync": "Invoke-BadSuccessor",
        "tasklist": "Get-NetProcess",
        "qwinsta": "Get-NetTerminalSession",
    }

    @staticmethod
    def _parser_commands():
        """Map parser variable -> every name it registers, aliases included."""
        import re
        with open("powerview/utils/parsers.py", encoding="utf-8") as handle:
            source = handle.read()
        var_to_commands = {}
        pattern = re.compile(r"(\w+)\s*=\s*subparsers\.add_parser\(\s*'([^']+)'([^\n]*)")
        for match in pattern.finditer(source):
            names = [match.group(2)]
            aliases = re.search(r"aliases\s*=\s*\[([^\]]*)\]", match.group(3))
            if aliases:
                names += re.findall(r"'([^']+)'", aliases.group(1))
            var_to_commands.setdefault(match.group(1), []).extend(names)
        json_vars = {m.group(1)
                     for m in re.finditer(r"(\w+)\.add_argument\('-Json'", source)}
        return var_to_commands, json_vars

    def test_allowlist_matches_parsers_that_declare_json(self):
        """Guards against the allowlist drifting from the parser definitions.

        argparse stores the alias the user typed in pv_args.module, so every
        alias of a JSON-capable command must be in the set too.
        """
        var_to_commands, json_vars = self._parser_commands()
        declared = {command.casefold()
                    for var in json_vars for command in var_to_commands.get(var, [])}
        self.assertEqual(declared, set(JSON_CAPABLE_MODULES))

    def test_result_aliases_are_capable_and_accept_json(self):
        """Aliases such as Get-ADObject must not be rejected by the gate."""
        for alias, canonical in self.RESULT_ALIASES.items():
            self.assertIn(alias.casefold(), JSON_CAPABLE_MODULES, alias)
            self.assertIn(canonical.casefold(), JSON_CAPABLE_MODULES, canonical)

    def test_alias_parsers_accept_the_json_flag(self):
        extra = {"tasklist": ["-Computer", "host"], "qwinsta": ["-Computer", "host"]}
        for alias in self.RESULT_ALIASES:
            parsed = powerview_arg_parse([alias] + extra.get(alias, []) + ["-Json"])
            self.assertIsNotNone(parsed, alias)
            self.assertTrue(parsed.json, alias)
            self.assertEqual(parsed.module.casefold(), alias.casefold())

    def test_action_aliases_are_rejected(self):
        for alias in ("Shutdown-Computer", "Reboot-Computer", "taskkill"):
            self.assertNotIn(alias.casefold(), JSON_CAPABLE_MODULES, alias)

    def test_completer_matches_parser_json_support(self):
        """Completions must not advertise -Json where the parser rejects it."""
        from powerview.utils.completer import COMMANDS
        advertised_but_incapable = sorted(
            command for command, flags in COMMANDS.items()
            if "-Json" in flags and command.casefold() not in JSON_CAPABLE_MODULES)
        self.assertEqual(advertised_but_incapable, [])
        capable_without_completion = sorted(
            command for command, flags in COMMANDS.items()
            if command.casefold() in JSON_CAPABLE_MODULES
            and "-TableView" in flags and "-Json" not in flags)
        self.assertEqual(capable_without_completion, [])


if __name__ == "__main__":
    unittest.main()
