#!/usr/bin/env python3
"""Tests for optional LDAP schema feature resolution."""

import unittest
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import MagicMock

from powerview.lib.resolver import LDAP
from powerview.powerview import PowerView
from powerview.utils.connections import CONNECTION
from powerview.utils.schema import SchemaAttributeResolver, SchemaFeatureVariant


LEGACY_LAPS_ATTRIBUTES = {
    "ms-Mcs-AdmPwd",
    "ms-Mcs-AdmPwdExpirationTime",
}
WINDOWS_LAPS_ATTRIBUTES = {
    "msLAPS-Password",
    "msLAPS-EncryptedPassword",
    "msLAPS-PasswordExpirationTime",
}


def make_schema(attribute_names):
    return SimpleNamespace(
        attribute_types={name: object() for name in attribute_names}
    )


def make_powerview(attribute_names=None):
    powerview = PowerView.__new__(PowerView)
    schema = None if attribute_names is None else make_schema(attribute_names)
    powerview.ldap_server = SimpleNamespace(schema=schema)
    powerview.root_dn = "DC=example,DC=test"
    powerview.args = Namespace(stack_trace=True)

    paged_search = MagicMock(return_value=[])
    powerview.ldap_session = SimpleNamespace(
        extend=SimpleNamespace(
            standard=SimpleNamespace(paged_search=paged_search)
        )
    )
    return powerview, paged_search


def run_laps_query(attribute_names):
    powerview, paged_search = make_powerview(attribute_names)
    result = powerview.get_domaincomputer(args=Namespace(laps=True))
    return result, paged_search


class SchemaAttributeResolverTests(unittest.TestCase):
    def test_matching_is_case_insensitive_and_preserves_requested_names(self):
        resolver = SchemaAttributeResolver(
            make_schema(["msLAPS-Password", "cn"])
        )

        self.assertTrue(resolver.available)
        self.assertTrue(resolver.supports("MSLAPS-PASSWORD"))
        self.assertEqual(
            resolver.supported_attributes(
                ["MSLAPS-PASSWORD", "missing", "mslaps-password", "CN"]
            ),
            ("MSLAPS-PASSWORD", "CN"),
        )

    def test_feature_resolution_builds_a_reusable_presence_filter(self):
        variants = (
            SchemaFeatureVariant("first", "firstMarker", ("firstValue",)),
            SchemaFeatureVariant("second", "secondMarker", ("secondValue",)),
        )
        resolver = SchemaAttributeResolver(
            make_schema(["firstMarker", "firstValue", "secondMarker"])
        )

        resolved = resolver.resolve_feature(variants)

        self.assertEqual(
            resolved.presence_filter,
            "(|(firstMarker=*)(secondMarker=*))",
        )
        self.assertEqual(
            resolved.properties,
            ("firstMarker", "firstValue", "secondMarker"),
        )


class LapsSchemaTests(unittest.TestCase):
    def assert_query(self, paged_search, expected_filter, expected_properties):
        paged_search.assert_called_once()
        call = paged_search.call_args
        self.assertEqual(call.args[1], expected_filter)
        self.assertTrue(expected_properties.issubset(set(call.kwargs["attributes"])))

    def test_legacy_laps_schema_uses_only_legacy_attributes(self):
        result, paged_search = run_laps_query(
            {"cn", *LEGACY_LAPS_ATTRIBUTES}
        )

        self.assertEqual(result, [])
        self.assert_query(
            paged_search,
            "(&(objectClass=computer)(ms-Mcs-AdmPwdExpirationTime=*))",
            LEGACY_LAPS_ATTRIBUTES,
        )
        self.assertTrue(
            WINDOWS_LAPS_ATTRIBUTES.isdisjoint(
                set(paged_search.call_args.kwargs["attributes"])
            )
        )

    def test_windows_laps_schema_uses_only_windows_attributes(self):
        result, paged_search = run_laps_query(
            {"cn", *WINDOWS_LAPS_ATTRIBUTES}
        )

        self.assertEqual(result, [])
        self.assert_query(
            paged_search,
            "(&(objectClass=computer)(msLAPS-PasswordExpirationTime=*))",
            WINDOWS_LAPS_ATTRIBUTES,
        )
        self.assertTrue(
            LEGACY_LAPS_ATTRIBUTES.isdisjoint(
                set(paged_search.call_args.kwargs["attributes"])
            )
        )

    def test_both_laps_schemas_are_combined(self):
        result, paged_search = run_laps_query(
            {"cn", *LEGACY_LAPS_ATTRIBUTES, *WINDOWS_LAPS_ATTRIBUTES}
        )

        self.assertEqual(result, [])
        self.assert_query(
            paged_search,
            "(&(objectClass=computer)(|(ms-Mcs-AdmPwdExpirationTime=*)"
            "(msLAPS-PasswordExpirationTime=*)))",
            LEGACY_LAPS_ATTRIBUTES | WINDOWS_LAPS_ATTRIBUTES,
        )

    def test_missing_laps_schema_returns_without_searching(self):
        powerview, paged_search = make_powerview({"cn"})

        with self.assertLogs(level="WARNING") as logs:
            result = powerview.get_domaincomputer(args=Namespace(laps=True))

        self.assertEqual(result, [])
        paged_search.assert_not_called()
        self.assertIn("does not advertise LAPS attributes", logs.output[0])

    def test_unavailable_schema_returns_without_searching(self):
        powerview, paged_search = make_powerview()

        with self.assertLogs(level="WARNING") as logs:
            result = powerview.get_domaincomputer(args=Namespace(laps=True))

        self.assertEqual(result, [])
        paged_search.assert_not_called()
        self.assertIn("did not provide schema information", logs.output[0])

    def test_windows_laps_expiration_uses_filetime_formatter(self):
        formatter = CONNECTION._get_formatter()

        self.assertIs(
            formatter["msLAPS-PasswordExpirationTime"],
            LDAP.ldap2datetime,
        )


if __name__ == "__main__":
    unittest.main()
