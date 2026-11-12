import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from powerview.modules.vulnerabilities import VulnerabilityDetector
from powerview.lib.resolver import LDAP


class VulnerabilityRuleTests(unittest.TestCase):
    def detector(self, rules):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / 'vulns.json'
        path.write_text(json.dumps(rules))
        return VulnerabilityDetector(str(path)), path

    def rule(self, condition, **extra):
        return {'description': 'Custom check', 'severity': 'low',
                'rules': [{'attribute': 'description', 'condition': condition}], **extra}

    def test_custom_rules_are_loaded_without_rewriting_the_file(self):
        rules = {'custom': self.rule('exists')}
        detector, path = self.detector(rules)
        self.assertEqual(detector.rules, rules)
        self.assertEqual(json.loads(path.read_text()), rules)
        self.assertEqual(detector.detect_vulnerabilities({'DESCRIPTION': 'test'})[0]['name'], 'custom')

    def test_invalid_file_is_preserved_while_defaults_are_used_in_memory(self):
        detector, path = self.detector({})
        for contents in ('{broken', '[]'):
            path.write_text(contents)
            detector = VulnerabilityDetector(str(path))
            self.assertEqual(path.read_text(), contents)
            self.assertIsInstance(detector.rules, dict)
            self.assertTrue(detector.rules)

    def test_missing_attribute_can_match_not_exists(self):
        detector, _ = self.detector({'missing': self.rule('not_exists')})
        self.assertEqual(detector.detect_vulnerabilities({})[0]['name'], 'missing')

    def test_negated_exclusion_and_legacy_exclusion_are_honoured(self):
        for key in ('exclusion', 'exclusions'):
            exclusion = {'attribute': 'description', 'condition': 'equals', 'value': 'safe', 'negate': True}
            rule = self.rule('exists', **{key: exclusion if key == 'exclusion' else [exclusion]})
            detector, _ = self.detector({'custom': rule})
            self.assertIsNone(detector.detect_vulnerabilities({'description': 'other'}))
            self.assertTrue(detector.detect_vulnerabilities({'description': 'safe'}))

    def test_age_conditions_accept_timezone_aware_directory_values(self):
        detector = VulnerabilityDetector.__new__(VulnerabilityDetector)
        old = datetime.now(timezone.utc) - timedelta(days=100)
        recent = datetime.now(timezone(timedelta(hours=4))) - timedelta(days=1)
        self.assertTrue(detector._check_condition(old, 'older_than', 90))
        self.assertTrue(detector._check_condition(recent, 'newer_than', 7))

    def test_age_conditions_accept_the_actual_ldap_formatter_output(self):
        detector = VulnerabilityDetector.__new__(VulnerabilityDetector)
        old = datetime.now() - timedelta(days=100)
        value = LDAP.resolve_generalized_time(old)
        self.assertTrue(detector._check_condition(value, 'older_than', 90))
        recent = datetime.now(timezone.utc) - timedelta(days=1)
        self.assertIn('ago', LDAP.resolve_generalized_time(recent))
