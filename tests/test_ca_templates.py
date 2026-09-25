import unittest
from unittest.mock import MagicMock, patch

from powerview.powerview import PowerView


def template(cn):
	return {'attributes': {
		'cn': cn, 'name': cn, 'objectGUID': '{%s}' % cn,
		'distinguishedName': f'CN={cn},CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=test',
	}}


def authority(name, published):
	return {'attributes': {'name': name, 'objectGUID': '{%s}' % name, 'certificateTemplates': published}}


class TemplatePublishingTests(unittest.TestCase):
	def run_templates(self, authorities, findings=None, **kwargs):
		powerview = PowerView.__new__(PowerView)
		powerview.root_dn = 'DC=example,DC=test'
		powerview.whoami = 'EXAMPLE\\tester'
		powerview._resolve_current_user = MagicMock(return_value=[{'attributes': {'objectSid': 'S-1-5-21-1-2-3-1105'}}])
		powerview._is_cross_trust_user = MagicMock(return_value=False)
		powerview.ldap_session = MagicMock()
		powerview.convertfrom_sid = lambda sid: f'EXAMPLE\\{sid}'

		enum = MagicMock()
		enum.get_certificate_templates.return_value = [template('Alpha'), template('Bravo'), template('Charlie')]
		enum.fetch_enrollment_services.return_value = authorities
		enum.get_issuance_policies.return_value = []

		parsed = MagicMock()
		parsed.parse_dacl.return_value = {key: [] for key in ['Enrollment Rights', 'Extended Rights', 'Write Owner', 'Write Dacl', 'Write Property']}
		parsed.get_owner_sid.return_value = 'S-1-5-21-1-2-3-500'
		parsed.check_vulnerable_template.return_value = findings or {}

		with patch('powerview.powerview.CAEnum', return_value=enum), patch('powerview.powerview.PARSE_TEMPLATE', return_value=parsed):
			entries = powerview.get_domaincatemplate(**kwargs)
		return {entry['attributes']['cn']: entry['attributes'] for entry in entries}

	def test_every_publishing_authority_is_listed_and_enables_the_template(self):
		results = self.run_templates([
			authority('CA-One', ['Alpha', 'Bravo']),
			authority('CA-Two', ['bravo']),
		])
		self.assertEqual(results['Alpha']['Certificate Authorities'], ['CA-One'])
		self.assertEqual(results['Bravo']['Certificate Authorities'], ['CA-One', 'CA-Two'])
		self.assertEqual(results['Charlie']['Certificate Authorities'], [])
		self.assertEqual({cn: attributes['Enabled'] for cn, attributes in results.items()}, {'Alpha': True, 'Bravo': True, 'Charlie': False})

	def test_template_published_only_by_a_later_authority_is_enabled(self):
		results = self.run_templates([authority('CA-One', ['Alpha']), authority('CA-Two', 'Charlie')])
		self.assertTrue(results['Charlie']['Enabled'])
		self.assertEqual(results['Charlie']['Certificate Authorities'], ['CA-Two'])

	def test_finding_labels_are_kept_with_and_without_sid_resolution(self):
		findings = {'Finding-A': ['S-1-5-21-1-2-3-500', 'S-1-5-21-1-2-3-512'], 'Finding-B': 'note'}
		plain = self.run_templates([authority('CA-One', ['Alpha'])], findings=findings)
		self.assertEqual(plain['Alpha']['Vulnerable'], [
			"Finding-A - 'S-1-5-21-1-2-3-500' and 'S-1-5-21-1-2-3-512'",
			'Finding-B - note',
		])
		resolved = self.run_templates([authority('CA-One', ['Alpha'])], findings=findings, resolve_sids=True)
		self.assertTrue(resolved['Alpha']['Vulnerable'][0].startswith("Finding-A - 'EXAMPLE\\S-1-5-21-1-2-3-500'"))


if __name__ == '__main__':
	unittest.main()
