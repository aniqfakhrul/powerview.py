import unittest
from argparse import Namespace
from types import SimpleNamespace

from ldap3.protocol.rfc4512 import AttributeTypeInfo, DitContentRuleInfo, ObjectClassInfo
from ldap3.utils.ciDict import CaseInsensitiveDict

from powerview.utils.schema import SchemaCatalog
from powerview.web.api.server import APIServer

GENERALIZED_TIME = '1.3.6.1.4.1.1466.115.121.1.24'
DN = '1.3.6.1.4.1.1466.115.121.1.12'
INTEGER = '1.3.6.1.4.1.1466.115.121.1.27'
LARGE_INTEGER = '1.2.840.113556.1.4.906'
OCTET_STRING = '1.3.6.1.4.1.1466.115.121.1.40'
STRING = '1.3.6.1.4.1.1466.115.121.1.15'


def attribute(name, syntax=STRING, single=True, oid=None):
    return AttributeTypeInfo(oid=oid, name=[name], syntax=syntax, single_value=single)


def object_class(name, superior=None, must=(), may=()):
    return ObjectClassInfo(name=[name], superior=superior, must_contain=list(must), may_contain=list(may))


def fake_schema():
    attributes = CaseInsensitiveDict()
    for info in (
        attribute('objectClass', single=False), attribute('cn'), attribute('description'),
        attribute('whenCreated', GENERALIZED_TIME), attribute('manager', DN),
        attribute('userAccountControl', INTEGER), attribute('pwdLastSet', LARGE_INTEGER),
        attribute('objectSid', OCTET_STRING, oid='1.2.840.113556.1.4.146'), attribute('objectGUID', OCTET_STRING, oid='1.2.840.113556.1.4.2'), attribute('userCertificate', OCTET_STRING, single=False), attribute('memberOf', DN, single=False),
        attribute('sAMAccountName'), attribute('mail'), attribute('msLAPS-PasswordExpirationTime', LARGE_INTEGER), attribute('tokenGroups', OCTET_STRING, single=False),
    ):
        attributes[info.name[0]] = info
    classes = CaseInsensitiveDict()
    for info in (
        object_class('top', must=['objectClass'], may=['description', 'whenCreated']),
        object_class('person', ['top'], must=['cn']),
        object_class('user', ['person'], may=['manager', 'userAccountControl', 'pwdLastSet', 'objectSid', 'objectGUID', 'userCertificate', 'memberOf', 'tokenGroups', 'msLAPS-PasswordExpirationTime']),
        object_class('securityPrincipal', may=['sAMAccountName']),
        object_class('mailRecipient', may=['mail']),
    ):
        classes[info.name[0]] = info
    rules = CaseInsensitiveDict()
    rules['user'] = DitContentRuleInfo(name=['user'], auxiliary_classes=['securityPrincipal', 'mailRecipient'])
    return SimpleNamespace(attribute_types=attributes, object_classes=classes, dit_content_rules=rules)


class SchemaCatalogTests(unittest.TestCase):
    def test_class_attributes_include_inherited_and_auxiliary_with_kinds(self):
        attributes = {item.name: item for item in SchemaCatalog(fake_schema()).class_attributes('USER')}
        self.assertEqual(list(attributes), sorted(attributes, key=str.casefold))
        self.assertEqual(set(attributes), {
            'cn', 'description', 'mail', 'manager', 'memberOf', 'objectClass', 'objectGUID', 'objectSid', 'userCertificate',
            'pwdLastSet', 'sAMAccountName', 'userAccountControl', 'whenCreated', 'msLAPS-PasswordExpirationTime',
        })
        self.assertEqual(attributes['whenCreated'].kind, 'time')
        self.assertEqual(attributes['pwdLastSet'].kind, 'time')
        self.assertEqual(attributes['msLAPS-PasswordExpirationTime'].kind, 'time')
        self.assertEqual(attributes['manager'].kind, 'dn')
        self.assertEqual(attributes['userAccountControl'].kind, 'integer')
        self.assertEqual(attributes['objectSid'].kind, 'sid')
        self.assertEqual(attributes['objectGUID'].kind, 'guid')
        self.assertEqual(attributes['userCertificate'].kind, 'binary')
        self.assertEqual(attributes['mail'].kind, 'text')
        self.assertFalse(attributes['memberOf'].single_valued)
        self.assertTrue(attributes['cn'].single_valued)

    def test_missing_schema_or_class(self):
        self.assertFalse(SchemaCatalog(None).available)
        self.assertEqual(SchemaCatalog(None).class_attributes('user'), ())
        self.assertEqual(SchemaCatalog(fake_schema()).class_attributes('computer'), ())


class SchemaAttributesEndpointTests(unittest.TestCase):
    def make_server(self, schema):
        return APIServer(SimpleNamespace(
            flatName='EXAMPLE', ldap_server=SimpleNamespace(schema=schema),
            args=Namespace(web_auth=None, username='tester', ldap_address='dc.example.test'),
        ))

    def test_endpoint_lists_class_attributes_and_caches(self):
        schema = fake_schema()
        server = self.make_server(schema)
        with server.app.test_client() as client:
            first = client.get('/api/schema/attributes?class=user')
            self.assertEqual(first.status_code, 200)
            body = first.get_json()
            self.assertTrue(body['available'])
            self.assertIn({'name': 'manager', 'kind': 'dn', 'singleValued': True}, body['attributes'])
            schema.object_classes['user'].may_contain.append('mail')
            schema.object_classes.pop('mailRecipient')
            self.assertEqual(client.get('/api/schema/attributes?class=User').get_json(), body)

    def test_endpoint_rejects_invalid_and_unknown_classes(self):
        server = self.make_server(fake_schema())
        with server.app.test_client() as client:
            self.assertEqual(client.get('/api/schema/attributes').status_code, 400)
            self.assertEqual(client.get('/api/schema/attributes?class=user)(cn=*').status_code, 400)
            self.assertEqual(client.get('/api/schema/attributes?class=computer').status_code, 404)

    def test_endpoint_reports_unavailable_schema(self):
        server = self.make_server(None)
        with server.app.test_client() as client:
            response = client.get('/api/schema/attributes?class=user')
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json(), {'available': False, 'class': 'user', 'attributes': []})


if __name__ == '__main__':
    unittest.main()
