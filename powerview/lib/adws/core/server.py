from .. import ENUMERATION
from ldap3 import DSA, SCHEMA, ALL, BASE, SUBTREE, SEQUENCE_TYPES
from ldap3.protocol.rfc4512 import SchemaInfo, DsaInfo
from ldap3.protocol.formatters.standard import format_attribute_values

class Server(object):
    def __init__(self, host, ssl=False, port=9389, get_info=ALL, formatter=None, validator=None, resource=ENUMERATION):
        self.host = host
        self.port = port
        self.ssl = ssl
        self.custom_formatter = formatter
        self.custom_validator = validator
        self.resource = resource
        self.get_info = get_info
        self._dsa_info = None
        self._schema_info = None
    
    def get_info_from_server(self, connection):
        """
        reads info from DSE and from subschema
        """
        if connection:
            if self.get_info in [DSA, ALL]:
                self._get_dsa_info(connection)
            if self.get_info in [SCHEMA, ALL]:
                self._get_schema_info(connection)

    def _get_dsa_info(self, connection):
        """
        Retrieve DSE operational attribute as per RFC4512 (5.1) via ADWS.
        Querying RootDSE (empty base, base scope) for server info.
        """
        # Attributes commonly available via ADWS RootDSE
        # Requesting only attributes essential for PowerView initialization
        attributes_to_request = [
            'rootDomainNamingContext',       # Needed for forest_dn
            'defaultNamingContext',        # Needed for root_dn
            'configurationNamingContext',  # Needed for configuration_dn
            'ldapServiceName',           # Needed for flatName
            'dnsHostName',               # Needed for dc_dnshostname
            'supportedControl',          # Removed - less likely to be essential for init
            'supportedExtension',
            'supportedCapabilities',
            'supportedLDAPVersion',
            'supportedSASLMechanisms',
            'subschemaSubentry',         # Needed for _get_schema_info, but not init
            'serverName',
            'domainControllerFunctionality',
            'domainFunctionality',
            'forestFunctionality',
            'highestCommittedUSN',
            'isSynchronized',
            'isGlobalCatalogReady',
            'currentTime'
        ]
        response = connection.search(search_base='',
                                   search_filter='(objectClass=*)',
                                   search_scope=BASE,
                                   attributes=attributes_to_request)
        self._dsa_info = DsaInfo(response[0]['attributes'], response[0]['raw_attributes'])

    def _get_schema_info(self, connection, entry=''):
        """
        Retrieve schema from subschemaSubentry DSE attribute, per RFC
        4512 (4.4 and 5.1); entry = '' means DSE via ADWS.
        """
        schema_entry = None
        if self._dsa_info and entry == '':  # subschemaSubentry already present in dsaInfo
            if isinstance(self._dsa_info.schema_entry, SEQUENCE_TYPES):
                schema_entry = self._dsa_info.schema_entry[0] if self._dsa_info.schema_entry else None
            else:
                schema_entry = self._dsa_info.schema_entry if self._dsa_info.schema_entry else None
        else:
            result = connection.search(entry, '(objectClass=*)', BASE, attributes=['subschemaSubentry'], get_operational_attributes=True)
            if result and 'subschemaSubentry' in result[0]['raw_attributes']:
                if len(result[0]['raw_attributes']['subschemaSubentry']) > 0:
                    schema_entry = result[0]['raw_attributes']['subschemaSubentry'][0]
        
        if schema_entry:
            response = connection.search(schema_entry,
                                        search_filter='(objectClass=subschema)',
                                        search_scope=BASE,
                                        attributes=[
                                            'objectClasses',
                                            'attributeTypes',
                                            'createTimestamp',
                                            'modifyTimestamp'
                                        ])
            self._schema_info = SchemaInfo(schema_entry, response[0]['attributes'], response[0]['raw_attributes'])
            if self._schema_info:  # if schema is valid tries to apply formatter to the "other" dict with raw values for schema and info
                for attribute in self._schema_info.other:
                    self._schema_info.other[attribute] = format_attribute_values(self._schema_info, attribute, self._schema_info.raw[attribute], self.custom_formatter)
                if self._dsa_info:  # try to apply formatter to the "other" dict with dsa info raw values
                    for attribute in self._dsa_info.other:
                        self._dsa_info.other[attribute] = format_attribute_values(self._schema_info, attribute, self._dsa_info.raw[attribute], self.custom_formatter)

    @property
    def info(self):
        return self._dsa_info

    @property
    def schema(self):
        return self._schema_info