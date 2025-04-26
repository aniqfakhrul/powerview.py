from ..templates import LDAP_ADD_FSTRING

from ldap3 import SEQUENCE_TYPES
from ldap3.protocol.rfc4511 import LDAPDN
from uuid import uuid4

ATTRIBUTE_TYPE_AND_VALUE_FSTRING = """<AttributeTypeAndValue>
    <AttributeType>{attribute}</AttributeType>
    <AttributeValue>
        <ad:value xsi:type="xsd:string">{value}</ad:value>
    </AttributeValue>
</AttributeTypeAndValue>"""

def get_rdn(dn: str):
    return dn.split(',')[0]

def get_parent_dn(dn: str):
    return ','.join(dn.split(',')[1:])

def add_operation(fqdn: str, dn: str,  attributes: dict):
    attr_xml = ""

    parent_dn = get_parent_dn(dn)
    rdn = get_rdn(dn)
    if parent_dn:
        attr_xml += ATTRIBUTE_TYPE_AND_VALUE_FSTRING.format(attribute="ad:container-hierarchy-parent", value=parent_dn)

    if rdn:
        attr_xml += ATTRIBUTE_TYPE_AND_VALUE_FSTRING.format(attribute="ad:relativeDistinguishedName", value=rdn)
    
    for pos, attribute in enumerate(attributes):
        if isinstance(attributes[attribute], SEQUENCE_TYPES):
            for index, value in enumerate(attributes[attribute]):
                attr_xml += ATTRIBUTE_TYPE_AND_VALUE_FSTRING.format(attribute=f"addata:{attribute}", value=value)
        else:
            attr_xml += ATTRIBUTE_TYPE_AND_VALUE_FSTRING.format(attribute=f"addata:{attribute}", value=attributes[attribute])
    add_vars = {
        "fqdn": fqdn,
        "uuid": str(uuid4()),
        "attributes": attr_xml.strip(),
    }
    request = LDAP_ADD_FSTRING.format(**add_vars)
    return request

def add_response_to_dict(response):
    pass