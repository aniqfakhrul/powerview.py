"""ADWS add (WS-Transfer Create) request building and response parsing.

Mirrors ldap3.operation.add structure:
- add_operation()          builds Create SOAP request
- add_response_to_dict()   parses Create response
"""

from ..templates import LDAP_ADD_FSTRING
from .controls import serialize_controls
from .response import parse_soap_response

from ldap3 import SEQUENCE_TYPES
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


# ── Request builder ──────────────────────────────────────────────────

def add_operation(fqdn: str, dn: str, attributes: dict, controls=None):
    """Build WS-Transfer Create SOAP request for adding a new entry.

    Mirrors ldap3.operation.add.add_operation().

    Args:
        fqdn:       DC fully-qualified domain name
        dn:         DN of the new entry
        attributes: Dict of {attribute: value} or {attribute: [values]}
        controls:   Optional ldap3 controls

    Returns:
        str: SOAP XML request string
    """
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
        "controls": serialize_controls(controls),
    }
    request = LDAP_ADD_FSTRING.format(**add_vars)
    return request


# ── Response decoder ─────────────────────────────────────────────────

def add_response_to_dict(xml_string):
    """Parse WS-Transfer Create response.

    Mirrors ldap3.operation.add.add_response_to_dict().

    Args:
        xml_string: Raw SOAP XML response

    Returns:
        dict: Empty on success, contains 'Error'/'ErrorDetail' on fault.
    """
    _root, fault = parse_soap_response(xml_string)
    return fault
