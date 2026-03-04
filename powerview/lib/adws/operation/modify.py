"""ADWS modify (WS-Transfer Put) request building and response parsing.

Mirrors ldap3.operation.modify structure:
- modify_operation()          builds Put SOAP request
- modify_response_to_dict()   parses Put response
"""

from ldap3 import SEQUENCE_TYPES, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT
from ldap3.protocol.rfc4511 import AttributeDescription, PartialAttribute, Vals, Change, Operation, Changes
from ldap3.protocol.convert import prepare_for_sending, validate_attribute_value

from ..templates import LDAP_PUT_FSTRING
from .controls import serialize_controls
from .response import parse_soap_response

from uuid import uuid4
from base64 import b64encode
from xml.sax.saxutils import escape as xml_escape

def _serialize_value(value):
    """Serialize a single attribute value to an <ad:value> XML element."""
    if isinstance(value, (bytes, bytearray)):
        return f'<ad:value xsi:type="xsd:base64Binary">{b64encode(value).decode("ascii")}</ad:value>'
    return f'<ad:value xsi:type="xsd:string">{xml_escape(str(value))}</ad:value>'


change_table = {MODIFY_ADD: 0,
                MODIFY_DELETE: 1,
                MODIFY_REPLACE: 2,
                MODIFY_INCREMENT: 3,
                0: 0,
                1: 1,
                2: 2,
                3: 3}


# ── Request builder ──────────────────────────────────────────────────

def modify_operation(fqdn, dn, changes, auto_encode, schema=None,
                     validator=None, check_names=False, controls=None):
    """Build WS-Transfer Put SOAP request for modifying attributes.

    Mirrors ldap3.operation.modify.modify_operation().

    Args:
        fqdn:        DC fully-qualified domain name
        dn:          DN of object to modify
        changes:     Dict of {attribute: [(operation, [values]), ...]}
        auto_encode: Auto-encode attribute values
        schema:      Optional ldap3 schema for validation
        validator:   Optional custom validator
        check_names: Validate attribute names against schema
        controls:    Optional ldap3 controls

    Returns:
        str: SOAP XML request string
    """
    # changes is a dictionary in the form {'attribute': [(operation, [val1, ...]), ...], ...}
    # operation is 0 (add), 1 (delete), 2 (replace), 3 (increment)
    # increment as per RFC4525
    mRequest: str = ""
    change_list = Changes()
    pos = 0
    for attribute in changes:
        for change_operation in changes[attribute]:
            partial_attribute = PartialAttribute()
            partial_attribute['type'] = AttributeDescription(attribute)
            partial_attribute['vals'] = Vals()
            if isinstance(change_operation[1], SEQUENCE_TYPES):
                for index, value in enumerate(change_operation[1]):
                    partial_attribute['vals'].setComponentByPosition(index, prepare_for_sending(validate_attribute_value(schema, attribute, value, auto_encode, validator, check_names=check_names)))
            else:
                partial_attribute['vals'].setComponentByPosition(0, prepare_for_sending(validate_attribute_value(schema, attribute, change_operation[1], auto_encode, validator, check_names=check_names)))
            change = Change()
            change['operation'] = Operation(change_table[change_operation[0]])
            change['modification'] = partial_attribute

            change_list[pos] = change
            pos += 1

        for idx in range(len(change_list)):
                change = change_list[idx]
                operation = change['operation']
                attribute = str(change['modification']['type'])
                vals = change['modification']['vals']

                mRequest += f"""<da:ModifyRequest Dialect="http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">
            <da:Change Operation="{operation}">
                <da:AttributeType>addata:{attribute}</da:AttributeType>
                <da:AttributeValue>"""

                for v in vals:
                    mRequest += f"""
                    {_serialize_value(v)}"""

                mRequest += f"""
                </da:AttributeValue>
            </da:Change>
        </da:ModifyRequest>
        """

    put_vars = {
        "object_ref": xml_escape(dn),
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "attributes": mRequest,
        "controls": serialize_controls(controls),
    }
    return LDAP_PUT_FSTRING.format(**put_vars)


# ── Response decoder ─────────────────────────────────────────────────

def modify_response_to_dict(xml_string):
    """Parse WS-Transfer Put response.

    Mirrors ldap3.operation.modify.modify_response_to_dict().

    Args:
        xml_string: Raw SOAP XML response

    Returns:
        dict: Empty on success, contains 'Error'/'ErrorDetail' on fault.
    """
    _root, fault = parse_soap_response(xml_string)
    return fault
