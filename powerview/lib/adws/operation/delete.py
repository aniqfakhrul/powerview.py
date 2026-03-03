"""ADWS delete (WS-Transfer Delete) request building and response parsing.

Mirrors ldap3.operation.delete structure:
- delete_operation()          builds Delete SOAP request
- delete_response_to_dict()   parses Delete response
"""

from ..templates import LDAP_DELETE_FSTRING
from .controls import serialize_controls
from .response import parse_soap_response

from uuid import uuid4


# ── Request builder ──────────────────────────────────────────────────

def delete_operation(fqdn, dn, controls=None):
    """Build WS-Transfer Delete SOAP request.

    Mirrors ldap3.operation.delete.delete_operation().

    Args:
        fqdn:     DC fully-qualified domain name
        dn:       DN of the entry to delete
        controls: Optional ldap3 controls

    Returns:
        str: SOAP XML request string
    """
    delete_vars = {
        "fqdn": fqdn,
        "uuid": str(uuid4()),
        "object_ref": dn,
        "controls": serialize_controls(controls),
    }
    request = LDAP_DELETE_FSTRING.format(**delete_vars)
    return request


# ── Response decoder ─────────────────────────────────────────────────

def delete_response_to_dict(xml_string):
    """Parse WS-Transfer Delete response.

    Mirrors ldap3.operation.delete.delete_response_to_dict().

    Args:
        xml_string: Raw SOAP XML response

    Returns:
        dict: Empty on success, contains 'Error'/'ErrorDetail' on fault.
    """
    _root, fault = parse_soap_response(xml_string)
    return fault
