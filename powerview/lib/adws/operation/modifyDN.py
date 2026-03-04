"""ADWS ModifyDN request building and response parsing.

Mirrors ldap3.operation.modifyDn structure:
- modify_dn_operation()          builds ModifyDN SOAP request
- modify_dn_response_to_dict()   parses ModifyDN response
"""

from ..templates import LDAP_MODIFY_DN_FSTRING
from .controls import serialize_controls
from .response import parse_soap_response

from uuid import uuid4
from xml.sax.saxutils import escape as xml_escape


# ── Request builder ──────────────────────────────────────────────────

def modify_dn_operation(fqdn, dn, new_relative_dn, delete_old_rdn=True,
                        new_superior=None, controls=None):
    """Build ModifyDN SOAP request.

    Mirrors ldap3.operation.modifyDn.modify_dn_operation().

    Args:
        fqdn:             DC fully-qualified domain name
        dn:               Current DN of the entry
        new_relative_dn:  New RDN
        delete_old_rdn:   Whether to delete the old RDN (default True)
        new_superior:     Optional new parent DN for moving the entry
        controls:         Optional ldap3 controls

    Returns:
        str: SOAP XML request string
    """
    modify_dn_vars = {
        "fqdn": fqdn,
        "uuid": str(uuid4()),
        "object_ref": xml_escape(dn),
        "relative_dn": xml_escape(new_relative_dn),
        "delete_old_rdn": delete_old_rdn,
        "new_superior": xml_escape(new_superior) if new_superior is not None else new_superior,
        "controls": serialize_controls(controls),
    }
    return LDAP_MODIFY_DN_FSTRING.format(**modify_dn_vars)


# ── Response decoder ─────────────────────────────────────────────────

def modify_dn_response_to_dict(xml_string):
    """Parse ModifyDN response.

    Mirrors ldap3.operation.modifyDn.modify_dn_response_to_dict().

    Args:
        xml_string: Raw SOAP XML response

    Returns:
        dict: Empty on success, contains 'Error'/'ErrorDetail' on fault.
    """
    _root, fault = parse_soap_response(xml_string)
    return fault
