"""ADWS CustomAction (AccountManagement) request building and response parsing.

Implements SetPassword and ChangePassword operations per MS-ADCAP
(Active Directory Custom Actions Protocol).

- set_password_operation()        builds SetPassword SOAP request
- change_password_operation()     builds ChangePassword SOAP request
- password_response_to_dict()     parses SetPassword/ChangePassword response
"""

from xml.sax.saxutils import escape as xml_escape

from ..templates import SET_PASSWORD_FSTRING, CHANGE_PASSWORD_FSTRING
from .response import parse_soap_response

from uuid import uuid4


# ── Request builders ─────────────────────────────────────────────────

def set_password_operation(fqdn, account_dn, new_password, partition_dn):
    """Build AccountManagement SetPassword SOAP request.

    Args:
        fqdn:         DC fully-qualified domain name
        account_dn:   DN of target account
        new_password: New password to set
        partition_dn: Domain partition DN (e.g. DC=wonka,DC=lab)

    Returns:
        str: SOAP XML request string
    """
    return SET_PASSWORD_FSTRING.format(
        uuid=str(uuid4()),
        fqdn=fqdn,
        account_dn=xml_escape(account_dn),
        new_password=xml_escape(new_password),
        partition_dn=xml_escape(partition_dn),
    )


def change_password_operation(fqdn, account_dn, old_password, new_password,
                              partition_dn):
    """Build AccountManagement ChangePassword SOAP request.

    Args:
        fqdn:         DC fully-qualified domain name
        account_dn:   DN of target account
        old_password: Current password
        new_password: New password to set
        partition_dn: Domain partition DN (e.g. DC=wonka,DC=lab)

    Returns:
        str: SOAP XML request string
    """
    return CHANGE_PASSWORD_FSTRING.format(
        uuid=str(uuid4()),
        fqdn=fqdn,
        account_dn=xml_escape(account_dn),
        old_password=xml_escape(old_password),
        new_password=xml_escape(new_password),
        partition_dn=xml_escape(partition_dn),
    )


# ── Response decoder ─────────────────────────────────────────────────

def password_response_to_dict(xml_string):
    """Parse SetPassword/ChangePassword response.

    Returns:
        dict: Empty on success, contains 'Error'/'ErrorDetail' on fault.
    """
    _root, fault = parse_soap_response(xml_string)
    return fault
