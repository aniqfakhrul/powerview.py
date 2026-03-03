"""ADWS search (WS-Enumeration) request building and response parsing.

Mirrors ldap3.operation.search structure:
- search_operation()                    builds Enumerate SOAP request
- search_pull_operation()               builds Pull SOAP request
- search_enumerate_response_to_dict()   parses Enumerate response
- search_pull_response_to_dict()        parses Pull response with entries
"""

from ..templates import LDAP_QUERY_FSTRING, LDAP_PULL_FSTRING, NAMESPACES
from ..error import ADWSError
from .controls import serialize_controls
from .response import parse_soap_response
from powerview.utils.helpers import IDict

from ldap3 import ALL_ATTRIBUTES, NO_ATTRIBUTES, ALL_OPERATIONAL_ATTRIBUTES, BASE, LEVEL, SUBTREE

from uuid import uuid4
import base64
import logging

# ldap3 scope constants → ADWS scope strings (MS-ADDM 2.3.2)
_SCOPE_MAP = {
    BASE: "Base",
    LEVEL: "OneLevel",
    SUBTREE: "Subtree",
    "BASE": "Base",
    "LEVEL": "OneLevel",
    "SUBTREE": "Subtree",
}


# ── Request builders ─────────────────────────────────────────────────

def search_operation(fqdn, search_base, search_filter, search_scope,
                     attributes, controls=None):
    """Build WS-Enumeration Enumerate SOAP request.

    Mirrors ldap3.operation.search.search_operation().

    Args:
        fqdn:          DC fully-qualified domain name
        search_base:   LDAP search base DN
        search_filter: LDAP filter string
        search_scope:  Search scope (Base/Level/Subtree)
        attributes:    List of attribute names to return
        controls:      Optional ldap3 controls (serialized into SOAP)

    Returns:
        str: SOAP XML request string
    """
    # Build <ad:Selection> block.
    # Per MS-WSTIM 3.3.5.5.1: omitting <ad:Selection> returns all attributes.
    if ALL_ATTRIBUTES in attributes:
        selection_xml = ""
    elif NO_ATTRIBUTES in attributes:
        selection_xml = (
            '<ad:Selection Dialect='
            '"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">'
            '<ad:SelectionProperty>ad:distinguishedName</ad:SelectionProperty>'
            '</ad:Selection>'
        )
    else:
        props = '<ad:SelectionProperty>ad:distinguishedName</ad:SelectionProperty>\n'
        for attr in attributes:
            if attr == ALL_OPERATIONAL_ATTRIBUTES:
                continue
            props += (
                '<ad:SelectionProperty>addata:{attr}</ad:SelectionProperty>\n'
                .format(attr=attr)
            )
        selection_xml = (
            '<ad:Selection Dialect='
            '"http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath-Level-1">'
            + props +
            '</ad:Selection>'
        )

    query_vars = {
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "query": search_filter,
        "selection": selection_xml,
        "search_base": search_base,
        "search_scope": _SCOPE_MAP.get(search_scope, search_scope),
        "controls": serialize_controls(controls),
    }
    return LDAP_QUERY_FSTRING.format(**query_vars)


def search_pull_operation(fqdn, enum_ctx, controls=None):
    """Build WS-Enumeration Pull SOAP request.

    Args:
        fqdn:      DC fully-qualified domain name
        enum_ctx:  EnumerationContext from Enumerate or previous Pull response
        controls:  Optional ldap3 controls

    Returns:
        str: SOAP XML request string
    """
    pull_vars = {
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "enum_ctx": enum_ctx,
        "controls": serialize_controls(controls),
    }
    return LDAP_PULL_FSTRING.format(**pull_vars)


# ── Response decoders ────────────────────────────────────────────────

def search_enumerate_response_to_dict(xml_string):
    """Parse WS-Enumeration Enumerate response.

    Extracts the EnumerationContext needed to start pulling results.
    Mirrors the initial phase of ldap3's search response handling.

    Args:
        xml_string: Raw SOAP XML response

    Returns:
        dict with 'EnumerationContext' (and optionally 'Expires') keys

    Raises:
        ADWSError: On SOAP fault or missing EnumerationContext
    """
    root, fault = parse_soap_response(xml_string)
    if fault:
        raise ADWSError(xml_string)

    result = {}

    enum_context = root.find(".//wsen:EnumerationContext", NAMESPACES)
    if enum_context is not None and enum_context.text:
        result["EnumerationContext"] = enum_context.text
    else:
        raise ADWSError("EnumerationContext not found in Enumerate response")

    expires = root.find(".//wsen:Expires", NAMESPACES)
    if expires is not None and expires.text:
        result["Expires"] = expires.text

    return result


def search_pull_response_to_dict(xml_string, attributes=None):
    """Parse WS-Enumeration Pull response.

    Mirrors ldap3.operation.search.search_result_entry_response_to_dict()
    for entry parsing, plus enumeration state tracking.

    Args:
        xml_string: Raw SOAP XML response
        attributes: List of requested attribute names (for filtering)

    Returns:
        dict with keys:
        - 'entries': list of entry dicts (dn, attributes, raw_attributes, type)
        - 'EnumerationContext': str (session handle for next pull)
        - 'EndOfSequence': bool (True when server has no more results)
        On fault, returns dict with 'Error' and 'ErrorDetail' keys.
    """
    root, fault = parse_soap_response(xml_string)
    if fault:
        return fault

    result = {}

    # Enumeration state
    enum_context = root.find(".//wsen:EnumerationContext", NAMESPACES)
    if enum_context is not None and enum_context.text:
        result["EnumerationContext"] = enum_context.text

    end_of_sequence = root.find(".//wsen:EndOfSequence", NAMESPACES)
    if end_of_sequence is not None:
        result["EndOfSequence"] = True

    # Parse entries
    # '*' (ALL_ATTRIBUTES) and '+' (ALL_OPERATIONAL_ATTRIBUTES) mean accept everything
    accept_all = (
        not attributes
        or ALL_ATTRIBUTES in attributes
        or ALL_OPERATIONAL_ATTRIBUTES in attributes
    )
    attributes_lower = (
        None if accept_all
        else [attr.lower() for attr in attributes]
    )
    entries = []
    items = root.findall(".//wsen:Items/*", NAMESPACES)
    for obj in items:
        entry_dn = None
        attributes_dict = {}
        raw_attributes_dict = {}

        dn_element = obj.find(
            ".//ad:distinguishedName/ad:value", NAMESPACES
        )
        if dn_element is not None and dn_element.text:
            entry_dn = dn_element.text

        for attr in obj:
            attr_tag = attr.tag.split("}")[-1]

            if attributes_lower and attr_tag.lower() not in attributes_lower:
                continue

            ldap_syntax = attr.attrib.get('LdapSyntax', '')
            values = []
            raw_values = []

            for val in attr.findall(".//ad:value", NAMESPACES):
                if val.text is None:
                    continue

                raw_value_str = val.text
                raw_value_bytes = raw_value_str.encode('utf-8')

                value = raw_value_str
                xsi_type = val.get(
                    "{http://www.w3.org/2001/XMLSchema-instance}type"
                )

                if xsi_type == "xsd:base64Binary":
                    try:
                        value = base64.b64decode(raw_value_str + '==')
                    except base64.binascii.Error:
                        logging.warning(
                            f"Failed to decode base64 value for "
                            f"{attr_tag}: {raw_value_str}"
                        )
                        value = raw_value_bytes
                elif xsi_type and xsi_type.lower() == 'xsd:integer':
                    try:
                        value = int(raw_value_str)
                    except Exception:
                        pass
                elif ldap_syntax == 'integer':
                    try:
                        value = int(raw_value_str)
                    except Exception:
                        pass

                values.append(value)
                raw_values.append(raw_value_bytes)

            if values:
                if attr_tag not in attributes_dict:
                    attributes_dict[attr_tag] = (
                        values[0] if len(values) == 1 else values
                    )
                    raw_attributes_dict[attr_tag] = (
                        raw_values[0] if len(raw_values) == 1
                        else raw_values
                    )

        if entry_dn is None:
            if 'distinguishedName' in attributes_dict:
                entry_dn = attributes_dict['distinguishedName']
            else:
                fallback_id = (
                    next(iter(raw_attributes_dict.values()))
                    if raw_attributes_dict else str(uuid4())
                )
                if isinstance(fallback_id, bytes):
                    try:
                        fallback_id = fallback_id.decode(
                            'utf-8', errors='ignore'
                        )
                    except Exception:
                        fallback_id = str(uuid4())
                entry_dn = f"Object_{fallback_id}"

        entries.append({
            'dn': entry_dn,
            'attributes': IDict(attributes_dict),
            'raw_attributes': IDict(raw_attributes_dict),
            'type': 'searchResEntry',
        })

    if entries:
        result["entries"] = entries

    return result
