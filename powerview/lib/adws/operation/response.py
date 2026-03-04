"""Shared SOAP response parsing for ADWS operations.

Provides base XML/fault parsing that each per-operation
*_response_to_dict() function builds on. Mirrors ldap3's pattern
where each operation module has its own response decoder.
"""

from ..templates import NAMESPACES
from ..error import ADWSError
from xml.etree import ElementTree

import re

# Matches bare '&' not part of an XML entity reference.
_BARE_AMP_RE = re.compile(r'&(?!(?:amp|lt|gt|apos|quot|#\d+|#x[0-9a-fA-F]+);)')


def parse_soap_response(xml_string):
    """Parse a SOAP response XML string into a root element and fault dict.

    This is the shared base for all per-operation response decoders.
    Handles SOAP fault detection and error detail extraction.

    Args:
        xml_string: Raw XML response string from the ADWS server.

    Returns:
        tuple: (root, fault_dict) where:
            - root is the parsed ElementTree root element
            - fault_dict contains Error/ErrorDetail keys on SOAP fault,
              or is an empty dict on success

    Raises:
        ADWSError: If the XML cannot be parsed at all.
    """
    try:
        root = ElementTree.fromstring(xml_string)
    except ElementTree.ParseError:
        # ADWS sometimes returns attribute values with unescaped '&'
        # (e.g. "Domain Password & Lockout Policies"). Sanitize and retry.
        try:
            sanitized = _BARE_AMP_RE.sub('&amp;', xml_string)
            root = ElementTree.fromstring(sanitized)
        except ElementTree.ParseError:
            raise ADWSError(xml_string)

    fault_dict = {}

    fault = (root.find(".//soapenv:Fault", NAMESPACES)
             or root.find(".//s:Fault", NAMESPACES))
    if not fault:
        return root, fault_dict

    code = (fault.find(".//soapenv:Value", NAMESPACES)
            or fault.find(".//s:Value", NAMESPACES))
    if code is not None and code.text:
        fault_dict["FaultCode"] = code.text

    subcode = (fault.find(".//soapenv:Subcode/soapenv:Value", NAMESPACES)
               or fault.find(".//s:Subcode/s:Value", NAMESPACES))
    if subcode is not None and subcode.text:
        fault_dict["FaultSubcode"] = subcode.text

    reason = (fault.find(".//soapenv:Text", NAMESPACES)
              or fault.find(".//s:Text", NAMESPACES))
    if reason is not None and reason.text:
        fault_dict["Error"] = reason.text

    detail = (root.find(".//soapenv:Detail", NAMESPACES)
              or root.find(".//s:Detail", NAMESPACES))
    if detail is not None:
        detail_dict = {}

        def _parse_element(element, current_dict):
            for sub_element in element:
                sub_tag = sub_element.tag.split("}")[-1]
                if sub_element.text and sub_element.text.strip():
                    current_dict[sub_tag] = sub_element.text
                elif len(sub_element) > 0:
                    # Check if all children are leaf text nodes (e.g. Referral list)
                    children = list(sub_element)
                    if children and all(c.text and c.text.strip() and len(c) == 0 for c in children):
                        current_dict[sub_tag] = [c.text.strip() for c in children]
                    else:
                        nested_dict = {}
                        _parse_element(sub_element, nested_dict)
                        current_dict[sub_tag] = nested_dict

        _parse_element(detail, detail_dict)
        fault_dict["ErrorDetail"] = detail_dict

    return root, fault_dict
