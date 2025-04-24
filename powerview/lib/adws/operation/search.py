from ..templates import LDAP_QUERY_FSTRING, LDAP_PULL_FSTRING, NAMESPACES
from ..error import ADWSError
from powerview.utils.helpers import IDict

from uuid import uuid4
from xml.etree import ElementTree
import base64
import logging

# save this for later
def xml_to_dict(xml_string: str) -> dict:
    try:
        root = ElementTree.fromstring(xml_string)
        result = {}
        
        # Extract header information from SOAP envelope
        header = root.find(".//{http://www.w3.org/2003/05/soap-envelope}Header") or root.find(".//s:Header", NAMESPACES)
        if header is not None:
            for child in header:
                tag = child.tag.split("}")[-1]
                if child.text and child.text.strip():
                    result[tag] = child.text.strip()
        
        # Handle SOAP faults
        fault = root.find(".//soapenv:Fault", NAMESPACES) or root.find(".//s:Fault", NAMESPACES)
        if fault:
            code = fault.find(".//soapenv:Value", NAMESPACES) or fault.find(".//s:Value", NAMESPACES)
            if code is not None and code.text:
                result["FaultCode"] = code.text
            
            subcode = fault.find(".//soapenv:Subcode/soapenv:Value", NAMESPACES) or fault.find(".//s:Subcode/s:Value", NAMESPACES)
            if subcode is not None and subcode.text:
                result["FaultSubcode"] = subcode.text
            
            reason = fault.find(".//soapenv:Text", NAMESPACES) or fault.find(".//s:Text", NAMESPACES)
            if reason is not None and reason.text:
                result["Error"] = reason.text
            
            detail = fault.find(".//soapenv:Detail", NAMESPACES) or root.find(".//s:Detail", NAMESPACES)
            if detail is not None:
                detail_dict = {}
                # Recursively parse the detail element and its children
                def parse_element(element, current_dict):
                    for sub_element in element:
                        sub_tag = sub_element.tag.split("}")[-1]
                        if sub_element.text:
                            current_dict[sub_tag] = sub_element.text
                        elif len(sub_element) > 0:
                            nested_dict = {}
                            parse_element(sub_element, nested_dict)
                            current_dict[sub_tag] = nested_dict
                parse_element(detail, detail_dict)
                result["ErrorDetail"] = detail_dict
            
            return result
        
        # Handle enumeration context for paged results
        enum_context = root.find(".//wsen:EnumerationContext", NAMESPACES)
        if enum_context is not None and enum_context.text:
            result["EnumerationContext"] = enum_context.text
        
        # Handle expiration information
        expires = root.find(".//wsen:Expires", NAMESPACES)
        if expires is not None and expires.text:
            result["Expires"] = expires.text
        
        # Handle end of sequence marker
        end_of_sequence = root.find(".//wsen:EndOfSequence", NAMESPACES)
        if end_of_sequence is not None:
            result["EndOfSequence"] = True
        
        entries = []
        
        # Process all AD object types
        object_types = ["user", "computer", "group", "organizationalUnit", "container", "domainDNS"]
        for obj_type in object_types:
            objects = root.findall(f".//addata:{obj_type}", NAMESPACES)
            
            for obj in objects:
                obj_data = {"objectClass": obj_type}
                
                for attr in obj:
                    attr_tag = attr.tag.split("}")[-1]
                    ldap_syntax = attr.attrib.get('LdapSyntax', '')
                    values = []
                    
                    for val in attr.findall(".//ad:value", NAMESPACES):
                        if val.text is None:
                            continue
                            
                        value = val.text
                        xsi_type = val.get("{http://www.w3.org/2001/XMLSchema-instance}type")
                        
                        if xsi_type == "xsd:base64Binary":
                            try:
                                value = base64.b64decode(value)
                            except:
                                pass
                        elif xsi_type == "xsd:boolean":
                            value = value.lower() == "true"
                        elif xsi_type == "xsd:integer" or xsi_type == "xsd:int" or ldap_syntax == "Integer":
                            try:
                                value = int(value)
                            except:
                                pass
                        
                        values.append(value)
                    
                    if values:
                        if len(values) == 1:
                            obj_data[attr_tag] = values[0]
                        else:
                            obj_data[attr_tag] = values
                
                entries.append(obj_data)
        
        if entries:
            result["entries"] = entries
        
        return result
    except Exception as e:
        return {"Error": str(e), "RawXML": xml_string[:200] + "..." if len(xml_string) > 200 else xml_string}

def handle_str_to_xml(xmlstr):
    """Takes an xml string and returns an Element of the root
        node of an xml object.
    Also deals with error and faults in the response

    Args:
        xmlstr (str): str form of xml data

    Returns:
        Element: xml object
    """

    # Check for fault markers more reliably
    is_fault = ":Fault>" in xmlstr and (":Reason>" in xmlstr or ":Detail>" in xmlstr)
    if not is_fault:
        return ElementTree.fromstring(xmlstr)

    def manually_cut_out_fault(xml_str: str) -> str:
        """cut out the fault text description using
        slices.  This is dirty and not certain but
        if it cant be parsed with xml parsers, its
        all we have.

        Args:
            xml_str (str): str of xml data

        Returns:
            str: the fault msg
        """
        starttag = xml_str.find(":Text") + len(":Text")
        endtag = xml_str[starttag:].find(":Text")
        return xml_str[starttag : starttag + endtag]

    et: ElementTree.Element | None = None
    try:
        et = ElementTree.fromstring(xmlstr)
    except ElementTree.ParseError:
        # If parsing fails, raise ADWSError with the raw string
        raise ADWSError(xmlstr)

    base_msg = str()

    fault = et.find(".//soapenv:Fault", namespaces=NAMESPACES)
    if not fault:  # maybe there isnt actually anything erroring?
        if not et:
                raise ValueError("was unable to parse xml from the server response")
        return et

    reason = fault.find(".//soapenv:Text", namespaces=NAMESPACES)
    base_msg += reason.text if reason is not None else ""  # type: ignore

    detail = fault.find(".//soapenv:Detail", namespaces=NAMESPACES)
    if detail is not None:
        ElementTree.indent(detail)
        detail_xmlstr = (
            ElementTree.tostring(detail, encoding="unicode")
            if detail is not None
            else ""
        )
    else:
        detail_xmlstr = ""

    # Raise ADWSError with the combined message or raw XML if parsing occurred
    # ADWSError constructor will handle finding the specific <ad:Error>
    raise ADWSError(xmlstr) # Pass the original XML string to the custom handler

def search_operation(fqdn,
                    search_base,
                    search_filter,
                    search_scope,
                    attributes
                    ):
    fAttributes: str = ""
    for attr in attributes:
        fAttributes += (
            "<ad:SelectionProperty>addata:{attr}</ad:SelectionProperty>\n".format(
                attr=attr
            )
        )
    
    query_vars = {
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "query": search_filter,
        "attributes": fAttributes,
        "search_base": search_base,
        "search_scope": search_scope
    }

    return LDAP_QUERY_FSTRING.format(**query_vars)

def handle_enum_ctx(fqdn: str, enum_ctx: str):
    """
    Handle the enumeration context from the server.
    """
    _vars = {
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "enum_ctx": enum_ctx,
    }

    return LDAP_PULL_FSTRING.format(**_vars)

def parse_adws_pull_response(xml_string: str) -> list[dict]:
    """
    Parses the XML string from an ADWS PullResponse into a list of dictionaries,
    mimicking ldap3 search result structure.

    Args:
        xml_string: The raw XML string from the PullResponse.

    Returns:
        A list of dictionaries, where each dictionary represents an AD object.
        Example entry:
        {
            'dn': '<GUID identifying the object>', # Using GUID as DN placeholder
            'attributes': {
                'objectClass': ['user'], # Extracted from tag name
                'sAMAccountName': ['krbtgt'],
                'objectSid': [b'decoded_sid'], # Decoded value
                # ... other attributes
            },
            'raw_attributes': {
                'objectSid': [b'base64_encoded_sid_bytes'] # Raw value
                # ... other raw attributes
            }
        }
    """
    results = []
    try:
        for prefix, uri in NAMESPACES.items():
            ElementTree.register_namespace(prefix, uri)
        
        root = handle_str_to_xml(xml_string)
        items_element = root.find(".//wsen:Items", NAMESPACES)

        if items_element is None:
            if root.find(".//wsen:EndOfSequence", NAMESPACES) is not None:
                return []
            else:
                logging.warning("Could not find <wsen:Items> in PullResponse XML.")
                return []

        for entry_element in items_element:
            entry_dn_placeholder = None
            attributes = {}
            raw_attributes = {}

            for attr_element in entry_element:
                attr_tag_parts = attr_element.tag.split('}')
                attr_name = attr_tag_parts[-1] if len(attr_tag_parts) > 1 else attr_element.tag

                if attr_name == 'objectReferenceProperty':
                    value_element = attr_element.find(".//ad:value", NAMESPACES)
                    if value_element is not None and value_element.text:
                        entry_dn_placeholder = f"GUID={value_element.text}"
                    continue

                if attr_name not in attributes:
                    attributes[attr_name] = []
                    raw_attributes[attr_name] = []

                value_elements = attr_element.findall(".//ad:value", NAMESPACES)
                if not value_elements:
                    if attr_name not in attributes:
                         attributes[attr_name] = []
                         raw_attributes[attr_name] = []
                    continue

                # Check for LdapSyntax attribute on the parent (e.g., LdapSyntax="Integer")
                ldap_syntax = attr_element.attrib.get('LdapSyntax', '').lower()

                for value_element in value_elements:
                    if value_element is not None and value_element.text is not None:
                        raw_value_str = value_element.text
                        raw_value_bytes = raw_value_str.encode('utf-8')

                        value = raw_value_str
                        xsi_type = value_element.get('{http://www.w3.org/2001/XMLSchema-instance}type')
                        if xsi_type:
                            type_suffix = xsi_type.split(':')[-1]
                            if type_suffix == 'base64Binary':
                                try:
                                    value = base64.b64decode(raw_value_str + '==')
                                except base64.binascii.Error:
                                    logging.warning(f"Failed to decode base64 value for {attr_name}: {raw_value_str}")
                                    value = raw_value_bytes
                            elif type_suffix.lower() == 'integer':
                                try:
                                    value = int(raw_value_str)
                                except Exception:
                                    pass
                            #print(xsi_type, attr_name, value)
                        # Also check LdapSyntax for integer conversion
                        elif ldap_syntax == 'integer':
                            try:
                                value = int(raw_value_str)
                            except Exception:
                                pass
                        attributes[attr_name].append(value)
                        raw_attributes[attr_name].append(raw_value_bytes)

            if entry_dn_placeholder is None:
                 fallback_id = next(iter(raw_attributes.values()))[0].decode('utf-8', errors='ignore') if raw_attributes else uuid4()
                 entry_dn_placeholder = f"Object_{fallback_id}"

            processed_attributes = {}
            for attr_name_final, attr_values_final in attributes.items():
                if len(attr_values_final) == 1:
                    processed_attributes[attr_name_final] = attr_values_final[0]
                else:
                    processed_attributes[attr_name_final] = attr_values_final

            results.append({
                'dn': entry_dn_placeholder,
                'attributes': IDict(processed_attributes),
                'raw_attributes': IDict(raw_attributes),
                'type': 'searchResEntry'
            })

    except ElementTree.ParseError as e:
        raise ADWSError(f"Failed to parse PullResponse XML: {e}\nXML: {xml_string[:500]}...") from e
    except Exception as e:
        raise ADWSError(f"Error processing PullResponse items: {e}\nXML: {xml_string[:500]}...") from e


    return results
    