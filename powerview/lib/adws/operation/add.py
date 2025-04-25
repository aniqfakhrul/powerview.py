from ..templates import LDAP_ADD_FSTRING

from uuid import uuid4

def add_operation(fqdn, dn: str, object_class: str, attributes: dict):
    attr_xml = ""
    for attr_name, attr_values in attributes.items():
        if not isinstance(attr_values, list):
            attr_values = [attr_values]
        
        attr_xml += f'<addata:{attr_name}>'
        for value in attr_values:
            attr_xml += f'<addata:value>{value}</addata:value>'
        attr_xml += f'</addata:{attr_name}>'
    
    add_vars = {
        "fqdn": fqdn,
        "uuid": str(uuid4()),
        "object_ref": dn,
        "object_class": object_class,
        "attributes": attr_xml,
    }
    request = LDAP_ADD_FSTRING.format(**add_vars)
    return request

def add_response_to_dict(response):
    pass
