from ..templates import LDAP_DELETE_FSTRING

from uuid import uuid4

def delete_operation(fqdn, dn):
    delete_vars = {
        "fqdn": fqdn,
        "uuid": str(uuid4()),
        "object_ref": dn,
    }
    request = LDAP_DELETE_FSTRING.format(**delete_vars)
    return request

def delete_response_to_dict(response):
    pass
