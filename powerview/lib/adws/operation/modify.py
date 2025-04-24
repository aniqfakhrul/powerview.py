from ldap3 import SEQUENCE_TYPES, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT
from ldap3.protocol.rfc4511 import Changes, AttributeDescription

from ..templates import LDAP_PUT_FSTRING

from uuid import uuid4

change_table = {MODIFY_ADD: 0,  # accepts actual values too
                MODIFY_DELETE: 1,
                MODIFY_REPLACE: 2,
                MODIFY_INCREMENT: 3,
                0: 0,
                1: 1,
                2: 2,
                3: 3}

def modify_operation(dn,
                     changes,
                     auto_encode,
                     schema=None,
                     validator=None,
                     check_names=False):
    # changes is a dictionary in the form {'attribute': [(operation, [val1, ...]), ...], ...}
    # operation is 0 (add), 1 (delete), 2 (replace), 3 (increment)
    # increment as per RFC4525

    put_vars = {
        "object_ref": object_ref,
        "uuid": str(uuid4()),
        "fqdn": self._fqdn,
        "operation": operation,
        "attribute": attribute,
        "data_type": data_type,
        "value": value,
    }

    return LDAP_PUT_FSTRING.format(**put_vars)
