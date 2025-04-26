from ldap3 import SEQUENCE_TYPES, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, MODIFY_INCREMENT
from ldap3.protocol.rfc4511 import AttributeDescription, PartialAttribute, Vals, Change, Operation, Changes
from ldap3.protocol.convert import prepare_for_sending, validate_attribute_value

from ..templates import LDAP_PUT_FSTRING

from uuid import uuid4
import sys

change_table = {MODIFY_ADD: 0,  # accepts actual values too
                MODIFY_DELETE: 1,
                MODIFY_REPLACE: 2,
                MODIFY_INCREMENT: 3,
                0: 0,
                1: 1,
                2: 2,
                3: 3}

def modify_operation(fqdn,
                    dn,
                    changes,
                    auto_encode,
                    schema=None,
                    validator=None,
                    check_names=False):
    """CRUD on attribute

        Args:
            client (NMFConnection): connected client
            object_ref (str): DN of object to write attribute on
            fqdn (str): fqdn of the DC
            operation (str): operation to preform on the attribute: <MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE> [MS-WSTIM]: 3.2.4.2.3.1
            attribute (str): attribute type including the namespace
            data_type (str): datatype, <'string', 'base64Base'> [MS-ADDM]: 2.3.4
            value (str): string value for attribute in UTF-8

        Returns:
            str: error
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
                
                data_type = "string"
                for v in vals:
                    value = str(v)
                    mRequest += f"""
                    <ad:value xsi:type="xsd:{data_type}">{value}</ad:value>"""
                
                mRequest += f"""
                </da:AttributeValue>
            </da:Change>
        </da:ModifyRequest>
        """

    put_vars = {
        "object_ref": dn,
        "uuid": str(uuid4()),
        "fqdn": fqdn,
        "attributes": mRequest,
    }
    return LDAP_PUT_FSTRING.format(**put_vars)

def modify_response_to_dict(response):
    pass
