from powerview.utils.constants import (
    UAC_DICT,
    LDAP_ERROR_STATUS,
    switcher_trustDirection,
    switcher_trustType,
    switcher_trustAttributes
)

class UAC:
    def parse_value(uac_value):
        flags = []

        for key, value in UAC_DICT.items():
            if uac_value & key:
                flags.append(value)

        return flags

class LDAP:
    def resolve_err_status(error_status):
        return LDAP_ERROR_STATUS.get(error_status)

class TRUST:
    def resolve_trustDirection(flag):
        return switcher_trustDirection.get(flag)

    def resolve_trustType(flag):
        return switcher_trustType.get(flag)

    def resolve_trustAttributes(flag):
        return switcher_trustAttributes.get(flag)

