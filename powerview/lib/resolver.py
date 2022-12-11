import datetime

from impacket.uuid import bin_to_string
from ldap3.protocol.formatters.formatters import format_sid

from powerview.utils.constants import (
    UAC_DICT,
    LDAP_ERROR_STATUS,
    SUPPORTED_ENCRYPTION_TYPES,
    switcher_trustDirection,
    switcher_trustType,
    switcher_trustAttributes
)

class UAC:
    def parse_value(uac_value):
        uac_value = int(uac_value)
        flags = []

        for key, value in UAC_DICT.items():
            if uac_value & key:
                flags.append(value)

        return flags

class ENCRYPTION_TYPE:
    def parse_value(enc_value):
        enc_value = int(enc_value)
        flags = []

        for key, value in SUPPORTED_ENCRYPTION_TYPES.items():
            if enc_value & key:
                flags.append(value)

        return flags

class LDAP:
    def resolve_err_status(error_status):
        return LDAP_ERROR_STATUS.get(error_status)

    def ldap2datetime(ts):
        if isinstance(ts, datetime.datetime):
            return ts
        ts = int(ts)
        return datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=ts/10000000)

    def bin_to_guid(guid):
        return "{%s}" % bin_to_string(guid).lower()

    def bin_to_sid(sid):
        return format_sid(sid)

class TRUST:
    def resolve_trustDirection(flag):
        return switcher_trustDirection.get(flag)

    def resolve_trustType(flag):
        return switcher_trustType.get(flag)

    def resolve_trustAttributes(flag):
        return switcher_trustAttributes.get(flag)

