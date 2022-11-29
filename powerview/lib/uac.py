from powerview.utils.constants import (
    UAC_DICT
)

class UAC:
    def parse_value(uac_value):
        flags = []

        for key, value in UAC_DICT.items():
            if uac_value & key:
                flags.append(value)

        return flags

