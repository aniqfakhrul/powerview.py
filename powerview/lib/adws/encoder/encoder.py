import logging
from io import BytesIO

from .records import Net7BitInteger, record, dump_records, print_records
from .records.constants import DICTIONARY
from .xml_parser import XMLParser


class Encoder:
    """Performs encoding and decoding on xml data.

    Compliant with [MC-NBFX] and known extensions.

    Supports known encoding types:

        [MC-NBFS]
        [MC-NBFSE]
    """

    def __init__(self, encoding: int = 0x8):
        self._encoding = encoding
        self._inband_entries = {}

    def _extract_dict_from_xml(self) -> dict[int, str]:
        """TODO: needs to be populated"""

        return {}

    def _inband_dict_to_bin(self, inbandDict: dict[int, str]) -> bytes:
        """Convert dict into string table and serialize."""

        string_table = bytes()

        for _, v in inbandDict.items():
            size = Net7BitInteger.encode7bit(len(v.encode("utf-8")))
            string_table += size + v.encode("utf-8")

        size = Net7BitInteger.encode7bit(len(string_table))

        return size + string_table

    def _extract_stringtable_inband(self, data) -> dict[int, str]:
        """Extract strings from inband dict and place them into
        the string table.
        """

        string_table = {}
        idx = 1
        while data:
            size, len_len = Net7BitInteger.decode7bit(data)
            word = data[len_len : len_len + size]
            data = data[len_len + size :]
            string_table[idx] = word
            idx += 2

        return string_table

    # ========== Interface =============

    def encode(self, xml: str) -> bytes:
        """Serialize xml data with appropriate encoding type into bytes.

        Args:
            xml (str): xml data in string form

        Returns:
            (bytes): encoded xml data
        """
        r = XMLParser.parse(xml)

        base_data = dump_records(r)

        if self._encoding == 0x07:  # NBFS
            return base_data
        if self._encoding == 0x08:  # NBFSE
            inbandDict = self._inband_dict_to_bin(self._extract_dict_from_xml())
            return inbandDict + base_data

        raise ValueError(f"Unsupported encoding: {self._encoding:#x}")

    def decode(self, data: bytes) -> str:
        """Deserialize and decode xml bytes into string form.

        Args:
            data (bytes): serialized and encoded data

        Returns:
            (str): xml in string form
        """

        if self._encoding == 0x08:
            size3, len_len3 = Net7BitInteger.decode7bit(data)

            # if there is something in the inband dict
            if size3 != 0:
                # cut off just the dict part and try to extract it
                string_table = self._extract_stringtable_inband(
                    data[len_len3 : len_len3 + size3]
                )
                # Merge server in-band dictionary into both per-instance
                # tracking and the shared DICTIONARY (required because record
                # classes import DICTIONARY by reference at import time).
                for idx, val in string_table.items():
                    if isinstance(val, bytes):
                        val = val.decode('utf-8', errors='replace')
                    self._inband_entries[idx] = val
                    DICTIONARY[idx] = val
                    logging.debug(f"[NBFSE] In-band dict[{idx}] = {val}")

            # then index data to be the start of the actual xml blob
            data = data[len_len3 + size3 :]

        elif self._encoding != 0x07:
            raise ValueError(f"Unsupported encoding: {self._encoding:#x}")

        # Restore this instance's in-band entries into the shared DICTIONARY
        # before parsing, in case another Encoder instance overwrote entries
        # between calls (sequential multi-connection safety, not thread-safe).
        for idx, val in self._inband_entries.items():
            DICTIONARY[idx] = val

        r = record.parse(BytesIO(data))  # begin parsing from first record
        xml = print_records(r)

        return xml
