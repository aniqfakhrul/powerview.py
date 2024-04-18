#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DNWithBinary.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

import binascii


class EmptyRawDNWithBinary(Exception):
    """Raised when the input value is too small"""
    pass


class InvalidBinaryDataLength(Exception):
    """Raised when the input value is too large"""
    pass


class InvalidNumberOfPartsInRawDNWithBinary(Exception):
    """Raised when the input value is too large"""
    pass


class DNWithBinary(object):
    """
    The DNWithBinary class represents the DN-Binary LDAP attribute syntax,
    which contains a binary value and a distinguished name (DN).
    """

    # String representation of DN-Binary data: B:<char count>:<binary value>:<object DN>
    _StringFormat = "B:%d:%s:%s"
    _StringFormatPrefix = b"B:"
    _StringFormatSeparator = b":"

    DistinguishedName = b""
    BinaryData = b""

    def __init__(self, DistinguishedName: str, binaryData: bytes):
        super(DNWithBinary, self).__init__()
        assert (len(DistinguishedName) != 0)
        assert (len(binaryData) != 0)
        self.DistinguishedName = DistinguishedName
        self.BinaryData = binaryData

    @classmethod
    def fromRawDNWithBinary(cls, rawDNWithBinary:bytes):
        if len(rawDNWithBinary) == 0:
            raise EmptyRawDNWithBinary("rawDNWithBinary cannot be empty.")

        numberOfColons = rawDNWithBinary.count(cls._StringFormatSeparator)

        if numberOfColons != 3:
            raise InvalidNumberOfPartsInRawDNWithBinary("rawDNWithBinary should have exactly four parts separated by colons (:).")

        _B, size, binaryPart, DistinguishedName = rawDNWithBinary.split(cls._StringFormatSeparator)
        size = int(size)

        if len(binaryPart) != size:
            raise InvalidBinaryDataLength("Invalid BinaryData length. The length specified in the header does not match the data length.")

        binaryPart = binascii.unhexlify(binaryPart)

        return cls(DistinguishedName, binaryPart)

    def toString(self):
        hexdata = binascii.hexlify(self.BinaryData).decode("UTF-8")
        # return self._StringFormat % (len(self.BinaryData) * 2, hexdata, self.DistinguishedName.decode("UTF-8"))
        return self._StringFormat % (len(self.BinaryData) * 2, hexdata, self.DistinguishedName)

    def __repr__(self):
        return self.toString()