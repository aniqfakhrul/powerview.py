#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Guid.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

import re
import struct
import binascii
import random
from enum import Enum


class GuidFormat(Enum):
    """
    N => 32 digits : 00000000000000000000000000000000
    D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
    B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
    P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
    X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
    """
    N = 0
    D = 1
    B = 2
    P = 3
    X = 4


class GuidImportFormatPattern(Enum):
    """
    N => 32 digits : 00000000000000000000000000000000
    D => 32 digits separated by hyphens : 00000000-0000-0000-0000-000000000000
    B => 32 digits separated by hyphens, enclosed in braces : {00000000-0000-0000-0000-000000000000}
    P => 32 digits separated by hyphens, enclosed in parentheses : (00000000-0000-0000-0000-000000000000)
    X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of eight hexadecimal values that is also enclosed in braces : {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
    """
    N = "^([0-9a-f]{8})([0-9a-f]{4})([0-9a-f]{4})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$"
    D = "^([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})$"
    B = "^{([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})}$"
    P = "^\\(([0-9a-f]{8})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{4})-([0-9a-f]{12})\\)$"
    X = "^{0x([0-9a-f]{8}),0x([0-9a-f]{4}),0x([0-9a-f]{4}),{0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2}),0x([0-9a-f]{2})}}$"


class InvalidGuidFormat(Exception):
    pass


class Guid(object):
    """
    Guid

    See: https://docs.microsoft.com/en-us/dotnet/api/system.guid?view=net-5.0
    """

    Format: GuidFormat = None

    def __init__(self, a=None, b=None, c=None, d=None, e=None):
        super(Guid, self).__init__()
        if a is None:
            a = sum([random.randint(0, 0xff) << (8*k) for k in range(4)])
        if b is None:
            b = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if c is None:
            c = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if d is None:
            d = sum([random.randint(0, 0xff) << (8*k) for k in range(2)])
        if e is None:
            e = sum([random.randint(0, 0xff) << (8*k) for k in range(6)])
        self.a, self.b, self.c, self.d, self.e = a, b, c, d, e

    @classmethod
    def load(cls, data):
        self = None

        if type(data) == bytes and len(data) == 16:
            return Guid.fromRawBytes(data)

        elif type(data) == str:
            matched = re.match(GuidImportFormatPattern.X.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatX(matched.group(0))
                self.Format = GuidFormat.X
                return self

            matched = re.match(GuidImportFormatPattern.P.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatP(matched.group(0))
                self.Format = GuidFormat.P
                return self

            matched = re.match(GuidImportFormatPattern.D.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatD(matched.group(0))
                self.Format = GuidFormat.D
                return self

            matched = re.match(GuidImportFormatPattern.B.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatB(matched.group(0))
                self.Format = GuidFormat.B
                return self

            matched = re.match(GuidImportFormatPattern.N.value, data, re.IGNORECASE)
            if matched is not None:
                self = cls.fromFormatN(matched.group(0))
                self.Format = GuidFormat.N
                return self

        return self

    # Import formats

    @classmethod
    def fromRawBytes(cls, data: bytes):
        if len(data) != 16:
            raise InvalidGuidFormat("fromRawBytes takes exactly 16 bytes of data in input")
        # 0xffffff
        a = struct.unpack("<L", data[0:4])[0]
        # 0xffff
        b = struct.unpack("<H", data[4:6])[0]
        # 0xffff
        c = struct.unpack("<H", data[6:8])[0]
        # 0xffff
        d = struct.unpack(">H", data[8:10])[0]
        # 0xffffffffffff
        e = binascii.hexlify(data[10:16]).decode("UTF-8").rjust(6, '0')
        e = int(e, 16)
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatN(cls, data):
        # N => 32 digits : 00000000000000000000000000000000
        if not re.match(GuidImportFormatPattern.N.value, data, re.IGNORECASE):
            raise InvalidGuidFormat("Guid Format N should be 32 hexadecimal characters separated in five parts.")
        a = int(data[0:8], 16)
        b = int(data[8:12], 16)
        c = int(data[12:16], 16)
        d = int(data[16:20], 16)
        e = int(data[20:32], 16)
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatD(cls, data):
        # D => 32 digits separated by hyphens :
        # 00000000-0000-0000-0000-000000000000
        if not re.match(GuidImportFormatPattern.D.value, data, re.IGNORECASE):
            raise InvalidGuidFormat("Guid Format D should be 32 hexadecimal characters separated in five parts.")
        a, b, c, d, e = map(lambda x: int(x, 16), data.split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatB(cls, data):
        # B => 32 digits separated by hyphens, enclosed in braces :
        # {00000000-0000-0000-0000-000000000000}
        if not re.match(GuidImportFormatPattern.B.value, data, re.IGNORECASE):
            raise InvalidGuidFormat("Guid Format B should be 32 hexadecimal characters separated in five parts enclosed in braces.")
        a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatP(cls, data):
        # P => 32 digits separated by hyphens, enclosed in parentheses :
        # (00000000-0000-0000-0000-000000000000)
        if not re.match(GuidImportFormatPattern.P.value, data, re.IGNORECASE):
            raise InvalidGuidFormat("Guid Format P should be 32 hexadecimal characters separated in five parts enclosed in parentheses.")
        a, b, c, d, e = map(lambda x: int(x, 16), data[1:-1].split("-"))
        self = cls(a, b, c, d, e)
        return self

    @classmethod
    def fromFormatX(cls, data):
        # X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
        # eight hexadecimal values that is also enclosed in braces :
        # {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
        if not re.match(GuidImportFormatPattern.X.value, data, re.IGNORECASE):
            raise InvalidGuidFormat("Guid Format X should be in this format {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}.")
        hex_a, hex_b, hex_c, rest = data[1:-1].split(',', 3)
        rest = rest[1:-1].split(',')
        a = int(hex_a, 16)
        b = int(hex_b, 16)
        c = int(hex_c, 16)
        d = int(rest[0], 16) * 0x100 + int(rest[1], 16)
        e = int(rest[2], 16) * (0x1 << (8 * 5))
        e += int(rest[3], 16) * (0x1 << (8 * 4))
        e += int(rest[4], 16) * (0x1 << (8 * 3))
        e += int(rest[5], 16) * (0x1 << (8 * 2))
        e += int(rest[6], 16) * (0x1 << 8)
        e += int(rest[7], 16)
        self = cls(a, b, c, d, e)
        return self

    # Export formats

    def toRawBytes(self):
        data = b''
        data += struct.pack("<L", self.a)
        data += struct.pack("<H", self.b)
        data += struct.pack("<H", self.c)
        data += struct.pack(">H", self.d)
        data += binascii.unhexlify(hex(self.e)[2:].rjust(12, '0'))
        return data

    def toFormatN(self) -> str:
        # N => 32 digits :
        # 00000000000000000000000000000000
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "%s%s%s%s%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatD(self) -> str:
        # D => 32 digits separated by hyphens :
        # 00000000-0000-0000-0000-000000000000
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "%s-%s-%s-%s-%s" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatB(self) -> str:
        # B => 32 digits separated by hyphens, enclosed in braces :
        # {00000000-0000-0000-0000-000000000000}
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "{%s-%s-%s-%s-%s}" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatP(self) -> str:
        # P => 32 digits separated by hyphens, enclosed in parentheses :
        # (00000000-0000-0000-0000-000000000000)
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_e = hex(self.e)[2:].rjust(12, '0')
        return "(%s-%s-%s-%s-%s)" % (hex_a, hex_b, hex_c, hex_d, hex_e)

    def toFormatX(self) -> str:
        # X => Four hexadecimal values enclosed in braces, where the fourth value is a subset of
        # eight hexadecimal values that is also enclosed in braces :
        # {0x00000000,0x0000,0x0000,{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}}
        hex_a = hex(self.a)[2:].rjust(8, '0')
        hex_b = hex(self.b)[2:].rjust(4, '0')
        hex_c = hex(self.c)[2:].rjust(4, '0')
        hex_d = hex(self.d)[2:].rjust(4, '0')
        hex_d1, hex_d2 = hex_d[:2], hex_d[2:4]
        hex_e = hex(self.e)[2:].rjust(12, '0')
        hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6 = hex_e[:2], hex_e[2:4], hex_e[4:6], hex_e[6:8], hex_e[8:10], hex_e[10:12]
        return "{0x%s,0x%s,0x%s,{0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s,0x%s}}" % (hex_a, hex_b, hex_c, hex_d1, hex_d2, hex_e1, hex_e2, hex_e3, hex_e4, hex_e5, hex_e6)

    def __repr__(self):
        return "<Guid %s>" % self.toFormatB()
