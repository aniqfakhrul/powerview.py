#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RSAKeyMaterial.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

import io
import struct
from Cryptodome.Util.number import bytes_to_long, long_to_bytes


class RSAKeyMaterial(object):
    """
    RsaKeyMaterial

    See:
    https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/applying-cryptography-using-the-cng-api-in-windows-vista
    https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/images/cc163389.fig11.gif
    https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
    """

    def __init__(self, modulus: int, exponent: int, keySize: int, prime1: int = 0, prime2: int = 0):
        super(RSAKeyMaterial, self).__init__()
        if prime1 != 0 and prime2 != 0:
            try:
                assert((prime1 * prime2) == modulus)
            except AssertionError as e:
                raise ValueError("Modulus (N) does not match result of prime1 (p) * prime2 (q).")
        self.modulus = self.n = modulus
        self.exponent = self.e = exponent
        self.prime1 = self.p = prime1
        self.prime2 = self.q = prime2
        self.keySize = keySize
        # self.key = RSA.construct((self.modulus, self.exponent, None, self.prime1, self.prime2, None))


    @classmethod
    def fromRawBytes(cls, rawBytes: bytes):
        stream_data = io.BytesIO(rawBytes)
        # Parsing header
        blobType = stream_data.read(4)
        keySize = struct.unpack('<I', stream_data.read(4))[0]
        exponentSize = struct.unpack('<I', stream_data.read(4))[0]
        modulusSize = struct.unpack('<I', stream_data.read(4))[0]
        prime1Size = struct.unpack('<I', stream_data.read(4))[0]
        prime2Size = struct.unpack('<I', stream_data.read(4))[0]

        # Parsing body
        exponent = bytes_to_long(stream_data.read(exponentSize))
        modulus = bytes_to_long(stream_data.read(modulusSize))
        prime1 = bytes_to_long(stream_data.read(prime1Size))
        prime2 = bytes_to_long(stream_data.read(prime2Size))

        return RSAKeyMaterial(modulus, exponent, keySize, prime1=prime1, prime2=prime2)

    def toRawBytes(self):
        b_blobType = b'RSA1'
        b_keySize = struct.pack('<I', self.keySize)

        b_exponent = long_to_bytes(self.exponent)
        b_exponentSize = struct.pack('<I', len(b_exponent))

        b_modulus = long_to_bytes(self.modulus)
        b_modulusSize = struct.pack('<I', len(b_modulus))

        if self.prime1 == 0:
            b_prime1Size = struct.pack('<I', 0)
        else:
            b_prime1 = long_to_bytes(self.prime1)
            b_prime1Size = struct.pack('<I', len(b_prime1))

        if self.prime2 == 0:
            b_prime2Size = struct.pack('<I', 0)
        else:
            b_prime2 = long_to_bytes(self.prime2)
            b_prime2Size = struct.pack('<I', len(b_prime2))

        # Header
        data = b_blobType
        # Header
        data += b_keySize
        data += b_exponentSize + b_modulusSize + b_prime1Size + b_prime2Size
        # Content
        data += b_exponent + b_modulus
        if self.prime1 != 0:
            data += b_prime1
        if self.prime2 != 0:
            data += b_prime2
        return data

    def toDict(self):
        keyMaterialDict = {
            "modulus": self.modulus,
            "exponent": self.exponent,
            "prime1": self.prime1,
            "prime2": self.prime2,
            "keySize": self.keySize
        }
        return keyMaterialDict


    @classmethod
    def fromDict(cls, data):
        modulus = data["modulus"]
        exponent = data["exponent"]
        keySize = data["keySize"]
        prime1 = data["prime1"]
        prime2 = data["prime2"]
        keyMaterial = cls(modulus, exponent, keySize, prime1, prime2)
        return keyMaterial


    def show(self):
        print("<RsaKeyMaterial at 0x%x>" % id(self))
        print(" | Exponent (E): %s" % hex(self.exponent))
        print(" | Modulus (N): %s" % hex(self.modulus))
        print(" | Prime1 (P): %s" % hex(self.prime1))
        print(" | Prime2 (Q): %s" % hex(self.prime2))