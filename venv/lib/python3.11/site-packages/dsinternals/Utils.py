#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021


import base64
import binascii
import hashlib
import struct

from dsinternals.system.DateTime import DateTime
from dsinternals.common.data.hello.KeyCredentialVersion import KeyCredentialVersion
from dsinternals.common.data.hello.KeySource import KeySource


def ConvertToBinaryIdentifier(keyIdentifier, version: KeyCredentialVersion):
    if version in [KeyCredentialVersion.Version0.value, KeyCredentialVersion.Version1.value]:
        return binascii.unhexlify(keyIdentifier)
    if version == KeyCredentialVersion.Version2.value:
        return base64.b64decode(keyIdentifier + "===")
    else:
        return base64.b64decode(keyIdentifier + "===")


def ConvertFromBinaryIdentifier(keyIdentifier, version: KeyCredentialVersion):
    if version in [KeyCredentialVersion.Version0.value, KeyCredentialVersion.Version1.value]:
        return binascii.hexlify(keyIdentifier).decode("utf-8")
    if version == KeyCredentialVersion.Version2.value:
        return base64.b64encode(keyIdentifier).decode("utf-8")
    else:
        return base64.b64encode(keyIdentifier).decode("utf-8")


def ConvertFromBinaryTime(rawBinaryTime: bytes, source: KeySource, version: KeyCredentialVersion):
    """
    Documentation for ConvertFromBinaryTime

    Src : https://github.com/microsoft/referencesource/blob/master/mscorlib/system/datetime.cs
    """

    timeStamp = struct.unpack('<Q', rawBinaryTime)[0]

    # AD and AAD use a different time encoding.
    if version == KeyCredentialVersion.Version0.value:
        return DateTime(timeStamp)
    if version == KeyCredentialVersion.Version1.value:
        return DateTime(timeStamp)
    if version == KeyCredentialVersion.Version2.value:
        if source == KeySource.AD.value:
            return DateTime(timeStamp)
        else:
            # print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
            return DateTime(timeStamp)
    else:
        if source == KeySource.AD.value:
            return DateTime(timeStamp)
        else:
            # print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
            return DateTime(timeStamp)


def ConvertToBinaryTime(date: DateTime, source: KeySource, version: KeyCredentialVersion) -> bytes:
    """
    Documentation for ConvertToBinaryTime

    Src : https://github.com/microsoft/referencesource/blob/master/mscorlib/system/datetime.cs
    """

    # AD and AAD use a different time encoding.
    if version == KeyCredentialVersion.Version0.value:
        return struct.pack('<Q', date.toTicks())
    if version == KeyCredentialVersion.Version1.value:
        return struct.pack('<Q', date.toTicks())
    if version == KeyCredentialVersion.Version2.value:
        if source == KeySource.AD.value:
            return struct.pack('<Q', date.toTicks())
        else:
            # print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
            return struct.pack('<Q', date.toTicks())
    else:
        if source == KeySource.AD.value:
            return struct.pack('<Q', date.toTicks())
        else:
            # print("This is not fully supported right now, you may encounter issues. Please contact us @podalirius_ @_nwodtuhs if you are in this case")
            return struct.pack('<Q', date.toTicks())



"""
private static byte[] ConvertToBinaryTime(DateTime time, KeySource source, KeyCredentialVersion version)
{
    long timeStamp;
    switch (version)
    {
        case KeyCredentialVersion.Version0:
            timeStamp = time.Ticks;
            break;
        case KeyCredentialVersion.Version1:
            timeStamp = time.ToBinary();
            break;
        case KeyCredentialVersion.Version2:
        default:
            timeStamp = source == KeySource.AD ? time.ToFileTime() : time.ToBinary();
            break;
    }

    return BitConverter.GetBytes(timeStamp);
}
"""


def ComputeHash(data: bytes):
    sha256 = hashlib.sha256(data)
    return sha256.digest()


def ComputeKeyIdentifier(keyMaterial: bytes, version: KeyCredentialVersion):
    binaryId = ComputeHash(keyMaterial)
    return ConvertFromBinaryIdentifier(binaryId, version)


"""private static DateTime ConvertFromBinaryTime(byte[] binaryTime, KeySource source, KeyCredentialVersion version)
{
    long timeStamp = BitConverter.ToInt64(binaryTime, 0);

    // AD and AAD use a different time encoding.
    switch (version)
    {
        case KeyCredentialVersion.Version0:
            return new DateTime(timeStamp);
        case KeyCredentialVersion.Version1:
            return DateTime.FromBinary(timeStamp);
        case KeyCredentialVersion.Version2:
        default:
            return source == KeySource.AD ? DateTime.FromFileTime(timeStamp) : DateTime.FromBinary(timeStamp);
    }
}

private static byte[] ConvertToBinaryTime(DateTime time, KeySource source, KeyCredentialVersion version)
{
    long timeStamp;
    switch (version)
    {
        case KeyCredentialVersion.Version0:
            timeStamp = time.Ticks;
            break;
        case KeyCredentialVersion.Version1:
            timeStamp = time.ToBinary();
            break;
        case KeyCredentialVersion.Version2:
        default:
            timeStamp = source == KeySource.AD ? time.ToFileTime() : time.ToBinary();
            break;
    }

    return BitConverter.GetBytes(timeStamp);
}

"""
