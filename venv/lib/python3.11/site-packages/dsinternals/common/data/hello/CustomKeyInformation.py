#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : CustomKeyInformation.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021


import struct
import io

from dsinternals.common.data.hello.KeyFlags import KeyFlags
from dsinternals.common.data.hello.CustomKeyInformationVolumeType import CustomKeyInformationVolumeType
from dsinternals.common.data.hello.KeyStrength import KeyStrength


class CustomKeyInformation(dict):
    """
    Represents the CUSTOM_KEY_INFORMATION structure.

    See:  https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
    """

    Version: int = 0
    Flags: KeyFlags = KeyFlags.NONE
    CurrentVersion: int = 1

    ShortRepresentationSize: int = 2
    ReservedSize: int = 10

    VolumeType: CustomKeyInformationVolumeType = None

    # Specifies whether the device associated with this credential supports notification.
    SupportsNotification: bool = None

    # Specifies the version of the File Encryption Key (FEK).
    FekKeyVersion: bytes = None

    # Specifies the strength of the NGC key.
    Strength: KeyStrength = None

    # Reserved for future use.
    Reserved: bytes = None

    # Extended custom key information.
    EncodedExtendedCKI: bytes = None

    def __init__(self, flags=KeyFlags.NONE):
        super(CustomKeyInformation, self).__init__()
        self.Version = self.CurrentVersion
        self.Flags = flags
        self["Version"] = self.Version
        self["Flags"] = self.Flags

    @classmethod
    def fromBlob(self, blob: bytes, version):
        # Validate the input
        assert (len(blob) >= self.ShortRepresentationSize)

        self = CustomKeyInformation()

        stream_data = io.BytesIO(blob)
        # An 8-bit unsigned integer that must be set to 1:
        self.Version = None
        self.Version = struct.unpack('<B', stream_data.read(1))[0]
        self["Version"] = self.Version

        # An 8-bit unsigned integer that specifies zero or more bit-flag values.
        self.Flags = None
        self.Flags = KeyFlags(struct.unpack('<B', stream_data.read(1))[0])
        self["Flags"] = self.Flags

        # Note: This structure has two possible representations.
        # In the first representation, only the Version and Flags fields are
        # present; in this case the structure has a total size of two bytes.
        # In the second representation, all additional fields shown below are
        # also present; in this case, the structure's total size is variable.
        # Differentiating between the two representations must be inferred using
        # only the total size.

        # An 8-bit unsigned integer that specifies one of the volume types.
        data = stream_data.read(1)
        if len(data) != 0:
            self.VolumeType = struct.unpack('<B', data)[0]
        else:
            self.VolumeType = None
        self["VolumeType"] = self.VolumeType

        # An 8-bit unsigned integer that specifies whether the device associated with this credential supports notification.
        data = stream_data.read(1)
        if len(data) != 0:
            self.SupportsNotification = bool(struct.unpack('<B', data)[0]);
        else:
            self.SupportsNotification = None
        self["SupportsNotification"] = self.SupportsNotification

        # An 8-bit unsigned integer that specifies the version of the
        # File Encryption Key (FEK). This field must be set to 1.
        data = stream_data.read(1)
        if len(data) != 0:
            self.FekKeyVersion = struct.unpack('<B', data)[0]
        else:
            self.FekKeyVersion = None
        self["FekKeyVersion"] = self.FekKeyVersion

        # An 8-bit unsigned integer that specifies the strength of the NGC key.
        data = stream_data.read(1)
        if len(data) != 0:
            self.Strength = struct.unpack('<B', data)[0]
        else:
            self.Strength = None
        self["Strength"] = self.Strength

        # 10 bytes reserved for future use.
        # Note: With FIDO, Azure incorrectly puts here 9 bytes instead of 10.
        data = stream_data.read(10)
        if len(data) != 0:
            self.Reserved = data.ljust(10, b"\x00")
        else:
            self.Reserved = None
        self["Reserved"] = self.Reserved

        # Extended custom key information.
        data = stream_data.read()
        if len(data) != 0:
            self.EncodedExtendedCKI = data
        else:
            self.EncodedExtendedCKI = None
        self["EncodedExtendedCKI"] = self.EncodedExtendedCKI
        return self


    def toDict(self):
        CustomKeyInformationDict = {
            'Version': self.Version,
            'Flags': self.Flags.value,
            'VolumeType': self.VolumeType,
            'SupportsNotification': self.SupportsNotification,
            'FekKeyVersion': self.FekKeyVersion,
            'Strength': self.Strength,
            'Reserved': self.Reserved,
            'EncodedExtendedCKI': self.EncodedExtendedCKI
        }
        return CustomKeyInformationDict

    @classmethod
    def fromDict(cls, data):
        cki = cls(flags=KeyFlags(data["Flags"]))
        cki.Version = data["Version"]
        cki.VolumeType = CustomKeyInformationVolumeType(data["VolumeType"]) if data["VolumeType"] is not None else None
        cki.SupportsNotification = data["SupportsNotification"]
        cki.Strength = data["Strength"]
        cki.FekKeyVersion = data["FekKeyVersion"]
        cki.Reserved = data["Reserved"]
        cki.EncodedExtendedCKI = data["EncodedExtendedCKI"]
        cki["Version"] = cki.Version
        cki["VolumeType"] = cki.VolumeType
        cki["SupportsNotification"] = cki.SupportsNotification
        cki["FekKeyVersion"] = cki.FekKeyVersion
        cki["Strength"] = cki.Strength
        cki["Reserved"] = cki.Reserved
        cki["EncodedExtendedCKI"] = cki.EncodedExtendedCKI
        return cki


    def toByteArray(self) -> bytes:
        stream_data = b""
        stream_data += struct.pack("<B", self.Version)
        stream_data += struct.pack("<B", self.Flags.value)

        if self.VolumeType is not None:
            stream_data += struct.pack("<B", self.VolumeType.value)

        if self.SupportsNotification is not None:
            stream_data += struct.pack("<B", self.SupportsNotification)

        if self.FekKeyVersion is not None:
            stream_data += self.FekKeyVersion
            # stream_data += struct.pack("<B", self.FekKeyVersion.value)

        if self.Strength is not None:
            stream_data += struct.pack("<B", self.Strength.value)

        if self.Reserved is not None:
            stream_data += self.Reserved.ljust(10, b"\x00")

        if self.EncodedExtendedCKI is not None:
            stream_data += self.EncodedExtendedCKI

        return stream_data

    def __repr__(self):
        return "<CustomKeyInformation at 0x%x>" % id(self)
