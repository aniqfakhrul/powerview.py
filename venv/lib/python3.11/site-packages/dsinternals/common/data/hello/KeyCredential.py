#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : KeyCredential.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

import binascii
import io
import struct

from dsinternals.common.data.hello.KeyUsage import KeyUsage
from dsinternals.common.data.hello.KeyFlags import KeyFlags
from dsinternals.common.data.hello.KeySource import KeySource
from dsinternals.common.data.hello.KeyCredentialVersion import KeyCredentialVersion
from dsinternals.common.data.hello.KeyCredentialEntryType import KeyCredentialEntryType
from dsinternals.common.cryptography.X509Certificate2 import X509Certificate2
from dsinternals.common.cryptography.RSAKeyMaterial import RSAKeyMaterial
from dsinternals.common.data.hello.CustomKeyInformation import CustomKeyInformation
from dsinternals.common.data.DNWithBinary import DNWithBinary
from dsinternals.system.DateTime import DateTime
from dsinternals.Utils import ComputeKeyIdentifier, ConvertFromBinaryTime, ConvertToBinaryTime, ConvertFromBinaryIdentifier, ConvertToBinaryIdentifier, ComputeHash
from dsinternals.system.Guid import Guid


class KeyCredential(object):
    """
    This class represents a single AD/AAD key credential.

    In Active Directory, this structure is stored as the binary portion of the msDS-KeyCredentialLink DN-Binary attribute
    in the KEYCREDENTIALLINK_BLOB format.
    The Azure Active Directory Graph API represents this structure in JSON format.

    <see>https://msdn.microsoft.com/en-us/library/mt220505.aspx</see>
    """

    # Minimum length of the structure.
    MinLength = 4
    # Version

    # V0 structure alignment in bytes.
    PackSize = 4

    # Defines the version of the structure.
    Version: KeyCredentialVersion = KeyCredentialVersion.Version0

    # Version 1 keys had a guid in this field instead if a hash.
    Identifier: str = ""

    Usage: KeyUsage = None

    LegacyUsage: str = ""

    Source: KeySource = None

    """
    def  bool IsWeak: 
        get
        {
            var key = self.RSApublicKey
            return key.HasValue && key.Value.IsWeakKey()
        }
    }

    # Key material of the credential.
    def  byte[] RawKeyMaterial: 
    
    def  RSAParameters? RSApublicKey: 
        get
        {
            if(self.RawKeyMaterial == null)
            {
                return null
            }

            if(self.Usage == KeyUsage.NGC || self.Usage == KeyUsage.STK)
            {
                # The RSA def  key can be stored in at least 3 different formats.

                if (self.RawKeyMaterial.IsBCryptRSApublicKeyBlob()) : 
                    # This def  key is in DER format. This is typically true for device/computer keys.
                    return self.RawKeyMaterial.ImportRSApublicKeyBCrypt()
                }
                else if(self.RawKeyMaterial.IsTPM20publicKeyBlob()) : 
                    # This def  key is encoded as PCP_KEY_BLOB_WIN8. This is typically true for device keys protected by TPM.
                    # The PCP_KEY_BLOB_WIN8 structure is not yet supported by DSInternals.
                    return null
                }
                else if(self.RawKeyMaterial.IsDERpublicKeyBlob()) : 
                    # This def  key is encoded as BCRYPT_RSAKEY_BLOB. This is typically true for user keys.
                    return self.RawKeyMaterial.ImportRSApublicKeyDER()
                }
            }

            # Other key usages probably do not contain any def  keys.
            return null
        }
    }
    
    def  string RSAModulus: 
        get
        {
            var publicKey = self.RSApublicKey
            return publicKey.HasValue ? Convert.ToBase64String(publicKey.Value.Modulus) : null
        }
    }
    """

    CustomKeyInfo: CustomKeyInformation = None

    DeviceId: Guid = None

    # The approximate time this key was created.
    CreationTime: DateTime = None

    # The approximate time this key was last used.
    LastLogonTime: DateTime = None

    # Distinguished name of the AD object (UPN in case of AAD objects) that holds this key credential.
    Owner: str = ""

    @classmethod
    def fromX509Certificate2(cls, certificate: X509Certificate2, deviceId: Guid, owner: str, currentTime: DateTime = None, isComputerKey=False):
        assert (certificate is not None)

        # Computer NGC keys are DER-encoded, while user NGC keys are encoded as BCRYPT_RSAKEY_BLOB.
        if isComputerKey:
            publicKey = certificate.ExportRSAPublicKeyDER()
        else:
            publicKey = certificate.ExportRSAPublicKeyBCrypt()
        return cls(publicKey, deviceId, owner, currentTime, isComputerKey)

    def __init__(self, publicKey: RSAKeyMaterial, deviceId: Guid, owner: str, currentTime=None, isComputerKey: bool = False):
        # Process owner DN/UPN
        assert (len(owner) != 0)
        if type(owner) == str:
            self.Owner = owner
        elif type(owner) == bytes:
            self.Owner = owner.decode("UTF-8")

        # Initialize the Key Credential based on requirements stated in MS-KPP Processing Details:
        self.Version = KeyCredentialVersion.Version2
        self.Identifier = ComputeKeyIdentifier(publicKey.toRawBytes(), self.Version)
        self.KeyHash = None
        if currentTime is not None:
            if type(currentTime) == int:
                self.CreationTime = DateTime(currentTime)
            elif type(currentTime):
                self.CreationTime = currentTime
            else:
                pass
        else:
            self.CreationTime = DateTime()
        self.RawKeyMaterial = publicKey
        self.Usage = KeyUsage.NGC
        self.LegacyUsage = None
        self.Source = KeySource.AD
        self.DeviceId = deviceId
        self.computed_hash = "\x00"*16
        # Computer NGC keys have to meet some requirements to pass the validated write
        # The CustomKeyInformation entry is not present.
        # The KeyApproximateLastLogonTimeStamp entry is not present.
        if not isComputerKey:
            self.LastLogonTime = self.CreationTime
            self.CustomKeyInfo = CustomKeyInformation(KeyFlags.NONE)

    @classmethod
    def fromDNWithBinary(cls, dnWithBinary: DNWithBinary):
        # Input validation
        """Validator.AssertNotNull(blob, nameof(blob))
        Validator.AssertMinLength(blob, MinLength, nameof(blob))
        Validator.AssertNotNullOrEmpty(owner, nameof(owner))"""
        assert (len(dnWithBinary.BinaryData) >= cls.MinLength)
        assert (len(dnWithBinary.DistinguishedName) > 0)

        _Version = None
        _KeyID = None
        _KeyHash = None
        _KeyMaterial = None
        _KeyUsage = None
        _KeyLegacyUsage = None
        _KeySource = None
        _DeviceId = None
        _CustomKeyInformation = None
        _KeyApproximateLastLogonTimeStamp = None
        _KeyCreationTime = None

        # Parse binary input
        stream_data = io.BytesIO(dnWithBinary.BinaryData)

        _Version = KeyCredentialVersion(struct.unpack('<L', stream_data.read(4))[0])

        # Read all entries corresponding to the KEYCREDENTIALLINK_ENTRY structure:
        read_data = stream_data.read(3)
        while read_data != b'':
            # A 16-bit unsigned integer that specifies the length of the Value field.
            length, entryType = struct.unpack('<HB', read_data)
            # An 8-bit unsigned integer that specifies the type of data that is stored in the Value field.
            entry = {
                "entryType": entryType,
                "data": stream_data.read(length)
            }

            if entry["entryType"] == KeyCredentialEntryType.KeyID.value:
                _KeyID = ConvertFromBinaryIdentifier(entry["data"], _Version)

            elif entry["entryType"] == KeyCredentialEntryType.KeyHash.value:
                _KeyHash = entry["data"]

            elif entry["entryType"] == KeyCredentialEntryType.KeyMaterial.value:
                _KeyMaterial = RSAKeyMaterial.fromRawBytes(entry["data"])

            elif entry["entryType"] == KeyCredentialEntryType.KeyUsage.value:
                if len(entry["data"]) == 1:
                    # This is apparently a V2 structure
                    _KeyUsage = KeyUsage(entry["data"][0])
                else:
                    # This is a legacy structure that contains a string-encoded key usage instead of enum.
                    _KeyLegacyUsage = entry["data"]

            elif entry["entryType"] == KeyCredentialEntryType.KeySource.value:
                _KeySource = KeySource(entry["data"][0])

            elif entry["entryType"] == KeyCredentialEntryType.DeviceId.value:
                _DeviceId = Guid.fromRawBytes(entry["data"])

            elif entry["entryType"] == KeyCredentialEntryType.CustomKeyInformation.value:
                _CustomKeyInformation = CustomKeyInformation.fromBlob(entry["data"], _Version)

            elif entry["entryType"] == KeyCredentialEntryType.KeyApproximateLastLogonTimeStamp.value:
                _KeyApproximateLastLogonTimeStamp = ConvertFromBinaryTime(entry["data"], _KeySource, _Version)

            elif entry["entryType"] == KeyCredentialEntryType.KeyCreationTime.value:
                _KeyCreationTime = ConvertFromBinaryTime(entry["data"], _KeySource, _Version)

            read_data = stream_data.read(3)

        self = cls(_KeyMaterial, _DeviceId, dnWithBinary.DistinguishedName, _KeyCreationTime)
        self.Version = _Version
        self.Identifier = _KeyID
        self.KeyHash = _KeyHash
        self.Usage = _KeyUsage
        self.LegacyUsage = _KeyLegacyUsage
        self.Source = _KeySource
        self.CustomKeyInfo = _CustomKeyInformation
        self.LastLogonTime = _KeyApproximateLastLogonTimeStamp

        return self

    def toString(self) -> str:
        return "Id: %s, Source: %s, Version: %s, Usage: %s, CreationTime: %s" % (
            self.Identifier,
            self.Source,
            self.Version,
            self.Usage,
            self.CreationTime
        )

    def toByteArray(self):
        # Note that we do not support the legacy V1 format yet.

        # Serialize properties 3-9 first, as property 2 must contain their hash:
        binaryData = b""
        binaryProperties = b""

        # Key Material
        _data = self.RawKeyMaterial.toRawBytes()
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyMaterial.value)
        binaryProperties += _data

        # Key Usage
        _data = None
        if self.LegacyUsage is not None and self.Usage is None:
            _data = self.LegacyUsage
        elif self.Usage is not None and self.LegacyUsage is None:
            _data = struct.pack("<B", self.Usage.value)
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyUsage.value)
        binaryProperties += _data

        # Key Source
        _data = struct.pack("<B", self.Source.value)
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeySource.value)
        binaryProperties += _data

        # Device ID
        if self.DeviceId is not None:
            _data = self.DeviceId.toRawBytes()
            binaryProperties += struct.pack("<H", len(_data))
            binaryProperties += struct.pack("<B", KeyCredentialEntryType.DeviceId.value)
            binaryProperties += _data

        # Custom Key Information
        if self.CustomKeyInfo is not None:
            _data = self.CustomKeyInfo.toByteArray()
            binaryProperties += struct.pack("<H", len(_data))
            binaryProperties += struct.pack("<B", KeyCredentialEntryType.CustomKeyInformation.value)
            binaryProperties += _data

        # Last Logon Time
        if self.LastLogonTime is not None:
            _data = ConvertToBinaryTime(self.LastLogonTime, self.Source, self.Version)
            binaryProperties += struct.pack("<H", len(_data))
            binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyApproximateLastLogonTimeStamp.value)
            binaryProperties += _data

        # Creation Time
        _data = ConvertToBinaryTime(self.CreationTime, self.Source, self.Version)
        binaryProperties += struct.pack("<H", len(_data))
        binaryProperties += struct.pack("<B", KeyCredentialEntryType.KeyCreationTime.value)
        binaryProperties += _data

        # Creating header + hash + binaryProperties
        # Version
        binaryData += struct.pack('<L', self.Version.value)

        # Key Identifier
        _data = ConvertToBinaryIdentifier(self.Identifier, self.Version)
        binaryData += struct.pack("<H", len(_data))
        binaryData += struct.pack("<B", KeyCredentialEntryType.KeyID.value)
        binaryData += _data

        # Key Hash
        self.computed_hash = ComputeHash(binaryProperties)
        binaryData += struct.pack("<H", len(self.computed_hash))
        binaryData += struct.pack("<B", KeyCredentialEntryType.KeyHash.value)
        binaryData += self.computed_hash

        # Append the remaining entries
        binaryData += binaryProperties

        return binaryData

    def toDNWithBinary(self) -> DNWithBinary:
        # This method should only be used when the owner is in the form of a Distinguished Name.
        return DNWithBinary(self.Owner, self.toByteArray())

    def verifyHash(self) -> bool:
        # Key Identifier
        self.toByteArray()
        return bool(self.computed_hash == self.KeyHash)

    def toDict(self) -> dict:
        keyCredentialDict = {
            'Owner': self.Owner,
            'Version': self.Version.value,
            'Identifier': self.Identifier,
            'KeyHash': binascii.hexlify(self.KeyHash).decode('UTF-8'),
            'CreationTime': self.CreationTime.toTicks(),
            'RawKeyMaterial': self.RawKeyMaterial.toDict(),
            'Usage': self.Usage.value,
            'LegacyUsage': self.LegacyUsage,
            'Source': self.Source.value,
            'DeviceId': self.DeviceId.toFormatD(),
            'LastLogonTime': self.LastLogonTime.toTicks(),
            #todo : toTicks doesn't seem to work
            'CustomKeyInfo': self.CustomKeyInfo.toDict()
        }
        return keyCredentialDict

    @classmethod
    def fromDict(cls, data):
        KeyMaterial = RSAKeyMaterial.fromDict(data["RawKeyMaterial"])
        keyCredential = cls(publicKey=KeyMaterial, deviceId=Guid.fromFormatD(data["DeviceId"]), owner=data["Owner"], currentTime=DateTime(data["CreationTime"]))
        keyCredential.Version = KeyCredentialVersion(data["Version"])
        keyCredential.Identifier = data["Identifier"]
        keyCredential.KeyHash = binascii.unhexlify(data["KeyHash"])
        keyCredential.Usage = KeyUsage(data["Usage"])
        keyCredential.LegacyUsage = data["LegacyUsage"]
        keyCredential.Source = KeySource(data["Source"])
        keyCredential.CustomKeyInfo = CustomKeyInformation.fromDict(data["CustomKeyInfo"])
        keyCredential.LastLogonTime = DateTime(data["LastLogonTime"])
        return keyCredential

    def show(self):
        print("<KeyCredential structure at %s>" % hex(id(self)))
        print("  | \x1b[93mOwner\x1b[0m:", self.Owner)
        print("  | \x1b[93mVersion\x1b[0m:", hex(self.Version.value))
        print("  | \x1b[93mKeyID\x1b[0m:", self.Identifier)
        """
        if self.verifyHash() == True:
            print("  | \x1b[93mKeyHash\x1b[0m: %s (verified=\x1b[92mTrue\x1b[0m)" % binascii.hexlify(self.KeyHash).decode('UTF-8'))
        else:
            print("  | \x1b[93mKeyHash\x1b[0m: %s (verified=\x1b[91mFalse\x1b[0m)" % binascii.hexlify(self.KeyHash).decode('UTF-8'))
        """
        print("  | \x1b[93mKeyHash\x1b[0m: %s" % binascii.hexlify(self.KeyHash).decode('UTF-8'))
        print("  | \x1b[93mRawKeyMaterial\x1b[0m:", self.RawKeyMaterial)
        print("  |  | \x1b[93mExponent (E)\x1b[0m: %d" % self.RawKeyMaterial.exponent)
        print("  |  | \x1b[93mModulus (N)\x1b[0m: %s" % hex(self.RawKeyMaterial.modulus))
        print("  |  | \x1b[93mPrime1 (P)\x1b[0m: %s" % hex(self.RawKeyMaterial.prime1))
        print("  |  | \x1b[93mPrime2 (Q)\x1b[0m: %s" % hex(self.RawKeyMaterial.prime2))

        print("  | \x1b[93mUsage\x1b[0m:", self.Usage)
        print("  | \x1b[93mLegacyUsage\x1b[0m:", self.LegacyUsage)
        print("  | \x1b[93mSource\x1b[0m:", self.Source)
        print("  | \x1b[93mDeviceId\x1b[0m:", self.DeviceId.toFormatD())
        print("  | \x1b[93mCustomKeyInfo\x1b[0m:", self.CustomKeyInfo)
        for key in self.CustomKeyInfo.keys():
            print("  |  | \x1b[93m%s\x1b[0m:" % key, self.CustomKeyInfo[key])
        print("  | \x1b[93mLastLogonTime (UTC)\x1b[0m:", self.LastLogonTime)
        print("  | \x1b[93mCreationTime (UTC)\x1b[0m:", self.CreationTime)

    def __bytes__(self):
        return self.toByteArray()
