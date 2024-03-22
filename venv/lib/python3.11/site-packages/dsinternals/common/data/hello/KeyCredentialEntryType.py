#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : KeyCredentialEntryType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021


from enum import Enum

class KeyCredentialEntryType(Enum):
    """
    Key Credential Link Entry Identifier

    Describes the data stored in the Value field.
    https://msdn.microsoft.com/en-us/library/mt220499.aspx
    """

    # A SHA256 hash of the Value field of the KeyMaterial entry.
    KeyID = 0x01

    # A SHA256 hash of all entries following this entry.
    KeyHash = 0x02

    # Key material of the credential.
    KeyMaterial = 0x03

    # Key Usage
    KeyUsage = 0x04

    # Key Source
    KeySource = 0x05

    # Device Identifier
    DeviceId = 0x06

    # Custom key information.
    CustomKeyInformation = 0x07

    # The approximate time this key was last used, in FILETIME format.
    KeyApproximateLastLogonTimeStamp = 0x08

    # The approximate time this key was created, in FILETIME format.
    KeyCreationTime = 0x09
