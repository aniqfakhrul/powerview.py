#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SecretEncryptionType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SecretEncryptionType(Enum):
    """
    SecretEncryptionType
    """

    # TODO: Add support for SAM encryption types

    # Database secret encryption using PEK without salt.
    # <remarks>Used until Windows Server 2000 Beta 2</remarks>
    DatabaseRC4 = 0x10

    # Database secret encryption using PEK with salt.
    # <remarks>Used in Windows Server 2000 - Windows Server 2012 R2.</remarks>
    DatabaseRC4WithSalt = 0x11

    # Replicated secret encryption using Session Key with salt.
    ReplicationRC4WithSalt = 0x12

    # Database secret encryption using PEK and AES.
    # <remarks>Used since Windows Server 2016 TP4.</remarks>
    DatabaseAES = 0x13

