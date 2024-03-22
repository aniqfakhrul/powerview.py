#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : KeyFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

from enum import Enum


class KeyFlags(Enum):
    """
    Custom Key Flags

    See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
    """

    # No flags specified.
    NONE = 0

    # Reserved for future use. (CUSTOMKEYINFO_FLAGS_ATTESTATION)
    Attestation = 0x01

    # During creation of this key, the requesting client authenticated using
    # only a single credential. (CUSTOMKEYINFO_FLAGS_MFA_NOT_USED)
    MFANotUsed = 0x02
