#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : KeyCredentialVersion.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021


from enum import Enum


class KeyCredentialVersion(Enum):
    """
    Key Credential Link Blob Structure Version

    See: https://msdn.microsoft.com/en-us/library/mt220501.aspx
    """
    Version0 = 0x0

    Version1 = 0x00000100

    Version2 = 0x00000200
