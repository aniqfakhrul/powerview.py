#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : PekListFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class PekListFlags(Enum):
    """
    PekListFlags

    Format of the Password Encryption Key.
    """

    # The PEK is not encrypted. This is a transient state between dcpromo and first boot.
    Clear = 0

    # The PEK is encrypted.
    Encrypted = 1

