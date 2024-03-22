#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : KeyStrength.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

from enum import Enum


class KeyStrength(Enum):
    """
    Specifies the strength of the NGC key.

    See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
    """

    # Key strength is unknown.
    Unknown = 0x00

    # Key strength is weak.
    Weak = 0x01

    # Key strength is normal.
    Normal = 0x02
