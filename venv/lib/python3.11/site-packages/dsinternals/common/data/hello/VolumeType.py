#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : VolumeType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class VolumeType(Enum):
    """
    VolumeType

    Specifies the volume type.

    See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
    """

    # Volume not specified.
    NONE = 0x00

    # Operating system volume (OSV).
    OperatingSystem = 0x01

    # Fixed data volume (FDV).
    Fixed = 0x02

    # Removable data volume (RDV).
    Removable = 0x03
