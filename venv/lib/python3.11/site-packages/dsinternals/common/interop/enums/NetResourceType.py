#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetResourceType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class NetResourceType(Enum):
    """
    NetResourceType

    The type of resource.

    See: https://msdn.microsoft.com/library/windows/desktop/aa385353.aspx
    """

    # All resources.
    Any = 0x00000000

    # Disk resources.
    Disk = 0x00000001

    # Print resources.
    Print = 0x00000002
    Reserved = 0x00000008
    Unknown = 0xFFFFFFFF