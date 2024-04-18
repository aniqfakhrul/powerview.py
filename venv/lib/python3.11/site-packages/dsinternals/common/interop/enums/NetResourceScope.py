#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetResourceScope.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class NetResourceScope(Enum):
    """
    NetResourceScope

    The scope of the enumeration.

    https://msdn.microsoft.com/library/windows/desktop/aa385353.aspx
    """

    # Enumerate currently connected resources. The dwUsage member cannot be specified.
    Connected = 0x00000001

    # Enumerate all resources on the network. The dwUsage member is specified.
    Globalnet = 0x00000002

    # Enumerate remembered (persistent) connections. The dwUsage member cannot be specified.
    Remembered = 0x00000003
    Recent = 0x00000004
    Context = 0x00000005
