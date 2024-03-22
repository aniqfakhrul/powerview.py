#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetResourceUsage.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class NetResourceUsage(Enum):
    """
    NetResourceUsage

    A set of bit flags describing how the resource can be used.

    See: https://msdn.microsoft.com/library/windows/desktop/aa385353.aspx
    """

    # The resource is a connectable resource.
    Connectable = 0x00000001

    # The resource is a container resource.
    Container = 0x00000002

    # The resource is not a local device.
    NoLocalDevice = 0x00000004

    # The resource is a sibling. This value is not used by Windows.
    Sibling = 0x00000008

    # The resource must be attached.
    Attached = 0x00000010
    All = Connectable | Container | Attached
    Reserved = 0x80000000
