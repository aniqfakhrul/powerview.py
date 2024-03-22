#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetCancelOptions.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class NetCancelOptions(Enum):
    """
    NetCancelOptions

    A set of connection options.

    See: https://msdn.microsoft.com/library/windows/desktop/aa385413.aspx
    """

    # The system does not update information about the connection.
    NoUpdate = 0

    # The system updates the user profile with the information that the connection is no longer a persistent one.
    UpdateProfile = 0x00000001
