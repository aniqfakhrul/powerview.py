#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamSidType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamSidType(Enum):
    """
    SamSidType

    See: https://msdn.microsoft.com/en-us/library/windows/desktop/aa379601%28v=vs.85%29.aspx
    """

    User = 1
    Group = 2
    Domain = 3
    Alias = 4
    WellKnownGroup = 5
    DeletedAccount = 6
    Invalid = 7
    Unknown = 8
    Computer = 9
    Label = 10
