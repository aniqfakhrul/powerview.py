#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ObjectInfoFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class ObjectInfoFlags(Enum):
    """
    ObjectInfoFlags

    Flags for ESENT objects (tables).  Used in <see cref="JET_OBJECTINFO"/>.
    """

    # Default options.
    NONE = 0

    # Object is for internal use only.
    System = -2147483648 # 0x80000000
    # It's possible to use bit shift to avoid triggering fxcop CA2217.
    # System = (0x1 << 31) # 0x80000000
    # (http://social.msdn.microsoft.com/Forums/en-US/vstscode/thread/a44aa5c1-c62a-46b7-8009-dc46ba21ba93)
    # But we don't want to change the type of the enum to a long.

    # Table's DDL is fixed.
    TableFixedDDL = 0x40000000

    # Table's DDL is inheritable.
    TableTemplate = 0x20000000

    # Table's DDL is inherited from a template table.
    TableDerived = 0x10000000

    # Fixed or variable columns in derived tables (so that fixed or variable
    # columns can be added to the template in the future).
    # Used in conjunction with <see cref="TableTemplate"/>.
    TableNoFixedVarColumnsInDerivedTables = 0x04000000
