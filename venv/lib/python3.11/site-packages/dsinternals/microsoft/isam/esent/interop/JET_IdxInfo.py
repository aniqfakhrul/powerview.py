#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_IdxInfo.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_IdxInfo(Enum):
    """
    JET_IdxInfo

    Info levels for retrieve index information with JetGetIndexInfo.
    and JetGetTableIndexInfo.

    <seealso cref="Win7.Windows7IdxInfo"/>
    <seealso cref="Win8.Windows8IdxInfo"/>
    """

    # Returns a <see cref="JET_INDEXLIST"/> structure with information about the index.
    Default = 0

    # Returns a <see cref="JET_INDEXLIST"/> structure with information about the index.
    List = 1

    # SysTabCursor is obsolete.

    # This value is not used, and is provided for completeness to match the published header in the SDK.
    SysTabCursor = 2

    # OLC is obsolete.
    # This value is not used, and is provided for completeness to match the published header in the SDK.
    OLC = 3

    # Reset OLC is obsolete.
    # This value is not used, and is provided for completeness to match the published header in the SDK.
    ResetOLC = 4

    # Returns an integer with the space usage of the index.
    SpaceAlloc = 5

    # Returns an integer with the LCID of the index.
    LCID = 6

    # Langid is obsolete. Use <see cref="LCID"/> instead.
    Langid = 6

    # Returns an integer with the count of indexes in the table.
    Count = 7

    # Returns a ushort with the value of cbVarSegMac the index was created with.
    VarSegMac = 8

    # Returns a <see cref="JET_INDEXID"/> identifying the index.
    IndexId = 9

    # Introduced in Windows Vista. Returns a ushort with the value of cbKeyMost the
    # index was created with.
    KeyMost = 10