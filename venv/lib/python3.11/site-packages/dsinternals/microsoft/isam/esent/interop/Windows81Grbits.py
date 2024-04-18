#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Windows81Grbits.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class ShrinkDatabaseGrbit(Enum):
    """
    ShrinkDatabaseGrbit
    
    Options for <see cref="Windows81Param.EnableShrinkDatabase"/>.
    """

    # Does not reduce the size of the database during normal operations.
    Off = 0x0

    # Turns on the database shrinking functionality. If this parameter is not
    # set, then <see cref="Windows8Api.JetResizeDatabase"/> will be unable to reclaim
    # space to the file system.
    # Uses the file system's Sparse Files feature to release space
    # in the middle of a file. When enough rows or tables get free up by
    # the Version Store Cleanup task, and space is reclaimed, the database
    # engine will attempt to return it to the file system, via sparse files.
    # Sparse files are currently only available on NTFS and ReFS file systems.
    On = 0x1

    # After space is release from a table to a the root Available Extent, the database
    # engine will attempt to release the space back to the file system. This parameter
    # requires that <see cref="On"/> is also specified.
    Realtime = 0x2


class Windows81Grbits(object):
    """
    Windows81Grbits
    
    Options that have been introduced in Windows 8.1.
    """

    # Only shrink the database to the desired size, but keeping an 
    # empty extent at the end. If the resize call would grow the database, do nothing.
    # In order to use this functionality, <see cref="InstanceParameters.EnableShrinkDatabase"/>
    # must be set to <see cref="ShrinkDatabaseGrbit.On"/>. Otherwise, an exception may
    # be thrown.
    OnlyShrink = ResizeDatabaseGrbit(0x2)

