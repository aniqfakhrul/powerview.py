#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : LegacyFileNames.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class LegacyFileNames(ENum):
    """
    LegacyFileNames
    
    Options for LegacyFileNames.
    """

    # When this option is present then the database engine will use the following naming conventions for its files:
    #   o Transaction Log files will use .LOG for their file extension.
    #   o Checkpoint files will use .CHK for their file extension.
    ESE98FileNames = 0x00000001

    # Preserve the 8.3 naming syntax for as long as possible. (this should not be changed, w/o ensuring there are no log files).
    EightDotThreeSoftCompat = 0x00000002

