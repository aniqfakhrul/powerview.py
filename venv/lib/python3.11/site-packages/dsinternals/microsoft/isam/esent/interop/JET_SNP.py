#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_SNP.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_SNP(Enum):
    """
    JET_SNP
    
    The type of operation that progress is being reported for.
    """

    # Callback is for a repair option.
    Repair = 2

    # Callback is for database defragmentation.
    Compact = 4

    # Callback is for a restore options.
    Restore = 8

    # Callback is for a backup options.
    Backup = 9

    # Callback is for database zeroing.
    Scrub = 11

    # Callback is for the process of upgrading the record format of
    # all database pages.
    UpgradeRecordFormat = 12

