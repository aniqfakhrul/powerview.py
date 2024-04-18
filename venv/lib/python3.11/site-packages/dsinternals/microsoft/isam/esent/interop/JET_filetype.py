#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_filetype.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_filetype(Enum):
    """
    JET_filetype

    Esent file types.
    """

    # Unknown file.
    Unknown = 0

    # Database file.
    Database = 1

    # Transaction log.
    Log = 3

    # Checkpoint file.
    Checkpoint = 4

    # Temporary database.
    TempDatabase = 5
