#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_dbstate.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_dbstate(Enum):
    """
    Database states (used in <see cref="JET_DBINFOMISC"/>).
    """

    # The database was just created.
    JustCreated = 1

    # Dirty shutdown (inconsistent) database.
    DirtyShutdown = 2

    # Clean shutdown (consistent) database.
    CleanShutdown = 3

    # Database is being converted.
    BeingConverted = 4

    # Database was force-detached.
    ForceDetach = 5
