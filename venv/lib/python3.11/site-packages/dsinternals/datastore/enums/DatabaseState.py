#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : databasestate.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class DatabaseState(Enum):
    """
    DatabaseState
    """

    # The initial DIT is being created.
    Initial = 0

    # The initial DIT has been created.
    Boot = 1

    # DcPromo completed. Used in Windows Server 2000.
    Installed = 2

    # DCPromo completed. Used since Windows Server 2003.
    Running = 3

    # Snapshot is being created.
    BackedUp = 4

    # DcPromo has failed.
    Error = 5

    # The first phase of restore is done.
    RestoredPhaseI = 6

    # DcPromo completed.
    RealInstalled = 7

    # DcPromo is performing IFM
    Ifm = 8

    # Demotion has begun.
    Demoting = 9

    # Demotion has finished.
    Demoted = 10
