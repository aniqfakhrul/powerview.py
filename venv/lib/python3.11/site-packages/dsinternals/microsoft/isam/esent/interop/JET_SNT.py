#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_SNT.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_SNT(Enum):
    """
    JET_SNT
    
    Type of progress being reported.
    """

    # Callback for the beginning of an operation.
    Begin = 5

    # Callback for operation progress.
    Progress = 0

    # Callback for the completion of an operation.
    Complete = 6

    # Callback for failure during the operation.
    Fail = 3

    # RecoveryStep was used for internal reserved functionality
    # prior to Windows 8. Windows 8 and later no longer use RecoveryStep.
    RecoveryStep = 8
