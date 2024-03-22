#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : DPAPIBackupKeyType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class DPAPIBackupKeyType(Enum):
    """
    DPAPIBackupKeyType
    """

    Unknown = 0,
    LegacyKey = 1
    RSAKey = 2
    PreferredLegacyKeyPointer = 3
    PreferredRSAKeyPointer = 4

