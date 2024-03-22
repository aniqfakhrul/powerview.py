#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RoamedCredentialFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class RoamedCredentialFlags(Enum):
    """
    RoamedCredentialFlags
    """

    Tombstone = (1 << 0)
    Unreadable = (1 << 1)
    Unwritable = (1 << 2)
    Unroamable = (1 << 3)
    KnownType = (1 << 4)
    EncryptionKey = (1 << 5)
