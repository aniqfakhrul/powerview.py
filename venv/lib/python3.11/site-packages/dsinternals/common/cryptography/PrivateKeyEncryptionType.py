#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : PrivateKeyEncryptionType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class PrivateKeyEncryptionType(Enum):
    """
    PrivateKeyEncryptionType
    """

    NONE = 0
    PasswordRC4 = 1
    PasswordRC2CBC = 2
