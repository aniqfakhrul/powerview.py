#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : PekListVersion.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class PekListVersion(Enum):
    """
    PekListVersion

    Password Encryption Key List Version
    """

    # Version used before Windows 2000 RC2.
    PreW2kRC2 = 1

    # Version used since Windows 2000 RC2.
    W2k = 2

    # Version used since Windows Server 2016 TP4
    W2016 = 3

