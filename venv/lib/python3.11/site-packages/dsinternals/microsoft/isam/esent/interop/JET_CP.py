#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_CP.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_CP(Enum):
    """
    JET_CP
    
    Codepage for an ESENT column.
    """

    # Code page for non-text columns.
    NONE = 0

    # Unicode encoding.
    Unicode = 1200

    # ASCII encoding.
    ASCII = 1252
