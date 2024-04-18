#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_Move.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_Move(Enum):
    """

    Offsets for JetMove.
    """

    # Move the cursor to the first index entry.
    First = -2147483648

    # Move to the previous index entry.
    Previous = -1

    # Move to the next index entry.
    Next = 1

    # Move to the last index entry.
    Last = 0x7fffffff
