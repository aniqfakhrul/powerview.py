#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ObjectInfoGrbit.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class ObjectInfoGrbit(Enum):
    """
    ObjectInfoGrbit

    Table options, used in <see cref="JET_OBJECTINFO"/>.
    """

    # The table can have bookmarks.
    Bookmark = 0x1

    # The table can be rolled back.
    Rollback = 0x2

    # The table can be updated.
    Updatable = 0x4
