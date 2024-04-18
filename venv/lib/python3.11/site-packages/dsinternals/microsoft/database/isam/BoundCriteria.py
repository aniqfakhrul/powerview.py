#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : BoundCriteria.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class BoundCriteria(Enum):
    # Choices for Cursor.FindRecordsBetween

    # Whether the bounds are included.
    Inclusive = 0

    # Whether the bounds are excluded.
    Exclusive = 1
