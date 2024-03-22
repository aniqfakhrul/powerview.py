#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : MatchCriteria.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class MatchCriteria(Enum):
    """
    MatchCriteria

    Choices for Cursor.FindRecords
    """

    # The cursor will be positioned at the index entry closest to the
    # start of the index that exactly matches the search key.
    EqualTo = SeekGrbit.SeekEQ

    # The cursor will be positioned at the index entry closest to the
    # end of the index that is less than an index entry that would
    # exactly match the search criteria.
    LessThan = SeekGrbit.SeekLT

    # The cursor will be positioned at the index entry closest to the
    # end of the index that is less than or equal to an index entry
    # that would exactly match the search criteria.
    LessThanOrEqualTo = SeekGrbit.SeekLE

    # The cursor will be positioned at the index entry closest to the
    # start of the index that is greater than or equal to an index
    # entry that would exactly match the search criteria.
    GreaterThanOrEqualTo = SeekGrbit.SeekGE

    # The cursor will be positioned at the index entry closest to the
    # start of the index that is greater than an index entry that
    # would exactly match the search criteria.
    GreaterThan = SeekGrbit.SeekGT
