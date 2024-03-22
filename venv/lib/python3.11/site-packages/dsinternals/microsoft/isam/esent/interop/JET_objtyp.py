#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_objtyp.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_objtyp(Enum):
    """
    JET_objtyp

    Type of an ESENT object.
    """

    # Invalid object type.
    Nil = 0

    # Object is a table.
    Table = 1
