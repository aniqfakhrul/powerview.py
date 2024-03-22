#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_coltyp.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_coltyp(Enum):
    """
    JET_coltyp
    
    ESENT column types. This list is not extensive. Some column types introduced later
    are in different classes, such as <see cref="VistaColtyp"/>.
    <seealso cref="VistaColtyp"/>
    <seealso cref="Windows10.Windows10Coltyp"/>
    """

    # Null column type. Invalid for column creation.
    Nil = 0

    # True, False or NULL.
    Bit = 1

    # 1-byte integer, unsigned.
    UnsignedByte = 2

    # 2-byte integer, signed.
    Short = 3

    # 4-byte integer, signed.
    Long = 4

    # 8-byte integer, signed.
    Currency = 5

    # 4-byte IEEE single-precisions.
    IEEESingle = 6

    # 8-byte IEEE double-precision.
    IEEEDouble = 7

    # Integral date, fractional time.
    DateTime = 8

    # Binary data, up to 255 bytes.
    Binary = 9

    # Text data, up to 255 bytes.
    Text = 10

    # Binary data, up to 2GB.
    LongBinary = 11

    # Text data, up to 2GB.
    LongText = 12
