#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ColumnFlags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class ColumnFlags(Enum):
    """
    ColumnFlags
    
    Column flags enumeration
    """

    # Default options.
    NONE = ColumndefGrbit.NONE

    # The column will be fixed. It will always use the same amount of space in a row,
    # regardless of how much data is being stored in the column. Fixed
    # cannot be used with Tagged. This bit cannot be used with long values (i.e. Text
    # and Binary longer than 255 bytes).
    Fixed = ColumndefGrbit.ColumnFixed

    # A variable sized column, cannot be bigger than 255 bytes.
    Variable = ColumndefGrbit.NONE

    # Sparse columns take no space in the record unless set (unlike Fixed
    # or Variable columns) and can be up to 2GB in length. Can't be used with
    # <see cref="Fixed"/>.
    Sparse = ColumndefGrbit.ColumnTagged

    # This column cannot be set to NULL
    NonNull = ColumndefGrbit.ColumnNotNULL

    # This column will contain a version number maintained by the ISAM
    # that will be incremented on every update of the record.
    # This option can only be applied to integer columns.
    # This option can't be used with <see cref="AutoIncrement"/>,
    # <see cref="EscrowUpdate"/>, or <see cref="Sparse"/>.
    Version = ColumndefGrbit.ColumnVersion

    # The column will automatically be incremented. The number is an increasing number, and
    # is guaranteed to be unique within a table. The numbers, however, might not be continuous.
    # For example, if five rows are inserted into a table, the "autoincrement" column could
    # contain the values { 1, 2, 6, 7, 8 }. This bit can only be used on columns of type
    # integer types (int and long).
    AutoIncrement = ColumndefGrbit.ColumnAutoincrement

    # This column can be updated by the application (read-only flag, returned
    # by GetInformation-style calls only).
    Updatable = ObjectInfoGrbit.Updatable

    # The column can be multi-valued.
    # A multi-valued column can have zero, one, or more values
    # associated with it. The various values in a multi-valued column are identified by a number
    # called the itagSequence member.
    # Multi-valued columns must be tagged columns; that is, they cannot be fixed-length or
    # variable-length columns.
    # All multi-
    # valued columns are also sparse columns.
    MultiValued = ColumndefGrbit.ColumnMultiValued

    #  Specifies that a column is an escrow update column. An escrow update column can be
    #  updated concurrently by different sessions with JetEscrowUpdate and will maintain
    #  transactional consistency. An escrow update column must also meet the following conditions:
    #  An escrow update column can be created only when the table is empty.
    #  An escrow update column must be of type JET_coltypLong.
    #  An escrow update column must have a default value.
    #  JET_bitColumnEscrowUpdate cannot be used in conjunction with <see cref="Sparse"/>,
    #  <see cref="Version"/>, or <see cref="AutoIncrement"/>.
    EscrowUpdate = ColumndefGrbit.ColumnEscrowUpdate

    # When the escrow-update column reaches a value of zero, the callback function will be invoked.
    Finalize = ColumndefGrbit.ColumnFinalize

    # The default value for a column will be provided by a callback function. A column that
    # has a user-defined default must be a tagged column.
    UserDefinedDefault = ColumndefGrbit.ColumnUserDefinedDefault

    # This is a finalizable column (delete record if escrow value equals 0).
    DeleteOnZero = Server2003Grbits.ColumnDeleteOnZero

