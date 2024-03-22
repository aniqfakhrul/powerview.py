#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : jet_index_column.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JetRelop(Enum):
    """
    Comparison operation for filter defined as <see cref="JET_INDEX_COLUMN"/>.
    """

    # Accept only rows which have column value equal to the given value.
    Equals = 0

    # Accept only rows which have columns whose prefix matches the given value.
    PrefixEquals = 1

    # Accept only rows which have column value not equal to the given value.
    NotEquals = 2

    # Accept only rows which have column value less than or equal a given value.
    LessThanOrEqual = 3

    # Accept only rows which have column value less than a given value.
    LessThan = 4

    # Accept only rows which have column value greater than or equal a given value.
    GreaterThanOrEqual = 5

    # Accept only rows which have column value greater than a given value.
    GreaterThan = 6

    # Accept only rows which have column value ANDed with a given bitmask yielding zero.
    BitmaskEqualsZero = 7

    # Accept only rows which have column value ANDed with a given bitmask yielding non-zero.
    BitmaskNotEqualsZero = 8


# The native version of the <see cref="JET_INDEX_COLUMN"/> structure.
NATIVE_INDEX_COLUMN = {
    # The column identifier for the column to check.
    columnid: "",
    # The comparison operation.
    relop: "",
    # A pointer to a value to compare.
    pvData: "",
    # The size of value beginning at pvData, in bytes.
    cbData: "",
    # Options regarding this column value.
    grbit: ""
}


class JET_INDEX_COLUMN(object):
    """
    JET_INDEX_COLUMN

    Contains filter definition for <see cref="Windows8Api.JetPrereadIndexRanges"/> and <see cref="Windows8Api.JetSetCursorFilter"/>.
    """

    # Gets or sets the column identifier for the column to retrieve.
    columnid: JET_COLUMNID = None

    # Gets or sets the filter comparison operation.
    relop: JetRelop = None

    # Gets or sets the value to comparte the column with.
    pvData: bytes = b""

    # Gets or sets the option for this column comparison.
    grbit: JetIndexColumnGrbit

    def toString(self) -> str:
        """
        Returns a <see cref="T:System.String"/> that represents the current <see cref="JET_INDEX_COLUMN"/>.

        A <see cref="T:System.String"/> that represents the current <see cref="JET_INDEX_COLUMN"/>.
        """
        return string.Format(CultureInfo.InvariantCulture, "JET_INDEX_COLUMN(0x{0:x})", self.columnid)

    def GetNativeIndexColumn(self, handles):
        """
        Gets the NATIVE_indexcolumn structure that represents the object.
        <param name="handles">GC handle collection to add any pinned handles.</param>
        <returns>The NATIVE_indexcolumn structure.</returns>
        """

        indexColumn = NATIVE_INDEX_COLUMN.copy()
        indexColumn['columnid'] = self.columnid.Value
        indexColumn['relop'] = self.relop
        indexColumn['grbit'] = self.grbit

        if self.pvData is not None:
            indexColumn.pvData = handles.Add(self.pvData)
            indexColumn.cbData = self.pvData.Length

        return indexColumn
