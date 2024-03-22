#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Server2003Grbits.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SnapshotAbortGrbit(Enum):
    """
    SnapshotAbortGrbit

    Options for <see cref="Server2003Api.JetOSSnapshotAbort"/>.
    """

    # Default options.
    NONE = 0


class UpdateGrbit(Enum):
    """
    UpdateGrbit

    Options for <see cref="Server2003Api.JetUpdate2"/>.
    """

    # Default options.
    NONE = 0

    # This flag causes the update to return an error if the update would
    # not have been possible in the Windows 2000 version of ESE, which
    # enforced a smaller maximum number of multi-valued column instances
    # in each record than later versions of ESE. This is important only
    # for applications that wish to replicate data between applications
    # hosted on Windows 2000 and applications hosted on Windows
    # 2003, or later versions of ESE. It should not be necessary for most
    # applications.
    CheckESE97Compatibility = 0x1

    # Grbits that have been added to the Windows Server 2003 version of ESENT.


class Server2003Grbits(object):
    """
    Server2003Grbits
    """

    # Delete all indexes with unicode columns.
    DeleteUnicodeIndexes = AttachDatabaseGrbit(0x400)

    # This is a finalizable column (delete record if escrow value equals 0).
    ColumnDeleteOnZero = ColumndefGrbit(0x20000)

    # This option requests that the temporary table only be created if the
    # temporary table manager can use the implementation optimized for
    # intermediate query results. If any characteristic of the temporary
    # table would prevent the use of this optimization then the operation
    # will fail with JET_errCannotMaterializeForwardOnlySort. A side effect
    # of this option is to allow the temporary table to contain records
    # with duplicate index keys. See <see cref="TempTableGrbit.Unique"/>
    # for more information.
    ForwardOnly = TempTableGrbit(0x40)

    # If a given column is not present in the record and it has a user
    # defined default value then no column value will be returned.
    # This option will prevent the callback that computes the user defined
    # default value for the column from being called when enumerating
    # the values for that column.

    # <remarks>
    # This option is only available for Windows Server 2003 SP1 and later
    # operating systems.
    # </remarks>
    EnumerateIgnoreUserDefinedDefault = EnumerateColumnsGrbit(0x00100000)

    # All transactions previously committed by any session that have not
    # yet been flushed to the transaction log file will be flushed immediately.
    # This API will wait until the transactions have been flushed before
    # returning to the caller. This option may be used even if the session
    # is not currently in a transaction. This option cannot be used in
    # combination with any other option.
    WaitAllLevel0Commit = CommitTransactionGrbit(0x8)
