#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_wrn.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum

class JET_wrn(Enum):
    """
    JET_wrn

    ESENT warning codes.
    """

    # Successful operation.
    Success = 0

    # The version store is still active
    RemainingVersions = 321

    # seek on non-unique index yielded a unique key
    UniqueKey = 345

    # Column is a separated long-value
    SeparateLongValue = 406

    # No more records to stream
    NoMoreRecords = 428

    # Existing log file has bad signature
    ExistingLogFileHasBadSignature = 558

    # Existing log file is not contiguous
    ExistingLogFileIsNotContiguous = 559

    # INTERNAL ERROR
    SkipThisRecord = 564

    # TargetInstance specified for restore is running
    TargetInstanceRunning = 578

    # One or more logs that were committed to this database, were not recovered.  The database is still clean/consistent, as though the lost log's transactions were committed lazily (and lost).
    CommittedLogFilesLost = 585

    # One or more logs that were committed to this database, were no recovered.  The database is still clean/consistent, as though the corrupted log's transactions were committed lazily (and lost).
    CommittedLogFilesRemoved = 587

    # Signal used by clients to indicate JetInit() finished with undo
    FinishWithUndo = 588

    # Database corruption has been repaired
    DatabaseRepaired = 595

    # Column is NULL-valued
    ColumnNull = 1004

    # Buffer too small for data
    BufferTruncated = 1006

    # Database is already attached
    DatabaseAttached = 1007

    # Sort does not fit in memory
    SortOverflow = 1009

    # Exact match not found during seek
    SeekNotEqual = 1039

    # No extended error information
    NoErrorInfo = 1055

    # No idle activity occured
    NoIdleActivity = 1058

    # No write lock at transaction level 0
    NoWriteLock = 1067

    # Column set to NULL-value
    ColumnSetNull = 1068

    # Database file could not be shrunk because there is not enough internal free space available or there is unmovable data present.
    ShrinkNotPossible = 1122

    # Warning code DTC callback should return if the specified transaction is to be committed
    DTCCommitTransaction = 1163

    # Warning code DTC callback should return if the specified transaction is to be rolled back
    DTCRollbackTransaction = 1164

    # Opened an empty table
    TableEmpty = 1301

    # System cleanup has a cursor open on the table
    TableInUseBySystem = 1327

    # Out of date index removed
    CorruptIndexDeleted = 1415

    # The Primary index is created with an incompatible OS sort version. The table can not be safely modified.
    PrimaryIndexOutOfDate = 1417

    # One or more Secondary index is created with an incompatible OS sort version. Any index over Unicode text should be deleted.
    SecondaryIndexOutOfDate = 1418

    # Max length too big, truncated
    ColumnMaxTruncated = 1512

    # Single instance column bursted
    CopyLongValue = 1520

    # RetrieveTaggedColumnList ran out of copy buffer before retrieving all tagged columns
    TaggedColumnsRemaining = 1523

    # Column value(s) not returned because the corresponding column id or itagSequence requested for enumeration was null
    ColumnSkipped = 1531

    # Column value(s) not returned because they could not be reconstructed from the data at hand
    ColumnNotLocal = 1532

    # Column values exist that were not requested for enumeration
    ColumnMoreTags = 1533

    # Column value truncated at the requested size limit during enumeration
    ColumnTruncated = 1534

    # Column values exist but were not returned by request
    ColumnPresent = 1535

    # Column value returned in JET_COLUMNENUM as a result of JET_bitEnumerateCompressOutput
    ColumnSingleValue = 1536

    # Column value(s) not returned because they were set to their default value(s) and JET_bitEnumerateIgnoreDefault was specified
    ColumnDefault = 1537

    # Column value(s) not returned because they could not be reconstructed from the data in the record
    ColumnNotInRecord = 1539

    # Column value returned as a reference because it could not be reconstructed from the data in the record
    ColumnReference = 1541

    # Data has changed
    DataHasChanged = 1610

    # Moved to new key
    KeyChanged = 1618

    # Database file is read only
    FileOpenReadOnly = 1813

    # Idle registry full
    IdleFull = 1908

    # Online defrag already running on specified database
    DefragAlreadyRunning = 2000

    # Online defrag not running on specified database
    DefragNotRunning = 2001

    # JetDatabaseScan already running on specified database
    DatabaseScanAlreadyRunning = 2002

    # JetDatabaseScan not running on specified database
    DatabaseScanNotRunning = 2003

    # Unregistered a non-existant callback function
    CallbackNotRegistered = 2100

    # The log data provided jumped to the next log suddenly, we have deleted the incomplete log file as a precautionary measure
    PreviousLogFileIncomplete = 2602


