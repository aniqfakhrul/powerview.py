#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : grbits.py
# Author             : Podalirius (@podalirius_)
# Date created       : 1 Aug 2021

from enum import Enum


class CreateInstanceGrbit(Enum):
    """
    CreateInstanceGrbit

    Options for <see cref="Api.JetCreateInstance2"/>.
    """

    # Default options.
    NONE = 0


class InitGrbit(Enum):
    """
    InitGrbit

    # Options for <see cref="Api.JetInit2"/>.
    # <seealso cref="Vista.VistaGrbits.RecoveryWithoutUndo"/>
    # <seealso cref="Vista.VistaGrbits.TruncateLogsAfterRecovery"/>
    # <seealso cref="Vista.VistaGrbits.ReplayMissingMapEntryDB"/>
    # <seealso cref="Vista.VistaGrbits.LogStreamMustExist"/>
    # <seealso cref="Windows7.Windows7Grbits.ReplayIgnoreLostLogs"/>
    # <seealso cref="Windows8.Windows8Grbits.KeepDbAttachedAtEndOfRecovery"/>
    """

    # Default options.
    NONE = 0


class TermGrbit(Enum):
    """
    TermGrbit

    Options for <see cref="Api.JetTerm2"/>.
    <seealso cref="Windows7.Windows7Grbits.Dirty"/>
    """

    # Default options.
    NONE = 0

    # Requests that the instance be shut down cleanly. Any optional
    # cleanup work that would ordinarily be done in the background at
    # run time is completed immediately.
    Complete = 1

    # Requests that the instance be shut down as quickly as possible.
    # Any optional work that would ordinarily be done in the
    # background at run time is abandoned.
    Abrupt = 2


class CreateDatabaseGrbit(Enum):
    """
    CreateDatabaseGrbit

    Options for <see cref="Api.JetCreateDatabase"/>.
    <seealso cref="Windows7.Windows7Grbits.EnableCreateDbBackgroundMaintenance"/>
    """
    # Default options.
    NONE = 0

    # By default, if JetCreateDatabase is called and the database already exists
    # the Api call will fail and the original database will not be overwritten.
    # OverwriteExisting changes this behavior, and the old database
    # will be overwritten with a new one.
    OverwriteExisting = 0x200

    # Turns off logging. Setting this bit loses the ability to replay log files
    # and recover the database to a consistent usable state after a crash.
    RecoveryOff = 0x8


class DetachDatabaseGrbit(Enum):
    """
    DetachDatabaseGrbit

    Options for <see cref="Api.JetDetachDatabase2"/>.
    """

    # Default options.
    NONE = 0

    # If <see cref="ForceDetach"/> is used, <see cref="EsentForceDetachNotAllowedException"/> will be returned.
    # [Obsolete("ForceDetach is no longer used.")]
    ForceDetach = 1

    # <see cref="ForceClose"/> is no longer used.
    # [Obsolete("ForceClose is no longer used.")]
    ForceClose = 0x2

    # If <see cref="ForceCloseAndDetach"/> is used, <see cref="EsentForceDetachNotAllowedException"/> will be returned.
    # [Obsolete("ForceCloseAndDetach is no longer used.")]
    ForceCloseAndDetach = (0x2 | 0x1)


class AttachDatabaseGrbit(Enum):
    """
    AttachDatabaseGrbit

    Options for <see cref="Api.JetAttachDatabase"/>.
    <seealso cref="Windows7.Windows7Grbits.EnableAttachDbBackgroundMaintenance"/>
    <seealso cref="Windows8.Windows8Grbits.PurgeCacheOnAttach"/>
    """

    # Default options.
    NONE = 0

    #  Prevents modifications to the database.
    ReadOnly = 0x1

    # If JET_paramEnableIndexChecking has been set, all indexes over Unicode
    # data will be deleted.
    DeleteCorruptIndexes = 0x10


class OpenDatabaseGrbit(Enum):
    """
    OpenDatabaseGrbit

    Options for <see cref="Api.JetOpenDatabase"/>.
    """
    # Default options.
    NONE = 0

    # Prevents modifications to the database.
    ReadOnly = 0x1

    # Allows only a single session to attach a database.
    # Normally, several sessions can open a database.
    Exclusive = 0x2


class CloseDatabaseGrbit(Enum):
    """
    CloseDatabaseGrbit

    Options for <see cref="Api.JetCloseDatabase"/>.
    """

    # Default options.
    NONE = 0


class CompactGrbit(Enum):
    """
    CompactGrbit

    Options for <see cref="Api.JetCompact"/>.
    """

    # Default options.
    NONE = 0

    # Causes JetCompact to dump statistics on the source database to a file
    #  named DFRGINFO.TXT. Statistics include the name of each table in
    # source database, number of rows in each table, total size in bytes of
    # all rows in each table, total size in bytes of all columns of type
    # <see cref="JET_coltyp.LongText"/> or <see cref="JET_coltyp.LongBinary"/>
    # that were large enough to be stored separate from the record, number
    # of clustered index leaf pages, and the number of long value leaf pages.
    # In addition, summary statistics including the size of the source database
    # destination database, time required for database compaction, temporary
    # database space are all dumped as well.
    Stats = 0x20

    # Used when the source database is known to be corrupt. It enables a
    # whole set of new behaviors intended to salvage as much data as
    # possible from the source database. JetCompact with this option set
    # may return <see cref="JET_err.Success"/> but not copy all of the data
    # created in the source database. Data that was in damaged portions of
    # the source database will be skipped.
    # [Obsolete("Use esentutl repair functionality instead.")]
    Repair = 0x40,


class SnapshotFreezeGrbit(Enum):
    """
    SnapshotFreezeGrbit

    Options for <see cref="Api.JetOSSnapshotFreeze"/>.
    """

    # Default options.
    NONE = 0


class SnapshotPrepareGrbit(Enum):
    """
    SnapshotPrepareGrbit

    Options for <see cref="Api.JetOSSnapshotPrepare"/>.
    <seealso cref="Vista.VistaGrbits.ContinueAfterThaw"/>
    <seealso cref="Windows7.Windows7Grbits.ExplicitPrepare"/>
    """
    # Default options.
    NONE = 0

    # Only logfiles will be taken.
    IncrementalSnapshot = 0x1

    # A copy snapshot (normal or incremental) with no log truncation.
    CopySnapshot = 0x2


class SnapshotThawGrbit(Enum):
    """
    SnapshotThawGrbit

    Options for <see cref="Api.JetOSSnapshotThaw"/>.
    """
    # Default options.
    NONE = 0


class BackupGrbit(Enum):
    """
    BackupGrbit

    Options for <see cref="Api.JetBackupInstance"/>.
    """
    # Default options.
    NONE = 0

    # Creates an incremental backup as opposed to a full backup. This
    # means that only the log files created since the last full or
    # incremental backup will be backed up.
    Incremental = 0x1

    # Creates a full backup of the database. This allows the preservation
    # of an existing backup in the same directory if the new backup fails.
    Atomic = 0x4


class BeginExternalBackupGrbit(Enum):
    """
    BeginExternalBackupGrbit

    Options for <see cref="Api.JetBeginExternalBackupInstance"/>.
    """
    # Default options.
    NONE = 0

    # Creates an incremental backup as opposed to a full backup. This
    # means that only the log files since the last full or incremental
    # backup will be backed up.
    Incremental = 0x1


class EndExternalBackupGrbit(Enum):
    """
    EndExternalBackupGrbit

    Options for <see cref="Api.JetEndExternalBackupInstance"/>.
    <seealso cref="Vista.VistaGrbits.TruncateDone"/>
    """
    # Default options.
    NONE = 0

    # The client application finished the backup completely, and is ending normally.
    Normal = 0x1

    # The client application is aborting the backup.
    Abort = 0x2


class BeginTransactionGrbit(Enum):
    """
    BeginTransactionGrbit

    Options for <see cref="Api.JetBeginTransaction2"/>.
    """
    # Default options.
    NONE = 0

    # The transaction will not modify the database. If an update is attempted
    # that operation will fail with <see cref="JET_err.TransReadOnly"/>. This
    # option is ignored unless it is requested when the given session is not
    # already in a transaction.
    ReadOnly = 0x1


class CommitTransactionGrbit(Enum):
    """
    CommitTransactionGrbit

    Options for JetCommitTransaction.
    <seealso cref="Windows7.Windows7Grbits.ForceNewLog"/>
    """
    # Default options.
    NONE = 0

    # The transaction is committed normally but this Api does not wait for
    # the transaction to be flushed to the transaction log file before returning
    # to the caller. This drastically reduces the duration of a commit operation
    # at the cost of durability. Any transaction that is not flushed to the log
    # before a crash will be automatically aborted during crash recovery during
    # the next call to JetInit. If WaitLastLevel0Commit or WaitAllLevel0Commit
    # are specified, this option is ignored.
    LazyFlush = 0x1

    #  If the session has previously committed any transactions and they have not yet
    #  been flushed to the transaction log file, they should be flushed immediately.
    #  This Api will wait until the transactions have been flushed before returning
    #  to the caller. This is useful if the application has previously committed several
    #  transactions using JET_bitCommitLazyFlush and now wants to flush all of them to disk.
    # <remarks>
    # This option may be used even if the session is not currently in a transaction.
    # This option cannot be used in combination with any other option.
    # </remarks>
    WaitLastLevel0Commit = 0x2


class RollbackTransactionGrbit(Enum):
    """
    RollbackTransactionGrbit

    Options for JetRollbackTransaction.
    """
    # Default options.
    NONE = 0

    # This option requests that all changes made to the state of the
    # database during all save points be undone. As a result, the
    # session will exit the transaction.
    RollbackAll = 0x1


class EndSessionGrbit(Enum):
    """
    EndSessionGrbit

    Options for JetEndSession.
    """

    # Default options.
    NONE = 0


class OpenTableGrbit(Enum):
    """
    OpenTableGrbit

    Options for JetOpenTable.
    """
    # Default options.
    NONE = 0

    # This table cannot be opened for write access by another session.
    DenyWrite = 0x1

    # This table cannot be opened for read access by another session.
    DenyRead = 0x2

    # Request read-only access to the table.
    ReadOnly = 0x4

    # Request write access to the table.
    Updatable = 0x8

    # Allow DDL modifications to a table flagged as FixedDDL. This option
    # must be used with DenyRead.
    PermitDDL = 0x10

    # Do not cache pages for this table.
    NoCache = 0x20

    # Provides a hint that the table is probably not in the buffer cache, and
    # that pre-reading may be beneficial to performance.
    Preread = 0x40

    # Assume a sequential access pattern and prefetch database pages.
    Sequential = 0x8000

    # Table belongs to stats class 1.
    TableClass1 = 0x00010000

    # Table belongs to stats class 2.
    TableClass2 = 0x00020000

    # Table belongs to stats class 3.
    TableClass3 = 0x00030000

    # Table belongs to stats class 4.
    TableClass4 = 0x00040000

    # Table belongs to stats class 5.
    TableClass5 = 0x00050000

    # Table belongs to stats class 6.
    TableClass6 = 0x00060000

    # Table belongs to stats class 7.
    TableClass7 = 0x00070000

    # Table belongs to stats class 8.
    TableClass8 = 0x00080000

    # Table belongs to stats class 9.
    TableClass9 = 0x00090000

    # Table belongs to stats class 10.
    TableClass10 = 0x000A0000

    # Table belongs to stats class 11.
    TableClass11 = 0x000B0000

    # Table belongs to stats class 12.
    TableClass12 = 0x000C0000

    # Table belongs to stats class 13.
    TableClass13 = 0x000D0000

    # Table belongs to stats class 14.
    TableClass14 = 0x000E0000

    # Table belongs to stats class 15.
    TableClass15 = 0x000F0000


class DupCursorGrbit(Enum):
    """
    DupCursorGrbit

    Options for <see cref="Api.JetDupCursor"/>.
    """

    # Default options.
    NONE = 0


class LsGrbit(Enum):
    """
    LsGrbit

    Options for <see cref="Api.JetSetLS"/> and <see cref="Api.JetGetLS"/>.
    """

    # Default options.
    NONE = 0

    # The context handle for the chosen object should be reset to JET_LSNil.
    Reset = 0x1

    # Specifies the context handle should be associated with the given cursor.
    Cursor = 0x2

    # Specifies that the context handle should be associated with the
    # table associated with the given cursor. It is illegal to use this
    # option with <see cref="Cursor"/>.
    Table = 0x4


class SetColumnGrbit(Enum):
    """
    SetColumnGrbit

    Options for the <see cref="Api.JetSetColumn(JET_SESID, JET_TABLEID, JET_COLUMNID, byte[], int, int, SetColumnGrbit, JET_SETINFO)"/>
    and its associated overloads.
    <seealso cref="Windows7.Windows7Grbits.Compressed"/>
    <seealso cref="Windows7.Windows7Grbits.Uncompressed"/>
    """

    # Default options.
    NONE = 0

    # This option is used to append data to a column of type JET_coltypLongText
    # or JET_coltypLongBinary. The same behavior can be achieved by determining
    # the size of the existing long value and specifying ibLongValue in psetinfo.
    # However, its simpler to use this grbit since knowing the size of the existing
    # column value is not necessary.
    AppendLV = 0x1

    # This option is used replace the existing long value with the newly provided
    # data. When this option is used, it is as though the existing long value has
    # been set to 0 (zero) length prior to setting the new data.
    OverwriteLV = 0x4

    # This option is only applicable for tagged, sparse or multi-valued columns.
    # It causes the column to return the default column value on subsequent retrieve
    # column operations. All existing column values are removed.
    RevertToDefaultValue = 0x200

    # This option is used to force a long value, columns of type JET_coltyp.LongText
    # or JET_coltyp.LongBinary, to be stored separately from the remainder of record
    # data. This occurs normally when the size of the long value prevents it from being
    # stored with remaining record data. However, this option can be used to force the
    # long value to be stored separately. Note that long values four bytes in size
    # of smaller cannot be forced to be separate. In such cases, the option is ignored.
    SeparateLV = 0x40

    # This option is used to interpret the input buffer as a integer number of bytes
    # to set as the length of the long value described by the given columnid and if
    # provided, the sequence number in psetinfo->itagSequence. If the size given is
    # larger than the existing column value, the column will be extended with 0s.
    # If the size is smaller than the existing column value then the value will be
    # truncated.
    SizeLV = 0x8

    # This option is used to enforce that all values in a multi-valued column are
    # distinct. This option compares the source column data, without any
    # transformations, to other existing column values and an error is returned
    # if a duplicate is found. If this option is given, then AppendLV, OverwriteLV
    # and SizeLV cannot also be given.
    UniqueMultiValues = 0x80

    # This option is used to enforce that all values in a multi-valued column are
    # distinct. This option compares the key normalized transformation of column
    # data, to other similarly transformed existing column values and an error is
    # returned if a duplicate is found. If this option is given, then AppendLV,
    # OverwriteLV and SizeLV cannot also be given.
    UniqueNormalizedMultiValues = 0x100

    # This option is used to set a value to zero length. Normally, a column value
    # is set to NULL by passing a cbMax of 0 (zero). However, for some types, like
    # JET_coltyp.Text, a column value can be 0 (zero) length instead of NULL, and
    # this option is used to differentiate between NULL and 0 (zero) length.
    ZeroLength = 0x20

    # Try to store long-value columns in the record, even if they exceed the default
    # separation size.
    IntrinsicLV = 0x400


class RetrieveColumnGrbit(Enum):
    """
    RetrieveColumnGrbit

    Options for JetRetrieveColumn.
    """

    # Default options.
    NONE = 0

    #  This flag causes retrieve column to retrieve the modified value instead of
    #  the original value. If the value has not been modified, then the original
    #  value is retrieved. In this way, a value that has not yet been inserted or
    #  updated may be retrieved during the operation of inserting or updating a record.
    RetrieveCopy = 0x1

    # This option is used to retrieve column values from the index, if possible
    # without accessing the record. In this way, unnecessary loading of records
    # can be avoided when needed data is available from index entries themselves.
    RetrieveFromIndex = 0x2

    # This option is used to retrieve column values from the index bookmark
    # and may differ from the index value when a column appears both in the
    # primary index and the current index. This option should not be specified
    # if the current index is the clustered, or primary, index. This bit cannot
    # be set if RetrieveFromIndex is also set.
    RetrieveFromPrimaryBookmark = 0x4

    # This option is used to retrieve the sequence number of a multi-valued
    # column value in JET_RETINFO.itagSequence. Retrieving the sequence number
    # can be a costly operation and should only be done if necessary.
    RetrieveTag = 0x8

    # This option is used to retrieve multi-valued column NULL values. If
    # this option is not specified, multi-valued column NULL values will
    # automatically be skipped.
    RetrieveNull = 0x10

    # This option affects only multi-valued columns and causes a NULL
    # value to be returned when the requested sequence number is 1 and
    # there are no set values for the column in the record.
    RetrieveIgnoreDefault = 0x20


class EnumerateColumnsGrbit(Enum):
    """
    EnumerateColumnsGrbit

    Options for <see cref="Api.JetEnumerateColumns(JET_SESID, JET_TABLEID, EnumerateColumnsGrbit, out IEnumerable&lt;EnumeratedColumn&gt;)"/>
    and its associated overloads.
    <seealso cref="Server2003.Server2003Grbits.EnumerateIgnoreUserDefinedDefault"/>
    <seealso cref="Windows7.Windows7Grbits.EnumerateInRecordOnly"/>
    """
    # Default options.
    NONE = 0

    # When enumerating column values, all columns for which we are retrieving
    # all values and that have only one non-NULL column value may be returned
    # in a compressed format. The status for such columns will be set to
    # <see cref="JET_wrn.ColumnSingleValue"/> and the size of the column value
    # and the memory containing the column value will be returned directly in
    # the <see cref="JET_ENUMCOLUMN"/> structure. It is not guaranteed that
    # all eligible columns are compressed in this manner. See
    # <see cref="JET_ENUMCOLUMN"/> for more information.
    EnumerateCompressOutput = 0x00080000

    # This option indicates that the modified column values of the record
    # should be enumerated rather than the original column values. If a
    # column value has not been modified, the original column value is
    # enumerated. In this way, a column value that has not yet been inserted
    # or updated may be enumerated when inserting or updating a record.
    # <remarks>
    # This option is identical to <see cref="RetrieveColumnGrbit.RetrieveCopy"/>.
    # </remarks>
    EnumerateCopy = 0x1

    # If a given column is not present in the record then no column value
    # will be returned. Ordinarily, the default value for the column
    # if any, would be returned in this case. It is guaranteed that if the
    # column is set to a value different than the default value then that
    # different value will be returned (that is, if a column with a
    # default value is explicitly set to NULL then a NULL will be returned
    # as the value for that column). Even if this option is requested, it
    # is still possible to see a column value that happens to be equal to
    # the default value. No effort is made to remove column values that
    # match their default values.
    # It is important to remember that this option affects the output of
    # <see cref="Api.JetEnumerateColumns(JET_SESID, JET_TABLEID, EnumerateColumnsGrbit, out IEnumerable&lt;EnumeratedColumn&gt;)"/>
    # and its associated overloads when used with
    # <see cref="EnumerateColumnsGrbit.EnumeratePresenceOnly"/> or
    # <see cref="EnumerateColumnsGrbit.EnumerateTaggedOnly"/>.
    EnumerateIgnoreDefault = 0x20

    # If a non-NULL value exists for the requested column or column value
    # then the associated data is not returned. Instead, the associated
    # status for that column or column value will be set to
    # <see cref="JET_wrn.ColumnPresent"/>. If the column or column value
    # is NULL then <see cref="JET_wrn.ColumnNull"/> will be returned as usual.
    EnumeratePresenceOnly = 0x00020000

    # When enumerating all column values in the record (for example,that is
    # when numColumnids is zero), only tagged column values will be returned.
    # This option is not allowed when enumerating a specific array of column IDs.
    EnumerateTaggedOnly = 0x00040000,


class GetRecordSizeGrbit(Enum):
    """
    GetRecordSizeGrbit

    Options for <see cref="Vista.VistaApi.JetGetRecordSize"/>.
    """
    # Default options.
    NONE = 0

    # Retrieve the size of the record that is in the copy buffer prepared
    # or update. Otherwise, the tableid must be positioned on a record
    # and that record will be used.
    InCopyBuffer = 0x1

    # The JET_RECSIZE is not zeroed before filling the contents, effectively
    # acting as an accumulation of the statistics for multiple records visited
    # or updated.
    RunningTotal = 0x2

    # Ignore non-intrinsic Long Values. Only the local record on the page
    # will be used.
    Local = 0x4


class GetSecondaryIndexBookmarkGrbit(Enum):
    """
    GetSecondaryIndexBookmarkGrbit

    Options for <see cref="Api.JetGetSecondaryIndexBookmark"/>.
    """

    # Default options.
    NONE = 0


class GotoSecondaryIndexBookmarkGrbit(Enum):
    """
    GotoSecondaryIndexBookmarkGrbit

    Options for <see cref="Api.JetGotoSecondaryIndexBookmark"/>.
    """

    # Default options.
    NONE = 0

    # In the event that the index entry can no longer be found, the cursor
    # will be left positioned where that index entry was previously found.
    # The operation will still fail with JET_errRecordDeleted; however
    # it will be possible to move to the next or previous index entry
    # relative to the index entry that is now missing.
    BookmarkPermitVirtualCurrency = 0x1


class MoveGrbit(Enum):
    """
    MoveGrbit

    Options for JetMove.
    """
    # Default options.
    NONE = 0

    # Moves the cursor forward or backward by the number of index entries
    # required to skip the requested number of index key values encountered
    # in the index. This has the effect of collapsing index entries with
    # duplicate key values into a single index entry.
    MoveKeyNE = 0x1


class MakeKeyGrbit(Enum):
    """
    MakeKeyGrbit

    Options for JetMakeKey.
    """
    # Default options.
    NONE = 0

    # A new search key should be constructed. Any previously existing search
    # key is discarded.
    NewKey = 0x1

    # When this option is specified, all other options are ignored, any
    # previously existing search key is discarded, and the contents of the
    # input buffer are loaded as the new search key.
    NormalizedKey = 0x8

    # If the size of the input buffer is zero and the current key column
    # is a variable length column, this option indicates that the input
    # buffer contains a zero length value. Otherwise, an input buffer size
    # of zero would indicate a NULL value.
    KeyDataZeroLength = 0x10

    # This option indicates that the search key should be constructed
    # such that any key columns that come after the current key column
    # should be considered to be wildcards.
    StrLimit = 0x2

    # This option indicates that the search key should be constructed
    # such that the current key column is considered to be a prefix
    # wildcard and that any key columns that come after the current
    # key column should be considered to be wildcards.
    SubStrLimit = 0x4

    # The search key should be constructed such that any key columns
    # that come after the current key column should be considered to
    # be wildcards.
    FullColumnStartLimit = 0x100

    # The search key should be constructed in such a way that any key
    # columns that come after the current key column are considered to
    # be wildcards.
    FullColumnEndLimit = 0x200

    # The search key should be constructed such that the current key
    # column is considered to be a prefix wildcard and that any key
    # columns that come after the current key column should be considered
    # to be wildcards.
    PartialColumnStartLimit = 0x400

    # The search key should be constructed such that the current key
    # column is considered to be a prefix wildcard and that any key
    # columns that come after the current key column should be considered
    # to be wildcards.
    PartialColumnEndLimit = 0x800


class RetrieveKeyGrbit(Enum):
    """
    RetrieveKeyGrbit

    Options for JetRetrieveKey.
    """

    # Default options.
    NONE = 0

    # Retrieve the currently constructed key.
    RetrieveCopy = 0x1


class SeekGrbit(Enum):
    """
    SeekGrbit

    Options for <see cref="Api.JetSeek"/>.
    """

    # The cursor will be positioned at the index entry closest to the
    # start of the index that exactly matches the search key.
    SeekEQ = 0x1

    # The cursor will be positioned at the index entry closest to the
    # end of the index that is less than an index entry that would
    # exactly match the search criteria.
    SeekLT = 0x2

    # The cursor will be positioned at the index entry closest to the
    # end of the index that is less than or equal to an index entry
    # that would exactly match the search criteria.
    SeekLE = 0x4

    # The cursor will be positioned at the index entry closest to the
    # start of the index that is greater than or equal to an index
    # entry that would exactly match the search criteria.
    SeekGE = 0x8

    # The cursor will be positioned at the index entry closest to the
    # start of the index that is greater than an index entry that
    # would exactly match the search criteria.
    SeekGT = 0x10

    # An index range will automatically be setup for all keys that
    # exactly match the search key.
    SetIndexRange = 0x20


class SetIndexRangeGrbit(Enum):
    """
    SetIndexRangeGrbit

    Options for <see cref="Api.JetSetIndexRange"/>.
    """

    # Default options.
    NONE = 0x0

    # This option indicates that the limit of the index range is inclusive.
    RangeInclusive = 0x1

    # The search key in the cursor represents the search criteria for the
    # index entry closest to the end of the index that will match the index
    # range.
    RangeUpperLimit = 0x2

    # The index range should be removed as soon as it has been established.
    # This is useful for testing for the existence of index entries that
    # match the search criteria.
    RangeInstantDuration = 0x4

    # Cancel and existing index range.
    RangeRemove = 0x8


class IndexRangeGrbit(Enum):
    """
    IndexRangeGrbit

    Options for the <see cref="JET_INDEXRANGE"/> object.
    """

    # Records in the cursors indexrange should be included in the output.
    RecordInIndex = 0x1


class IntersectIndexesGrbit(Enum):
    """
    IntersectIndexesGrbit

    Options for <see cref="Api.JetIntersectIndexes"/>.
    """
    # Default options.
    NONE = 0


class SetCurrentIndexGrbit(Enum):
    """
    SetCurrentIndexGrbit

    Options for <see cref="Api.JetSetCurrentIndex2"/> and
    <see cref="Api.JetSetCurrentIndex3"/>.
    """

    # Default options. This is the same as <see cref="MoveFirst"/>.
    NONE = 0

    # Indicates that the cursor should be positioned on the first entry of
    # the specified index. If the current index is being selected then this
    # option is ignored.
    MoveFirst = 0

    # Indicates that the cursor should be positioned on the index entry
    # of the new index that corresponds to the record associated with the
    # index entry at the current position of the cursor on the old index.
    NoMove = 0x2


class SetTableSequentialGrbit(Enum):
    """
    SetTableSequentialGrbit

    Options for <see cref="Api.JetSetTableSequential"/>.
    <seealso cref="Windows7.Windows7Grbits.Backward"/>
    """
    # Default options.
    NONE = 0


class ResetTableSequentialGrbit(Enum):
    """
    ResetTableSequentialGrbit

    Options for <see cref="Api.JetResetTableSequential"/>.
    """
    # Default options.
    NONE = 0


class GetLockGrbit(Enum):
    """
    GetLockGrbit

    Options for JetGetLock.
    """
    # Acquire a read lock on the current record. Read locks are incompatible with
    # write locks already held by other sessions but are compatible with read locks
    # held by other sessions.
    Read = 0x1

    #  Acquire a write lock on the current record. Write locks are not compatible
    #  with write or read locks held by other sessions but are compatible with
    #  read locks held by the same session.
    Write = 0x2


class EscrowUpdateGrbit(Enum):
    """
    EscrowUpdateGrbit

    Options for <see cref="Api.JetEscrowUpdate"/>.
    """

    # Default options.
    NONE = 0

    # Even if the session performing the escrow update has its transaction rollback
    # this update will not be undone. As the log records may not be flushed to disk
    # recent escrow updates done with this flag may be lost if there is a crash.
    NoRollback = 0x1


class ColumndefGrbit(Enum):
    """
    ColumndefGrbit

    Options for the <see cref="JET_COLUMNDEF"/> structure.
    <seealso cref="Windows7.Windows7Grbits.ColumnCompressed"/>
    """
    # Default options.
    NONE = 0x0

    # The column will be fixed. It will always use the same amount of space in a row
    # regardless of how much data is being stored in the column. ColumnFixed
    # cannot be used with ColumnTagged. This bit cannot be used with long values
    # (that is JET_coltyp.LongText and JET_coltyp.LongBinary).
    ColumnFixed = 0x1

    #  The column will be tagged. Tagged columns do not take up any space in the database
    #  if they do not contain data. This bit cannot be used with ColumnFixed.
    ColumnTagged = 0x2

    # The column must never be set to a NULL value. On Windows XP this can only be applied to
    # fixed columns (bit, byte, integer, etc).
    ColumnNotNULL = 0x4

    # The column is a version column that specifies the version of the row. The value of
    # this column starts at zero and will be automatically incremented for each update on
    # the row. This option can only be applied to <see cref="JET_coltyp.Long"/> columns. This option cannot
    # be used with <see cref="ColumnAutoincrement"/>, <see cref="ColumnEscrowUpdate"/>, or <see cref="ColumnTagged"/>.
    ColumnVersion = 0x8

    # The column will automatically be incremented. The number is an increasing number, and
    # is guaranteed to be unique within a table. The numbers, however, might not be continuous.
    # For example, if five rows are inserted into a table, the "autoincrement" column could
    # contain the values { 1, 2, 6, 7, 8 }. This bit can only be used on columns of type
    # <see cref="JET_coltyp.Long"/> or <see cref="JET_coltyp.Currency"/>.
    ColumnAutoincrement = 0x10

    # The column can be updated. This is NOT a valid grbit to set on input to any API. It is
    # returned as part of the <see cref="JET_COLUMNDEF"/> structure's grbit member, as an
    # output from Api.JetGetColumnInfo.
    ColumnUpdatable = 0x20

    # The column can be multi-valued.
    # A multi-valued column can have zero, one, or more values
    # associated with it. The various values in a multi-valued column are identified by a number
    # called the itagSequence member, which belongs to various structures, including:
    # <see cref="JET_RETINFO"/>, <see cref="JET_SETINFO"/>, <see cref="JET_SETCOLUMN"/>, <see cref="JET_RETRIEVECOLUMN"/>, and <see cref="JET_ENUMCOLUMNVALUE"/>.
    # Multi-valued columns must be tagged columns; that is, they cannot be fixed-length or
    # variable-length columns.
    ColumnMultiValued = 0x400

    #  Specifies that a column is an escrow update column. An escrow update column can be
    #  updated concurrently by different sessions with JetEscrowUpdate and will maintain
    #  transactional consistency. An escrow update column must also meet the following conditions:
    #  An escrow update column can be created only when the table is empty.
    #  An escrow update column must be of type JET_coltypLong.
    #  An escrow update column must have a default value.
    #  ColumnEscrowUpdate cannot be used in conjunction with <see cref="ColumnTagged"/>
    #  <see cref="ColumnVersion"/>, or <see cref="ColumnAutoincrement"/>.
    ColumnEscrowUpdate = 0x800

    # The column will be created in an without version information. This means that other
    # transactions that attempt to add a column with the same name will fail. This bit
    # is only useful with JetAddColumn. It cannot be used within a transaction.
    ColumnUnversioned = 0x1000

    # In doing an outer join, the retrieve column operation might not have a match
    # from the inner table.
    ColumnMaybeNull = 0x2000

    # When the escrow-update column reaches a value of zero, the callback function will be invoked.
    ColumnFinalize = 0x4000

    # The default value for a column will be provided by a callback function. A column that
    # has a user-defined default must be a tagged column. Specifying <see cref="ColumnUserDefinedDefault"/>
    # means that pvDefault must point to a JET_USERDEFINEDDEFAULT structure, and cbDefault must be
    # set to sizeof( JET_USERDEFINEDDEFAULT ).
    ColumnUserDefinedDefault = 0x8000

    # The column will be a key column for the temporary table. The order
    # of the column definitions with this option specified in the input
    # array will determine the precedence of each key column for the
    # temporary table. The first column definition in the array that
    # has this option set will be the most significant key column and
    # so on. If more key columns are requested than can be supported
    # by the database engine then this option is ignored for the
    # unsupportable key columns.
    TTKey = 0x40

    # The sort order of the key column for the temporary table should
    # be descending rather than ascending. If this option is specified
    #  without <see cref="TTKey"/> then this option is ignored.
    TTDescending = 0x80


class CreateTableColumnIndexGrbit(Enum):
    """
    CreateTableColumnIndexGrbit

    Options for the <see cref="JET_TABLECREATE"/> parameter used by
    <see cref="Api.JetCreateTableColumnIndex3"/>.
    <seealso cref="Windows10.Windows10Grbits.TableCreateImmutableStructure"/>
    """
    # Default options.
    NONE = 0x0

    # The DDL is fixed.
    FixedDDL = 0x1

    # The DDL is inheritable. Implies FixedDDL.
    TemplateTable = 0x2

    # Used in conjunction with TemplateTable.
    NoFixedVarColumnsInDerivedTables = 0x4


class CreateIndexGrbit(Enum):
    """
    CreateIndexGrbit

    Options for <see cref="Api.JetCreateIndex"/> and <see cref="JET_INDEXCREATE"/>.
    <seealso cref="Vista.VistaGrbits.IndexCrossProduct"/>
    <seealso cref="Vista.VistaGrbits.IndexDisallowTruncation"/>
    <seealso cref="Vista.VistaGrbits.IndexNestedTable"/>
    <seealso cref="Vista.VistaGrbits.IndexUnicode"/>
    <seealso cref="Vista.VistaGrbits.IndexKeyMost"/>
    <seealso cref="Windows8.Windows8Grbits.IndexDotNetGuid"/>
    <seealso cref="Windows10.Windows10Grbits.IndexCreateImmutableStructure"/>
    """
    # Default options.
    NONE = 0x0

    # Duplicate index entries (keys) are disallowed. This is enforced when JetUpdate is called
    # not when JetSetColumn is called.
    IndexUnique = 0x1

    # The index is a primary (clustered) index. Every table must have exactly one primary index.
    # If no primary index is explicitly defined over a table, then the database engine will
    # create its own primary index.
    IndexPrimary = 0x2

    # None of the columns over which the index is created may contain a NULL value.
    IndexDisallowNull = 0x4

    # Do not add an index entry for a row if all of the columns being indexed are NULL.
    IndexIgnoreNull = 0x8

    # Do not add an index entry for a row if any of the columns being indexed are NULL.
    IndexIgnoreAnyNull = 0x20

    # Do not add an index entry for a row if the first column being indexed is NULL.
    IndexIgnoreFirstNull = 0x40

    # Specifies that the index operations will be logged lazily. JET_bitIndexLazyFlush does not
    # affect the laziness of data updates. If the indexing operations is interrupted by process
    # termination, Soft Recovery will still be able to able to get the database to a consistent
    # state, but the index may not be present.
    IndexLazyFlush = 0x80

    # Do not attempt to build the index, because all entries would evaluate to NULL. grbit MUST
    # also specify JET_bitIgnoreAnyNull when JET_bitIndexEmpty is passed. This is a performance
    # enhancement. For example if a new column is added to a table, then an index is created over
    # this newly added column, all of the records in the table would be scanned even though they
    # would never get added to the index anyway. Specifying JET_bitIndexEmpty skips the scanning
    # of the table, which could potentially take a long time.
    IndexEmpty = 0x100

    # Causes index creation to be visible to other transactions. Normally a session in a
    # transaction will not be able to see an index creation operation in another session. This
    # flag can be useful if another transaction is likely to create the same index, so that the
    # second index-create will simply fail instead of potentially causing many unnecessary database
    # operations. The second transaction may not be able to use the index immediately. The index
    # creation operation needs to complete before it is usable. The session must not currently be in
    # a transaction to create an index without version information.
    IndexUnversioned = 0x200

    # Specifying this flag causes NULL values to be sorted after data for all columns in the index.
    IndexSortNullsHigh = 0x400


class IndexKeyGrbit(Enum):
    """
    IndexKeyGrbit

    Key definition grbits. Used when retrieving information about an index, contained
    in the column specified in <see cref="JET_INDEXLIST.columnidgrbitColumn"/>.
    """

    # Key segment is ascending.
    Ascending = 0x0

    # Key segment is descending.
    Descending = 0x1


class ConditionalColumnGrbit(Enum):
    """
    ConditionalColumnGrbit

    Options for the <seealso cref="JET_CONDITIONALCOLUMN"/> structure.
    """

    # The column must be null for an index entry to appear in the index.
    ColumnMustBeNull = 0x1

    # The column must be non-null for an index entry to appear in the index.
    ColumnMustBeNonNull = 0x2


class TempTableGrbit(Enum):
    """
    TempTableGrbit

    Options for temporary table creation, with <see cref="Api.JetOpenTempTable"/>
    Api.JetOpenTempTable2, and <see cref="Api.JetOpenTempTable3"/>.
    <seealso cref="Server2003.Server2003Grbits.ForwardOnly"/>
    <seealso cref="Windows7.Windows7Grbits.IntrinsicLVsOnly"/>
    <seealso cref="Windows8.Windows8Grbits.TTDotNetGuid"/>
    """

    # Default options.
    NONE = 0

    # This option requests that the temporary table be flexible enough to
    # permit the use of JetSeek to lookup records by index key. If this
    # functionality it not required then it is best to not request it. If this
    # functionality is not requested then the temporary table manager may be
    # able to choose a strategy for managing the temporary table that will
    # result in improved performance.
    Indexed = 0x1

    # This option requests that records with duplicate index keys be removed
    # from the final set of records in the temporary table.
    # Prior to Windows Server 2003, the database engine always assumed this
    # option to be in effect due to the fact that all clustered indexes must
    # also be a primary key and thus must be unique. As of Windows Server
    # 2003, it is now possible to create a temporary table that does NOT
    # remove duplicates when the <see cref="Server2003.Server2003Grbits.ForwardOnly"/>
    # option is also specified.
    # It is not possible to know which duplicate will win and which duplicates
    # will be discarded in general. However, when the
    # <see cref="ErrorOnDuplicateInsertion"/> option is requested then the first
    # record with a given index key to be inserted into the temporary table
    # will always win.
    Unique = 0x2

    # This option requests that the temporary table be flexible enough to
    # allow records that have previously been inserted to be subsequently
    # changed. If this functionality it not required then it is best to not
    # request it. If this functionality is not requested then the temporary
    # table manager may be able to choose a strategy for managing the
    # temporary table that will result in improved performance.
    Updatable = 0x4

    # This option requests that the temporary table be flexible enough to
    # allow records to be scanned in arbitrary order and direction using
    # <see cref="Api.JetMove(JET_SESID,JET_TABLEID,int,MoveGrbit)"/>.
    # If this functionality it not required then it is best to not
    # request it. If this functionality is not requested then the temporary
    # table manager may be able to choose a strategy for managing the
    # temporary table that will result in improved performance.
    # </summary>
    Scrollable = 0x8

    # This option requests that NULL key column values sort closer
    # to the end of the index than non-NULL key column values.
    SortNullsHigh = 0x10

    # This option forces the temporary table manager to abandon
    # any attempt to choose a clever strategy for managing the
    # temporary table that will result in enhanced performance.
    ForceMaterialization = 0x20

    # This option requests that any attempt to insert a record with the same
    # index key as a previously inserted record will immediately fail with
    # <see cref="JET_err.KeyDuplicate"/>. If this option is not requested then a duplicate
    # may be detected immediately and fail or may be silently removed later
    # depending on the strategy chosen by the database engine to implement the
    # temporary table based on the requested functionality. If this
    # functionality it not required then it is best to not request it. If this
    # functionality is not requested then the temporary table manager may be
    # able to choose a strategy for managing the temporary table that will
    # result in improved performance.
    ErrorOnDuplicateInsertion = 0x20


class DeleteColumnGrbit(Enum):
    """
    DeleteColumnGrbit

    Options for <see cref="Api.JetDeleteColumn2"/>.
    """
    # Default options.
    NONE = 0

    # The API should only attempt to delete columns in the derived table.
    # If a column of that name exists in the base table it will be ignored.
    IgnoreTemplateColumns = 0x1


class RenameColumnGrbit(Enum):
    """
    RenameColumnGrbit

    Options for <see cref="Api.JetRenameColumn"/>.
    """
    # Default options.
    NONE = 0


class SetColumnDefaultValueGrbit(Enum):
    """
    SetColumnDefaultValueGrbit

    Options for <see cref="Api.JetSetColumnDefaultValue"/>.
    """
    # Default options.
    NONE = 0


class IdleGrbit(Enum):
    """
    IdleGrbit

    Options for <see cref="Api.JetIdle"/>.
    """
    # Default options.
    NONE = 0x0

    # Reserved for future use. If this flag is specified, the API will return <see cref="JET_err.InvalidGrbit"/>.
    FlushBuffers = 0x01

    # Triggers cleanup of the version store.
    Compact = 0x02

    # Returns <see cref="JET_wrn.IdleFull"/> if version store is more than half full.
    GetStatus = 0x04


class DefragGrbit(Enum):
    """
    DefragGrbit

    Options for <see cref="Api.JetDefragment"/>.
    <seealso cref="Windows7.Windows7Grbits.NoPartialMerges"/>
    <seealso cref="Windows7.Windows7Grbits.DefragmentBTree"/>
    """
    # Defragments the available space portion of ESE database space
    # allocation. Database space is divided into two types, owned
    # space and available space. Owned space is allocated to a table
    # or index while available space is ready for use within the table
    # or index, respectively. Available space is much more dynamic in
    # behavior and requires on-line defragmentation more so than owned
    # space or table or index data.
    AvailSpaceTreesOnly = 0x40

    # Starts a new defragmentation task.
    BatchStart = 0x1

    # Stops a defragmentation task.
    BatchStop = 0x2,


class ColInfoGrbit(Enum):
    """
    ColInfoGrbit

    Grbits for the various Api.JetGetColumnInfo and Api.JetGetTableColumnInfo
    overloads.
    Internally this value is OR'ed together with the
    <see cref="JET_ColInfo"/> info level. The info level is not publically exposed
    in this CLR code because it's only used to differentiate the type of the output
    parameter, which is covered by having explicit function overloads with different
    signatures. There is no need to expose JET_ColInfo to CLR.
    """
    # Default options.
    NONE = 0x0

    # For lists (example: <see cref="JET_ColInfo.List"/>), only return
    # non-derived columns (if the table is derived from a template).
    # <remarks>This value is 0x80000000.</remarks>
    NonDerivedColumnsOnly = int.MinValue

    # For lists (example: <see cref="JET_ColInfo.List"/>), only return
    # the column name and columnid of each column.
    MinimalInfo = 0x40000000

    # For lists (example: <see cref="JET_ColInfo.List"/>), sort
    # returned column list by columnid (the default is to sort list by column name).
    SortByColumnid = 0x20000000


class SpaceHintsGrbit(Enum):
    """
    SpaceHintsGrbit

    Options for <see cref="JET_SPACEHINTS"/>.
    """
    # Default options.
    NONE = 0x0

    # Generic bits.

    # This changes the internal allocation policy to get space hierarchically
    # from a B-Tree's immediate parent.
    SpaceHintUtilizeParentSpace = 0x00000001

    # Create bits.

    # This bit will enable Append split behavior to grow according to the
    # growth dynamics of the table (set by cbMinExtent, ulGrowth, cbMaxExtent).
    CreateHintAppendSequential = 0x00000002

    # This bit will enable Hotpoint split behavior to grow according to the
    # growth dynamics of the table (set by cbMinExtent, ulGrowth, cbMaxExtent).
    CreateHintHotpointSequential = 0x00000004

    # Retrieve bits.

    # Reserved and ignored.
    RetrieveHintReserve1 = 0x00000008

    # By setting this the client indicates that forward sequential scan is
    # the predominant usage pattern of this table (causing B+ Tree defrag to
    # be auto-triggered to clean it up if fragmented).
    RetrieveHintTableScanForward = 0x00000010

    # By setting this the client indicates that backwards sequential scan
    # is the predominant usage pattern of this table(causing B+ Tree defrag to
    # be auto-triggered to clean it up if fragmented).
    RetrieveHintTableScanBackward = 0x00000020

    # Reserved and ignored.
    RetrieveHintReserve2 = 0x00000040

    # Reserved and ignored.
    RetrieveHintReserve3 = 0x00000080

    # Delete bits.

    # The application expects this table to be cleaned up in-order
    # sequentially (from lowest key to highest key).
    DeleteHintTableSequential = 0x00000100
