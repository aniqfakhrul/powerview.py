#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Windows7Grbits.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class CrashDumpGrbit(Enum):
    """
    CrashDumpGrbit

    Options for <see cref="Windows7Api.JetConfigureProcessForCrashDump"/>.
    """
    # Default options.
    NONE = 0

    # Dump minimum includes <see cref="CacheMinimum"/>.
    Minimum = 0x1

    # Dump maximum includes <see cref="CacheMaximum"/>.
    Maximum = 0x2

    # CacheMinimum includes pages that are latched.
    # CacheMinimum includes pages that are used for memory.
    # CacheMinimum includes pages that are flagged with errors.
    CacheMinimum = 0x4

    # Cache maximum includes cache minimum.
    # Cache maximum includes the entire cache image.
    CacheMaximum = 0x8

    # Dump includes pages that are modified.
    CacheIncludeDirtyPages = 0x10

    # Dump includes pages that contain valid data.
    CacheIncludeCachedPages = 0x20

    # Dump includes pages that are corrupted (expensive to compute).
    CacheIncludeCorruptedPages = 0x40


class PrereadKeysGrbit(Enum):
    """
    PrereadKeysGrbit
    
    Options for <see cref="Windows7Api.JetPrereadKeys(JET_SESID, JET_TABLEID, byte[][], int[], int, int, out int, PrereadKeysGrbit)"/>.
    """

    # Preread forward.
    Forward = 0x1

    # Preread backwards.
    Backwards = 0x2


class Windows7Grbits(object):
    """
    Windows7Grbits

    Grbits that have been added to the Windows 7 version of ESENT.
    """

    # Compress data in the column, if possible.
    ColumnCompressed = ColumndefGrbit(0x80000)

    # Try to compress the data when storing it.
    Compressed = SetColumnGrbit(0x20000)

    # Don't compress the data when storing it.
    Uncompressed = SetColumnGrbit(0x10000)

    # Recover without error even if uncommitted logs have been lost. Set
    # the recovery waypoint with Windows7Param.WaypointLatency to enable
    # this type of recovery.
    ReplayIgnoreLostLogs = InitGrbit(0x80)

    # Terminate without flushing the database cache.
    Dirty = TermGrbit(0x8)

    # Permit only intrinsic LV's (so materialisation is not required simply
    # because a TT has an LV column).
    IntrinsicLVsOnly = TempTableGrbit(0x80)

    # When enumerating column values only retrieve data that is present in
    # the record. This means that BLOB columns will not always be retrieved.
    EnumerateInRecordOnly = EnumerateColumnsGrbit(0x00200000)

    # Force a new logfile to be created. This option may be used even if
    # the session is not currently in a transaction. This option cannot
    # be used in combination with any other option.
    ForceNewLog = CommitTransactionGrbit(0x10)

    # No instances will be prepared by default. Instances must be added explicitly.
    ExplicitPrepare = SnapshotPrepareGrbit(0x8)

    # Hint that the sequential traversal will be in the forward direction.
    Forward = SetTableSequentialGrbit(0x1)

    # While running Online Defragmentation, do not perform partial merges of pages.
    NoPartialMerges = DefragGrbit(0x80)

    # Defragment a single BTree.
    DefragmentBTree = DefragGrbit(0x100)

    # Hint that the sequential traversal will be in the backward direction.
    Backward = SetTableSequentialGrbit(0x2)

    # The database engine will initiate automatic background database maintenance upon database attachment.
    EnableAttachDbBackgroundMaintenance = AttachDatabaseGrbit(0x800)

    # The database engine will initiate automatic background database maintenance upon database creation.
    EnableCreateDbBackgroundMaintenance = CreateDatabaseGrbit(0x800)

