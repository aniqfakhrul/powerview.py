#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Windows8Grbits.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class ErrorInfoGrbit(Enum):
    """
    ErrorInfoGrbit

    Options for <see cref="Windows8Api.JetGetErrorInfo"/>.
    """

    # No option.
    NONE = 0


class ResizeDatabaseGrbit(Enum):
    """
    ResizeDatabaseGrbit

    Options for <see cref="Windows8Api.JetResizeDatabase"/>.
    <seealso cref="Windows81.Windows81Grbits.OnlyShrink"/>
    """

    # No option.
    NONE = 0

    # Only grow the database. If the resize call would shrink the database, do nothing.
    OnlyGrow = 0x1


class DurableCommitCallbackGrbit(Enum):
    """
    DurableCommitCallbackGrbit

    Options passed to log flush callback.
    <seealso cref="Microsoft.Isam.Esent.Interop.Windows10.Windows10Grbits.LogUnavailable"/>
    """

    # Default options.
    NONE = 0


class PrereadIndexRangesGrbit(Enum):
    """
    PrereadIndexRangesGrbit

    Options for <see cref="Windows8Api.JetPrereadIndexRanges"/>.
    """

    # Preread forward.
    Forward = 0x1

    # Preread backwards.
    Backwards = 0x2

    # Preread only first page of any long column.
    FirstPageOnly = 0x4

    # Normalized key/bookmark provided instead of column value.
    NormalizedKey = 0x8


    # Options for <see cref="Windows8Api.JetStopServiceInstance2"/>.


class StopServiceGrbit(Enum):
    """
    StopServiceGrbit
    """
    
    # Stops all ESE services for the specified instance.
    All = 0x00000000

    # Stops restartable client specificed background maintenance tasks (B+ Tree Defrag).
    BackgroundUserTasks = 0x00000002

    # Quiesces all dirty caches to disk. Asynchronous. Quiescing is cancelled if the <see cref="Resume"/>
    # bit is called subsequently.
    QuiesceCaches = 0x00000004

    # Resumes previously issued StopService operations, i.e. "restarts service".  Can be combined
    # with above grbits to Resume specific services, or with 0x0 Resumes all previous stopped services.

    # Warning: This bit can only be used to resume JET_bitStopServiceBackground and JET_bitStopServiceQuiesceCaches, if you
    # did a JET_bitStopServiceAll or JET_bitStopServiceAPI, attempting to use JET_bitStopServiceResume will fail.
    Resume = 0x80000000


class CursorFilterGrbit(Enum):
    """
    CursorFilterGrbit

    Options passed while setting cursor filters.
    <seealso cref="Windows8Api.JetSetCursorFilter"/>
    """

    # Default options.
    NONE = 0


class JetIndexColumnGrbit(Enum):
    """
    JetIndexColumnGrbit

    Options for <see cref="JET_INDEX_COLUMN"/>.
    """

    # Default options.
    NONE = 0

    # Zero-length value (non-null).
    ZeroLength = 0x1


class Windows8Grbits(object):
    """
    Windows8Grbits

    System parameters that have been introduced in Windows 8.
    """

    # Allows db to remain attached at the end of recovery (for faster
    # transition to running state).
    KeepDbAttachedAtEndOfRecovery = InitGrbit(0x1000)

    # Purge database pages on attach.
    PurgeCacheOnAttach = AttachDatabaseGrbit(0x1000)

    # Specifying this flag will change GUID sort order to .Net standard.
    IndexDotNetGuid = CreateIndexGrbit(0x00040000)

    # This option requests that the temporary table sort columns of type
    # JET_coltypGUID according to .Net Guid sort order.
    TTDotNetGuid = TempTableGrbit(0x100)
