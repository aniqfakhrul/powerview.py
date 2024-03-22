#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : VistaGrbits.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SnapshotEndGrbit(Enum):
    """
    SnapshotEndGrbit
    
    Options for <see cref="VistaApi.JetOSSnapshotEnd"/>.
    """

    # Default options.
    NONE = 0

    # The snapshot session aborted.
    AbortSnapshot = 0x1


class SnapshotPrepareInstanceGrbit(Enum):
    """
    SnapshotPrepareInstanceGrbit

    Options for <see cref="VistaApi.JetOSSnapshotPrepareInstance"/>.
    """

    # Default options.
    NONE = 0


class SnapshotTruncateLogGrbit(Enum):
    """
    SnapshotTruncateLogGrbit

    Options for <see cref="VistaApi.JetOSSnapshotTruncateLog"/>
    and <see cref="VistaApi.JetOSSnapshotTruncateLogInstance"/>.
    """

    # No truncation will occur.
    NONE = 0

    # All the databases are attached so the storage engine can compute
    # and do the log truncation.
    AllDatabasesSnapshot = 0x1


class SnapshotGetFreezeInfoGrbit(Enum):
    """
    SnapshotGetFreezeInfoGrbit

    Options for <see cref="VistaApi.JetOSSnapshotGetFreezeInfo"/>.
    """

    # Default options.
    NONE = 0


class JET_InstanceMiscInfo(Enum):
    """
    JET_InstanceMiscInfo

    Information levels for <see cref="VistaApi.JetGetInstanceMiscInfo"/>.
    """

    # Get the signature of the transaction log associated with this sequence.
    LogSignature = 0


class VistaGrbits(Enum):
    """
    VistaGrbits

    Grbits that have been added to the Vista version of ESENT.
    """

    # Specifying this flag for an index that has more than one key column
    # that is a multi-valued column will result in an index entry being
    # created for each result of a cross product of all the values in
    # those key columns. Otherwise, the index would only have one entry
    # for each multi-value in the most significant key column that is a
    # multi-valued column and each of those index entries would use the
    # first multi-value from any other key columns that are multi-valued columns.
    # <para>
    # For example, if you specified this flag for an index over column
    # A that has the values "red" and "blue" and over column B that has
    # the values "1" and "2" then the following index entries would be
    # created: "red", "1"; "red", "2"; "blue", "1"; "blue", "2". Otherwise,
    # the following index entries would be created: "red", "1"; "blue", "1".
    # </para>
    IndexCrossProduct = CreateIndexGrbit(0x4000)

    # Specifying this flag will cause any update to the index that would
    # result in a truncated key to fail with <see cref="JET_err.KeyTruncated"/>.
    # Otherwise, keys will be silently truncated.
    IndexDisallowTruncation = CreateIndexGrbit(0x10000)

    # Index over multiple multi-valued columns but only with values of same itagSequence.
    IndexNestedTable = CreateIndexGrbit(0x20000)

    # The engine can mark the database headers as appropriate (for example,
    # a full backup completed), even though the call to truncate was not completed.
    TruncateDone = EndExternalBackupGrbit(0x100)

    # Perform recovery, but halt at the Undo phase. Allows whatever logs are present to
    # be replayed, then later additional logs can be copied and replayed.
    RecoveryWithoutUndo = InitGrbit(0x8)

    # On successful soft recovery, truncate log files.
    TruncateLogsAfterRecovery = InitGrbit(0x00000010)

    # Missing database map entry default to same location.
    ReplayMissingMapEntryDB = InitGrbit(0x00000020)

    # Transaction logs must exist in the log file directory
    # (i.e. can't auto-start a new stream).
    LogStreamMustExist = InitGrbit(0x40)

    # The snapshot session continues after JetOSSnapshotThaw and will
    # require a JetOSSnapshotEnd function call.
    ContinueAfterThaw = SnapshotPrepareGrbit(0x4)

    # Specifying this flag will cause the index to use the maximum key size
    # specified in the cbKeyMost field in the structure. Otherwise, the
    # index will use JET_cbKeyMost (255) as its maximum key size.

    # Set internally when the NATIVE_INDEXCREATE structure is generated.
    IndexKeyMost = CreateIndexGrbit(0x8000)

    # LCID field of JET_INDEXCREATE actually points to a JET_UNICODEINDEX
    # struct to allow user-defined LCMapString() flags.
    IndexUnicode = CreateIndexGrbit(0x00000800)
