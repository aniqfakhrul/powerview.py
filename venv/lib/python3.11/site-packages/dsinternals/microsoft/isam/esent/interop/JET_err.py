#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_err.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_err(Enum):
    """
    JET_err
    ESENT error codes.
    """

    # Successful operation.
    Success = 0
    #region Errors

    # Resource Failure Simulator failure
    RfsFailure = -100

    # Resource Failure Simulator not initialized
    RfsNotArmed = -101

    # Could not close file
    FileClose = -102

    # Could not start thread
    OutOfThreads = -103

    # System busy due to too many IOs
    TooManyIO = -105

    # A requested async task could not be executed
    TaskDropped = -106

    # Fatal internal error
    InternalError = -107

    # You are running MinESE, that does not have all features compiled in.  This functionality is only supported in a full version of ESE.
    DisabledFunctionality = -112

    # The desired OS functionality could not be located and loaded / linked.
    UnloadableOSFunctionality = -113

    # Buffer dependencies improperly set. Recovery failure
    DatabaseBufferDependenciesCorrupted = -255

    # Version already existed. Recovery failure
    PreviousVersion = -322

    # Reached Page Boundary
    PageBoundary = -323

    # Reached Key Boundary
    KeyBoundary = -324

    # Database corrupted
    BadPageLink = -327

    # Bookmark has no corresponding address in database
    BadBookmark = -328

    # A call to the operating system failed
    NTSystemCallFailed = -334

    # Database corrupted
    BadParentPageLink = -338

    # AvailExt cache doesn't match btree
    SPAvailExtCacheOutOfSync = -340

    # AvailExt space tree is corrupt
    SPAvailExtCorrupted = -341

    # Out of memory allocating an AvailExt cache node
    SPAvailExtCacheOutOfMemory = -342

    # OwnExt space tree is corrupt
    SPOwnExtCorrupted = -343

    # Dbtime on current page is greater than global database dbtime
    DbTimeCorrupted = -344

    # key truncated on index that disallows key truncation
    KeyTruncated = -346

    # Some database pages have become unreachable even from the avail tree, only an offline defragmentation can return the lost space.
    DatabaseLeakInSpace = -348

    # Database corrupted. Searching an unexpectedly empty page.
    BadEmptyPage = -351

    # Number of lines on the page is too few compared to the line being operated on
    BadLineCount = -354

    # Key is too large
    KeyTooBig = -408

    # illegal attempt to separate an LV which must be intrinsic
    CannotSeparateIntrinsicLV = -416

    # Operation not supported on separated long-value
    SeparatedLongValue = -421

    # Can only preread long value columns that can be separate, e.g. not size constrained so that they are fixed or variable columns
    MustBeSeparateLongValue = -423

    # Cannot preread long values when current index secondary
    InvalidPreread = -424

    # Column reference is invalid
    InvalidColumnReference = -426

    # Column reference is stale
    StaleColumnReference = -427

    # A compression integrity check failed. Decompressing data failed the integrity checksum indicating a data corruption in the compress/decompress pipeline.
    CompressionIntegrityCheckFailed = -431

    # Logged operation cannot be redone
    InvalidLoggedOperation = -500

    # Log file is corrupt
    LogFileCorrupt = -501

    # No backup directory given
    NoBackupDirectory = -503

    # The backup directory is not emtpy
    BackupDirectoryNotEmpty = -504

    # Backup is active already
    BackupInProgress = -505

    # Restore in progress
    RestoreInProgress = -506

    # Missing the log file for check point
    MissingPreviousLogFile = -509

    # Failure writing to log file
    LogWriteFail = -510

    # Try to log something after recovery faild
    LogDisabledDueToRecoveryFailure = -511

    # Try to log something during recovery redo
    CannotLogDuringRecoveryRedo = -512

    # Name of logfile does not match internal generation number
    LogGenerationMismatch = -513

    # Version of log file is not compatible with Jet version
    BadLogVersion = -514

    # Timestamp in next log does not match expected
    InvalidLogSequence = -515

    # Log is not active
    LoggingDisabled = -516

    # Log buffer is too small for recovery
    LogBufferTooSmall = -517

    # Maximum log file number exceeded
    LogSequenceEnd = -519

    # No backup in progress
    NoBackup = -520

    # Backup call out of sequence
    InvalidBackupSequence = -521

    # Cannot do backup now
    BackupNotAllowedYet = -523

    # Could not delete backup file
    DeleteBackupFileFail = -524

    # Could not make backup temp directory
    MakeBackupDirectoryFail = -525

    # Cannot perform incremental backup when circular logging enabled
    InvalidBackup = -526

    # Restored with errors
    RecoveredWithErrors = -527

    # Current log file missing
    MissingLogFile = -528

    # Log disk full
    LogDiskFull = -529

    # Bad signature for a log file
    BadLogSignature = -530

    # Bad signature for a db file
    BadDbSignature = -531

    # Bad signature for a checkpoint file
    BadCheckpointSignature = -532

    # Checkpoint file not found or corrupt
    CheckpointCorrupt = -533

    # Patch file page not found during recovery
    MissingPatchPage = -534

    # Patch file page is not valid
    BadPatchPage = -535

    # Redo abruptly ended due to sudden failure in reading logs from log file
    RedoAbruptEnded = -536

    # Hard restore detected that patch file is missing from backup set
    PatchFileMissing = -538

    # Database does not belong with the current set of log files
    DatabaseLogSetMismatch = -539

    # Database and streaming file do not match each other
    DatabaseStreamingFileMismatch = -540

    # actual log file size does not match JET_paramLogFileSize
    LogFileSizeMismatch = -541

    # Could not locate checkpoint file
    CheckpointFileNotFound = -542

    # The required log files for recovery is missing.
    RequiredLogFilesMissing = -543

    # Soft recovery is intended on a backup database. Restore should be used instead
    SoftRecoveryOnBackupDatabase = -544

    # databases have been recovered, but the log file size used during recovery does not match JET_paramLogFileSize
    LogFileSizeMismatchDatabasesConsistent = -545

    # the log file sector size does not match the current volume's sector size
    LogSectorSizeMismatch = -546

    # databases have been recovered, but the log file sector size (used during recovery) does not match the current volume's sector size
    LogSectorSizeMismatchDatabasesConsistent = -547

    # databases have been recovered, but all possible log generations in the current sequence are used; delete all log files and the checkpoint file and backup the databases before continuing
    LogSequenceEndDatabasesConsistent = -548

    # Illegal attempt to replay a streaming file operation where the data wasn't logged. Probably caused by an attempt to roll-forward with circular logging enabled
    StreamingDataNotLogged = -549

    # Database was not shutdown cleanly. Recovery must first be run to properly complete database operations for the previous shutdown.
    DatabaseDirtyShutdown = -550

    # Database last consistent time unmatched
    ConsistentTimeMismatch = -551

    # Patch file is not generated from this backup
    DatabasePatchFileMismatch = -552

    # The starting log number too low for the restore
    EndingRestoreLogTooLow = -553

    # The starting log number too high for the restore
    StartingRestoreLogTooHigh = -554

    # Restore log file has bad signature
    GivenLogFileHasBadSignature = -555

    # Restore log file is not contiguous
    GivenLogFileIsNotContiguous = -556

    # Some restore log files are missing
    MissingRestoreLogFiles = -557

    # The database missed a previous full backup before incremental backup
    MissingFullBackup = -560

    # The backup database size is not in 4k
    BadBackupDatabaseSize = -561

    # Attempted to upgrade a database that is already current
    DatabaseAlreadyUpgraded = -562

    # Attempted to use a database which was only partially converted to the current format -- must restore from backup
    DatabaseIncompleteUpgrade = -563

    # Some current log files are missing for continuous restore
    MissingCurrentLogFiles = -565

    # dbtime on page smaller than dbtimeBefore in record
    DbTimeTooOld = -566

    # dbtime on page in advance of the dbtimeBefore in record
    DbTimeTooNew = -567

    # Some log or patch files are missing during backup
    MissingFileToBackup = -569

    # torn-write was detected in a backup set during hard restore
    LogTornWriteDuringHardRestore = -570

    # torn-write was detected during hard recovery (log was not part of a backup set)
    LogTornWriteDuringHardRecovery = -571

    # corruption was detected in a backup set during hard restore
    LogCorruptDuringHardRestore = -573

    # corruption was detected during hard recovery (log was not part of a backup set)
    LogCorruptDuringHardRecovery = -574

    # Cannot have logging enabled while attempting to upgrade db
    MustDisableLoggingForDbUpgrade = -575

    # TargetInstance specified for restore is not found or log files don't match
    BadRestoreTargetInstance = -577

    # Soft recovery successfully replayed all operations, but the Undo phase of recovery was skipped
    RecoveredWithoutUndo = -579

    # Databases to be restored are not from the same shadow copy backup
    DatabasesNotFromSameSnapshot = -580

    # Soft recovery on a database from a shadow copy backup set
    SoftRecoveryOnSnapshot = -581

    # One or more logs that were committed to this database, are missing.  These log files are required to maintain durable ACID semantics, but not required to maintain consistency if the JET_bitReplayIgnoreLostLogs bit is specified during recovery.
    CommittedLogFilesMissing = -582

    # The physical sector size reported by the disk subsystem, is unsupported by ESE for a specific file type.
    SectorSizeNotSupported = -583

    # Soft recovery successfully replayed all operations and intended to skip the Undo phase of recovery, but the Undo phase was not required
    RecoveredWithoutUndoDatabasesConsistent = -584

    # One or more logs were found to be corrupt during recovery.  These log files are required to maintain durable ACID semantics, but not required to maintain consistency if the JET_bitIgnoreLostLogs bit and JET_paramDeleteOutOfRangeLogs is specified during recovery.
    CommittedLogFileCorrupt = -586

    # The previous log's accumulated segment checksum doesn't match the next log
    LogSequenceChecksumMismatch = -590

    # Database divergence mismatch. Page was uninitialized on remote node, but initialized on local node.
    PageInitializedMismatch = -596

    # Unicode translation buffer too small
    UnicodeTranslationBufferTooSmall = -601

    # Unicode normalization failed
    UnicodeTranslationFail = -602

    # OS does not provide support for Unicode normalisation (and no normalisation callback was specified)
    UnicodeNormalizationNotSupported = -603

    # Can not validate the language
    UnicodeLanguageValidationFailure = -604

    # Existing log file has bad signature
    ExistingLogFileHasBadSignature = -610

    # Existing log file is not contiguous
    ExistingLogFileIsNotContiguous = -611

    # Checksum error in log file during backup
    LogReadVerifyFailure = -612

    # too many outstanding generations between checkpoint and current generation
    CheckpointDepthTooDeep = -614

    # hard recovery attempted on a database that wasn't a backup database
    RestoreOfNonBackupDatabase = -615

    # log truncation attempted but not all required logs were copied
    LogFileNotCopied = -616

    # A surrogate backup is in progress.
    SurrogateBackupInProgress = -617

    # Too many outstanding generations between JetBeginTransaction and current generation.
    TransactionTooLong = -618

    # The specified JET_ENGINEFORMATVERSION value is too low to be supported by this version of ESE.
    EngineFormatVersionNoLongerSupportedTooLow = -619

    # The specified JET_ENGINEFORMATVERSION value is too high, higher than this version of ESE knows about.
    EngineFormatVersionNotYetImplementedTooHigh = -620

    # Thrown by a format feature (not at JetSetSystemParameter) if the client requests a feature that requires a version higher than that set for the JET_paramEngineFormatVersion.
    EngineFormatVersionParamTooLowForRequestedFeature = -621

    # The specified JET_ENGINEFORMATVERSION is set too low for this log stream, the log files have already been upgraded to a higher version.  A higher JET_ENGINEFORMATVERSION value must be set in the param.
    EngineFormatVersionSpecifiedTooLowForLogVersion = -622

    # The specified JET_ENGINEFORMATVERSION is set too low for this database file, the database file has already been upgraded to a higher version.  A higher JET_ENGINEFORMATVERSION value must be set in the param.
    EngineFormatVersionSpecifiedTooLowForDatabaseVersion = -623

    # Backup was aborted by server by calling JetTerm with JET_bitTermStopBackup or by calling JetStopBackup
    BackupAbortByServer = -801

    # Invalid flags parameter
    InvalidGrbit = -900

    # Termination in progress
    TermInProgress = -1000

    # API not supported
    FeatureNotAvailable = -1001

    # Invalid name
    InvalidName = -1002

    # Invalid API parameter
    InvalidParameter = -1003

    # Tried to attach a read-only database file for read/write operations
    DatabaseFileReadOnly = -1008

    # Invalid database id
    InvalidDatabaseId = -1010

    # Out of Memory
    OutOfMemory = -1011

    # Maximum database size reached
    OutOfDatabaseSpace = -1012

    # Out of table cursors
    OutOfCursors = -1013

    # Out of database page buffers
    OutOfBuffers = -1014

    # Too many indexes
    TooManyIndexes = -1015

    # Too many columns in an index
    TooManyKeys = -1016

    # Record has been deleted
    RecordDeleted = -1017

    # Checksum error on a database page
    ReadVerifyFailure = -1018

    # Blank database page
    PageNotInitialized = -1019

    # Out of file handles
    OutOfFileHandles = -1020

    # The OS returned ERROR_CRC from file IO
    DiskReadVerificationFailure = -1021

    # Disk IO error
    DiskIO = -1022

    # Invalid file path
    InvalidPath = -1023

    # Invalid system path
    InvalidSystemPath = -1024

    # Invalid log directory
    InvalidLogDirectory = -1025

    # Record larger than maximum size
    RecordTooBig = -1026

    # Too many open databases
    TooManyOpenDatabases = -1027

    # Not a database file
    InvalidDatabase = -1028

    # Database engine not initialized
    NotInitialized = -1029

    # Database engine already initialized
    AlreadyInitialized = -1030

    # Database engine is being initialized
    InitInProgress = -1031

    # Cannot access file, the file is locked or in use
    FileAccessDenied = -1032

    # Query support unavailable
    QueryNotSupported = -1034

    # SQL Link support unavailable
    SQLLinkNotSupported = -1035

    # Buffer is too small
    BufferTooSmall = -1038

    # Too many columns defined
    TooManyColumns = -1040

    # Container is not empty
    ContainerNotEmpty = -1043

    # Filename is invalid
    InvalidFilename = -1044

    # Invalid bookmark
    InvalidBookmark = -1045

    # Column used in an index
    ColumnInUse = -1046

    # Data buffer doesn't match column size
    InvalidBufferSize = -1047

    # Cannot set column value
    ColumnNotUpdatable = -1048

    # Index is in use
    IndexInUse = -1051

    # Link support unavailable
    LinkNotSupported = -1052

    # Null keys are disallowed on index
    NullKeyDisallowed = -1053

    # Operation must be within a transaction
    NotInTransaction = -1054

    # Transaction must rollback because failure of unversioned update
    MustRollback = -1057

    # Too many active database users
    TooManyActiveUsers = -1059

    # Invalid or unknown country/region code
    InvalidCountry = -1061

    # Invalid or unknown language id
    InvalidLanguageId = -1062

    # Invalid or unknown code page
    InvalidCodePage = -1063

    # Invalid flags for LCMapString()
    InvalidLCMapStringFlags = -1064

    # Attempted to create a version store entry (RCE) larger than a version bucket
    VersionStoreEntryTooBig = -1065

    # Version store out of memory (and cleanup attempt failed to complete)
    VersionStoreOutOfMemoryAndCleanupTimedOut = -1066

    # Version store out of memory (cleanup already attempted)
    VersionStoreOutOfMemory = -1069

    # UNUSED: lCSRPerfFUCB * g_lCursorsMax exceeded (XJET only)
    CurrencyStackOutOfMemory = -1070

    # Cannot index escrow column
    CannotIndex = -1071

    # Record has not been deleted
    RecordNotDeleted = -1072

    # Too many mempool entries requested
    TooManyMempoolEntries = -1073

    # Out of btree ObjectIDs (perform offline defrag to reclaim freed/unused ObjectIds)
    OutOfObjectIDs = -1074

    # Long-value ID counter has reached maximum value. (perform offline defrag to reclaim free/unused LongValueIDs)
    OutOfLongValueIDs = -1075

    # Auto-increment counter has reached maximum value (offline defrag WILL NOT be able to reclaim free/unused Auto-increment values).
    OutOfAutoincrementValues = -1076

    # Dbtime counter has reached maximum value (perform offline defrag to reclaim free/unused Dbtime values)
    OutOfDbtimeValues = -1077

    # Sequential index counter has reached maximum value (perform offline defrag to reclaim free/unused SequentialIndex values)
    OutOfSequentialIndexValues = -1078

    # Multi-instance call with single-instance mode enabled
    RunningInOneInstanceMode = -1080

    # Single-instance call with multi-instance mode enabled
    RunningInMultiInstanceMode = -1081

    # Global system parameters have already been set
    SystemParamsAlreadySet = -1082

    # System path already used by another database instance
    SystemPathInUse = -1083

    # Logfile path already used by another database instance
    LogFilePathInUse = -1084

    # Temp path already used by another database instance
    TempPathInUse = -1085

    # Instance Name already in use
    InstanceNameInUse = -1086

    # Global system parameters have already been set, but to a conflicting or disagreeable state to the specified values.
    SystemParameterConflict = -1087

    # This instance cannot be used because it encountered a fatal error
    InstanceUnavailable = -1090

    # This database cannot be used because it encountered a fatal error
    DatabaseUnavailable = -1091

    # This instance cannot be used because it encountered a log-disk-full error performing an operation (likely transaction rollback) that could not tolerate failure
    InstanceUnavailableDueToFatalLogDiskFull = -1092

    # This JET_sesparam* identifier is not known to the ESE engine.
    InvalidSesparamId = -1093

    # Out of sessions
    OutOfSessions = -1101

    # Write lock failed due to outstanding write lock
    WriteConflict = -1102

    # Transactions nested too deeply
    TransTooDeep = -1103

    # Invalid session handle
    InvalidSesid = -1104

    # Update attempted on uncommitted primary index
    WriteConflictPrimaryIndex = -1105

    # Operation not allowed within a transaction
    InTransaction = -1108

    # Must rollback current transaction -- cannot commit or begin a new one
    RollbackRequired = -1109

    # Read-only transaction tried to modify the database
    TransReadOnly = -1110

    # Attempt to replace the same record by two diffrerent cursors in the same session
    SessionWriteConflict = -1111

    # record would be too big if represented in a database format from a previous version of Jet
    RecordTooBigForBackwardCompatibility = -1112

    # The temp table could not be created due to parameters that conflict with JET_bitTTForwardOnly
    CannotMaterializeForwardOnlySort = -1113

    # This session handle can't be used with this table id
    SesidTableIdMismatch = -1114

    # Invalid instance handle
    InvalidInstance = -1115

    # The instance was shutdown successfully but all the attached databases were left in a dirty state by request via JET_bitTermDirty
    DirtyShutdown = -1116

    # The database page read from disk had the wrong page number.
    ReadPgnoVerifyFailure = -1118

    # The database page read from disk had a previous write not represented on the page.
    ReadLostFlushVerifyFailure = -1119

    # File system operation failed with an error indicating the file system is corrupt.
    FileSystemCorruption = -1121

    # One or more database pages read from disk during recovery do not match the expected state.
    RecoveryVerifyFailure = -1123

    # Attempted to provide a filter to JetSetCursorFilter() in an unsupported scenario.
    FilteredMoveNotSupported = -1124

    # Attempted to PrepareToCommit a distributed transaction to non-zero level
    MustCommitDistributedTransactionToLevel0 = -1150

    # Attempted a write-operation after a distributed transaction has called PrepareToCommit
    DistributedTransactionAlreadyPreparedToCommit = -1151

    # Attempted to PrepareToCommit a non-distributed transaction
    NotInDistributedTransaction = -1152

    # Attempted to commit a distributed transaction, but PrepareToCommit has not yet been called
    DistributedTransactionNotYetPreparedToCommit = -1153

    # Attempted to begin a distributed transaction when not at level 0
    CannotNestDistributedTransactions = -1154

    # Attempted to begin a distributed transaction but no callback for DTC coordination was specified on initialisation
    DTCMissingCallback = -1160

    # Attempted to recover a distributed transaction but no callback for DTC coordination was specified on initialisation
    DTCMissingCallbackOnRecovery = -1161

    # Unexpected error code returned from DTC callback
    DTCCallbackUnexpectedError = -1162

    # Database already exists
    DatabaseDuplicate = -1201

    # Database in use
    DatabaseInUse = -1202

    # No such database
    DatabaseNotFound = -1203

    # Invalid database name
    DatabaseInvalidName = -1204

    # Invalid number of pages
    DatabaseInvalidPages = -1205

    # Non database file or corrupted db
    DatabaseCorrupted = -1206

    # Database exclusively locked
    DatabaseLocked = -1207

    # Cannot disable versioning for this database
    CannotDisableVersioning = -1208

    # Database engine is incompatible with database
    InvalidDatabaseVersion = -1209

    # The database is in an older (200) format
    Database200Format = -1210

    # The database is in an older (400) format
    Database400Format = -1211

    # The database is in an older (500) format
    Database500Format = -1212

    # The database page size does not match the engine
    PageSizeMismatch = -1213

    # Cannot start any more database instances
    TooManyInstances = -1214

    # A different database instance is using this database
    DatabaseSharingViolation = -1215

    # An outstanding database attachment has been detected at the start or end of recovery, but database is missing or does not match attachment info
    AttachedDatabaseMismatch = -1216

    # Specified path to database file is illegal
    DatabaseInvalidPath = -1217

    # A database is being assigned an id already in use
    DatabaseIdInUse = -1218

    # Force Detach allowed only after normal detach errored out
    ForceDetachNotAllowed = -1219

    # Corruption detected in catalog
    CatalogCorrupted = -1220

    # Database is partially attached. Cannot complete attach operation
    PartiallyAttachedDB = -1221

    # Database with same signature in use
    DatabaseSignInUse = -1222

    # Corrupted db but repair not allowed
    DatabaseCorruptedNoRepair = -1224

    # recovery tried to replay a database creation, but the database was originally created with an incompatible (likely older) version of the database engine
    InvalidCreateDbVersion = -1225

    # The database cannot be attached because it is currently being rebuilt as part of an incremental reseed.
    DatabaseIncompleteIncrementalReseed = -1226

    # The database is not a valid state to perform an incremental reseed.
    DatabaseInvalidIncrementalReseed = -1227

    # The incremental reseed being performed on the specified database cannot be completed due to a fatal error.  A full reseed is required to recover this database.
    DatabaseFailedIncrementalReseed = -1228

    # The incremental reseed being performed on the specified database cannot be completed because the min required log contains no attachment info.  A full reseed is required to recover this database.
    NoAttachmentsFailedIncrementalReseed = -1229

    # Recovery on this database has not yet completed enough to permit access.
    DatabaseNotReady = -1230

    # Database is attached but only for recovery.  It must be explicitly attached before it can be opened.
    DatabaseAttachedForRecovery = -1231

    # Recovery has not seen any Begin0/Commit0 records and so does not know what trxBegin0 to assign to this transaction
    TransactionsNotReadyDuringRecovery = -1232

    # Table is exclusively locked
    TableLocked = -1302

    # Table already exists
    TableDuplicate = -1303

    # Table is in use, cannot lock
    TableInUse = -1304

    # No such table or object
    ObjectNotFound = -1305

    # Bad file/index density
    DensityInvalid = -1307

    # Table is not empty
    TableNotEmpty = -1308

    # Invalid table id
    InvalidTableId = -1310

    # Cannot open any more tables (cleanup already attempted)
    TooManyOpenTables = -1311

    # Oper. not supported on table
    IllegalOperation = -1312

    # Cannot open any more tables (cleanup attempt failed to complete)
    TooManyOpenTablesAndCleanupTimedOut = -1313

    # Table or object name in use
    ObjectDuplicate = -1314

    # Object is invalid for operation
    InvalidObject = -1316

    # Use CloseTable instead of DeleteTable to delete temp table
    CannotDeleteTempTable = -1317

    # Illegal attempt to delete a system table
    CannotDeleteSystemTable = -1318

    # Illegal attempt to delete a template table
    CannotDeleteTemplateTable = -1319

    # Must have exclusive lock on table.
    ExclusiveTableLockRequired = -1322

    # DDL operations prohibited on this table
    FixedDDL = -1323

    # On a derived table, DDL operations are prohibited on inherited portion of DDL
    FixedInheritedDDL = -1324

    # Nesting of hierarchical DDL is not currently supported.
    CannotNestDDL = -1325

    # Tried to inherit DDL from a table not marked as a template table.
    DDLNotInheritable = -1326

    # System parameters were set improperly
    InvalidSettings = -1328

    # Client has requested stop service
    ClientRequestToStopJetService = -1329

    # Template table was created with NoFixedVarColumnsInDerivedTables
    CannotAddFixedVarColumnToDerivedTable = -1330

    # Index build failed
    IndexCantBuild = -1401

    # Primary index already defined
    IndexHasPrimary = -1402

    # Index is already defined
    IndexDuplicate = -1403

    # No such index
    IndexNotFound = -1404

    # Cannot delete clustered index
    IndexMustStay = -1405

    # Illegal index definition
    IndexInvalidDef = -1406

    # Invalid create index description
    InvalidCreateIndex = -1409

    # Out of index description blocks
    TooManyOpenIndexes = -1410

    # Non-unique inter-record index keys generated for a multivalued index
    MultiValuedIndexViolation = -1411

    # Failed to build a secondary index that properly reflects primary index
    IndexBuildCorrupted = -1412

    # Primary index is corrupt. The database must be defragmented or the table deleted.
    PrimaryIndexCorrupted = -1413

    # Secondary index is corrupt. The database must be defragmented or the affected index must be deleted. If the corrupt index is over Unicode text, a likely cause is a sort-order change.
    SecondaryIndexCorrupted = -1414

    # Illegal index id
    InvalidIndexId = -1416

    # tuple index can only be on a secondary index
    IndexTuplesSecondaryIndexOnly = -1430

    # tuple index may only have eleven columns in the index
    IndexTuplesTooManyColumns = -1431

    # tuple index must be a non-unique index
    IndexTuplesNonUniqueOnly = -1432

    # tuple index must be on a text/binary column
    IndexTuplesTextBinaryColumnsOnly = -1433

    # tuple index does not allow setting cbVarSegMac
    IndexTuplesVarSegMacNotAllowed = -1434

    # invalid min/max tuple length or max characters to index specified
    IndexTuplesInvalidLimits = -1435

    # cannot call RetrieveColumn() with RetrieveFromIndex on a tuple index
    IndexTuplesCannotRetrieveFromIndex = -1436

    # specified key does not meet minimum tuple length
    IndexTuplesKeyTooSmall = -1437

    # Specified LV chunk size is not supported
    InvalidLVChunkSize = -1438

    # Only JET_coltypLongText and JET_coltypLongBinary columns without default values can be encrypted
    ColumnCannotBeEncrypted = -1439

    # Cannot index encrypted column
    CannotIndexOnEncryptedColumn = -1440

    # Column value is long
    ColumnLong = -1501

    # No such chunk in long value
    ColumnNoChunk = -1502

    # Field will not fit in record
    ColumnDoesNotFit = -1503

    # Null not valid
    NullInvalid = -1504

    # Column indexed, cannot delete
    ColumnIndexed = -1505

    # Field length is greater than maximum
    ColumnTooBig = -1506

    # No such column
    ColumnNotFound = -1507

    # Field is already defined
    ColumnDuplicate = -1508

    # Attempted to create a multi-valued column, but column was not Tagged
    MultiValuedColumnMustBeTagged = -1509

    # Second autoincrement or version column
    ColumnRedundant = -1510

    # Invalid column data type
    InvalidColumnType = -1511

    # No non-NULL tagged columns
    TaggedNotNULL = -1514

    # Invalid w/o a current index
    NoCurrentIndex = -1515

    # The key is completely made
    KeyIsMade = -1516

    # Column Id Incorrect
    BadColumnId = -1517

    # Bad itagSequence for tagged column
    BadItagSequence = -1518

    # Cannot delete, column participates in relationship
    ColumnInRelationship = -1519

    # AutoIncrement and Version cannot be tagged
    CannotBeTagged = -1521

    # Default value exceeds maximum size
    DefaultValueTooBig = -1524

    # Duplicate detected on a unique multi-valued column
    MultiValuedDuplicate = -1525

    # Corruption encountered in long-value tree
    LVCorrupted = -1526

    # Duplicate detected on a unique multi-valued column after data was normalized, and normalizing truncated the data before comparison
    MultiValuedDuplicateAfterTruncation = -1528

    # Invalid column in derived table
    DerivedColumnCorruption = -1529

    # Tried to convert column to a primary index placeholder, but column doesn't meet necessary criteria
    InvalidPlaceholderColumn = -1530

    # Only JET_coltypLongText and JET_coltypLongBinary columns can be compressed
    ColumnCannotBeCompressed = -1538

    # Cannot retrieve/set encrypted column without an encryption key
    ColumnNoEncryptionKey = -1540

    # The key was not found
    RecordNotFound = -1601

    # No working buffer
    RecordNoCopy = -1602

    # Currently not on a record
    NoCurrentRecord = -1603

    # Primary key may not change
    RecordPrimaryChanged = -1604

    # Illegal duplicate key
    KeyDuplicate = -1605

    # Attempted to update record when record update was already in progress
    AlreadyPrepared = -1607

    # No call to JetMakeKey
    KeyNotMade = -1608

    # No call to JetPrepareUpdate
    UpdateNotPrepared = -1609

    # Data has changed, operation aborted
    DataHasChanged = -1611

    # Windows installation does not support language
    LanguageNotSupported = -1619

    # Internal error: data could not be decompressed
    DecompressionFailed = -1620

    # No version updates only for uncommitted tables
    UpdateMustVersion = -1621

    # Data could not be decrypted
    DecryptionFailed = -1622

    # Cannot encrypt tagged columns with itag>1
    EncryptionBadItag = -1623

    # Too many sort processes
    TooManySorts = -1701

    # Invalid operation on Sort
    InvalidOnSort = -1702

    # Temp file could not be opened
    TempFileOpenError = -1803

    # Too many open databases
    TooManyAttachedDatabases = -1805

    # No space left on disk
    DiskFull = -1808

    # Permission denied
    PermissionDenied = -1809

    # File not found
    FileNotFound = -1811

    # Invalid file type
    FileInvalidType = -1812

    # File already exists
    FileAlreadyExists = -1814

    # Cannot Restore after init.
    AfterInitialization = -1850

    # Logs could not be interpreted
    LogCorrupted = -1852

    # Invalid operation
    InvalidOperation = -1906

    # Access denied
    AccessDenied = -1907

    # Infinite split
    TooManySplits = -1909

    # Multiple threads are using the same session
    SessionSharingViolation = -1910

    # An entry point in a DLL we require could not be found
    EntryPointNotFound = -1911

    # Specified session already has a session context set
    SessionContextAlreadySet = -1912

    # Tried to reset session context, but current thread did not orignally set the session context
    SessionContextNotSetByThisThread = -1913

    # Tried to terminate session in use
    SessionInUse = -1914

    # Internal error during dynamic record format conversion
    RecordFormatConversionFailed = -1915

    # Just one open user database per session is allowed (JET_paramOneDatabasePerSession)
    OneDatabasePerSession = -1916

    # error during rollback
    RollbackError = -1917

    # The version of the persisted flush map is not supported by this version of the engine.
    FlushMapVersionUnsupported = -1918

    # The persisted flush map and the database do not match.
    FlushMapDatabaseMismatch = -1919

    # The persisted flush map cannot be reconstructed.
    FlushMapUnrecoverable = -1920

    # The operation did not complete successfully because the database is already running maintenance on specified database
    DatabaseAlreadyRunningMaintenance = -2004

    # A callback failed
    CallbackFailed = -2101

    # A callback function could not be found
    CallbackNotResolved = -2102

    # An element of the JET space hints structure was not correct or actionable.
    SpaceHintsInvalid = -2103

    # OS Shadow copy API used in an invalid sequence
    OSSnapshotInvalidSequence = -2401

    # OS Shadow copy ended with time-out
    OSSnapshotTimeOut = -2402

    # OS Shadow copy not allowed (backup or recovery in progress)
    OSSnapshotNotAllowed = -2403

    # invalid JET_OSSNAPID
    OSSnapshotInvalidSnapId = -2404

    # Internal test injection limit hit
    TooManyTestInjections = -2501

    # Test injection not supported
    TestInjectionNotSupported = -2502

    # Some how the log data provided got out of sequence with the current state of the instance
    InvalidLogDataSequence = -2601

    # Attempted to use Local Storage without a callback function being specified
    LSCallbackNotSpecified = -3000

    # Attempted to set Local Storage for an object which already had it set
    LSAlreadySet = -3001

    # Attempted to retrieve Local Storage from an object which didn't have it set
    LSNotSet = -3002

    # an I/O was issued to a location that was sparse
    FileIOSparse = -4000

    # a read was issued to a location beyond EOF (writes will expand the file)
    FileIOBeyondEOF = -4001

    # instructs the JET_ABORTRETRYFAILCALLBACK caller to abort the specified I/O
    FileIOAbort = -4002

    # instructs the JET_ABORTRETRYFAILCALLBACK caller to retry the specified I/O
    FileIORetry = -4003

    # instructs the JET_ABORTRETRYFAILCALLBACK caller to fail the specified I/O
    FileIOFail = -4004

    # read/write access is not supported on compressed files
    FileCompressed = -4005
    #endregion

