#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : Win32ErrorCode.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class Win32ErrorCode(Enum):
    """
    Win32ErrorCode

    Win32 Error Code

    See: https://msdn.microsoft.com/en-us/library/cc231199.aspx
    """

    # The operation completed successfully.
    Success = 0

    # Incorrect function.
    INVALID_FUNCTION = 1

    # The system cannot find the file specified.
    FILE_NOT_FOUND = 2

    # The system cannot find the path specified.
    PATH_NOT_FOUND = 3

    # The system cannot open the file.
    TOO_MANY_OPEN_FILES = 4

    # Access is denied.
    ACCESS_DENIED = 5

    # The handle is invalid.
    INVALID_HANDLE = 6

    # The storage control blocks were destroyed.
    ARENA_TRASHED = 7

    # Not enough storage is available to process this command.
    NOT_ENOUGH_MEMORY = 8

    # The storage control block address is invalid.
    INVALID_BLOCK = 9

    # The environment is incorrect.
    BAD_ENVIRONMENT = 10

    # An attempt was made to load a program with an incorrect format.
    BAD_FORMAT = 11

    # The access code is invalid.
    INVALID_ACCESS = 12

    # The data is invalid.
    INVALID_DATA = 13

    # Not enough storage is available to complete this operation.
    OUTOFMEMORY = 14

    # The system cannot find the drive specified.
    INVALID_DRIVE = 15

    # The directory cannot be removed.
    CURRENT_DIRECTORY = 16

    # The system cannot move the file to a different disk drive.
    NOT_SAME_DEVICE = 17

    # There are no more files.
    NO_MORE_FILES = 18

    # The media is write protected.
    WRITE_PROTECT = 19

    # The system cannot find the device specified.
    BAD_UNIT = 20

    # The device is not ready.
    NOT_READY = 21

    # The device does not recognize the command.
    BAD_COMMAND = 22

    # Data error (cyclic redundancy check).
    CRC = 23

    # The program issued a command but the command length is incorrect.
    BAD_LENGTH = 24

    # The drive cannot locate a specific area or track on the disk.
    SEEK = 25

    # The specified disk or diskette cannot be accessed.
    NOT_DOS_DISK = 26

    # The drive cannot find the sector requested.
    SECTOR_NOT_FOUND = 27

    # The printer is out of paper.
    OUT_OF_PAPER = 28

    # The system cannot write to the specified device.
    WRITE_FAULT = 29

    # The system cannot read from the specified device.
    READ_FAULT = 30

    # A device attached to the system is not functioning.
    GEN_FAILURE = 31

    # The process cannot access the file because it is being used by another process.
    SHARING_VIOLATION = 32

    # The process cannot access the file because another process has locked a portion of the file.
    LOCK_VIOLATION = 33

    # The wrong diskette is in the drive.
    # Insert %2 (Volume Serial Number: %3) into drive %1.
    WRONG_DISK = 34

    # Too many files opened for sharing.
    SHARING_BUFFER_EXCEEDED = 36

    # Reached the end of the file.
    HANDLE_EOF = 38

    # The disk is full.
    HANDLE_DISK_FULL = 39

    # The request is not supported.
    NOT_SUPPORTED = 50

    # Windows cannot find the network path. Verify that the network path is correct and the destination computer is not busy or turned off. If Windows still cannot find the network path, contact your network administrator.
    REM_NOT_LIST = 51

    # You were not connected because a duplicate name exists on the network. Go to System in Control Panel to change the computer name and try again.
    DUP_NAME = 52

    # The network path was not found.
    BAD_NETPATH = 53

    # The network is busy.
    NETWORK_BUSY = 54

    # The specified network resource or device is no longer available.
    DEV_NOT_EXIST = 55

    # The network BIOS command limit has been reached.
    TOO_MANY_CMDS = 56

    # A network adapter hardware error occurred.
    ADAP_HDW_ERR = 57

    # The specified server cannot perform the requested operation.
    BAD_NET_RESP = 58

    # An unexpected network error occurred.
    UNEXP_NET_ERR = 59

    # The remote adapter is not compatible.
    BAD_REM_ADAP = 60

    # The printer queue is full.
    PRINTQ_FULL = 61

    # Space to store the file waiting to be printed is not available on the server.
    NO_SPOOL_SPACE = 62

    # Your file waiting to be printed was deleted.
    PRINT_CANCELLED = 63

    # The specified network name is no longer available.
    NETNAME_DELETED = 64

    # Network access is denied.
    NETWORK_ACCESS_DENIED = 65

    # The network resource type is not correct.
    BAD_DEV_TYPE = 66

    # The network name cannot be found.
    BAD_NET_NAME = 67

    # The name limit for the local computer network adapter card was exceeded.
    TOO_MANY_NAMES = 68

    # The network BIOS session limit was exceeded.
    TOO_MANY_SESS = 69

    # The remote server has been paused or is in the process of being started.
    SHARING_PAUSED = 70

    # No more connections can be made to this remote computer at this time because there are already as many connections as the computer can accept.
    REQ_NOT_ACCEP = 71

    # The specified printer or disk device has been paused.
    REDIR_PAUSED = 72

    # The file exists.
    FILE_EXISTS = 80

    # The directory or file cannot be created.
    CANNOT_MAKE = 82

    # Fail on INT 24.
    FAIL_I24 = 83

    # Storage to process this request is not available.
    OUT_OF_STRUCTURES = 84

    # The local device name is already in use.
    ALREADY_ASSIGNED = 85

    # The specified network password is not correct.
    INVALID_PASSWORD = 86

    # The parameter is incorrect.
    INVALID_PARAMETER = 87

    # A write fault occurred on the network.
    NET_WRITE_FAULT = 88

    # The system cannot start another process at this time.
    NO_PROC_SLOTS = 89

    # Cannot create another system semaphore.
    TOO_MANY_SEMAPHORES = 100

    # The exclusive semaphore is owned by another process.
    EXCL_SEM_ALREADY_OWNED = 101

    # The semaphore is set and cannot be closed.
    SEM_IS_SET = 102

    # The semaphore cannot be set again.
    TOO_MANY_SEM_REQUESTS = 103

    # Cannot request exclusive semaphores at interrupt time.
    INVALID_AT_INTERRUPT_TIME = 104

    # The previous ownership of this semaphore has ended.
    SEM_OWNER_DIED = 105

    # Insert the diskette for drive %1.
    SEM_USER_LIMIT = 106

    # The program stopped because an alternate diskette was not inserted.
    DISK_CHANGE = 107

    # The disk is in use or locked by another process.
    DRIVE_LOCKED = 108

    # The pipe has been ended.
    BROKEN_PIPE = 109

    # The system cannot open the device or file specified.
    OPEN_FAILED = 110

    # The file name is too long.
    BUFFER_OVERFLOW = 111

    # There is not enough space on the disk.
    DISK_FULL = 112

    # No more internal file identifiers available.
    NO_MORE_SEARCH_HANDLES = 113

    # The target internal file identifier is incorrect.
    INVALID_TARGET_HANDLE = 114

    # The IOCTL call made by the application program is not correct.
    INVALID_CATEGORY = 117

    # The verify-on-write switch parameter value is not correct.
    INVALID_VERIFY_SWITCH = 118

    # The system does not support the command requested.
    BAD_DRIVER_LEVEL = 119

    # This function is not supported on this system.
    CALL_NOT_IMPLEMENTED = 120

    # The semaphore timeout period has expired.
    SEM_TIMEOUT = 121

    # The data area passed to a system call is too small.
    INSUFFICIENT_BUFFER = 122

    # The filename, directory name, or volume label syntax is incorrect.
    INVALID_NAME = 123

    # The system call level is not correct.
    INVALID_LEVEL = 124

    # The disk has no volume label.
    NO_VOLUME_LABEL = 125

    # The specified module could not be found.
    MOD_NOT_FOUND = 126

    # The specified procedure could not be found.
    PROC_NOT_FOUND = 127

    # There are no child processes to wait for.
    WAIT_NO_CHILDREN = 128

    # The %1 application cannot be run in Win32 mode.
    CHILD_NOT_COMPLETE = 129

    # Attempt to use a file handle to an open disk partition for an operation other than raw disk I/O.
    DIRECT_ACCESS_HANDLE = 130

    # An attempt was made to move the file pointer before the beginning of the file.
    NEGATIVE_SEEK = 131

    # The file pointer cannot be set on the specified device or file.
    SEEK_ON_DEVICE = 132

    # A JOIN or SUBST command cannot be used for a drive that contains previously joined drives.
    IS_JOIN_TARGET = 133

    # An attempt was made to use a JOIN or SUBST command on a drive that has already been joined.
    IS_JOINED = 134

    # An attempt was made to use a JOIN or SUBST command on a drive that has already been substituted.
    IS_SUBSTED = 135

    # The system tried to delete the JOIN of a drive that is not joined.
    NOT_JOINED = 136

    # The system tried to delete the substitution of a drive that is not substituted.
    NOT_SUBSTED = 137

    # The system tried to join a drive to a directory on a joined drive.
    JOIN_TO_JOIN = 138

    # The system tried to substitute a drive to a directory on a substituted drive.
    SUBST_TO_SUBST = 139

    # The system tried to join a drive to a directory on a substituted drive.
    JOIN_TO_SUBST = 140

    # The system tried to SUBST a drive to a directory on a joined drive.
    SUBST_TO_JOIN = 141

    # The system cannot perform a JOIN or SUBST at this time.
    BUSY_DRIVE = 142

    # The system cannot join or substitute a drive to or for a directory on the same drive.
    SAME_DRIVE = 143

    # The directory is not a subdirectory of the root directory.
    DIR_NOT_ROOT = 144

    # The directory is not empty.
    DIR_NOT_EMPTY = 145

    # The path specified is being used in a substitute.
    IS_SUBST_PATH = 146

    # Not enough resources are available to process this command.
    IS_JOIN_PATH = 147

    # The path specified cannot be used at this time.
    PATH_BUSY = 148

    # An attempt was made to join or substitute a drive for which a directory on the drive is the target of a previous substitute.
    IS_SUBST_TARGET = 149

    # System trace information was not specified in your CONFIG.SYS file, or tracing is disallowed.
    SYSTEM_TRACE = 150

    # The number of specified semaphore events for DosMuxSemWait is not correct.
    INVALID_EVENT_COUNT = 151

    # DosMuxSemWait did not execute, too many semaphores are already set.
    TOO_MANY_MUXWAITERS = 152

    # The DosMuxSemWait list is not correct.
    INVALID_LIST_FORMAT = 153

    # The volume label you entered exceeds the label character limit of the target file system.
    LABEL_TOO_LONG = 154

    # Cannot create another thread.
    TOO_MANY_TCBS = 155

    # The recipient process has refused the signal.
    SIGNAL_REFUSED = 156

    # The segment is already discarded and cannot be locked.
    DISCARDED = 157

    # The segment is already unlocked.
    NOT_LOCKED = 158

    # The address for the thread ID is not correct.
    BAD_THREADID_ADDR = 159

    # One or more arguments are not correct.
    BAD_ARGUMENTS = 160

    # The specified path is invalid.
    BAD_PATHNAME = 161

    # A signal is already pending.
    SIGNAL_PENDING = 162

    # No more threads can be created in the system.
    MAX_THRDS_REACHED = 164

    # Unable to lock a region of a file.
    LOCK_FAILED = 167

    # The requested resource is in use.
    BUSY = 170

    # A lock request was not outstanding for the supplied cancel region.
    CANCEL_VIOLATION = 173

    # The file system does not support atomic changes to the lock type.
    ATOMIC_LOCKS_NOT_SUPPORTED = 174

    # The system detected a segment number that was not correct.
    INVALID_SEGMENT_NUMBER = 180

    # The operating system cannot run %1.
    INVALID_ORDINAL = 182

    # Cannot create a file when that file already exists.
    ALREADY_EXISTS = 183

    # The flag passed is not correct.
    INVALID_FLAG_NUMBER = 186

    # The specified system semaphore name was not found.
    SEM_NOT_FOUND = 187

    # The operating system cannot run %1.
    INVALID_STARTING_CODESEG = 188

    # The operating system cannot run %1.
    INVALID_STACKSEG = 189

    # The operating system cannot run %1.
    INVALID_MODULETYPE = 190

    # Cannot run %1 in Win32 mode.
    INVALID_EXE_SIGNATURE = 191

    # The operating system cannot run %1.
    EXE_MARKED_INVALID = 192

    # %1 is not a valid Win32 application.

    BAD_EXE_FORMAT = 193

    # The operating system cannot run %1.
    ITERATED_DATA_EXCEEDS_64k = 194

    # The operating system cannot run %1.
    INVALID_MINALLOCSIZE = 195

    # The operating system cannot run this application program.
    DYNLINK_FROM_INVALID_RING = 196

    # The operating system is not presently configured to run this application.
    IOPL_NOT_ENABLED = 197

    # The operating system cannot run %1.
    INVALID_SEGDPL = 198

    # The operating system cannot run this application program.
    AUTODATASEG_EXCEEDS_64k = 199

    # The code segment cannot be greater than or equal to 64K.
    RING2SEG_MUST_BE_MOVABLE = 200

    # The operating system cannot run %1.
    RELOC_CHAIN_XEEDS_SEGLIM = 201

    # The operating system cannot run %1.
    INFLOOP_IN_RELOC_CHAIN = 202

    # The system could not find the environment option that was entered.
    ENVVAR_NOT_FOUND = 203

    # No process in the command subtree has a signal handler.
    NO_SIGNAL_SENT = 205

    # The filename or extension is too long.
    FILENAME_EXCED_RANGE = 206

    # The ring 2 stack is in use.
    RING2_STACK_IN_USE = 207

    # The global filename characters, * or ?, are entered incorrectly or too many global filename characters are specified.
    META_EXPANSION_TOO_LONG = 208

    # The signal being posted is not correct.
    INVALID_SIGNAL_NUMBER = 209

    # The signal handler cannot be set.
    THREAD_1_INACTIVE = 210

    # The segment is locked and cannot be reallocated.
    LOCKED = 212

    # Too many dynamic-link modules are attached to this program or dynamic-link module.
    TOO_MANY_MODULES = 214

    # Cannot nest calls to LoadModule.
    NESTING_NOT_ALLOWED = 215

    # The image file %1 is valid, but is for a machine type other than the current machine.
    EXE_MACHINE_TYPE_MISMATCH = 216

    # No information avialable.
    EXE_CANNOT_MODIFY_SIGNED_BINARY = 217

    # No information avialable.
    EXE_CANNOT_MODIFY_STRONG_SIGNED_BINARY = 218

    # The pipe state is invalid.
    BAD_PIPE = 230

    # All pipe instances are busy.
    PIPE_BUSY = 231

    # The pipe is being closed.
    NO_DATA = 232

    # No process is on the other end of the pipe.
    PIPE_NOT_CONNECTED = 233

    # More data is available.
    MORE_DATA = 234

    # The session was canceled.
    VC_DISCONNECTED = 240

    # The specified extended attribute name was invalid.
    INVALID_EA_NAME = 254

    # The extended attributes are inconsistent.
    EA_LIST_INCONSISTENT = 255

    # The wait operation timed out.
    WAIT_TIMEOUT = 258

    # No more data is available.
    NO_MORE_ITEMS = 259

    # The copy functions cannot be used.
    CANNOT_COPY = 266

    # The directory name is invalid.
    DIRECTORY = 267

    # The extended attributes did not fit in the buffer.
    EAS_DIDNT_FIT = 275

    # The extended attribute file on the mounted file system is corrupt.
    EA_FILE_CORRUPT = 276

    # The extended attribute table file is full.
    EA_TABLE_FULL = 277

    # The specified extended attribute handle is invalid.
    INVALID_EA_HANDLE = 278

    # The mounted file system does not support extended attributes.
    EAS_NOT_SUPPORTED = 282

    # Attempt to release mutex not owned by caller.
    NOT_OWNER = 288

    # Too many posts were made to a semaphore.
    TOO_MANY_POSTS = 298

    # Only part of a ReadProcessMemory or WriteProcessMemory request was completed.
    PARTIAL_COPY = 299

    # The oplock request is denied.
    OPLOCK_NOT_GRANTED = 300

    # An invalid oplock acknowledgment was received by the system.
    INVALID_OPLOCK_PROTOCOL = 301

    # The volume is too fragmented to complete this operation.
    DISK_TOO_FRAGMENTED = 302

    # The file cannot be opened because it is in the process of being deleted.
    DELETE_PENDING = 303

    # The system cannot find message text for message number 0x%1 in the message file for %2.
    MR_MID_NOT_FOUND = 317

    # No information avialable.
    SCOPE_NOT_FOUND = 318

    # Attempt to access invalid address.
    INVALID_ADDRESS = 487

    # Arithmetic result exceeded 32 bits.
    ARITHMETIC_OVERFLOW = 534

    # There is a process on other end of the pipe.
    PIPE_CONNECTED = 535

    # Waiting for a process to open the other end of the pipe.
    PIPE_LISTENING = 536

    # Access to the extended attribute was denied.
    EA_ACCESS_DENIED = 994

    # The I/O operation has been aborted because of either a thread exit or an application request.
    OPERATION_ABORTED = 995

    # Overlapped I/O event is not in a signaled state.
    IO_INCOMPLETE = 996

    # Overlapped I/O operation is in progress.
    IO_PENDING = 997

    # Invalid access to memory location.
    NOACCESS = 998

    # Error performing inpage operation.
    SWAPERROR = 999

    # Recursion too deep, the stack overflowed.
    STACK_OVERFLOW = 1001

    # The window cannot act on the sent message.
    INVALID_MESSAGE = 1002

    # Cannot complete this function.
    CAN_NOT_COMPLETE = 1003

    # Invalid flags.
    INVALID_FLAGS = 1004

    # The volume does not contain a recognized file system.
    # Please make sure that all required file system drivers are loaded and that the volume is not corrupted.
    UNRECOGNIZED_VOLUME = 1005

    # The volume for a file has been externally altered so that the opened file is no longer valid.
    FILE_INVALID = 1006

    # The requested operation cannot be performed in full-screen mode.
    FULLSCREEN_MODE = 1007

    # An attempt was made to reference a token that does not exist.
    NO_TOKEN = 1008

    # The configuration registry database is corrupt.
    BADDB = 1009

    # The configuration registry key is invalid.
    BADKEY = 1010

    # The configuration registry key could not be opened.
    CANTOPEN = 1011

    # The configuration registry key could not be read.
    CANTREAD = 1012

    # The configuration registry key could not be written.
    CANTWRITE = 1013

    # One of the files in the registry database had to be recovered by use of a log or alternate copy. The recovery was successful.
    REGISTRY_RECOVERED = 1014

    # The registry is corrupted. The structure of one of the files containing registry data is corrupted, or the system's memory image of the file is corrupted, or the file could not be recovered because the alternate copy or log was absent or corrupted.
    REGISTRY_CORRUPT = 1015

    # An I/O operation initiated by the registry failed unrecoverably. The registry could not read in, or write out, or flush, one of the files that contain the system's image of the registry.
    REGISTRY_IO_FAILED = 1016

    # The system has attempted to load or restore a file into the registry, but the specified file is not in a registry file format.
    NOT_REGISTRY_FILE = 1017

    # Illegal operation attempted on a registry key that has been marked for deletion.
    KEY_DELETED = 1018

    # System could not allocate the required space in a registry log.
    NO_LOG_SPACE = 1019

    # Cannot create a symbolic link in a registry key that already has subkeys or values.
    KEY_HAS_CHILDREN = 1020

    # Cannot create a stable subkey under a volatile parent key.
    CHILD_MUST_BE_VOLATILE = 1021

    # A notify change request is being completed and the information is not being returned in the caller's buffer. The caller now needs to enumerate the files to find the changes.
    NOTIFY_ENUM_DIR = 1022

    # A stop control has been sent to a service that other running services are dependent on.
    DEPENDENT_SERVICES_RUNNING = 1051

    # The requested control is not valid for this service.
    INVALID_SERVICE_CONTROL = 1052

    # The service did not respond to the start or control request in a timely fashion.
    SERVICE_REQUEST_TIMEOUT = 1053

    # A thread could not be created for the service.
    SERVICE_NO_THREAD = 1054

    # The service database is locked.
    SERVICE_DATABASE_LOCKED = 1055

    # An instance of the service is already running.
    SERVICE_ALREADY_RUNNING = 1056

    # The account name is invalid or does not exist, or the password is invalid for the account name specified.
    INVALID_SERVICE_ACCOUNT = 1057

    # The service cannot be started, either because it is disabled or because it has no enabled devices associated with it.
    SERVICE_DISABLED = 1058

    # Circular service dependency was specified.
    CIRCULAR_DEPENDENCY = 1059

    # The specified service does not exist as an installed service.
    SERVICE_DOES_NOT_EXIST = 1060

    # The service cannot accept control messages at this time.
    SERVICE_CANNOT_ACCEPT_CTRL = 1061

    # The service has not been started.
    SERVICE_NOT_ACTIVE = 1062

    # The service process could not connect to the service controller.
    FAILED_SERVICE_CONTROLLER_CONNECT = 1063

    # An exception occurred in the service when handling the control request.
    EXCEPTION_IN_SERVICE = 1064

    # The database specified does not exist.
    DATABASE_DOES_NOT_EXIST = 1065

    # The service has returned a service-specific error code.
    SERVICE_SPECIFIC_ERROR = 1066

    # The process terminated unexpectedly.
    PROCESS_ABORTED = 1067

    # The dependency service or group failed to start.
    SERVICE_DEPENDENCY_FAIL = 1068

    # The service did not start due to a logon failure.
    SERVICE_LOGON_FAILED = 1069

    # After starting, the service hung in a start-pending state.
    SERVICE_START_HANG = 1070

    # The specified service database lock is invalid.
    INVALID_SERVICE_LOCK = 1071

    # The specified service has been marked for deletion.
    SERVICE_MARKED_FOR_DELETE = 1072

    # The specified service already exists.
    SERVICE_EXISTS = 1073

    # The system is currently running with the last-known-good configuration.
    ALREADY_RUNNING_LKG = 1074

    # The dependency service does not exist or has been marked for deletion.
    SERVICE_DEPENDENCY_DELETED = 1075

    # The current boot has already been accepted for use as the last-known-good control set.
    BOOT_ALREADY_ACCEPTED = 1076

    # No attempts to start the service have been made since the last boot.
    SERVICE_NEVER_STARTED = 1077

    # The name is already in use as either a service name or a service display name.
    DUPLICATE_SERVICE_NAME = 1078

    # The account specified for this service is different from the account specified for other services running in the same process.
    DIFFERENT_SERVICE_ACCOUNT = 1079

    # Failure actions can only be set for Win32 services, not for drivers.
    CANNOT_DETECT_DRIVER_FAILURE = 1080

    # This service runs in the same process as the service control manager.
    # Therefore, the service control manager cannot take action if this service's process terminates unexpectedly.
    CANNOT_DETECT_PROCESS_ABORT = 1081

    # No recovery program has been configured for this service.
    NO_RECOVERY_PROGRAM = 1082

    # The executable program that this service is configured to run in does not implement the service.
    SERVICE_NOT_IN_EXE = 1083

    # This service cannot be started in Safe Mode
    NOT_SAFEBOOT_SERVICE = 1084

    # The physical end of the tape has been reached.
    END_OF_MEDIA = 1100

    # A tape access reached a filemark.
    FILEMARK_DETECTED = 1101

    # The beginning of the tape or a partition was encountered.
    BEGINNING_OF_MEDIA = 1102

    # A tape access reached the end of a set of files.
    SETMARK_DETECTED = 1103

    # No more data is on the tape.
    NO_DATA_DETECTED = 1104

    # Tape could not be partitioned.
    PARTITION_FAILURE = 1105

    # When accessing a new tape of a multivolume partition, the current block size is incorrect.
    INVALID_BLOCK_LENGTH = 1106

    # Tape partition information could not be found when loading a tape.
    DEVICE_NOT_PARTITIONED = 1107

    # Unable to lock the media eject mechanism.
    UNABLE_TO_LOCK_MEDIA = 1108

    # Unable to unload the media.
    UNABLE_TO_UNLOAD_MEDIA = 1109

    # The media in the drive may have changed.
    MEDIA_CHANGED = 1110

    # The I/O bus was reset.
    BUS_RESET = 1111

    # No media in drive.
    NO_MEDIA_IN_DRIVE = 1112

    # No mapping for the Unicode character exists in the target multi-byte code page.
    NO_UNICODE_TRANSLATION = 1113

    # A dynamic link library (DLL) initialization routine failed.
    DLL_INIT_FAILED = 1114

    # A system shutdown is in progress.
    SHUTDOWN_IN_PROGRESS = 1115

    # Unable to abort the system shutdown because no shutdown was in progress.
    NO_SHUTDOWN_IN_PROGRESS = 1116

    # The request could not be performed because of an I/O device error.
    IO_DEVICE = 1117

    # No serial device was successfully initialized. The serial driver will unload.
    SERIAL_NO_DEVICE = 1118

    # Unable to open a device that was sharing an interrupt request (IRQ) with other devices. At least one other device that uses that IRQ was already opened.
    IRQ_BUSY = 1119

    # A serial I/O operation was completed by another write to the serial port.
    # (The IOCTL_SERIAL_XOFF_COUNTER reached zero.)
    MORE_WRITES = 1120

    # A serial I/O operation completed because the timeout period expired.
    # (The IOCTL_SERIAL_XOFF_COUNTER did not reach zero.)
    COUNTER_TIMEOUT = 1121

    # No ID address mark was found on the floppy disk.
    FLOPPY_ID_MARK_NOT_FOUND = 1122

    # Mismatch between the floppy disk sector ID field and the floppy disk controller track address.
    FLOPPY_WRONG_CYLINDER = 1123

    # The floppy disk controller reported an error that is not recognized by the floppy disk driver.
    FLOPPY_UNKNOWN_ERROR = 1124

    # The floppy disk controller returned inconsistent results in its registers.
    FLOPPY_BAD_REGISTERS = 1125

    # While accessing the hard disk, a recalibrate operation failed, even after retries.
    DISK_RECALIBRATE_FAILED = 1126

    # While accessing the hard disk, a disk operation failed even after retries.
    DISK_OPERATION_FAILED = 1127

    # While accessing the hard disk, a disk controller reset was needed, but even that failed.
    DISK_RESET_FAILED = 1128

    # Physical end of tape encountered.
    EOM_OVERFLOW = 1129

    # Not enough server storage is available to process this command.
    NOT_ENOUGH_SERVER_MEMORY = 1130

    # A potential deadlock condition has been detected.
    POSSIBLE_DEADLOCK = 1131

    # The base address or the file offset specified does not have the proper alignment.
    MAPPED_ALIGNMENT = 1132

    # An attempt to change the system power state was vetoed by another application or driver.
    SET_POWER_STATE_VETOED = 1140

    # The system BIOS failed an attempt to change the system power state.
    SET_POWER_STATE_FAILED = 1141

    # An attempt was made to create more links on a file than the file system supports.
    TOO_MANY_LINKS = 1142

    # The specified program requires a newer version of Windows.
    OLD_WIN_VERSION = 1150

    # The specified program is not a Windows or MS-DOS program.
    APP_WRONG_OS = 1151

    # Cannot start more than one instance of the specified program.
    SINGLE_INSTANCE_APP = 1152

    # The specified program was written for an earlier version of Windows.
    RMODE_APP = 1153

    # One of the library files needed to run this application is damaged.
    INVALID_DLL = 1154

    # No application is associated with the specified file for this operation.
    NO_ASSOCIATION = 1155

    # An error occurred in sending the command to the application.
    DDE_FAIL = 1156

    # One of the library files needed to run this application cannot be found.
    DLL_NOT_FOUND = 1157

    # The current process has used all of its system allowance of handles for Window Manager objects.
    NO_MORE_USER_HANDLES = 1158

    # The message can be used only with synchronous operations.
    MESSAGE_SYNC_ONLY = 1159

    # The indicated source element has no media.
    SOURCE_ELEMENT_EMPTY = 1160

    # The indicated destination element already contains media.
    DESTINATION_ELEMENT_FULL = 1161

    # The indicated element does not exist.
    ILLEGAL_ELEMENT_ADDRESS = 1162

    # The indicated element is part of a magazine that is not present.
    MAGAZINE_NOT_PRESENT = 1163

    # The indicated device requires reinitialization due to hardware errors.
    DEVICE_REINITIALIZATION_NEEDED = 1164

    # The device has indicated that cleaning is required before further operations are attempted.
    DEVICE_REQUIRES_CLEANING = 1165

    # The device has indicated that its door is open.
    DEVICE_DOOR_OPEN = 1166

    # The device is not connected.
    DEVICE_NOT_CONNECTED = 1167

    # Element not found.
    NOT_FOUND = 1168

    # There was no match for the specified key in the index.
    NO_MATCH = 1169

    # The property set specified does not exist on the object.
    SET_NOT_FOUND = 1170

    # The point passed to GetMouseMovePoints is not in the buffer.
    POINT_NOT_FOUND = 1171

    # The tracking (workstation) service is not running.
    NO_TRACKING_SERVICE = 1172

    # The Volume ID could not be found.
    NO_VOLUME_ID = 1173

    # Unable to remove the file to be replaced.
    UNABLE_TO_REMOVE_REPLACED = 1175

    # Unable to move the replacement file to the file to be replaced. The file to be replaced has retained its original name.
    UNABLE_TO_MOVE_REPLACEMENT = 1176

    # Unable to move the replacement file to the file to be replaced. The file to be replaced has been renamed using the backup name.
    UNABLE_TO_MOVE_REPLACEMENT_2 = 1177

    # The volume change journal is being deleted.
    JOURNAL_DELETE_IN_PROGRESS = 1178

    # The volume change journal is not active.
    JOURNAL_NOT_ACTIVE = 1179

    # A file was found, but it may not be the correct file.
    POTENTIAL_FILE_FOUND = 1180

    # The journal entry has been deleted from the journal.
    JOURNAL_ENTRY_DELETED = 1181

    # The specified device name is invalid.
    BAD_DEVICE = 1200

    # The device is not currently connected but it is a remembered connection.
    CONNECTION_UNAVAIL = 1201

    # The local device name has a remembered connection to another network resource.
    DEVICE_ALREADY_REMEMBERED = 1202

    # No network provider accepted the given network path.
    NO_NET_OR_BAD_PATH = 1203

    # The specified network provider name is invalid.
    BAD_PROVIDER = 1204

    # Unable to open the network connection profile.
    CANNOT_OPEN_PROFILE = 1205

    # The network connection profile is corrupted.
    BAD_PROFILE = 1206

    # Cannot enumerate a noncontainer.
    NOT_CONTAINER = 1207

    # An extended error has occurred.
    EXTENDED_ERROR = 1208

    # The format of the specified group name is invalid.
    INVALID_GROUPNAME = 1209

    # The format of the specified computer name is invalid.
    INVALID_COMPUTERNAME = 1210

    # The format of the specified event name is invalid.
    INVALID_EVENTNAME = 1211

    # The format of the specified domain name is invalid.
    INVALID_DOMAINNAME = 1212

    # The format of the specified service name is invalid.
    INVALID_SERVICENAME = 1213

    # The format of the specified network name is invalid.
    INVALID_NETNAME = 1214

    # The format of the specified share name is invalid.
    INVALID_SHARENAME = 1215

    # The format of the specified password is invalid.
    INVALID_PASSWORDNAME = 1216

    # The format of the specified message name is invalid.
    INVALID_MESSAGENAME = 1217

    # The format of the specified message destination is invalid.
    INVALID_MESSAGEDEST = 1218

    # Multiple connections to a server or shared resource by the same user, using more than one user name, are not allowed. Disconnect all previous connections to the server or shared resource and try again..
    SESSION_CREDENTIAL_CONFLICT = 1219

    # An attempt was made to establish a session to a network server, but there are already too many sessions established to that server.
    REMOTE_SESSION_LIMIT_EXCEEDED = 1220

    # The workgroup or domain name is already in use by another computer on the network.
    DUP_DOMAINNAME = 1221

    # The network is not present or not started.
    NO_NETWORK = 1222

    # The operation was canceled by the user.
    CANCELLED = 1223

    # The requested operation cannot be performed on a file with a user-mapped section open.
    USER_MAPPED_FILE = 1224

    # The remote system refused the network connection.
    CONNECTION_REFUSED = 1225

    # The network connection was gracefully closed.
    GRACEFUL_DISCONNECT = 1226

    # The network transport endpoint already has an address associated with it.
    ADDRESS_ALREADY_ASSOCIATED = 1227

    # An address has not yet been associated with the network endpoint.
    ADDRESS_NOT_ASSOCIATED = 1228

    # An operation was attempted on a nonexistent network connection.
    CONNECTION_INVALID = 1229

    # An invalid operation was attempted on an active network connection.
    CONNECTION_ACTIVE = 1230

    # The network location cannot be reached. For information about network troubleshooting, see Windows Help.
    NETWORK_UNREACHABLE = 1231

    # The network location cannot be reached. For information about network troubleshooting, see Windows Help.
    HOST_UNREACHABLE = 1232

    # The network location cannot be reached. For information about network troubleshooting, see Windows Help.
    PROTOCOL_UNREACHABLE = 1233

    # No service is operating at the destination network endpoint on the remote system.
    PORT_UNREACHABLE = 1234

    # The request was aborted.
    REQUEST_ABORTED = 1235

    # The network connection was aborted by the local system.
    CONNECTION_ABORTED = 1236

    # The operation could not be completed. A retry should be performed.
    RETRY = 1237

    # A connection to the server could not be made because the limit on the number of concurrent connections for this account has been reached.
    CONNECTION_COUNT_LIMIT = 1238

    # Attempting to log in during an unauthorized time of day for this account.
    LOGIN_TIME_RESTRICTION = 1239

    # The account is not authorized to log in from this station.
    LOGIN_WKSTA_RESTRICTION = 1240

    # The network address could not be used for the operation requested.
    INCORRECT_ADDRESS = 1241

    # The service is already registered.
    ALREADY_REGISTERED = 1242

    # The specified service does not exist.
    SERVICE_NOT_FOUND = 1243

    # The operation being requested was not performed because the user has not been authenticated.
    NOT_AUTHENTICATED = 1244

    # The operation being requested was not performed because the user has not logged on to the network.
    # The specified service does not exist.
    NOT_LOGGED_ON = 1245

    # Continue with work in progress.
    CONTINUE = 1246

    # An attempt was made to perform an initialization operation when initialization has already been completed.
    ALREADY_INITIALIZED = 1247

    # No more local devices.
    NO_MORE_DEVICES = 1248

    # The specified site does not exist.
    NO_SUCH_SITE = 1249

    # A domain controller with the specified name already exists.
    DOMAIN_CONTROLLER_EXISTS = 1250

    # This operation is supported only when you are connected to the server.
    ONLY_IF_CONNECTED = 1251

    # The group policy framework should call the extension even if there are no changes.
    OVERRIDE_NOCHANGES = 1252

    # The specified user does not have a valid profile.
    BAD_USER_PROFILE = 1253

    # This operation is not supported on a Microsoft Small Business Server
    NOT_SUPPORTED_ON_SBS = 1254

    # The server machine is shutting down.
    SERVER_SHUTDOWN_IN_PROGRESS = 1255

    # The remote system is not available. For information about network troubleshooting, see Windows Help.
    HOST_DOWN = 1256

    # The security identifier provided is not from an account domain.
    NON_ACCOUNT_SID = 1257

    # The security identifier provided does not have a domain component.
    NON_DOMAIN_SID = 1258

    # AppHelp dialog canceled thus preventing the application from starting.
    APPHELP_BLOCK = 1259

    # Windows cannot open this program because it has been prevented by a software restriction policy. For more information, open Event Viewer or contact your system administrator.
    ACCESS_DISABLED_BY_POLICY = 1260

    # A program attempt to use an invalid register value.  Normally caused by an uninitialized register. This error is Itanium specific.
    REG_NAT_CONSUMPTION = 1261

    # The share is currently offline or does not exist.
    CSCSHARE_OFFLINE = 1262

    # The kerberos protocol encountered an error while validating the
    # KDC certificate during smartcard logon.
    PKINIT_FAILURE = 1263

    # The kerberos protocol encountered an error while attempting to utilize
    # the smartcard subsystem.
    SMARTCARD_SUBSYSTEM_FAILURE = 1264

    # The system detected a possible attempt to compromise security. Please ensure that you can contact the server that authenticated you.
    DOWNGRADE_DETECTED = 1265

    # The machine is locked and can not be shut down without the force option.
    MACHINE_LOCKED = 1271

    # An application-defined callback gave invalid data when called.
    CALLBACK_SUPPLIED_INVALID_DATA = 1273

    # The group policy framework should call the extension in the synchronous foreground policy refresh.
    SYNC_FOREGROUND_REFRESH_REQUIRED = 1274

    # This driver has been blocked from loading
    DRIVER_BLOCKED = 1275

    # A dynamic link library (DLL) referenced a module that was neither a DLL nor the process's executable image.
    INVALID_IMPORT_OF_NON_DLL = 1276

    # No information avialable.
    ACCESS_DISABLED_WEBBLADE = 1277

    # No information avialable.
    ACCESS_DISABLED_WEBBLADE_TAMPER = 1278

    # No information avialable.
    RECOVERY_FAILURE = 1279

    # No information avialable.
    ALREADY_FIBER = 1280

    # No information avialable.
    ALREADY_THREAD = 1281

    # No information avialable.
    STACK_BUFFER_OVERRUN = 1282

    # No information avialable.
    PARAMETER_QUOTA_EXCEEDED = 1283

    # No information avialable.
    DEBUGGER_INACTIVE = 1284

    # No information avialable.
    DELAY_LOAD_FAILED = 1285

    # No information avialable.
    VDM_DISALLOWED = 1286

    # Not all privileges referenced are assigned to the caller.
    NOT_ALL_ASSIGNED = 1300

    # Some mapping between account names and security IDs was not done.
    SOME_NOT_MAPPED = 1301

    # No system quota limits are specifically set for this account.
    NO_QUOTAS_FOR_ACCOUNT = 1302

    # No encryption key is available. A well-known encryption key was returned.
    LOCAL_USER_SESSION_KEY = 1303

    # The password is too complex to be converted to a LAN Manager password. The LAN Manager password returned is a NULL string.
    NULL_LM_PASSWORD = 1304

    # The revision level is unknown.
    UNKNOWN_REVISION = 1305

    # Indicates two revision levels are incompatible.
    REVISION_MISMATCH = 1306

    # This security ID may not be assigned as the owner of this object.
    INVALID_OWNER = 1307

    # This security ID may not be assigned as the primary group of an object.
    INVALID_PRIMARY_GROUP = 1308

    # An attempt has been made to operate on an impersonation token by a thread that is not currently impersonating a client.
    NO_IMPERSONATION_TOKEN = 1309

    # The group may not be disabled.
    CANT_DISABLE_MANDATORY = 1310

    # There are currently no logon servers available to service the logon request.
    NO_LOGON_SERVERS = 1311

    # A specified logon session does not exist. It may already have been terminated.
    NO_SUCH_LOGON_SESSION = 1312

    # A specified privilege does not exist.
    NO_SUCH_PRIVILEGE = 1313

    # A required privilege is not held by the client.
    PRIVILEGE_NOT_HELD = 1314

    # The name provided is not a properly formed account name.
    INVALID_ACCOUNT_NAME = 1315

    # The specified user already exists.
    USER_EXISTS = 1316

    # The specified user does not exist.
    NO_SUCH_USER = 1317

    # The specified group already exists.
    GROUP_EXISTS = 1318

    # The specified group does not exist.
    NO_SUCH_GROUP = 1319

    # Either the specified user account is already a member of the specified group, or the specified group cannot be deleted because it contains a member.
    MEMBER_IN_GROUP = 1320

    # The specified user account is not a member of the specified group account.
    MEMBER_NOT_IN_GROUP = 1321

    # The last remaining administration account cannot be disabled or deleted.
    LAST_ADMIN = 1322

    # Unable to update the password. The value provided as the current password is incorrect.
    WRONG_PASSWORD = 1323

    # Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.
    ILL_FORMED_PASSWORD = 1324

    # Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirement of the domain.
    PASSWORD_RESTRICTION = 1325

    # Logon failure: unknown user name or bad password.
    LOGON_FAILURE = 1326

    # Logon failure: user account restriction.  Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced.
    ACCOUNT_RESTRICTION = 1327

    # Logon failure: account logon time restriction violation.
    INVALID_LOGON_HOURS = 1328

    # Logon failure: user not allowed to log on to this computer.
    INVALID_WORKSTATION = 1329

    # Logon failure: the specified account password has expired.
    PASSWORD_EXPIRED = 1330

    # Logon failure: account currently disabled.
    ACCOUNT_DISABLED = 1331

    # No mapping between account names and security IDs was done.
    NONE_MAPPED = 1332

    # Too many local user identifiers (LUIDs) were requested at one time.
    TOO_MANY_LUIDS_REQUESTED = 1333

    # No more local user identifiers (LUIDs) are available.
    LUIDS_EXHAUSTED = 1334

    # The subauthority part of a security ID is invalid for this particular use.
    INVALID_SUB_AUTHORITY = 1335

    # The access control list (ACL) structure is invalid.
    INVALID_ACL = 1336

    # The security ID structure is invalid.
    INVALID_SID = 1337

    # The security descriptor structure is invalid.
    INVALID_SECURITY_DESCR = 1338

    # The inherited access control list (ACL) or access control entry (ACE) could not be built.
    BAD_INHERITANCE_ACL = 1340

    # The server is currently disabled.
    SERVER_DISABLED = 1341

    # The server is currently enabled.
    SERVER_NOT_DISABLED = 1342

    # The value provided was an invalid value for an identifier authority.
    INVALID_ID_AUTHORITY = 1343

    # No more memory is available for security information updates.
    ALLOTTED_SPACE_EXCEEDED = 1344

    # The specified attributes are invalid, or incompatible with the attributes for the group as a whole.
    INVALID_GROUP_ATTRIBUTES = 1345

    # Either a required impersonation level was not provided, or the provided impersonation level is invalid.
    BAD_IMPERSONATION_LEVEL = 1346

    # Cannot open an anonymous level security token.
    CANT_OPEN_ANONYMOUS = 1347

    # The validation information class requested was invalid.
    BAD_VALIDATION_CLASS = 1348

    # The type of the token is inappropriate for its attempted use.
    BAD_TOKEN_TYPE = 1349

    # Unable to perform a security operation on an object that has no associated security.
    NO_SECURITY_ON_OBJECT = 1350

    # Configuration information could not be read from the domain controller, either because the machine is unavailable, or access has been denied.
    CANT_ACCESS_DOMAIN_INFO = 1351

    # The security account manager (SAM) or local security authority (LSA) server was in the wrong state to perform the security operation.
    INVALID_SERVER_STATE = 1352

    # The domain was in the wrong state to perform the security operation.
    INVALID_DOMAIN_STATE = 1353

    # This operation is only allowed for the Primary Domain Controller of the domain.
    INVALID_DOMAIN_ROLE = 1354

    # The specified domain either does not exist or could not be contacted.
    NO_SUCH_DOMAIN = 1355

    # The specified domain already exists.
    DOMAIN_EXISTS = 1356

    # An attempt was made to exceed the limit on the number of domains per server.
    DOMAIN_LIMIT_EXCEEDED = 1357

    # Unable to complete the requested operation because of either a catastrophic media failure or a data structure corruption on the disk.
    INTERNAL_DB_CORRUPTION = 1358

    # An internal error occurred.
    INTERNAL_ERROR = 1359

    # Generic access types were contained in an access mask which should already be mapped to nongeneric types.
    GENERIC_NOT_MAPPED = 1360

    # A security descriptor is not in the right format (absolute or self-relative).
    BAD_DESCRIPTOR_FORMAT = 1361

    # The requested action is restricted for use by logon processes only. The calling process has not registered as a logon process.
    NOT_LOGON_PROCESS = 1362

    # Cannot start a new logon session with an ID that is already in use.
    LOGON_SESSION_EXISTS = 1363

    # A specified authentication package is unknown.
    NO_SUCH_PACKAGE = 1364

    # The logon session is not in a state that is consistent with the requested operation.
    BAD_LOGON_SESSION_STATE = 1365

    # The logon session ID is already in use.
    LOGON_SESSION_COLLISION = 1366

    # A logon request contained an invalid logon type value.
    INVALID_LOGON_TYPE = 1367

    # Unable to impersonate using a named pipe until data has been read from that pipe.
    CANNOT_IMPERSONATE = 1368

    # The transaction state of a registry subtree is incompatible with the requested operation.
    RXACT_INVALID_STATE = 1369

    # An internal security database corruption has been encountered.
    RXACT_COMMIT_FAILURE = 1370

    # Cannot perform this operation on built-in accounts.
    SPECIAL_ACCOUNT = 1371

    # Cannot perform this operation on this built-in special group.
    SPECIAL_GROUP = 1372

    # Cannot perform this operation on this built-in special user.
    SPECIAL_USER = 1373

    # The user cannot be removed from a group because the group is currently the user's primary group.
    MEMBERS_PRIMARY_GROUP = 1374

    # The token is already in use as a primary token.
    TOKEN_ALREADY_IN_USE = 1375

    # The specified local group does not exist.
    NO_SUCH_ALIAS = 1376

    # The specified account name is not a member of the local group.
    MEMBER_NOT_IN_ALIAS = 1377

    # The specified account name is already a member of the local group.
    MEMBER_IN_ALIAS = 1378

    # The specified local group already exists.
    ALIAS_EXISTS = 1379

    # Logon failure: the user has not been granted the requested logon type at this computer.
    LOGON_NOT_GRANTED = 1380

    # The maximum number of secrets that may be stored in a single system has been exceeded.
    TOO_MANY_SECRETS = 1381

    # The length of a secret exceeds the maximum length allowed.
    SECRET_TOO_LONG = 1382

    # The local security authority database contains an internal inconsistency.
    INTERNAL_DB_ERROR = 1383

    # During a logon attempt, the user's security context accumulated too many security IDs.
    TOO_MANY_CONTEXT_IDS = 1384

    # Logon failure: the user has not been granted the requested logon type at this computer.
    LOGON_TYPE_NOT_GRANTED = 1385

    # A cross-encrypted password is necessary to change a user password.
    NT_CROSS_ENCRYPTION_REQUIRED = 1386

    # A member could not be added to or removed from the local group because the member does not exist.
    NO_SUCH_MEMBER = 1387

    # A new member could not be added to a local group because the member has the wrong account type.
    INVALID_MEMBER = 1388

    # Too many security IDs have been specified.
    TOO_MANY_SIDS = 1389

    # A cross-encrypted password is necessary to change this user password.
    LM_CROSS_ENCRYPTION_REQUIRED = 1390

    # Indicates an ACL contains no inheritable components.
    NO_INHERITANCE = 1391

    # The file or directory is corrupted and unreadable.
    FILE_CORRUPT = 1392

    # The disk structure is corrupted and unreadable.
    DISK_CORRUPT = 1393

    # There is no user session key for the specified logon session.
    NO_USER_SESSION_KEY = 1394

    # The service being accessed is licensed for a particular number of connections.
    # No more connections can be made to the service at this time because there are already as many connections as the service can accept.
    LICENSE_QUOTA_EXCEEDED = 1395

    # Logon Failure: The target account name is incorrect.
    WRONG_TARGET_NAME = 1396

    # Mutual Authentication failed. The server's password is out of date at the domain controller.
    MUTUAL_AUTH_FAILED = 1397

    # There is a time and/or date difference between the client and server.
    TIME_SKEW = 1398

    # This operation can not be performed on the current domain.
    CURRENT_DOMAIN_NOT_ALLOWED = 1399

    # Invalid window handle.
    INVALID_WINDOW_HANDLE = 1400

    # Invalid menu handle.
    INVALID_MENU_HANDLE = 1401

    # Invalid cursor handle.
    INVALID_CURSOR_HANDLE = 1402

    # Invalid accelerator table handle.
    INVALID_ACCEL_HANDLE = 1403

    # Invalid hook handle.
    INVALID_HOOK_HANDLE = 1404

    # Invalid handle to a multiple-window position structure.
    INVALID_DWP_HANDLE = 1405

    # Cannot create a top-level child window.
    TLW_WITH_WSCHILD = 1406

    # Cannot find window class.
    CANNOT_FIND_WND_CLASS = 1407

    # Invalid window, it belongs to other thread.
    WINDOW_OF_OTHER_THREAD = 1408

    # Hot key is already registered.
    HOTKEY_ALREADY_REGISTERED = 1409

    # Class already exists.
    CLASS_ALREADY_EXISTS = 1410

    # Class does not exist.
    CLASS_DOES_NOT_EXIST = 1411

    # Class still has open windows.
    CLASS_HAS_WINDOWS = 1412

    # Invalid index.
    INVALID_INDEX = 1413

    # Invalid icon handle.
    INVALID_ICON_HANDLE = 1414

    # Using private DIALOG window words.
    PRIVATE_DIALOG_INDEX = 1415

    # The list box identifier was not found.
    LISTBOX_ID_NOT_FOUND = 1416

    # No wildcards were found.
    NO_WILDCARD_CHARACTERS = 1417

    # Thread does not have a clipboard open.
    CLIPBOARD_NOT_OPEN = 1418

    # Hot key is not registered.
    HOTKEY_NOT_REGISTERED = 1419

    # The window is not a valid dialog window.
    WINDOW_NOT_DIALOG = 1420

    # Control ID not found.
    CONTROL_ID_NOT_FOUND = 1421

    # Invalid message for a combo box because it does not have an edit control.
    INVALID_COMBOBOX_MESSAGE = 1422

    # The window is not a combo box.
    WINDOW_NOT_COMBOBOX = 1423

    # Height must be less than 256.
    INVALID_EDIT_HEIGHT = 1424

    # Invalid device context (DC) handle.
    DC_NOT_FOUND = 1425

    # Invalid hook procedure type.
    INVALID_HOOK_FILTER = 1426

    # Invalid hook procedure.
    INVALID_FILTER_PROC = 1427

    # Cannot set nonlocal hook without a module handle.
    HOOK_NEEDS_HMOD = 1428

    # This hook procedure can only be set globally.
    GLOBAL_ONLY_HOOK = 1429

    # The journal hook procedure is already installed.
    JOURNAL_HOOK_SET = 1430

    # The hook procedure is not installed.
    HOOK_NOT_INSTALLED = 1431

    # Invalid message for single-selection list box.
    INVALID_LB_MESSAGE = 1432

    # LB_SETCOUNT sent to non-lazy list box.
    SETCOUNT_ON_BAD_LB = 1433

    # This list box does not support tab stops.
    LB_WITHOUT_TABSTOPS = 1434

    # Cannot destroy object created by another thread.
    DESTROY_OBJECT_OF_OTHER_THREAD = 1435

    # Child windows cannot have menus.
    CHILD_WINDOW_MENU = 1436

    # The window does not have a system menu.
    NO_SYSTEM_MENU = 1437

    # Invalid message box style.
    INVALID_MSGBOX_STYLE = 1438

    # Invalid system-wide (SPI_*) parameter.
    INVALID_SPI_VALUE = 1439

    # Screen already locked.
    SCREEN_ALREADY_LOCKED = 1440

    # All handles to windows in a multiple-window position structure must have the same parent.
    HWNDS_HAVE_DIFF_PARENT = 1441

    # The window is not a child window.
    NOT_CHILD_WINDOW = 1442

    # Invalid GW_* command.
    INVALID_GW_COMMAND = 1443

    # Invalid thread identifier.
    INVALID_THREAD_ID = 1444

    # Cannot process a message from a window that is not a multiple document interface (MDI) window.
    NON_MDICHILD_WINDOW = 1445

    # Popup menu already active.
    POPUP_ALREADY_ACTIVE = 1446

    # The window does not have scroll bars.
    NO_SCROLLBARS = 1447

    # Scroll bar range cannot be greater than MAXLONG.
    INVALID_SCROLLBAR_RANGE = 1448

    # Cannot show or remove the window in the way specified.
    INVALID_SHOWWIN_COMMAND = 1449

    # Insufficient system resources exist to complete the requested service.
    NO_SYSTEM_RESOURCES = 1450

    # Insufficient system resources exist to complete the requested service.
    NONPAGED_SYSTEM_RESOURCES = 1451

    # Insufficient system resources exist to complete the requested service.
    PAGED_SYSTEM_RESOURCES = 1452

    # Insufficient quota to complete the requested service.
    WORKING_SET_QUOTA = 1453

    # Insufficient quota to complete the requested service.
    PAGEFILE_QUOTA = 1454

    # The paging file is too small for this operation to complete.
    COMMITMENT_LIMIT = 1455

    # A menu item was not found.
    MENU_ITEM_NOT_FOUND = 1456

    # Invalid keyboard layout handle.
    INVALID_KEYBOARD_HANDLE = 1457

    # Hook type not allowed.
    HOOK_TYPE_NOT_ALLOWED = 1458

    # This operation requires an interactive window station.
    REQUIRES_INTERACTIVE_WINDOWSTATION = 1459

    # This operation returned because the timeout period expired.
    TIMEOUT = 1460

    # Invalid monitor handle.
    INVALID_MONITOR_HANDLE = 1461

    # The event log file is corrupted.
    EVENTLOG_FILE_CORRUPT = 1500

    # No event log file could be opened, so the event logging service did not start.
    EVENTLOG_CANT_START = 1501

    # The event log file is full.
    LOG_FILE_FULL = 1502

    # The event log file has changed between read operations.
    EVENTLOG_FILE_CHANGED = 1503

    # The Windows Installer Service could not be accessed. This can occur if you are running Windows in safe mode, or if the Windows Installer is not correctly installed. Contact your support personnel for assistance.
    INSTALL_SERVICE_FAILURE = 1601

    # User cancelled installation.
    INSTALL_USEREXIT = 1602

    # Fatal error during installation.
    INSTALL_FAILURE = 1603

    # Installation suspended, incomplete.
    INSTALL_SUSPEND = 1604

    # This action is only valid for products that are currently installed.
    UNKNOWN_PRODUCT = 1605

    # Feature ID not registered.
    UNKNOWN_FEATURE = 1606

    # Component ID not registered.
    UNKNOWN_COMPONENT = 1607

    # Unknown property.
    UNKNOWN_PROPERTY = 1608

    # Handle is in an invalid state.
    INVALID_HANDLE_STATE = 1609

    # The configuration data for this product is corrupt.  Contact your support personnel.
    BAD_CONFIGURATION = 1610

    # Component qualifier not present.
    INDEX_ABSENT = 1611

    # The installation source for this product is not available.  Verify that the source exists and that you can access it.
    INSTALL_SOURCE_ABSENT = 1612

    # This installation package cannot be installed by the Windows Installer service.  You must install a Windows service pack that contains a newer version of the Windows Installer service.
    INSTALL_PACKAGE_VERSION = 1613

    # Product is uninstalled.
    PRODUCT_UNINSTALLED = 1614

    # SQL query syntax invalid or unsupported.
    BAD_QUERY_SYNTAX = 1615

    # Record field does not exist.
    INVALID_FIELD = 1616

    # The device has been removed.
    DEVICE_REMOVED = 1617

    # Another installation is already in progress.  Complete that installation before proceeding with this install.
    INSTALL_ALREADY_RUNNING = 1618

    # This installation package could not be opened.  Verify that the package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer package.
    INSTALL_PACKAGE_OPEN_FAILED = 1619

    # This installation package could not be opened.  Contact the application vendor to verify that this is a valid Windows Installer package.
    INSTALL_PACKAGE_INVALID = 1620

    # There was an error starting the Windows Installer service user interface.  Contact your support personnel.
    INSTALL_UI_FAILURE = 1621

    # Error opening installation log file. Verify that the specified log file location exists and that you can write to it.
    INSTALL_LOG_FAILURE = 1622

    # The language of this installation package is not supported by your system.
    INSTALL_LANGUAGE_UNSUPPORTED = 1623

    # Error applying transforms.  Verify that the specified transform paths are valid.
    INSTALL_TRANSFORM_FAILURE = 1624

    # This installation is forbidden by system policy.  Contact your system administrator.
    INSTALL_PACKAGE_REJECTED = 1625

    # Function could not be executed.
    FUNCTION_NOT_CALLED = 1626

    # Function failed during execution.
    FUNCTION_FAILED = 1627

    # Invalid or unknown table specified.
    INVALID_TABLE = 1628

    # Data supplied is of wrong type.
    DATATYPE_MISMATCH = 1629

    # Data of this type is not supported.
    UNSUPPORTED_TYPE = 1630

    # The Windows Installer service failed to start.  Contact your support personnel.
    CREATE_FAILED = 1631

    # The Temp folder is on a drive that is full or is inaccessible. Free up space on the drive or verify that you have write permission on the Temp folder.
    INSTALL_TEMP_UNWRITABLE = 1632

    # This installation package is not supported by this processor type. Contact your product vendor.
    INSTALL_PLATFORM_UNSUPPORTED = 1633

    # Component not used on this computer.
    INSTALL_NOTUSED = 1634

    # This patch package could not be opened.  Verify that the patch package exists and that you can access it, or contact the application vendor to verify that this is a valid Windows Installer patch package.
    PATCH_PACKAGE_OPEN_FAILED = 1635

    # This patch package could not be opened.  Contact the application vendor to verify that this is a valid Windows Installer patch package.
    PATCH_PACKAGE_INVALID = 1636

    # This patch package cannot be processed by the Windows Installer service.  You must install a Windows service pack that contains a newer version of the Windows Installer service.
    PATCH_PACKAGE_UNSUPPORTED = 1637

    # Another version of this product is already installed.  Installation of this version cannot continue.  To configure or remove the existing version of this product, use Add/Remove Programs on the Control Panel.
    PRODUCT_VERSION = 1638

    # Invalid command line argument.  Consult the Windows Installer SDK for detailed command line help.
    INVALID_COMMAND_LINE = 1639

    # Only administrators have permission to add, remove, or configure server software during a Terminal services remote session. If you want to install or configure software on the server, contact your network administrator.
    INSTALL_REMOTE_DISALLOWED = 1640

    # The requested operation completed successfully.  The system will be restarted so the changes can take effect.
    SUCCESS_REBOOT_INITIATED = 1641

    # The upgrade patch cannot be installed by the Windows Installer service because the program to be upgraded may be missing, or the upgrade patch may update a different version of the program. Verify that the program to be upgraded exists on your computer an
    # d that you have the correct upgrade patch.
    PATCH_TARGET_NOT_FOUND = 1642

    # The patch package is not permitted by software restriction policy.
    PATCH_PACKAGE_REJECTED = 1643

    # One or more customizations are not permitted by software restriction policy.
    INSTALL_TRANSFORM_REJECTED = 1644

    # No information avialable.
    INSTALL_REMOTE_PROHIBITED = 1645

    # The string binding is invalid.
    RPC_S_INVALID_STRING_BINDING = 1700

    # The binding handle is not the correct type.
    RPC_S_WRONG_KIND_OF_BINDING = 1701

    # The binding handle is invalid.
    RPC_S_INVALID_BINDING = 1702

    # The RPC protocol sequence is not supported.
    RPC_S_PROTSEQ_NOT_SUPPORTED = 1703

    # The RPC protocol sequence is invalid.
    RPC_S_INVALID_RPC_PROTSEQ = 1704

    # The string universal unique identifier (UUID) is invalid.
    RPC_S_INVALID_STRING_UUID = 1705

    # The endpoint format is invalid.
    RPC_S_INVALID_ENDPOINT_FORMAT = 1706

    # The network address is invalid.
    RPC_S_INVALID_NET_ADDR = 1707

    # No endpoint was found.
    RPC_S_NO_ENDPOINT_FOUND = 1708

    # The timeout value is invalid.
    RPC_S_INVALID_TIMEOUT = 1709

    # The object universal unique identifier (UUID) was not found.
    RPC_S_OBJECT_NOT_FOUND = 1710

    # The object universal unique identifier (UUID) has already been registered.
    RPC_S_ALREADY_REGISTERED = 1711

    # The type universal unique identifier (UUID) has already been registered.
    RPC_S_TYPE_ALREADY_REGISTERED = 1712

    # The RPC server is already listening.
    RPC_S_ALREADY_LISTENING = 1713

    # No protocol sequences have been registered.
    RPC_S_NO_PROTSEQS_REGISTERED = 1714

    # The RPC server is not listening.
    RPC_S_NOT_LISTENING = 1715

    # The manager type is unknown.
    RPC_S_UNKNOWN_MGR_TYPE = 1716

    # The interface is unknown.
    RPC_S_UNKNOWN_IF = 1717

    # There are no bindings.
    RPC_S_NO_BINDINGS = 1718

    # There are no protocol sequences.
    RPC_S_NO_PROTSEQS = 1719

    # The endpoint cannot be created.
    RPC_S_CANT_CREATE_ENDPOINT = 1720

    # Not enough resources are available to complete this operation.
    RPC_S_OUT_OF_RESOURCES = 1721

    # The RPC server is unavailable.
    RPC_S_SERVER_UNAVAILABLE = 1722

    # The RPC server is too busy to complete this operation.
    RPC_S_SERVER_TOO_BUSY = 1723

    # The network options are invalid.
    RPC_S_INVALID_NETWORK_OPTIONS = 1724

    # There are no remote procedure calls active on this thread.
    RPC_S_NO_CALL_ACTIVE = 1725

    # The remote procedure call failed.
    RPC_S_CALL_FAILED = 1726

    # The remote procedure call failed and did not execute.
    RPC_S_CALL_FAILED_DNE = 1727

    # A remote procedure call (RPC) protocol error occurred.
    RPC_S_PROTOCOL_ERROR = 1728

    # The transfer syntax is not supported by the RPC server.
    RPC_S_UNSUPPORTED_TRANS_SYN = 1730

    # The universal unique identifier (UUID) type is not supported.
    RPC_S_UNSUPPORTED_TYPE = 1732

    # The tag is invalid.
    RPC_S_INVALID_TAG = 1733

    # The array bounds are invalid.
    RPC_S_INVALID_BOUND = 1734

    # The binding does not contain an entry name.
    RPC_S_NO_ENTRY_NAME = 1735

    # The name syntax is invalid.
    RPC_S_INVALID_NAME_SYNTAX = 1736

    # The name syntax is not supported.
    RPC_S_UNSUPPORTED_NAME_SYNTAX = 1737

    # No network address is available to use to construct a universal unique identifier (UUID).
    RPC_S_UUID_NO_ADDRESS = 1739

    # The endpoint is a duplicate.
    RPC_S_DUPLICATE_ENDPOINT = 1740

    # The authentication type is unknown.
    RPC_S_UNKNOWN_AUTHN_TYPE = 1741

    # The maximum number of calls is too small.
    RPC_S_MAX_CALLS_TOO_SMALL = 1742

    # The string is too long.
    RPC_S_STRING_TOO_LONG = 1743

    # The RPC protocol sequence was not found.
    RPC_S_PROTSEQ_NOT_FOUND = 1744

    # The procedure number is out of range.
    RPC_S_PROCNUM_OUT_OF_RANGE = 1745

    # The binding does not contain any authentication information.
    RPC_S_BINDING_HAS_NO_AUTH = 1746

    # The authentication service is unknown.
    RPC_S_UNKNOWN_AUTHN_SERVICE = 1747

    # The authentication level is unknown.
    RPC_S_UNKNOWN_AUTHN_LEVEL = 1748

    # The security context is invalid.
    RPC_S_INVALID_AUTH_IDENTITY = 1749

    # The authorization service is unknown.
    RPC_S_UNKNOWN_AUTHZ_SERVICE = 1750

    # The entry is invalid.
    EPT_S_INVALID_ENTRY = 1751

    # The server endpoint cannot perform the operation.
    EPT_S_CANT_PERFORM_OP = 1752

    # There are no more endpoints available from the endpoint mapper.
    EPT_S_NOT_REGISTERED = 1753

    # No interfaces have been exported.
    RPC_S_NOTHING_TO_EXPORT = 1754

    # The entry name is incomplete.
    RPC_S_INCOMPLETE_NAME = 1755

    # The version option is invalid.
    RPC_S_INVALID_VERS_OPTION = 1756

    # There are no more members.
    RPC_S_NO_MORE_MEMBERS = 1757

    # There is nothing to unexport.
    RPC_S_NOT_ALL_OBJS_UNEXPORTED = 1758

    # The interface was not found.
    RPC_S_INTERFACE_NOT_FOUND = 1759

    # The entry already exists.
    RPC_S_ENTRY_ALREADY_EXISTS = 1760

    # The entry is not found.
    RPC_S_ENTRY_NOT_FOUND = 1761

    # The name service is unavailable.
    RPC_S_NAME_SERVICE_UNAVAILABLE = 1762

    # The network address family is invalid.
    RPC_S_INVALID_NAF_ID = 1763

    # The requested operation is not supported.
    RPC_S_CANNOT_SUPPORT = 1764

    # No security context is available to allow impersonation.
    RPC_S_NO_CONTEXT_AVAILABLE = 1765

    # An internal error occurred in a remote procedure call (RPC).
    RPC_S_INTERNAL_ERROR = 1766

    # The RPC server attempted an integer division by zero.
    RPC_S_ZERO_DIVIDE = 1767

    # An addressing error occurred in the RPC server.
    RPC_S_ADDRESS_ERROR = 1768

    # A floating-point operation at the RPC server caused a division by zero.
    RPC_S_FP_DIV_ZERO = 1769

    # A floating-point underflow occurred at the RPC server.
    RPC_S_FP_UNDERFLOW = 1770

    # A floating-point overflow occurred at the RPC server.
    RPC_S_FP_OVERFLOW = 1771

    # The list of RPC servers available for the binding of auto handles has been exhausted.
    RPC_X_NO_MORE_ENTRIES = 1772

    # Unable to open the character translation table file.
    RPC_X_SS_CHAR_TRANS_OPEN_FAIL = 1773

    # The file containing the character translation table has fewer than 512 bytes.
    RPC_X_SS_CHAR_TRANS_LONG_FILE = 1774

    # A null context handle was passed from the client to the host during a remote procedure call.
    RPC_X_SS_IN_NULL_CONTEXT = 1775

    # The context handle changed during a remote procedure call.
    RPC_X_SS_CONTEXT_DAMAGED = 1777

    # The binding handles passed to a remote procedure call do not match.
    RPC_X_SS_HANDLES_MISMATCH = 1778

    # The stub is unable to get the remote procedure call handle.
    RPC_X_SS_CANNOT_GET_CALL_HANDLE = 1779

    # A null reference pointer was passed to the stub.
    RPC_X_NULL_REF_POINTER = 1780

    # The enumeration value is out of range.
    RPC_X_ENUM_VALUE_OUT_OF_RANGE = 1781

    # The byte count is too small.
    RPC_X_BYTE_COUNT_TOO_SMALL = 1782

    # The stub received bad data.
    RPC_X_BAD_STUB_DATA = 1783

    # The supplied user buffer is not valid for the requested operation.
    INVALID_USER_BUFFER = 1784

    # The disk media is not recognized. It may not be formatted.
    UNRECOGNIZED_MEDIA = 1785

    # The workstation does not have a trust secret.
    NO_TRUST_LSA_SECRET = 1786

    # The security database on the server does not have a computer account for this workstation trust relationship.
    NO_TRUST_SAM_ACCOUNT = 1787

    # The trust relationship between the primary domain and the trusted domain failed.
    TRUSTED_DOMAIN_FAILURE = 1788

    # The trust relationship between this workstation and the primary domain failed.
    TRUSTED_RELATIONSHIP_FAILURE = 1789

    # The network logon failed.
    TRUST_FAILURE = 1790

    # A remote procedure call is already in progress for this thread.
    RPC_S_CALL_IN_PROGRESS = 1791

    # An attempt was made to logon, but the network logon service was not started.
    NETLOGON_NOT_STARTED = 1792

    # The user's account has expired.
    ACCOUNT_EXPIRED = 1793

    # The redirector is in use and cannot be unloaded.
    REDIRECTOR_HAS_OPEN_HANDLES = 1794

    # The specified printer driver is already installed.
    PRINTER_DRIVER_ALREADY_INSTALLED = 1795

    # The specified port is unknown.
    UNKNOWN_PORT = 1796

    # The printer driver is unknown.
    UNKNOWN_PRINTER_DRIVER = 1797

    # The print processor is unknown.
    UNKNOWN_PRINTPROCESSOR = 1798

    # The specified separator file is invalid.
    INVALID_SEPARATOR_FILE = 1799

    # The specified priority is invalid.
    INVALID_PRIORITY = 1800

    # The printer name is invalid.
    INVALID_PRINTER_NAME = 1801

    # The printer already exists.
    PRINTER_ALREADY_EXISTS = 1802

    # The printer command is invalid.
    INVALID_PRINTER_COMMAND = 1803

    # The specified datatype is invalid.
    INVALID_DATATYPE = 1804

    # The environment specified is invalid.
    INVALID_ENVIRONMENT = 1805

    # There are no more bindings.
    RPC_S_NO_MORE_BINDINGS = 1806

    # The account used is an interdomain trust account. Use your global user account or local user account to access this server.
    NOLOGON_INTERDOMAIN_TRUST_ACCOUNT = 1807

    # The account used is a computer account. Use your global user account or local user account to access this server.
    NOLOGON_WORKSTATION_TRUST_ACCOUNT = 1808

    # The account used is a server trust account. Use your global user account or local user account to access this server.
    NOLOGON_SERVER_TRUST_ACCOUNT = 1809

    # The name or security ID (SID) of the domain specified is inconsistent with the trust information for that domain.
    DOMAIN_TRUST_INCONSISTENT = 1810

    # The server is in use and cannot be unloaded.
    SERVER_HAS_OPEN_HANDLES = 1811

    # The specified image file did not contain a resource section.
    RESOURCE_DATA_NOT_FOUND = 1812

    # The specified resource type cannot be found in the image file.
    RESOURCE_TYPE_NOT_FOUND = 1813

    # The specified resource name cannot be found in the image file.
    RESOURCE_NAME_NOT_FOUND = 1814

    # The specified resource language ID cannot be found in the image file.
    RESOURCE_LANG_NOT_FOUND = 1815

    # Not enough quota is available to process this command.
    NOT_ENOUGH_QUOTA = 1816

    # No interfaces have been registered.
    RPC_S_NO_INTERFACES = 1817

    # The remote procedure call was cancelled.
    RPC_S_CALL_CANCELLED = 1818

    # The binding handle does not contain all required information.
    RPC_S_BINDING_INCOMPLETE = 1819

    # A communications failure occurred during a remote procedure call.
    RPC_S_COMM_FAILURE = 1820

    # The requested authentication level is not supported.
    RPC_S_UNSUPPORTED_AUTHN_LEVEL = 1821

    # No principal name registered.
    RPC_S_NO_PRINC_NAME = 1822

    # The error specified is not a valid Windows RPC error code.
    RPC_S_NOT_RPC_ERROR = 1823

    # A UUID that is valid only on this computer has been allocated.
    RPC_S_UUID_LOCAL_ONLY = 1824

    # A security package specific error occurred.
    RPC_S_SEC_PKG_ERROR = 1825

    # Thread is not canceled.
    RPC_S_NOT_CANCELLED = 1826

    # Invalid operation on the encoding/decoding handle.
    RPC_X_INVALID_ES_ACTION = 1827

    # Incompatible version of the serializing package.
    RPC_X_WRONG_ES_VERSION = 1828

    # Incompatible version of the RPC stub.
    RPC_X_WRONG_STUB_VERSION = 1829

    # The RPC pipe object is invalid or corrupted.
    RPC_X_INVALID_PIPE_OBJECT = 1830

    # An invalid operation was attempted on an RPC pipe object.
    RPC_X_WRONG_PIPE_ORDER = 1831

    # Unsupported RPC pipe version.
    RPC_X_WRONG_PIPE_VERSION = 1832

    # The group member was not found.
    RPC_S_GROUP_MEMBER_NOT_FOUND = 1898

    # The endpoint mapper database entry could not be created.
    EPT_S_CANT_CREATE = 1899

    # The object universal unique identifier (UUID) is the nil UUID.
    RPC_S_INVALID_OBJECT = 1900

    # The specified time is invalid.
    INVALID_TIME = 1901

    # The specified form name is invalid.
    INVALID_FORM_NAME = 1902

    # The specified form size is invalid.
    INVALID_FORM_SIZE = 1903

    # The specified printer handle is already being waited on
    ALREADY_WAITING = 1904

    # The specified printer has been deleted.
    PRINTER_DELETED = 1905

    # The state of the printer is invalid.
    INVALID_PRINTER_STATE = 1906

    # The user's password must be changed before logging on the first time.
    PASSWORD_MUST_CHANGE = 1907

    # Could not find the domain controller for this domain.
    DOMAIN_CONTROLLER_NOT_FOUND = 1908

    # The referenced account is currently locked out and may not be logged on to.
    ACCOUNT_LOCKED_OUT = 1909

    # The object exporter specified was not found.
    OR_INVALID_OXID = 1910

    # The object specified was not found.
    OR_INVALID_OID = 1911

    # The object resolver set specified was not found.
    OR_INVALID_SET = 1912

    # Some data remains to be sent in the request buffer.
    RPC_S_SEND_INCOMPLETE = 1913

    # Invalid asynchronous remote procedure call handle.
    RPC_S_INVALID_ASYNC_HANDLE = 1914

    # Invalid asynchronous RPC call handle for this operation.
    RPC_S_INVALID_ASYNC_CALL = 1915

    # The RPC pipe object has already been closed.
    RPC_X_PIPE_CLOSED = 1916

    # The RPC call completed before all pipes were processed.
    RPC_X_PIPE_DISCIPLINE_ERROR = 1917

    # No more data is available from the RPC pipe.
    RPC_X_PIPE_EMPTY = 1918

    # No site name is available for this machine.
    NO_SITENAME = 1919

    # The file can not be accessed by the system.
    CANT_ACCESS_FILE = 1920

    # The name of the file cannot be resolved by the system.
    CANT_RESOLVE_FILENAME = 1921

    # The entry is not of the expected type.
    RPC_S_ENTRY_TYPE_MISMATCH = 1922

    # Not all object UUIDs could be exported to the specified entry.
    RPC_S_NOT_ALL_OBJS_EXPORTED = 1923

    # Interface could not be exported to the specified entry.
    RPC_S_INTERFACE_NOT_EXPORTED = 1924

    # The specified profile entry could not be added.
    RPC_S_PROFILE_NOT_ADDED = 1925

    # The specified profile element could not be added.
    RPC_S_PRF_ELT_NOT_ADDED = 1926

    # The specified profile element could not be removed.
    RPC_S_PRF_ELT_NOT_REMOVED = 1927

    # The group element could not be added.
    RPC_S_GRP_ELT_NOT_ADDED = 1928

    # The group element could not be removed.
    RPC_S_GRP_ELT_NOT_REMOVED = 1929

    # The printer driver is not compatible with a policy enabled on your computer that blocks NT 4.0 drivers.
    KM_DRIVER_BLOCKED = 1930

    # The context has expired and can no longer be used.
    CONTEXT_EXPIRED = 1931

    # No information avialable.
    PER_USER_TRUST_QUOTA_EXCEEDED = 1932

    # No information avialable.
    ALL_USER_TRUST_QUOTA_EXCEEDED = 1933

    # No information avialable.
    USER_DELETE_TRUST_QUOTA_EXCEEDED = 1934

    # No information avialable.
    AUTHENTICATION_FIREWALL_FAILED = 1935

    # No information avialable.
    REMOTE_PRINT_CONNECTIONS_BLOCKED = 1936

    # The pixel format is invalid.
    INVALID_PIXEL_FORMAT = 2000

    # The specified driver is invalid.
    BAD_DRIVER = 2001

    # The window style or class attribute is invalid for this operation.
    INVALID_WINDOW_STYLE = 2002

    # The requested metafile operation is not supported.
    METAFILE_NOT_SUPPORTED = 2003

    # The requested transformation operation is not supported.
    TRANSFORM_NOT_SUPPORTED = 2004

    # The requested clipping operation is not supported.
    CLIPPING_NOT_SUPPORTED = 2005

    # The specified color management module is invalid.
    INVALID_CMM = 2010

    # The specified color profile is invalid.
    INVALID_PROFILE = 2011

    # The specified tag was not found.
    TAG_NOT_FOUND = 2012

    # A required tag is not present.
    TAG_NOT_PRESENT = 2013

    # The specified tag is already present.
    DUPLICATE_TAG = 2014

    # The specified color profile is not associated with any device.
    PROFILE_NOT_ASSOCIATED_WITH_DEVICE = 2015

    # The specified color profile was not found.
    PROFILE_NOT_FOUND = 2016

    # The specified color space is invalid.
    INVALID_COLORSPACE = 2017

    # Image Color Management is not enabled.
    ICM_NOT_ENABLED = 2018

    # There was an error while deleting the color transform.
    DELETING_ICM_XFORM = 2019

    # The specified color transform is invalid.
    INVALID_TRANSFORM = 2020

    # The specified transform does not match the bitmap's color space.
    COLORSPACE_MISMATCH = 2021

    # The specified named color index is not present in the profile.
    INVALID_COLORINDEX = 2022

    # The network connection was made successfully, but the user had to be prompted for a password other than the one originally specified.
    CONNECTED_OTHER_PASSWORD = 2108

    # The network connection was made successfully using default credentials.
    CONNECTED_OTHER_PASSWORD_DEFAULT = 2109

    # The specified username is invalid.
    BAD_USERNAME = 2202

    # This network connection does not exist.
    NOT_CONNECTED = 2250

    # This network connection has files open or requests pending.
    OPEN_FILES = 2401

    # Active connections still exist.
    ACTIVE_CONNECTIONS = 2402

    # The device is in use by an active process and cannot be disconnected.
    DEVICE_IN_USE = 2404

    # The specified print monitor is unknown.
    UNKNOWN_PRINT_MONITOR = 3000

    # The specified printer driver is currently in use.
    PRINTER_DRIVER_IN_USE = 3001

    # The spool file was not found.
    SPOOL_FILE_NOT_FOUND = 3002

    # A StartDocPrinter call was not issued.
    SPL_NO_STARTDOC = 3003

    # An AddJob call was not issued.
    SPL_NO_ADDJOB = 3004

    # The specified print processor has already been installed.
    PRINT_PROCESSOR_ALREADY_INSTALLED = 3005

    # The specified print monitor has already been installed.
    PRINT_MONITOR_ALREADY_INSTALLED = 3006

    # The specified print monitor does not have the required functions.
    INVALID_PRINT_MONITOR = 3007

    # The specified print monitor is currently in use.
    PRINT_MONITOR_IN_USE = 3008

    # The requested operation is not allowed when there are jobs queued to the printer.
    PRINTER_HAS_JOBS_QUEUED = 3009

    # The requested operation is successful. Changes will not be effective until the system is rebooted.
    SUCCESS_REBOOT_REQUIRED = 3010

    # The requested operation is successful. Changes will not be effective until the service is restarted.
    SUCCESS_RESTART_REQUIRED = 3011

    # No printers were found.
    PRINTER_NOT_FOUND = 3012

    # The printer driver is known to be unreliable.
    PRINTER_DRIVER_WARNED = 3013

    # The printer driver is known to harm the system.
    PRINTER_DRIVER_BLOCKED = 3014

    # WINS encountered an error while processing the command.
    WINS_INTERNAL = 4000

    # The local WINS can not be deleted.
    CAN_NOT_DEL_LOCAL_WINS = 4001

    # The importation from the file failed.
    STATIC_INIT = 4002

    # The backup failed. Was a full backup done before?
    INC_BACKUP = 4003

    # The backup failed. Check the directory to which you are backing the database.
    FULL_BACKUP = 4004

    # The name does not exist in the WINS database.
    REC_NON_EXISTENT = 4005

    # Replication with a nonconfigured partner is not allowed.
    RPL_NOT_ALLOWED = 4006

    # The DHCP client has obtained an IP address that is already in use on the network. The local interface will be disabled until the DHCP client can obtain a new address.
    DHCP_ADDRESS_CONFLICT = 4100

    # The GUID passed was not recognized as valid by a WMI data provider.
    WMI_GUID_NOT_FOUND = 4200

    # The instance name passed was not recognized as valid by a WMI data provider.
    WMI_INSTANCE_NOT_FOUND = 4201

    # The data item ID passed was not recognized as valid by a WMI data provider.
    WMI_ITEMID_NOT_FOUND = 4202

    # The WMI request could not be completed and should be retried.
    WMI_TRY_AGAIN = 4203

    # The WMI data provider could not be located.
    WMI_DP_NOT_FOUND = 4204

    # The WMI data provider references an instance set that has not been registered.
    WMI_UNRESOLVED_INSTANCE_REF = 4205

    # The WMI data block or event notification has already been enabled.
    WMI_ALREADY_ENABLED = 4206

    # The WMI data block is no longer available.
    WMI_GUID_DISCONNECTED = 4207

    # The WMI data service is not available.
    WMI_SERVER_UNAVAILABLE = 4208

    # The WMI data provider failed to carry out the request.
    WMI_DP_FAILED = 4209

    # The WMI MOF information is not valid.
    WMI_INVALID_MOF = 4210

    # The WMI registration information is not valid.
    WMI_INVALID_REGINFO = 4211

    # The WMI data block or event notification has already been disabled.
    WMI_ALREADY_DISABLED = 4212

    # The WMI data item or data block is read only.
    WMI_READ_ONLY = 4213

    # The WMI data item or data block could not be changed.
    WMI_SET_FAILURE = 4214

    # The media identifier does not represent a valid medium.
    INVALID_MEDIA = 4300

    # The library identifier does not represent a valid library.
    INVALID_LIBRARY = 4301

    # The media pool identifier does not represent a valid media pool.
    INVALID_MEDIA_POOL = 4302

    # The drive and medium are not compatible or exist in different libraries.
    DRIVE_MEDIA_MISMATCH = 4303

    # The medium currently exists in an offline library and must be online to perform this operation.
    MEDIA_OFFLINE = 4304

    # The operation cannot be performed on an offline library.
    LIBRARY_OFFLINE = 4305

    # The library, drive, or media pool is empty.
    EMPTY = 4306

    # The library, drive, or media pool must be empty to perform this operation.
    NOT_EMPTY = 4307

    # No media is currently available in this media pool or library.
    MEDIA_UNAVAILABLE = 4308

    # A resource required for this operation is disabled.
    RESOURCE_DISABLED = 4309

    # The media identifier does not represent a valid cleaner.
    INVALID_CLEANER = 4310

    # The drive cannot be cleaned or does not support cleaning.
    UNABLE_TO_CLEAN = 4311

    # The object identifier does not represent a valid object.
    OBJECT_NOT_FOUND = 4312

    # Unable to read from or write to the database.
    DATABASE_FAILURE = 4313

    # The database is full.
    DATABASE_FULL = 4314

    # The medium is not compatible with the device or media pool.
    MEDIA_INCOMPATIBLE = 4315

    # The resource required for this operation does not exist.
    RESOURCE_NOT_PRESENT = 4316

    # The operation identifier is not valid.
    INVALID_OPERATION = 4317

    # The media is not mounted or ready for use.
    MEDIA_NOT_AVAILABLE = 4318

    # The device is not ready for use.
    DEVICE_NOT_AVAILABLE = 4319

    # The operator or administrator has refused the request.
    REQUEST_REFUSED = 4320

    # The drive identifier does not represent a valid drive.
    INVALID_DRIVE_OBJECT = 4321

    # Library is full.  No slot is available for use.
    LIBRARY_FULL = 4322

    # The transport cannot access the medium.
    MEDIUM_NOT_ACCESSIBLE = 4323

    # Unable to load the medium into the drive.
    UNABLE_TO_LOAD_MEDIUM = 4324

    # Unable to retrieve the drive status.
    UNABLE_TO_INVENTORY_DRIVE = 4325

    # Unable to retrieve the slot status.
    UNABLE_TO_INVENTORY_SLOT = 4326

    # Unable to retrieve status about the transport.
    UNABLE_TO_INVENTORY_TRANSPORT = 4327

    # Cannot use the transport because it is already in use.
    TRANSPORT_FULL = 4328

    # Unable to open or close the inject/eject port.
    CONTROLLING_IEPORT = 4329

    # Unable to eject the medium because it is in a drive.
    UNABLE_TO_EJECT_MOUNTED_MEDIA = 4330

    # A cleaner slot is already reserved.
    CLEANER_SLOT_SET = 4331

    # A cleaner slot is not reserved.
    CLEANER_SLOT_NOT_SET = 4332

    # The cleaner cartridge has performed the maximum number of drive cleanings.
    CLEANER_CARTRIDGE_SPENT = 4333

    # Unexpected on-medium identifier.
    UNEXPECTED_OMID = 4334

    # The last remaining item in this group or resource cannot be deleted.
    CANT_DELETE_LAST_ITEM = 4335

    # The message provided exceeds the maximum size allowed for this parameter.
    MESSAGE_EXCEEDS_MAX_SIZE = 4336

    # The volume contains system or paging files.
    VOLUME_CONTAINS_SYS_FILES = 4337

    # The media type cannot be removed from this library since at least one drive in the library reports it can support this media type.
    INDIGENOUS_TYPE = 4338

    # This offline media cannot be mounted on this system since no enabled drives are present which can be used.
    NO_SUPPORTING_DRIVES = 4339

    # A cleaner cartridge is present in the tape library.
    CLEANER_CARTRIDGE_INSTALLED = 4340

    # The remote storage service was not able to recall the file.
    FILE_OFFLINE = 4350

    # The remote storage service is not operational at this time.
    REMOTE_STORAGE_NOT_ACTIVE = 4351

    # The remote storage service encountered a media error.
    REMOTE_STORAGE_MEDIA_ERROR = 4352

    # The file or directory is not a reparse point.
    NOT_A_REPARSE_POINT = 4390

    # The reparse point attribute cannot be set because it conflicts with an existing attribute.
    REPARSE_ATTRIBUTE_CONFLICT = 4391

    # The data present in the reparse point buffer is invalid.
    INVALID_REPARSE_DATA = 4392

    # The tag present in the reparse point buffer is invalid.
    REPARSE_TAG_INVALID = 4393

    # There is a mismatch between the tag specified in the request and the tag present in the reparse point.
    REPARSE_TAG_MISMATCH = 4394

    # Single Instance Storage is not available on this volume.
    VOLUME_NOT_SIS_ENABLED = 4500

    # The cluster resource cannot be moved to another group because other resources are dependent on it.
    DEPENDENT_RESOURCE_EXISTS = 5001

    # The cluster resource dependency cannot be found.
    DEPENDENCY_NOT_FOUND = 5002

    # The cluster resource cannot be made dependent on the specified resource because it is already dependent.
    DEPENDENCY_ALREADY_EXISTS = 5003

    # The cluster resource is not online.
    RESOURCE_NOT_ONLINE = 5004

    # A cluster node is not available for this operation.
    HOST_NODE_NOT_AVAILABLE = 5005

    # The cluster resource is not available.
    RESOURCE_NOT_AVAILABLE = 5006

    # The cluster resource could not be found.
    RESOURCE_NOT_FOUND = 5007

    # The cluster is being shut down.
    SHUTDOWN_CLUSTER = 5008

    # A cluster node cannot be evicted from the cluster unless the node is down or it is the last node.
    CANT_EVICT_ACTIVE_NODE = 5009

    # The object already exists.
    OBJECT_ALREADY_EXISTS = 5010

    # The object is already in the list.
    OBJECT_IN_LIST = 5011

    # The cluster group is not available for any new requests.
    GROUP_NOT_AVAILABLE = 5012

    # The cluster group could not be found.
    GROUP_NOT_FOUND = 5013

    # The operation could not be completed because the cluster group is not online.
    GROUP_NOT_ONLINE = 5014

    # The cluster node is not the owner of the resource.
    HOST_NODE_NOT_RESOURCE_OWNER = 5015

    # The cluster node is not the owner of the group.
    HOST_NODE_NOT_GROUP_OWNER = 5016

    # The cluster resource could not be created in the specified resource monitor.
    RESMON_CREATE_FAILED = 5017

    # The cluster resource could not be brought online by the resource monitor.
    RESMON_ONLINE_FAILED = 5018

    # The operation could not be completed because the cluster resource is online.
    RESOURCE_ONLINE = 5019

    # The cluster resource could not be deleted or brought offline because it is the quorum resource.
    QUORUM_RESOURCE = 5020

    # The cluster could not make the specified resource a quorum resource because it is not capable of being a quorum resource.
    NOT_QUORUM_CAPABLE = 5021

    # The cluster software is shutting down.
    CLUSTER_SHUTTING_DOWN = 5022

    # The group or resource is not in the correct state to perform the requested operation.
    INVALID_STATE = 5023

    # The properties were stored but not all changes will take effect until the next time the resource is brought online.
    RESOURCE_PROPERTIES_STORED = 5024

    # The cluster could not make the specified resource a quorum resource because it does not belong to a shared storage class.
    NOT_QUORUM_CLASS = 5025

    # The cluster resource could not be deleted since it is a core resource.
    CORE_RESOURCE = 5026

    # The quorum resource failed to come online.
    QUORUM_RESOURCE_ONLINE_FAILED = 5027

    # The quorum log could not be created or mounted successfully.
    QUORUMLOG_OPEN_FAILED = 5028

    # The cluster log is corrupt.
    CLUSTERLOG_CORRUPT = 5029

    # The record could not be written to the cluster log since it exceeds the maximum size.
    CLUSTERLOG_RECORD_EXCEEDS_MAXSIZE = 5030

    # The cluster log exceeds its maximum size.
    CLUSTERLOG_EXCEEDS_MAXSIZE = 5031

    # No checkpoint record was found in the cluster log.
    CLUSTERLOG_CHKPOINT_NOT_FOUND = 5032

    # The minimum required disk space needed for logging is not available.
    CLUSTERLOG_NOT_ENOUGH_SPACE = 5033

    # The cluster node failed to take control of the quorum resource because the resource is owned by another active node.
    QUORUM_OWNER_ALIVE = 5034

    # A cluster network is not available for this operation.
    NETWORK_NOT_AVAILABLE = 5035

    # A cluster node is not available for this operation.
    NODE_NOT_AVAILABLE = 5036

    # All cluster nodes must be running to perform this operation.
    ALL_NODES_NOT_AVAILABLE = 5037

    # A cluster resource failed.
    RESOURCE_FAILED = 5038

    # The cluster node is not valid.
    CLUSTER_INVALID_NODE = 5039

    # The cluster node already exists.
    CLUSTER_NODE_EXISTS = 5040

    # A node is in the process of joining the cluster.
    CLUSTER_JOIN_IN_PROGRESS = 5041

    # The cluster node was not found.
    CLUSTER_NODE_NOT_FOUND = 5042

    # The cluster local node information was not found.
    CLUSTER_LOCAL_NODE_NOT_FOUND = 5043

    # The cluster network already exists.
    CLUSTER_NETWORK_EXISTS = 5044

    # The cluster network was not found.
    CLUSTER_NETWORK_NOT_FOUND = 5045

    # The cluster network interface already exists.
    CLUSTER_NETINTERFACE_EXISTS = 5046

    # The cluster network interface was not found.
    CLUSTER_NETINTERFACE_NOT_FOUND = 5047

    # The cluster request is not valid for this object.
    CLUSTER_INVALID_REQUEST = 5048

    # The cluster network provider is not valid.
    CLUSTER_INVALID_NETWORK_PROVIDER = 5049

    # The cluster node is down.
    CLUSTER_NODE_DOWN = 5050

    # The cluster node is not reachable.
    CLUSTER_NODE_UNREACHABLE = 5051

    # The cluster node is not a member of the cluster.
    CLUSTER_NODE_NOT_MEMBER = 5052

    # A cluster join operation is not in progress.
    CLUSTER_JOIN_NOT_IN_PROGRESS = 5053

    # The cluster network is not valid.
    CLUSTER_INVALID_NETWORK = 5054

    # The cluster node is up.
    CLUSTER_NODE_UP = 5056

    # The cluster IP address is already in use.
    CLUSTER_IPADDR_IN_USE = 5057

    # The cluster node is not paused.
    CLUSTER_NODE_NOT_PAUSED = 5058

    # No cluster security context is available.
    CLUSTER_NO_SECURITY_CONTEXT = 5059

    # The cluster network is not configured for internal cluster communication.
    CLUSTER_NETWORK_NOT_INTERNAL = 5060

    # The cluster node is already up.
    CLUSTER_NODE_ALREADY_UP = 5061

    # The cluster node is already down.
    CLUSTER_NODE_ALREADY_DOWN = 5062

    # The cluster network is already online.
    CLUSTER_NETWORK_ALREADY_ONLINE = 5063

    # The cluster network is already offline.
    CLUSTER_NETWORK_ALREADY_OFFLINE = 5064

    # The cluster node is already a member of the cluster.
    CLUSTER_NODE_ALREADY_MEMBER = 5065

    # The cluster network is the only one configured for internal cluster communication between two or more active cluster nodes. The internal communication capability cannot be removed from the network.
    CLUSTER_LAST_INTERNAL_NETWORK = 5066

    # One or more cluster resources depend on the network to provide service to clients. The client access capability cannot be removed from the network.
    CLUSTER_NETWORK_HAS_DEPENDENTS = 5067

    # This operation cannot be performed on the cluster resource as it the quorum resource. You may not bring the quorum resource offline or modify its possible owners list.
    INVALID_OPERATION_ON_QUORUM = 5068

    # The cluster quorum resource is not allowed to have any dependencies.
    DEPENDENCY_NOT_ALLOWED = 5069

    # The cluster node is paused.
    CLUSTER_NODE_PAUSED = 5070

    # The cluster resource cannot be brought online. The owner node cannot run this resource.
    NODE_CANT_HOST_RESOURCE = 5071

    # The cluster node is not ready to perform the requested operation.
    CLUSTER_NODE_NOT_READY = 5072

    # The cluster node is shutting down.
    CLUSTER_NODE_SHUTTING_DOWN = 5073

    # The cluster join operation was aborted.
    CLUSTER_JOIN_ABORTED = 5074

    # The cluster join operation failed due to incompatible software versions between the joining node and its sponsor.
    CLUSTER_INCOMPATIBLE_VERSIONS = 5075

    # This resource cannot be created because the cluster has reached the limit on the number of resources it can monitor.
    CLUSTER_MAXNUM_OF_RESOURCES_EXCEEDED = 5076

    # The system configuration changed during the cluster join or form operation. The join or form operation was aborted.
    CLUSTER_SYSTEM_CONFIG_CHANGED = 5077

    # The specified resource type was not found.
    CLUSTER_RESOURCE_TYPE_NOT_FOUND = 5078

    # The specified node does not support a resource of this type.  This may be due to version inconsistencies or due to the absence of the resource DLL on this node.
    CLUSTER_RESTYPE_NOT_SUPPORTED = 5079

    # The specified resource name is not supported by this resource DLL. This may be due to a bad (or changed) name supplied to the resource DLL.
    CLUSTER_RESNAME_NOT_FOUND = 5080

    # No authentication package could be registered with the RPC server.
    CLUSTER_NO_RPC_PACKAGES_REGISTERED = 5081

    # You cannot bring the group online because the owner of the group is not in the preferred list for the group. To change the owner node for the group, move the group.
    CLUSTER_OWNER_NOT_IN_PREFLIST = 5082

    # The join operation failed because the cluster database sequence number has changed or is incompatible with the locker node. This may happen during a join operation if the cluster database was changing during the join.
    CLUSTER_DATABASE_SEQMISMATCH = 5083

    # The resource monitor will not allow the fail operation to be performed while the resource is in its current state. This may happen if the resource is in a pending state.
    RESMON_INVALID_STATE = 5084

    # A non locker code got a request to reserve the lock for making global updates.
    CLUSTER_GUM_NOT_LOCKER = 5085

    # The quorum disk could not be located by the cluster service.
    QUORUM_DISK_NOT_FOUND = 5086

    # The backed up cluster database is possibly corrupt.
    DATABASE_BACKUP_CORRUPT = 5087

    # A DFS root already exists in this cluster node.
    CLUSTER_NODE_ALREADY_HAS_DFS_ROOT = 5088

    # An attempt to modify a resource property failed because it conflicts with another existing property.
    RESOURCE_PROPERTY_UNCHANGEABLE = 5089

    # An operation was attempted that is incompatible with the current membership state of the node.
    CLUSTER_MEMBERSHIP_INVALID_STATE = 5890

    # The quorum resource does not contain the quorum log.
    CLUSTER_QUORUMLOG_NOT_FOUND = 5891

    # The membership engine requested shutdown of the cluster service on this node.
    CLUSTER_MEMBERSHIP_HALT = 5892

    # The join operation failed because the cluster instance ID of the joining node does not match the cluster instance ID of the sponsor node.
    CLUSTER_INSTANCE_ID_MISMATCH = 5893

    # A matching network for the specified IP address could not be found. Please also specify a subnet mask and a cluster network.
    CLUSTER_NETWORK_NOT_FOUND_FOR_IP = 5894

    # The actual data type of the property did not match the expected data type of the property.
    CLUSTER_PROPERTY_DATA_TYPE_MISMATCH = 5895

    # The cluster node was evicted from the cluster successfully, but the node was not cleaned up.  Extended status information explaining why the node was not cleaned up is available.
    CLUSTER_EVICT_WITHOUT_CLEANUP = 5896

    # Two or more parameter values specified for a resource's properties are in conflict.
    CLUSTER_PARAMETER_MISMATCH = 5897

    # This computer cannot be made a member of a cluster.
    NODE_CANNOT_BE_CLUSTERED = 5898

    # This computer cannot be made a member of a cluster because it does not have the correct version of Windows installed.
    CLUSTER_WRONG_OS_VERSION = 5899

    # A cluster cannot be created with the specified cluster name because that cluster name is already in use. Specify a different name for the cluster.
    CLUSTER_CANT_CREATE_DUP_CLUSTER_NAME = 5900

    # No information avialable.
    CLUSCFG_ALREADY_COMMITTED = 5901

    # No information avialable.
    CLUSCFG_ROLLBACK_FAILED = 5902

    # No information avialable.
    CLUSCFG_SYSTEM_DISK_DRIVE_LETTER_CONFLICT = 5903

    # No information avialable.
    CLUSTER_OLD_VERSION = 5904

    # No information avialable.
    CLUSTER_MISMATCHED_COMPUTER_ACCT_NAME = 5905

    # The specified file could not be encrypted.
    ENCRYPTION_FAILED = 6000

    # The specified file could not be decrypted.
    DECRYPTION_FAILED = 6001

    # The specified file is encrypted and the user does not have the ability to decrypt it.
    FILE_ENCRYPTED = 6002

    # There is no valid encryption recovery policy configured for this system.
    NO_RECOVERY_POLICY = 6003

    # The required encryption driver is not loaded for this system.
    NO_EFS = 6004

    # The file was encrypted with a different encryption driver than is currently loaded.
    WRONG_EFS = 6005

    # There are no EFS keys defined for the user.
    NO_USER_KEYS = 6006

    # The specified file is not encrypted.
    FILE_NOT_ENCRYPTED = 6007

    # The specified file is not in the defined EFS export format.
    NOT_EXPORT_FORMAT = 6008

    # The specified file is read only.
    FILE_READ_ONLY = 6009

    # The directory has been disabled for encryption.
    DIR_EFS_DISALLOWED = 6010

    # The server is not trusted for remote encryption operation.
    EFS_SERVER_NOT_TRUSTED = 6011

    # Recovery policy configured for this system contains invalid recovery certificate.
    BAD_RECOVERY_POLICY = 6012

    # The encryption algorithm used on the source file needs a bigger key buffer than the one on the destination file.
    EFS_ALG_BLOB_TOO_BIG = 6013

    # The disk partition does not support file encryption.
    VOLUME_NOT_SUPPORT_EFS = 6014

    # This machine is disabled for file encryption.
    EFS_DISABLED = 6015

    # A newer system is required to decrypt this encrypted file.
    EFS_VERSION_NOT_SUPPORT = 6016

    # The list of servers for this workgroup is not currently available
    NO_BROWSER_SERVERS_FOUND = 6118

    # The Task Scheduler service must be configured to run in the System account to function properly.  Individual tasks may be configured to run in other accounts.
    SCHED_E_SERVICE_NOT_LOCALSYSTEM = 6200

    # The specified session name is invalid.
    CTX_WINSTATION_NAME_INVALID = 7001

    # The specified protocol driver is invalid.
    CTX_INVALID_PD = 7002

    # The specified protocol driver was not found in the system path.
    CTX_PD_NOT_FOUND = 7003

    # The specified terminal connection driver was not found in the system path.
    CTX_WD_NOT_FOUND = 7004

    # A registry key for event logging could not be created for this session.
    CTX_CANNOT_MAKE_EVENTLOG_ENTRY = 7005

    # A service with the same name already exists on the system.
    CTX_SERVICE_NAME_COLLISION = 7006

    # A close operation is pending on the session.
    CTX_CLOSE_PENDING = 7007

    # There are no free output buffers available.
    CTX_NO_OUTBUF = 7008

    # The MODEM.INF file was not found.
    CTX_MODEM_INF_NOT_FOUND = 7009

    # The modem name was not found in MODEM.INF.
    CTX_INVALID_MODEMNAME = 7010

    # The modem did not accept the command sent to it. Verify that the configured modem name matches the attached modem.
    CTX_MODEM_RESPONSE_ERROR = 7011

    # The modem did not respond to the command sent to it. Verify that the modem is properly cabled and powered on.
    CTX_MODEM_RESPONSE_TIMEOUT = 7012

    # Carrier detect has failed or carrier has been dropped due to disconnect.
    CTX_MODEM_RESPONSE_NO_CARRIER = 7013

    # Dial tone not detected within the required time. Verify that the phone cable is properly attached and functional.
    CTX_MODEM_RESPONSE_NO_DIALTONE = 7014

    # Busy signal detected at remote site on callback.
    CTX_MODEM_RESPONSE_BUSY = 7015

    # Voice detected at remote site on callback.
    CTX_MODEM_RESPONSE_VOICE = 7016

    # Transport driver error
    CTX_TD_ERROR = 7017

    # The specified session cannot be found.
    CTX_WINSTATION_NOT_FOUND = 7022

    # The specified session name is already in use.
    CTX_WINSTATION_ALREADY_EXISTS = 7023

    # The requested operation cannot be completed because the terminal connection is currently busy processing a connect, disconnect, reset, or delete operation.
    CTX_WINSTATION_BUSY = 7024

    # An attempt has been made to connect to a session whose video mode is not supported by the current client.
    CTX_BAD_VIDEO_MODE = 7025

    # The application attempted to enable DOS graphics mode.
    # DOS graphics mode is not supported.
    CTX_GRAPHICS_INVALID = 7035

    # Your interactive logon privilege has been disabled.
    # Please contact your administrator.
    CTX_LOGON_DISABLED = 7037

    # The requested operation can be performed only on the system console.
    # This is most often the result of a driver or system DLL requiring direct console access.
    CTX_NOT_CONSOLE = 7038

    # The client failed to respond to the server connect message.
    CTX_CLIENT_QUERY_TIMEOUT = 7040

    # Disconnecting the console session is not supported.
    CTX_CONSOLE_DISCONNECT = 7041

    # Reconnecting a disconnected session to the console is not supported.
    CTX_CONSOLE_CONNECT = 7042

    # The request to control another session remotely was denied.
    CTX_SHADOW_DENIED = 7044

    # The requested session access is denied.
    CTX_WINSTATION_ACCESS_DENIED = 7045

    # The specified terminal connection driver is invalid.
    CTX_INVALID_WD = 7049

    # The requested session cannot be controlled remotely.
    # This may be because the session is disconnected or does not currently have a user logged on.
    CTX_SHADOW_INVALID = 7050

    # The requested session is not configured to allow remote control.
    CTX_SHADOW_DISABLED = 7051

    # Your request to connect to this Terminal Server has been rejected. Your Terminal Server client license number is currently being used by another user.
    # Please call your system administrator to obtain a unique license number.
    CTX_CLIENT_LICENSE_IN_USE = 7052

    # Your request to connect to this Terminal Server has been rejected. Your Terminal Server client license number has not been entered for this copy of the Terminal Server client.
    # Please contact your system administrator.
    CTX_CLIENT_LICENSE_NOT_SET = 7053

    # The system has reached its licensed logon limit.
    # Please try again later.
    CTX_LICENSE_NOT_AVAILABLE = 7054

    # The client you are using is not licensed to use this system.  Your logon request is denied.
    CTX_LICENSE_CLIENT_INVALID = 7055

    # The system license has expired.  Your logon request is denied.
    CTX_LICENSE_EXPIRED = 7056

    # Remote control could not be terminated because the specified session is not currently being remotely controlled.
    CTX_SHADOW_NOT_RUNNING = 7057

    # The remote control of the console was terminated because the display mode was changed. Changing the display mode in a remote control session is not supported.
    CTX_SHADOW_ENDED_BY_MODE_CHANGE = 7058

    # No information avialable.
    ACTIVATION_COUNT_EXCEEDED = 7059

    # The file replication service API was called incorrectly.
    FRS_ERR_INVALID_API_SEQUENCE = 8001

    # The file replication service cannot be started.
    FRS_ERR_STARTING_SERVICE = 8002

    # The file replication service cannot be stopped.
    FRS_ERR_STOPPING_SERVICE = 8003

    # The file replication service API terminated the request.
    # The event log may have more information.
    FRS_ERR_INTERNAL_API = 8004

    # The file replication service terminated the request.
    # The event log may have more information.
    FRS_ERR_INTERNAL = 8005

    # The file replication service cannot be contacted.
    # The event log may have more information.
    FRS_ERR_SERVICE_COMM = 8006

    # The file replication service cannot satisfy the request because the user has insufficient privileges.
    # The event log may have more information.
    FRS_ERR_INSUFFICIENT_PRIV = 8007

    # The file replication service cannot satisfy the request because authenticated RPC is not available.
    # The event log may have more information.
    FRS_ERR_AUTHENTICATION = 8008

    # The file replication service cannot satisfy the request because the user has insufficient privileges on the domain controller.
    # The event log may have more information.
    FRS_ERR_PARENT_INSUFFICIENT_PRIV = 8009

    # The file replication service cannot satisfy the request because authenticated RPC is not available on the domain controller.
    # The event log may have more information.
    FRS_ERR_PARENT_AUTHENTICATION = 8010

    # The file replication service cannot communicate with the file replication service on the domain controller.
    # The event log may have more information.
    FRS_ERR_CHILD_TO_PARENT_COMM = 8011

    # The file replication service on the domain controller cannot communicate with the file replication service on this computer.
    # The event log may have more information.
    FRS_ERR_PARENT_TO_CHILD_COMM = 8012

    # The file replication service cannot populate the system volume because of an internal error.
    # The event log may have more information.
    FRS_ERR_SYSVOL_POPULATE = 8013

    # The file replication service cannot populate the system volume because of an internal timeout.
    # The event log may have more information.
    FRS_ERR_SYSVOL_POPULATE_TIMEOUT = 8014

    # The file replication service cannot process the request. The system volume is busy with a previous request.
    FRS_ERR_SYSVOL_IS_BUSY = 8015

    # The file replication service cannot stop replicating the system volume because of an internal error.
    # The event log may have more information.
    FRS_ERR_SYSVOL_DEMOTE = 8016

    # The file replication service detected an invalid parameter.
    FRS_ERR_INVALID_SERVICE_PARAMETER = 8017

    # An error occurred while installing the directory service. For more information, see the event log.
    DS_NOT_INSTALLED = 8200

    # The directory service evaluated group memberships locally.
    DS_MEMBERSHIP_EVALUATED_LOCALLY = 8201

    # The specified directory service attribute or value does not exist.
    DS_NO_ATTRIBUTE_OR_VALUE = 8202

    # The attribute syntax specified to the directory service is invalid.
    DS_INVALID_ATTRIBUTE_SYNTAX = 8203

    # The attribute type specified to the directory service is not defined.
    DS_ATTRIBUTE_TYPE_UNDEFINED = 8204

    # The specified directory service attribute or value already exists.
    DS_ATTRIBUTE_OR_VALUE_EXISTS = 8205

    # The directory service is busy.
    DS_BUSY = 8206

    # The directory service is unavailable.
    DS_UNAVAILABLE = 8207

    # The directory service was unable to allocate a relative identifier.
    DS_NO_RIDS_ALLOCATED = 8208

    # The directory service has exhausted the pool of relative identifiers.
    DS_NO_MORE_RIDS = 8209

    # The requested operation could not be performed because the directory service is not the master for that type of operation.
    DS_INCORRECT_ROLE_OWNER = 8210

    # The directory service was unable to initialize the subsystem that allocates relative identifiers.
    DS_RIDMGR_INIT_ERROR = 8211

    # The requested operation did not satisfy one or more constraints associated with the class of the object.
    DS_OBJ_CLASS_VIOLATION = 8212

    # The directory service can perform the requested operation only on a leaf object.
    DS_CANT_ON_NON_LEAF = 8213

    # The directory service cannot perform the requested operation on the RDN attribute of an object.
    DS_CANT_ON_RDN = 8214

    # The directory service detected an attempt to modify the object class of an object.
    DS_CANT_MOD_OBJ_CLASS = 8215

    # The requested cross-domain move operation could not be performed.
    DS_CROSS_DOM_MOVE_ERROR = 8216

    # Unable to contact the global catalog server.
    DS_GC_NOT_AVAILABLE = 8217

    # The policy object is shared and can only be modified at the root.
    SHARED_POLICY = 8218

    # The policy object does not exist.
    POLICY_OBJECT_NOT_FOUND = 8219

    # The requested policy information is only in the directory service.
    POLICY_ONLY_IN_DS = 8220

    # A domain controller promotion is currently active.
    PROMOTION_ACTIVE = 8221

    # A domain controller promotion is not currently active
    NO_PROMOTION_ACTIVE = 8222

    # An operations error occurred.
    DS_OPERATIONS_ERROR = 8224

    # A protocol error occurred.
    DS_PROTOCOL_ERROR = 8225

    # The time limit for this request was exceeded.
    DS_TIMELIMIT_EXCEEDED = 8226

    # The size limit for this request was exceeded.
    DS_SIZELIMIT_EXCEEDED = 8227

    # The administrative limit for this request was exceeded.
    DS_ADMIN_LIMIT_EXCEEDED = 8228

    # The compare response was false.
    DS_COMPARE_FALSE = 8229

    # The compare response was true.
    DS_COMPARE_TRUE = 8230

    # The requested authentication method is not supported by the server.
    DS_AUTH_METHOD_NOT_SUPPORTED = 8231

    # A more secure authentication method is required for this server.
    DS_STRONG_AUTH_REQUIRED = 8232

    # Inappropriate authentication.
    DS_INAPPROPRIATE_AUTH = 8233

    # The authentication mechanism is unknown.
    DS_AUTH_UNKNOWN = 8234

    # A referral was returned from the server.
    DS_REFERRAL = 8235

    # The server does not support the requested critical extension.
    DS_UNAVAILABLE_CRIT_EXTENSION = 8236

    # This request requires a secure connection.
    DS_CONFIDENTIALITY_REQUIRED = 8237

    # Inappropriate matching.
    DS_INAPPROPRIATE_MATCHING = 8238

    # A constraint violation occurred.
    DS_CONSTRAINT_VIOLATION = 8239

    # There is no such object on the server.
    DS_NO_SUCH_OBJECT = 8240

    # There is an alias problem.
    DS_ALIAS_PROBLEM = 8241

    # An invalid dn syntax has been specified.
    DS_INVALID_DN_SYNTAX = 8242

    # The object is a leaf object.
    DS_IS_LEAF = 8243

    # There is an alias dereferencing problem.
    DS_ALIAS_DEREF_PROBLEM = 8244

    # The server is unwilling to process the request.
    DS_UNWILLING_TO_PERFORM = 8245

    # A loop has been detected.
    DS_LOOP_DETECT = 8246

    # There is a naming violation.
    DS_NAMING_VIOLATION = 8247

    # The result set is too large.
    DS_OBJECT_RESULTS_TOO_LARGE = 8248

    # The operation affects multiple DSAs
    DS_AFFECTS_MULTIPLE_DSAS = 8249

    # The server is not operational.
    DS_SERVER_DOWN = 8250

    # A local error has occurred.
    DS_LOCAL_ERROR = 8251

    # An encoding error has occurred.
    DS_ENCODING_ERROR = 8252

    # A decoding error has occurred.
    DS_DECODING_ERROR = 8253

    # The search filter cannot be recognized.
    DS_FILTER_UNKNOWN = 8254

    # One or more parameters are illegal.
    DS_PARAM_ERROR = 8255

    # The specified method is not supported.
    DS_NOT_SUPPORTED = 8256

    # No results were returned.
    DS_NO_RESULTS_RETURNED = 8257

    # The specified control is not supported by the server.
    DS_CONTROL_NOT_FOUND = 8258

    # A referral loop was detected by the client.
    DS_CLIENT_LOOP = 8259

    # The preset referral limit was exceeded.
    DS_REFERRAL_LIMIT_EXCEEDED = 8260

    # The search requires a SORT control.
    DS_SORT_CONTROL_MISSING = 8261

    # The search results exceed the offset range specified.
    DS_OFFSET_RANGE_ERROR = 8262

    # The root object must be the head of a naming context. The root object cannot have an instantiated parent.
    DS_ROOT_MUST_BE_NC = 8301

    # The add replica operation cannot be performed. The naming context must be writable in order to create the replica.
    DS_ADD_REPLICA_INHIBITED = 8302

    # A reference to an attribute that is not defined in the schema occurred.
    DS_ATT_NOT_DEF_IN_SCHEMA = 8303

    # The maximum size of an object has been exceeded.
    DS_MAX_OBJ_SIZE_EXCEEDED = 8304

    # An attempt was made to add an object to the directory with a name that is already in use.
    DS_OBJ_STRING_NAME_EXISTS = 8305

    # An attempt was made to add an object of a class that does not have an RDN defined in the schema.
    DS_NO_RDN_DEFINED_IN_SCHEMA = 8306

    # An attempt was made to add an object using an RDN that is not the RDN defined in the schema.
    DS_RDN_DOESNT_MATCH_SCHEMA = 8307

    # None of the requested attributes were found on the objects.
    DS_NO_REQUESTED_ATTS_FOUND = 8308

    # The user buffer is too small.
    DS_USER_BUFFER_TO_SMALL = 8309

    # The attribute specified in the operation is not present on the object.
    DS_ATT_IS_NOT_ON_OBJ = 8310

    # Illegal modify operation. Some aspect of the modification is not permitted.
    DS_ILLEGAL_MOD_OPERATION = 8311

    # The specified object is too large.
    DS_OBJ_TOO_LARGE = 8312

    # The specified instance type is not valid.
    DS_BAD_INSTANCE_TYPE = 8313

    # The operation must be performed at a master DSA.
    DS_MASTERDSA_REQUIRED = 8314

    # The object class attribute must be specified.
    DS_OBJECT_CLASS_REQUIRED = 8315

    # A required attribute is missing.
    DS_MISSING_REQUIRED_ATT = 8316

    # An attempt was made to modify an object to include an attribute that is not legal for its class.
    DS_ATT_NOT_DEF_FOR_CLASS = 8317

    # The specified attribute is already present on the object.
    DS_ATT_ALREADY_EXISTS = 8318

    # The specified attribute is not present, or has no values.
    DS_CANT_ADD_ATT_VALUES = 8320

    # Mutliple values were specified for an attribute that can have only one value.
    DS_SINGLE_VALUE_CONSTRAINT = 8321

    # A value for the attribute was not in the acceptable range of values.
    DS_RANGE_CONSTRAINT = 8322

    # The specified value already exists.
    DS_ATT_VAL_ALREADY_EXISTS = 8323

    # The attribute cannot be removed because it is not present on the object.
    DS_CANT_REM_MISSING_ATT = 8324

    # The attribute value cannot be removed because it is not present on the object.
    DS_CANT_REM_MISSING_ATT_VAL = 8325

    # The specified root object cannot be a subref.
    DS_ROOT_CANT_BE_SUBREF = 8326

    # Chaining is not permitted.
    DS_NO_CHAINING = 8327

    # Chained evaluation is not permitted.
    DS_NO_CHAINED_EVAL = 8328

    # The operation could not be performed because the object's parent is either uninstantiated or deleted.
    DS_NO_PARENT_OBJECT = 8329

    # Having a parent that is an alias is not permitted. Aliases are leaf objects.
    DS_PARENT_IS_AN_ALIAS = 8330

    # The object and parent must be of the same type, either both masters or both replicas.
    DS_CANT_MIX_MASTER_AND_REPS = 8331

    # The operation cannot be performed because child objects exist. This operation can only be performed on a leaf object.
    DS_CHILDREN_EXIST = 8332

    # Directory object not found.
    DS_OBJ_NOT_FOUND = 8333

    # The aliased object is missing.
    DS_ALIASED_OBJ_MISSING = 8334

    # The object name has bad syntax.
    DS_BAD_NAME_SYNTAX = 8335

    # It is not permitted for an alias to refer to another alias.
    DS_ALIAS_POINTS_TO_ALIAS = 8336

    # The alias cannot be dereferenced.
    DS_CANT_DEREF_ALIAS = 8337

    # The operation is out of scope.
    DS_OUT_OF_SCOPE = 8338

    # The operation cannot continue because the object is in the process of being removed.
    DS_OBJECT_BEING_REMOVED = 8339

    # The DSA object cannot be deleted.
    DS_CANT_DELETE_DSA_OBJ = 8340

    # A directory service error has occurred.
    DS_GENERIC_ERROR = 8341

    # The operation can only be performed on an internal master DSA object.
    DS_DSA_MUST_BE_INT_MASTER = 8342

    # The object must be of class DSA.
    DS_CLASS_NOT_DSA = 8343

    # Insufficient access rights to perform the operation.
    DS_INSUFF_ACCESS_RIGHTS = 8344

    # The object cannot be added because the parent is not on the list of possible superiors.
    DS_ILLEGAL_SUPERIOR = 8345

    # Access to the attribute is not permitted because the attribute is owned by the Security Accounts Manager (SAM).
    DS_ATTRIBUTE_OWNED_BY_SAM = 8346

    # The name has too many parts.
    DS_NAME_TOO_MANY_PARTS = 8347

    # The name is too long.
    DS_NAME_TOO_LONG = 8348

    # The name value is too long.
    DS_NAME_VALUE_TOO_LONG = 8349

    # The directory service encountered an error parsing a name.
    DS_NAME_UNPARSEABLE = 8350

    # The directory service cannot get the attribute type for a name.
    DS_NAME_TYPE_UNKNOWN = 8351

    # The name does not identify an object, the name identifies a phantom.
    DS_NOT_AN_OBJECT = 8352

    # The security descriptor is too short.
    DS_SEC_DESC_TOO_LONG = 8353

    # The security descriptor is invalid.
    DS_SEC_DESC_INVALID = 8354

    # Failed to create name for deleted object.
    DS_NO_DELETED_NAME = 8355

    # The parent of a new subref must exist.
    DS_SUBREF_MUST_HAVE_PARENT = 8356

    # The object must be a naming context.
    DS_NCNAME_MUST_BE_NC = 8357

    # It is not permitted to add an attribute which is owned by the system.
    DS_CANT_ADD_SYSTEM_ONLY = 8358

    # The class of the object must be structural, you cannot instantiate an abstract class.
    DS_CLASS_MUST_BE_CONCRETE = 8359

    # The schema object could not be found.
    DS_INVALID_DMD = 8360

    # A local object with this GUID (dead or alive) already exists.
    DS_OBJ_GUID_EXISTS = 8361

    # The operation cannot be performed on a back link.
    DS_NOT_ON_BACKLINK = 8362

    # The cross reference for the specified naming context could not be found.
    DS_NO_CROSSREF_FOR_NC = 8363

    # The operation could not be performed because the directory service is shutting down.
    DS_SHUTTING_DOWN = 8364

    # The directory service request is invalid.
    DS_UNKNOWN_OPERATION = 8365

    # The role owner attribute could not be read.
    DS_INVALID_ROLE_OWNER = 8366

    # The requested FSMO operation failed. The current FSMO holder could not be contacted.
    DS_COULDNT_CONTACT_FSMO = 8367

    # Modification of a DN across a naming context is not permitted.
    DS_CROSS_NC_DN_RENAME = 8368

    # The attribute cannot be modified because it is owned by the system.
    DS_CANT_MOD_SYSTEM_ONLY = 8369

    # Only the replicator can perform this function.
    DS_REPLICATOR_ONLY = 8370

    # The specified class is not defined.
    DS_OBJ_CLASS_NOT_DEFINED = 8371

    # The specified class is not a subclass.
    DS_OBJ_CLASS_NOT_SUBCLASS = 8372

    # The name reference is invalid.
    DS_NAME_REFERENCE_INVALID = 8373

    # A cross reference already exists.
    DS_CROSS_REF_EXISTS = 8374

    # It is not permitted to delete a master cross reference.
    DS_CANT_DEL_MASTER_CROSSREF = 8375

    # Subtree notifications are only supported on NC heads.
    DS_SUBTREE_NOTIFY_NOT_NC_HEAD = 8376

    # Notification filter is too complex.
    DS_NOTIFY_FILTER_TOO_COMPLEX = 8377

    # Schema update failed: duplicate RDN.
    DS_DUP_RDN = 8378

    # Schema update failed: duplicate OID.
    DS_DUP_OID = 8379

    # Schema update failed: duplicate MAPI identifier.
    DS_DUP_MAPI_ID = 8380

    # Schema update failed: duplicate schema-id GUID.
    DS_DUP_SCHEMA_ID_GUID = 8381

    # Schema update failed: duplicate LDAP display name.
    DS_DUP_LDAP_DISPLAY_NAME = 8382

    # Schema update failed: range-lower less than range upper.
    DS_SEMANTIC_ATT_TEST = 8383

    # Schema update failed: syntax mismatch.
    DS_SYNTAX_MISMATCH = 8384

    # Schema deletion failed: attribute is used in must-contain.
    DS_EXISTS_IN_MUST_HAVE = 8385

    # Schema deletion failed: attribute is used in may-contain.
    DS_EXISTS_IN_MAY_HAVE = 8386

    # Schema update failed: attribute in may-contain does not exist.
    DS_NONEXISTENT_MAY_HAVE = 8387

    # Schema update failed: attribute in must-contain does not exist.
    DS_NONEXISTENT_MUST_HAVE = 8388

    # Schema update failed: class in aux-class list does not exist or is not an auxiliary class.
    DS_AUX_CLS_TEST_FAIL = 8389

    # Schema update failed: class in poss-superiors does not exist.
    DS_NONEXISTENT_POSS_SUP = 8390

    # Schema update failed: class in subclassof list does not exist or does not satisfy hierarchy rules.
    DS_SUB_CLS_TEST_FAIL = 8391

    # Schema update failed: Rdn-Att-Id has wrong syntax.
    DS_BAD_RDN_ATT_ID_SYNTAX = 8392

    # Schema deletion failed: class is used as auxiliary class.
    DS_EXISTS_IN_AUX_CLS = 8393

    # Schema deletion failed: class is used as sub class.
    DS_EXISTS_IN_SUB_CLS = 8394

    # Schema deletion failed: class is used as poss superior.
    DS_EXISTS_IN_POSS_SUP = 8395

    # Schema update failed in recalculating validation cache.
    DS_RECALCSCHEMA_FAILED = 8396

    # The tree deletion is not finished.  The request must be made again to continue deleting the tree.
    DS_TREE_DELETE_NOT_FINISHED = 8397

    # The requested delete operation could not be performed.
    DS_CANT_DELETE = 8398

    # Cannot read the governs class identifier for the schema record.
    DS_ATT_SCHEMA_REQ_ID = 8399

    # The attribute schema has bad syntax.
    DS_BAD_ATT_SCHEMA_SYNTAX = 8400

    # The attribute could not be cached.
    DS_CANT_CACHE_ATT = 8401

    # The class could not be cached.
    DS_CANT_CACHE_CLASS = 8402

    # The attribute could not be removed from the cache.
    DS_CANT_REMOVE_ATT_CACHE = 8403

    # The class could not be removed from the cache.
    DS_CANT_REMOVE_CLASS_CACHE = 8404

    # The distinguished name attribute could not be read.
    DS_CANT_RETRIEVE_DN = 8405

    # A required subref is missing.
    DS_MISSING_SUPREF = 8406

    # The instance type attribute could not be retrieved.
    DS_CANT_RETRIEVE_INSTANCE = 8407

    # An internal error has occurred.
    DS_CODE_INCONSISTENCY = 8408

    # A database error has occurred.
    DS_DATABASE_ERROR = 8409

    # The attribute GOVERNSID is missing.
    DS_GOVERNSID_MISSING = 8410

    # An expected attribute is missing.
    DS_MISSING_EXPECTED_ATT = 8411

    # The specified naming context is missing a cross reference.
    DS_NCNAME_MISSING_CR_REF = 8412

    # A security checking error has occurred.
    DS_SECURITY_CHECKING_ERROR = 8413

    # The schema is not loaded.
    DS_SCHEMA_NOT_LOADED = 8414

    # Schema allocation failed. Please check if the machine is running low on memory.
    DS_SCHEMA_ALLOC_FAILED = 8415

    # Failed to obtain the required syntax for the attribute schema.
    DS_ATT_SCHEMA_REQ_SYNTAX = 8416

    # The global catalog verification failed. The global catalog is not available or does not support the operation. Some part of the directory is currently not available.
    DS_GCVERIFY_ERROR = 8417

    # The replication operation failed because of a schema mismatch between the servers involved.
    DS_DRA_SCHEMA_MISMATCH = 8418

    # The DSA object could not be found.
    DS_CANT_FIND_DSA_OBJ = 8419

    # The naming context could not be found.
    DS_CANT_FIND_EXPECTED_NC = 8420

    # The naming context could not be found in the cache.
    DS_CANT_FIND_NC_IN_CACHE = 8421

    # The child object could not be retrieved.
    DS_CANT_RETRIEVE_CHILD = 8422

    # The modification was not permitted for security reasons.
    DS_SECURITY_ILLEGAL_MODIFY = 8423

    # The operation cannot replace the hidden record.
    DS_CANT_REPLACE_HIDDEN_REC = 8424

    # The hierarchy file is invalid.
    DS_BAD_HIERARCHY_FILE = 8425

    # The attempt to build the hierarchy table failed.
    DS_BUILD_HIERARCHY_TABLE_FAILED = 8426

    # The directory configuration parameter is missing from the registry.
    DS_CONFIG_PARAM_MISSING = 8427

    # The attempt to count the address book indices failed.
    DS_COUNTING_AB_INDICES_FAILED = 8428

    # The allocation of the hierarchy table failed.
    DS_HIERARCHY_TABLE_MALLOC_FAILED = 8429

    # The directory service encountered an internal failure.
    DS_INTERNAL_FAILURE = 8430

    # The directory service encountered an unknown failure.
    DS_UNKNOWN_ERROR = 8431

    # A root object requires a class of 'top'.
    DS_ROOT_REQUIRES_CLASS_TOP = 8432

    # This directory server is shutting down, and cannot take ownership of new floating single-master operation roles.
    DS_REFUSING_FSMO_ROLES = 8433

    # The directory service is missing mandatory configuration information, and is unable to determine the ownership of floating single-master operation roles.
    DS_MISSING_FSMO_SETTINGS = 8434

    # The directory service was unable to transfer ownership of one or more floating single-master operation roles to other servers.
    DS_UNABLE_TO_SURRENDER_ROLES = 8435

    # The replication operation failed.
    DS_DRA_GENERIC = 8436

    # An invalid parameter was specified for this replication operation.
    DS_DRA_INVALID_PARAMETER = 8437

    # The directory service is too busy to complete the replication operation at this time.
    DS_DRA_BUSY = 8438

    # The distinguished name specified for this replication operation is invalid.
    DS_DRA_BAD_DN = 8439

    # The naming context specified for this replication operation is invalid.
    DS_DRA_BAD_NC = 8440

    # The distinguished name specified for this replication operation already exists.
    DS_DRA_DN_EXISTS = 8441

    # The replication system encountered an internal error.
    DS_DRA_INTERNAL_ERROR = 8442

    # The replication operation encountered a database inconsistency.
    DS_DRA_INCONSISTENT_DIT = 8443

    # The server specified for this replication operation could not be contacted.
    DS_DRA_CONNECTION_FAILED = 8444

    # The replication operation encountered an object with an invalid instance type.
    DS_DRA_BAD_INSTANCE_TYPE = 8445

    # The replication operation failed to allocate memory.
    DS_DRA_OUT_OF_MEM = 8446

    # The replication operation encountered an error with the mail system.
    DS_DRA_MAIL_PROBLEM = 8447

    # The replication reference information for the target server already exists.
    DS_DRA_REF_ALREADY_EXISTS = 8448

    # The replication reference information for the target server does not exist.
    DS_DRA_REF_NOT_FOUND = 8449

    # The naming context cannot be removed because it is replicated to another server.
    DS_DRA_OBJ_IS_REP_SOURCE = 8450

    # The replication operation encountered a database error.
    DS_DRA_DB_ERROR = 8451

    # The naming context is in the process of being removed or is not replicated from the specified server.
    DS_DRA_NO_REPLICA = 8452

    # Replication access was denied.
    DS_DRA_ACCESS_DENIED = 8453

    # The requested operation is not supported by this version of the directory service.
    DS_DRA_NOT_SUPPORTED = 8454

    # The replication remote procedure call was cancelled.
    DS_DRA_RPC_CANCELLED = 8455

    # The source server is currently rejecting replication requests.
    DS_DRA_SOURCE_DISABLED = 8456

    # The destination server is currently rejecting replication requests.
    DS_DRA_SINK_DISABLED = 8457

    # The replication operation failed due to a collision of object names.
    DS_DRA_NAME_COLLISION = 8458

    # The replication source has been reinstalled.
    DS_DRA_SOURCE_REINSTALLED = 8459

    # The replication operation failed because a required parent object is missing.
    DS_DRA_MISSING_PARENT = 8460

    # The replication operation was preempted.
    DS_DRA_PREEMPTED = 8461

    # The replication synchronization attempt was abandoned because of a lack of updates.
    DS_DRA_ABANDON_SYNC = 8462

    # The replication operation was terminated because the system is shutting down.
    DS_DRA_SHUTDOWN = 8463

    # The replication synchronization attempt failed as the destination partial attribute set is not a subset of source partial attribute set.
    DS_DRA_INCOMPATIBLE_PARTIAL_SET = 8464

    # The replication synchronization attempt failed because a master replica attempted to sync from a partial replica.
    DS_DRA_SOURCE_IS_PARTIAL_REPLICA = 8465

    # The server specified for this replication operation was contacted, but that server was unable to contact an additional server needed to complete the operation.
    DS_DRA_EXTN_CONNECTION_FAILED = 8466

    # The version of the Active Directory schema of the source forest is not compatible with the version of Active Directory on this computer.  You must upgrade the operating system on a domain controller in the source forest before this computer can be added as a domain controller to that forest.
    DS_INSTALL_SCHEMA_MISMATCH = 8467

    # Schema update failed: An attribute with the same link identifier already exists.
    DS_DUP_LINK_ID = 8468

    # Name translation: Generic processing error.
    DS_NAME_ERROR_RESOLVING = 8469

    # Name translation: Could not find the name or insufficient right to see name.
    DS_NAME_ERROR_NOT_FOUND = 8470

    # Name translation: Input name mapped to more than one output name.
    DS_NAME_ERROR_NOT_UNIQUE = 8471

    # Name translation: Input name found, but not the associated output format.
    DS_NAME_ERROR_NO_MAPPING = 8472

    # Name translation: Unable to resolve completely, only the domain was found.
    DS_NAME_ERROR_DOMAIN_ONLY = 8473

    # Name translation: Unable to perform purely syntactical mapping at the client without going out to the wire.
    DS_NAME_ERROR_NO_SYNTACTICAL_MAPPING = 8474

    # Modification of a constructed att is not allowed.
    DS_CONSTRUCTED_ATT_MOD = 8475

    # The OM-Object-Class specified is incorrect for an attribute with the specified syntax.
    DS_WRONG_OM_OBJ_CLASS = 8476

    # The replication request has been posted, waiting for reply.
    DS_DRA_REPL_PENDING = 8477

    # The requested operation requires a directory service, and none was available.
    DS_DS_REQUIRED = 8478

    # The LDAP display name of the class or attribute contains non-ASCII characters.
    DS_INVALID_LDAP_DISPLAY_NAME = 8479

    # The requested search operation is only supported for base searches.
    DS_NON_BASE_SEARCH = 8480

    # The search failed to retrieve attributes from the database.
    DS_CANT_RETRIEVE_ATTS = 8481

    # The schema update operation tried to add a backward link attribute that has no corresponding forward link.
    DS_BACKLINK_WITHOUT_LINK = 8482

    # Source and destination of a cross-domain move do not agree on the object's epoch number.  Either source or destination does not have the latest version of the object.
    DS_EPOCH_MISMATCH = 8483

    # Source and destination of a cross-domain move do not agree on the object's current name.  Either source or destination does not have the latest version of the object.
    DS_SRC_NAME_MISMATCH = 8484

    # Source and destination for the cross-domain move operation are identical.  Caller should use local move operation instead of cross-domain move operation.
    DS_SRC_AND_DST_NC_IDENTICAL = 8485

    # Source and destination for a cross-domain move are not in agreement on the naming contexts in the forest.  Either source or destination does not have the latest version of the Partitions container.
    DS_DST_NC_MISMATCH = 8486

    # Destination of a cross-domain move is not authoritative for the destination naming context.
    DS_NOT_AUTHORITIVE_FOR_DST_NC = 8487

    # Source and destination of a cross-domain move do not agree on the identity of the source object.  Either source or destination does not have the latest version of the source object.
    DS_SRC_GUID_MISMATCH = 8488

    # Object being moved across-domains is already known to be deleted by the destination server.  The source server does not have the latest version of the source object.
    DS_CANT_MOVE_DELETED_OBJECT = 8489

    # Another operation which requires exclusive access to the PDC FSMO is already in progress.
    DS_PDC_OPERATION_IN_PROGRESS = 8490

    # A cross-domain move operation failed such that two versions of the moved object exist - one each in the source and destination domains.  The destination object needs to be removed to restore the system to a consistent state.
    DS_CROSS_DOMAIN_CLEANUP_REQD = 8491

    # This object may not be moved across domain boundaries either because cross-domain moves for this class are disallowed, or the object has some special characteristics, eg: trust account or restricted RID, which prevent its move.
    DS_ILLEGAL_XDOM_MOVE_OPERATION = 8492

    # Can't move objects with memberships across domain boundaries as once moved, this would violate the membership conditions of the account group.  Remove the object from any account group memberships and retry.
    DS_CANT_WITH_ACCT_GROUP_MEMBERSHPS = 8493

    # A naming context head must be the immediate child of another naming context head, not of an interior node.
    DS_NC_MUST_HAVE_NC_PARENT = 8494

    # The directory cannot validate the proposed naming context name because it does not hold a replica of the naming context above the proposed naming context.  Please ensure that the domain naming master role is held by a server that is configured as a global catalog server, and that the server is up to date with its replication partners. (Applies only to Windows 2000 Domain Naming masters)
    DS_CR_IMPOSSIBLE_TO_VALIDATE = 8495

    # Destination domain must be in native mode.
    DS_DST_DOMAIN_NOT_NATIVE = 8496

    # The operation can not be performed because the server does not have an infrastructure container in the domain of interest.
    DS_MISSING_INFRASTRUCTURE_CONTAINER = 8497

    # Cross-domain move of non-empty account groups is not allowed.
    DS_CANT_MOVE_ACCOUNT_GROUP = 8498

    # Cross-domain move of non-empty resource groups is not allowed.
    DS_CANT_MOVE_RESOURCE_GROUP = 8499

    # The search flags for the attribute are invalid. The ANR bit is valid only on attributes of Unicode or Teletex strings.
    DS_INVALID_SEARCH_FLAG = 8500

    # Tree deletions starting at an object which has an NC head as a descendant are not allowed.
    DS_NO_TREE_DELETE_ABOVE_NC = 8501

    # The directory service failed to lock a tree in preparation for a tree deletion because the tree was in use.
    DS_COULDNT_LOCK_TREE_FOR_DELETE = 8502

    # The directory service failed to identify the list of objects to delete while attempting a tree deletion.
    DS_COULDNT_IDENTIFY_OBJECTS_FOR_TREE_DELETE = 8503

    # Security Accounts Manager initialization failed because of the following error: %1.
    # Error Status: 0x%2. Click OK to shut down the system and reboot into Directory Services Restore Mode. Check the event log for detailed information.
    DS_SAM_INIT_FAILURE = 8504

    # Only an administrator can modify the membership list of an administrative group.
    DS_SENSITIVE_GROUP_VIOLATION = 8505

    # Cannot change the primary group ID of a domain controller account.
    DS_CANT_MOD_PRIMARYGROUPID = 8506

    # An attempt is made to modify the base schema.
    DS_ILLEGAL_BASE_SCHEMA_MOD = 8507

    # Adding a new mandatory attribute to an existing class, deleting a mandatory attribute from an existing class, or adding an optional attribute to the special class Top that is not a backlink attribute (directly or through inheritance, for example, by adding or deleting an auxiliary class) is not allowed.
    DS_NONSAFE_SCHEMA_CHANGE = 8508

    # Schema update is not allowed on this DC because the DC is not the schema FSMO Role Owner.
    DS_SCHEMA_UPDATE_DISALLOWED = 8509

    # An object of this class cannot be created under the schema container. You can only create attribute-schema and class-schema objects under the schema container.
    DS_CANT_CREATE_UNDER_SCHEMA = 8510

    # The replica/child install failed to get the objectVersion attribute on the schema container on the source DC. Either the attribute is missing on the schema container or the credentials supplied do not have permission to read it.
    DS_INSTALL_NO_SRC_SCH_VERSION = 8511

    # The replica/child install failed to read the objectVersion attribute in the SCHEMA section of the file schema.ini in the system32 directory.
    DS_INSTALL_NO_SCH_VERSION_IN_INIFILE = 8512

    # The specified group type is invalid.
    DS_INVALID_GROUP_TYPE = 8513

    # You cannot nest global groups in a mixed domain if the group is security-enabled.
    DS_NO_NEST_GLOBALGROUP_IN_MIXEDDOMAIN = 8514

    # You cannot nest local groups in a mixed domain if the group is security-enabled.
    DS_NO_NEST_LOCALGROUP_IN_MIXEDDOMAIN = 8515

    # A global group cannot have a local group as a member.
    DS_GLOBAL_CANT_HAVE_LOCAL_MEMBER = 8516

    # A global group cannot have a universal group as a member.
    DS_GLOBAL_CANT_HAVE_UNIVERSAL_MEMBER = 8517

    # A universal group cannot have a local group as a member.
    DS_UNIVERSAL_CANT_HAVE_LOCAL_MEMBER = 8518

    # A global group cannot have a cross-domain member.
    DS_GLOBAL_CANT_HAVE_CROSSDOMAIN_MEMBER = 8519

    # A local group cannot have another cross domain local group as a member.
    DS_LOCAL_CANT_HAVE_CROSSDOMAIN_LOCAL_MEMBER = 8520

    # A group with primary members cannot change to a security-disabled group.
    DS_HAVE_PRIMARY_MEMBERS = 8521

    # The schema cache load failed to convert the string default SD on a class-schema object.
    DS_STRING_SD_CONVERSION_FAILED = 8522

    # Only DSAs configured to be Global Catalog servers should be allowed to hold the Domain Naming Master FSMO role. (Applies only to Windows 2000 servers)
    DS_NAMING_MASTER_GC = 8523

    # The DSA operation is unable to proceed because of a DNS lookup failure.
    DS_DNS_LOOKUP_FAILURE = 8524

    # While processing a change to the DNS Host Name for an object, the Service Principal Name values could not be kept in sync.
    DS_COULDNT_UPDATE_SPNS = 8525

    # The Security Descriptor attribute could not be read.
    DS_CANT_RETRIEVE_SD = 8526

    # The object requested was not found, but an object with that key was found.
    DS_KEY_NOT_UNIQUE = 8527

    # The syntax of the linked attribute being added is incorrect. Forward links can only have syntax 2.5.5.1, 2.5.5.7, and 2.5.5.14, and backlinks can only have syntax 2.5.5.1
    DS_WRONG_LINKED_ATT_SYNTAX = 8528

    # Security Account Manager needs to get the boot password.
    DS_SAM_NEED_BOOTKEY_PASSWORD = 8529

    # Security Account Manager needs to get the boot key from floppy disk.
    DS_SAM_NEED_BOOTKEY_FLOPPY = 8530

    # Directory Service cannot start.
    DS_CANT_START = 8531

    # Directory Services could not start.
    DS_INIT_FAILURE = 8532

    # The connection between client and server requires packet privacy or better.
    DS_NO_PKT_PRIVACY_ON_CONNECTION = 8533

    # The source domain may not be in the same forest as destination.
    DS_SOURCE_DOMAIN_IN_FOREST = 8534

    # The destination domain must be in the forest.
    DS_DESTINATION_DOMAIN_NOT_IN_FOREST = 8535

    # The operation requires that destination domain auditing be enabled.
    DS_DESTINATION_AUDITING_NOT_ENABLED = 8536

    # The operation couldn't locate a DC for the source domain.
    DS_CANT_FIND_DC_FOR_SRC_DOMAIN = 8537

    # The source object must be a group or user.
    DS_SRC_OBJ_NOT_GROUP_OR_USER = 8538

    # The source object's SID already exists in destination forest.
    DS_SRC_SID_EXISTS_IN_FOREST = 8539

    # The source and destination object must be of the same type.
    DS_SRC_AND_DST_OBJECT_CLASS_MISMATCH = 8540

    # Security Accounts Manager initialization failed because of the following error: %1.
    # Error Status: 0x%2. Click OK to shut down the system and reboot into Safe Mode. Check the event log for detailed information.
    SAM_INIT_FAILURE = 8541

    # Schema information could not be included in the replication request.
    DS_DRA_SCHEMA_INFO_SHIP = 8542

    # The replication operation could not be completed due to a schema incompatibility.
    DS_DRA_SCHEMA_CONFLICT = 8543

    # The replication operation could not be completed due to a previous schema incompatibility.
    DS_DRA_EARLIER_SCHEMA_CONFLICT = 8544

    # The replication update could not be applied because either the source or the destination has not yet received information regarding a recent cross-domain move operation.
    DS_DRA_OBJ_NC_MISMATCH = 8545

    # The requested domain could not be deleted because there exist domain controllers that still host this domain.
    DS_NC_STILL_HAS_DSAS = 8546

    # The requested operation can be performed only on a global catalog server.
    DS_GC_REQUIRED = 8547

    # A local group can only be a member of other local groups in the same domain.
    DS_LOCAL_MEMBER_OF_LOCAL_ONLY = 8548

    # Foreign security principals cannot be members of universal groups.
    DS_NO_FPO_IN_UNIVERSAL_GROUPS = 8549

    # The attribute is not allowed to be replicated to the GC because of security reasons.
    DS_CANT_ADD_TO_GC = 8550

    # The checkpoint with the PDC could not be taken because there too many modifications being processed currently.
    DS_NO_CHECKPOINT_WITH_PDC = 8551

    # The operation requires that source domain auditing be enabled.
    DS_SOURCE_AUDITING_NOT_ENABLED = 8552

    # Security principal objects can only be created inside domain naming contexts.
    DS_CANT_CREATE_IN_NONDOMAIN_NC = 8553

    # A Service Principal Name (SPN) could not be constructed because the provided hostname is not in the necessary format.
    DS_INVALID_NAME_FOR_SPN = 8554

    # A Filter was passed that uses constructed attributes.
    DS_FILTER_USES_CONTRUCTED_ATTRS = 8555

    # The unicodePwd attribute value must be enclosed in double quotes.
    DS_UNICODEPWD_NOT_IN_QUOTES = 8556

    # Your computer could not be joined to the domain. You have exceeded the maximum number of computer accounts you are allowed to create in this domain. Contact your system administrator to have this limit reset or increased.
    DS_MACHINE_ACCOUNT_QUOTA_EXCEEDED = 8557

    # For security reasons, the operation must be run on the destination DC.
    DS_MUST_BE_RUN_ON_DST_DC = 8558

    # For security reasons, the source DC must be NT4SP4 or greater.
    DS_SRC_DC_MUST_BE_SP4_OR_GREATER = 8559

    # Critical Directory Service System objects cannot be deleted during tree delete operations.  The tree delete may have been partially performed.
    DS_CANT_TREE_DELETE_CRITICAL_OBJ = 8560

    # Directory Services could not start because of the following error: %1.
    # Error Status: 0x%2. Please click OK to shutdown the system. You can use the recovery console to diagnose the system further.
    DS_INIT_FAILURE_CONSOLE = 8561

    # Security Accounts Manager initialization failed because of the following error: %1.
    # Error Status: 0x%2. Please click OK to shutdown the system. You can use the recovery console to diagnose the system further.
    DS_SAM_INIT_FAILURE_CONSOLE = 8562

    # This version of Windows is too old to support the current directory forest behavior.  You must upgrade the operating system on this server before it can become a domain controller in this forest.
    DS_FOREST_VERSION_TOO_HIGH = 8563

    # This version of Windows is too old to support the current domain behavior.  You must upgrade the operating system on this server before it can become a domain controller in this domain.
    DS_DOMAIN_VERSION_TOO_HIGH = 8564

    # This version of Windows no longer supports the behavior version in use in this directory forest.  You must advance the forest behavior version before this server can become a domain controller in the forest.
    DS_FOREST_VERSION_TOO_LOW = 8565

    # This version of Windows no longer supports the behavior version in use in this domain.  You must advance the domain behavior version before this server can become a domain controller in the domain.
    DS_DOMAIN_VERSION_TOO_LOW = 8566

    # The version of Windows is incompatible with the behavior version of the domain or forest.
    DS_INCOMPATIBLE_VERSION = 8567

    # The behavior version cannot be increased to the requested value because Domain Controllers still exist with versions lower than the requested value.
    DS_LOW_DSA_VERSION = 8568

    # The behavior version value cannot be increased while the domain is still in mixed domain mode.  You must first change the domain to native mode before increasing the behavior version.
    DS_NO_BEHAVIOR_VERSION_IN_MIXEDDOMAIN = 8569

    # The sort order requested is not supported.
    DS_NOT_SUPPORTED_SORT_ORDER = 8570

    # Found an object with a non unique name.
    DS_NAME_NOT_UNIQUE = 8571

    # The machine account was created pre-NT4.  The account needs to be recreated.
    DS_MACHINE_ACCOUNT_CREATED_PRENT4 = 8572

    # The database is out of version store.
    DS_OUT_OF_VERSION_STORE = 8573

    # Unable to continue operation because multiple conflicting controls were used.
    DS_INCOMPATIBLE_CONTROLS_USED = 8574

    # Unable to find a valid security descriptor reference domain for this partition.
    DS_NO_REF_DOMAIN = 8575

    # Schema update failed: The link identifier is reserved.
    DS_RESERVED_LINK_ID = 8576

    # Schema update failed: There are no link identifiers available.
    DS_LINK_ID_NOT_AVAILABLE = 8577

    # A account group can not have a universal group as a member.
    DS_AG_CANT_HAVE_UNIVERSAL_MEMBER = 8578

    # Rename or move operations on naming context heads or read-only objects are not allowed.
    DS_MODIFYDN_DISALLOWED_BY_INSTANCE_TYPE = 8579

    # Move operations on objects in the schema naming context are not allowed.
    DS_NO_OBJECT_MOVE_IN_SCHEMA_NC = 8580

    # A system flag has been set on the object and does not allow the object to be moved or renamed.
    DS_MODIFYDN_DISALLOWED_BY_FLAG = 8581

    # This object is not allowed to change its grandparent container. Moves are not forbidden on this object, but are restricted to sibling containers.
    DS_MODIFYDN_WRONG_GRANDPARENT = 8582

    # Unable to resolve completely, a referral to another forest is generated.
    DS_NAME_ERROR_TRUST_REFERRAL = 8583

    # The requested action is not supported on standard server.
    NOT_SUPPORTED_ON_STANDARD_SERVER = 8584

    # Could not access a partition of the Active Directory located on a remote server.  Make sure at least one server is running for the partition in question.
    DS_CANT_ACCESS_REMOTE_PART_OF_AD = 8585

    # The directory cannot validate the proposed naming context (or partition) name because it does not hold a replica nor can it contact a replica of the naming context above the proposed naming context.  Please ensure that the parent naming context is properly registered in DNS, and at least one replica of this naming context is reachable by the Domain Naming master.
    DS_CR_IMPOSSIBLE_TO_VALIDATE_V2 = 8586

    # The thread limit for this request was exceeded.
    DS_THREAD_LIMIT_EXCEEDED = 8587

    # The Global catalog server is not in the closest site.
    DS_NOT_CLOSEST = 8588

    # The DS cannot derive a service principal name (SPN) with which to mutually authenticate the target server because the corresponding server object in the local DS database has no serverReference attribute.
    DS_CANT_DERIVE_SPN_WITHOUT_SERVER_REF = 8589

    # The Directory Service failed to enter single user mode.
    DS_SINGLE_USER_MODE_FAILED = 8590

    # The Directory Service cannot parse the script because of a syntax error.
    DS_NTDSCRIPT_SYNTAX_ERROR = 8591

    # The Directory Service cannot process the script because of an error.
    DS_NTDSCRIPT_PROCESS_ERROR = 8592

    # The directory service cannot perform the requested operation because the servers
    # involved are of different replication epochs (which is usually related to a
    # domain rename that is in progress).
    DS_DIFFERENT_REPL_EPOCHS = 8593

    # The directory service binding must be renegotiated due to a change in the server
    # extensions information.
    DS_DRS_EXTENSIONS_CHANGED = 8594

    # Operation not allowed on a disabled cross ref.
    DS_REPLICA_SET_CHANGE_NOT_ALLOWED_ON_DISABLED_CR = 8595

    # Schema update failed: No values for msDS-IntId are available.
    DS_NO_MSDS_INTID = 8596

    # Schema update failed: Duplicate msDS-INtId. Retry the operation.
    DS_DUP_MSDS_INTID = 8597

    # Schema deletion failed: attribute is used in rDNAttID.
    DS_EXISTS_IN_RDNATTID = 8598

    # The directory service failed to authorize the request.
    DS_AUTHORIZATION_FAILED = 8599

    # The Directory Service cannot process the script because it is invalid.
    DS_INVALID_SCRIPT = 8600

    # The remote create cross reference operation failed on the Domain Naming Master FSMO.  The operation's error is in the extended data.
    DS_REMOTE_CROSSREF_OP_FAILED = 8601

    # No information avialable.
    DS_CROSS_REF_BUSY = 8602

    # No information avialable.
    DS_CANT_DERIVE_SPN_FOR_DELETED_DOMAIN = 8603

    # No information avialable.
    DS_CANT_DEMOTE_WITH_WRITEABLE_NC = 8604

    # No information avialable.
    DS_DUPLICATE_ID_FOUND = 8605

    # No information avialable.
    DS_INSUFFICIENT_ATTR_TO_CREATE_OBJECT = 8606

    # No information avialable.
    DS_GROUP_CONVERSION_ERROR = 8607

    # No information avialable.
    DS_CANT_MOVE_APP_BASIC_GROUP = 8608

    # No information avialable.
    DS_CANT_MOVE_APP_QUERY_GROUP = 8609

    # No information avialable.
    DS_ROLE_NOT_VERIFIED = 8610

    # No information avialable.
    DS_WKO_CONTAINER_CANNOT_BE_SPECIAL = 8611

    # No information avialable.
    DS_DOMAIN_RENAME_IN_PROGRESS = 8612

    # No information avialable.
    DS_EXISTING_AD_CHILD_NC = 8613

    # No information avialable.
    DS_REPL_LIFETIME_EXCEEDED = 8614

    # No information avialable.
    DS_DISALLOWED_IN_SYSTEM_CONTAINER = 8615

    # No information avialable.
    DS_LDAP_SEND_QUEUE_FULL = 8616

    # No information avialable.
    DNS_ERROR_RESPONSE_CODES_BASE = 9000

    # DNS server unable to interpret format.
    DNS_ERROR_RCODE_FORMAT_ERROR = 9001

    # DNS server failure.
    DNS_ERROR_RCODE_SERVER_FAILURE = 9002

    # DNS name does not exist.
    DNS_ERROR_RCODE_NAME_ERROR = 9003

    # DNS request not supported by name server.
    DNS_ERROR_RCODE_NOT_IMPLEMENTED = 9004

    # DNS operation refused.
    DNS_ERROR_RCODE_REFUSED = 9005

    # DNS name that ought not exist, does exist.
    DNS_ERROR_RCODE_YXDOMAIN = 9006

    # DNS RR set that ought not exist, does exist.
    DNS_ERROR_RCODE_YXRRSET = 9007

    # DNS RR set that ought to exist, does not exist.
    DNS_ERROR_RCODE_NXRRSET = 9008

    # DNS server not authoritative for zone.
    DNS_ERROR_RCODE_NOTAUTH = 9009

    # DNS name in update or prereq is not in zone.
    DNS_ERROR_RCODE_NOTZONE = 9010

    # DNS signature failed to verify.
    DNS_ERROR_RCODE_BADSIG = 9016

    # DNS bad key.
    DNS_ERROR_RCODE_BADKEY = 9017

    # DNS signature validity expired.
    DNS_ERROR_RCODE_BADTIME = 9018

    # No information avialable.
    DNS_ERROR_PACKET_FMT_BASE = 9500

    # No records found for given DNS query.
    DNS_INFO_NO_RECORDS = 9501

    # Bad DNS packet.
    DNS_ERROR_BAD_PACKET = 9502

    # No DNS packet.
    DNS_ERROR_NO_PACKET = 9503

    # DNS error, check rcode.
    DNS_ERROR_RCODE = 9504

    # Unsecured DNS packet.
    DNS_ERROR_UNSECURE_PACKET = 9505

    # No information avialable.
    DNS_ERROR_GENERAL_API_BASE = 9550

    # Invalid DNS type.
    DNS_ERROR_INVALID_TYPE = 9551

    # Invalid IP address.
    DNS_ERROR_INVALID_IP_ADDRESS = 9552

    # Invalid property.
    DNS_ERROR_INVALID_PROPERTY = 9553

    # Try DNS operation again later.
    DNS_ERROR_TRY_AGAIN_LATER = 9554

    # Record for given name and type is not unique.
    DNS_ERROR_NOT_UNIQUE = 9555

    # DNS name does not comply with RFC specifications.
    DNS_ERROR_NON_RFC_NAME = 9556

    # DNS name is a fully-qualified DNS name.
    DNS_STATUS_FQDN = 9557

    # DNS name is dotted (multi-label).
    DNS_STATUS_DOTTED_NAME = 9558

    # DNS name is a single-part name.
    DNS_STATUS_SINGLE_PART_NAME = 9559

    # DNS name contains an invalid character.
    DNS_ERROR_INVALID_NAME_CHAR = 9560

    # DNS name is entirely numeric.
    DNS_ERROR_NUMERIC_NAME = 9561

    # The operation requested is not permitted on a DNS root server.
    DNS_ERROR_NOT_ALLOWED_ON_ROOT_SERVER = 9562

    # No information avialable.
    DNS_ERROR_NOT_ALLOWED_UNDER_DELEGATION = 9563

    # No information avialable.
    DNS_ERROR_CANNOT_FIND_ROOT_HINTS = 9564

    # No information avialable.
    DNS_ERROR_INCONSISTENT_ROOT_HINTS = 9565

    # No information avialable.
    DNS_ERROR_ZONE_BASE = 9600

    # DNS zone does not exist.
    DNS_ERROR_ZONE_DOES_NOT_EXIST = 9601

    # DNS zone information not available.
    DNS_ERROR_NO_ZONE_INFO = 9602

    # Invalid operation for DNS zone.
    DNS_ERROR_INVALID_ZONE_OPERATION = 9603

    # Invalid DNS zone configuration.
    DNS_ERROR_ZONE_CONFIGURATION_ERROR = 9604

    # DNS zone has no start of authority (SOA) record.
    DNS_ERROR_ZONE_HAS_NO_SOA_RECORD = 9605

    # DNS zone has no Name Server (NS) record.
    DNS_ERROR_ZONE_HAS_NO_NS_RECORDS = 9606

    # DNS zone is locked.
    DNS_ERROR_ZONE_LOCKED = 9607

    # DNS zone creation failed.
    DNS_ERROR_ZONE_CREATION_FAILED = 9608

    # DNS zone already exists.
    DNS_ERROR_ZONE_ALREADY_EXISTS = 9609

    # DNS automatic zone already exists.
    DNS_ERROR_AUTOZONE_ALREADY_EXISTS = 9610

    # Invalid DNS zone type.
    DNS_ERROR_INVALID_ZONE_TYPE = 9611

    # Secondary DNS zone requires master IP address.
    DNS_ERROR_SECONDARY_REQUIRES_MASTER_IP = 9612

    # DNS zone not secondary.
    DNS_ERROR_ZONE_NOT_SECONDARY = 9613

    # Need secondary IP address.
    DNS_ERROR_NEED_SECONDARY_ADDRESSES = 9614

    # WINS initialization failed.
    DNS_ERROR_WINS_INIT_FAILED = 9615

    # Need WINS servers.
    DNS_ERROR_NEED_WINS_SERVERS = 9616

    # NBTSTAT initialization call failed.
    DNS_ERROR_NBSTAT_INIT_FAILED = 9617

    # Invalid delete of start of authority (SOA)
    DNS_ERROR_SOA_DELETE_INVALID = 9618

    # A conditional forwarding zone already exists for that name.
    DNS_ERROR_FORWARDER_ALREADY_EXISTS = 9619

    # This zone must be configured with one or more master DNS server IP addresses.
    DNS_ERROR_ZONE_REQUIRES_MASTER_IP = 9620

    # The operation cannot be performed because this zone is shutdown.
    DNS_ERROR_ZONE_IS_SHUTDOWN = 9621

    # No information avialable.
    DNS_ERROR_DATAFILE_BASE = 9650

    # Primary DNS zone requires datafile.
    DNS_ERROR_PRIMARY_REQUIRES_DATAFILE = 9651

    # Invalid datafile name for DNS zone.
    DNS_ERROR_INVALID_DATAFILE_NAME = 9652

    # Failed to open datafile for DNS zone.
    DNS_ERROR_DATAFILE_OPEN_FAILURE = 9653

    # Failed to write datafile for DNS zone.
    DNS_ERROR_FILE_WRITEBACK_FAILED = 9654

    # Failure while reading datafile for DNS zone.
    DNS_ERROR_DATAFILE_PARSING = 9655

    # No information avialable.
    DNS_ERROR_DATABASE_BASE = 9700

    # DNS record does not exist.
    DNS_ERROR_RECORD_DOES_NOT_EXIST = 9701

    # DNS record format error.
    DNS_ERROR_RECORD_FORMAT = 9702

    # Node creation failure in DNS.
    DNS_ERROR_NODE_CREATION_FAILED = 9703

    # Unknown DNS record type.
    DNS_ERROR_UNKNOWN_RECORD_TYPE = 9704

    # DNS record timed out.
    DNS_ERROR_RECORD_TIMED_OUT = 9705

    # Name not in DNS zone.
    DNS_ERROR_NAME_NOT_IN_ZONE = 9706

    # CNAME loop detected.
    DNS_ERROR_CNAME_LOOP = 9707

    # Node is a CNAME DNS record.
    DNS_ERROR_NODE_IS_CNAME = 9708

    # A CNAME record already exists for given name.
    DNS_ERROR_CNAME_COLLISION = 9709

    # Record only at DNS zone root.
    DNS_ERROR_RECORD_ONLY_AT_ZONE_ROOT = 9710

    # DNS record already exists.
    DNS_ERROR_RECORD_ALREADY_EXISTS = 9711

    # Secondary DNS zone data error.
    DNS_ERROR_SECONDARY_DATA = 9712

    # Could not create DNS cache data.
    DNS_ERROR_NO_CREATE_CACHE_DATA = 9713

    # DNS name does not exist.
    DNS_ERROR_NAME_DOES_NOT_EXIST = 9714

    # Could not create pointer (PTR) record.
    DNS_WARNING_PTR_CREATE_FAILED = 9715

    # DNS domain was undeleted.
    DNS_WARNING_DOMAIN_UNDELETED = 9716

    # The directory service is unavailable.
    DNS_ERROR_DS_UNAVAILABLE = 9717

    # DNS zone already exists in the directory service.
    DNS_ERROR_DS_ZONE_ALREADY_EXISTS = 9718

    # DNS server not creating or reading the boot file for the directory service integrated DNS zone.
    DNS_ERROR_NO_BOOTFILE_IF_DS_ZONE = 9719

    # No information avialable.
    DNS_ERROR_OPERATION_BASE = 9750

    # DNS AXFR (zone transfer) complete.
    DNS_INFO_AXFR_COMPLETE = 9751

    # DNS zone transfer failed.
    DNS_ERROR_AXFR = 9752

    # Added local WINS server.
    DNS_INFO_ADDED_LOCAL_WINS = 9753

    # No information avialable.
    DNS_ERROR_SECURE_BASE = 9800

    # Secure update call needs to continue update request.
    DNS_STATUS_CONTINUE_NEEDED = 9801

    # No information avialable.
    DNS_ERROR_SETUP_BASE = 9850

    # TCP/IP network protocol not installed.
    DNS_ERROR_NO_TCPIP = 9851

    # No DNS servers configured for local system.
    DNS_ERROR_NO_DNS_SERVERS = 9852

    # No information avialable.
    DNS_ERROR_DP_BASE = 9900

    # The specified directory partition does not exist.
    DNS_ERROR_DP_DOES_NOT_EXIST = 9901

    # The specified directory partition already exists.
    DNS_ERROR_DP_ALREADY_EXISTS = 9902

    # The DS is not enlisted in the specified directory partition.
    DNS_ERROR_DP_NOT_ENLISTED = 9903

    # The DS is already enlisted in the specified directory partition.
    DNS_ERROR_DP_ALREADY_ENLISTED = 9904

    # No information avialable.
    DNS_ERROR_DP_NOT_AVAILABLE = 9905

    # No information avialable.
    WSABASEERR = 10000

    # A blocking operation was interrupted by a call to WSACancelBlockingCall.
    WSAEINTR = 10004

    # The file handle supplied is not valid.
    WSAEBADF = 10009

    # An attempt was made to access a socket in a way forbidden by its access permissions.
    WSAEACCES = 10013

    # The system detected an invalid pointer address in attempting to use a pointer argument in a call.
    WSAEFAULT = 10014

    # An invalid argument was supplied.
    WSAEINVAL = 10022

    # Too many open sockets.
    WSAEMFILE = 10024

    # A non-blocking socket operation could not be completed immediately.
    WSAEWOULDBLOCK = 10035

    # A blocking operation is currently executing.
    WSAEINPROGRESS = 10036

    # An operation was attempted on a non-blocking socket that already had an operation in progress.
    WSAEALREADY = 10037

    # An operation was attempted on something that is not a socket.
    WSAENOTSOCK = 10038

    # A required address was omitted from an operation on a socket.
    WSAEDESTADDRREQ = 10039

    # A message sent on a datagram socket was larger than the internal message buffer or some other network limit, or the buffer used to receive a datagram into was smaller than the datagram itself.
    WSAEMSGSIZE = 10040

    # A protocol was specified in the socket function call that does not support the semantics of the socket type requested.
    WSAEPROTOTYPE = 10041

    # An unknown, invalid, or unsupported option or level was specified in a getsockopt or setsockopt call.
    WSAENOPROTOOPT = 10042

    # The requested protocol has not been configured into the system, or no implementation for it exists.
    WSAEPROTONOSUPPORT = 10043

    # The support for the specified socket type does not exist in this address family.
    WSAESOCKTNOSUPPORT = 10044

    # The attempted operation is not supported for the type of object referenced.
    WSAEOPNOTSUPP = 10045

    # The protocol family has not been configured into the system or no implementation for it exists.
    WSAEPFNOSUPPORT = 10046

    # An address incompatible with the requested protocol was used.
    WSAEAFNOSUPPORT = 10047

    # Only one usage of each socket address (protocol/network address/port) is normally permitted.
    WSAEADDRINUSE = 10048

    # The requested address is not valid in its context.
    WSAEADDRNOTAVAIL = 10049

    # A socket operation encountered a dead network.
    WSAENETDOWN = 10050

    # A socket operation was attempted to an unreachable network.
    WSAENETUNREACH = 10051

    # The connection has been broken due to keep-alive activity detecting a failure while the operation was in progress.
    WSAENETRESET = 10052

    # An established connection was aborted by the software in your host machine.
    WSAECONNABORTED = 10053

    # An existing connection was forcibly closed by the remote host.
    WSAECONNRESET = 10054

    # An operation on a socket could not be performed because the system lacked sufficient buffer space or because a queue was full.
    WSAENOBUFS = 10055

    # A connect request was made on an already connected socket.
    WSAEISCONN = 10056

    # A request to send or receive data was disallowed because the socket is not connected and (when sending on a datagram socket using a sendto call) no address was supplied.
    WSAENOTCONN = 10057

    # A request to send or receive data was disallowed because the socket had already been shut down in that direction with a previous shutdown call.
    WSAESHUTDOWN = 10058

    # Too many references to some kernel object.
    WSAETOOMANYREFS = 10059

    # A connection attempt failed because the connected party did not properly respond after a period of time, or established connection failed because connected host has failed to respond.
    WSAETIMEDOUT = 10060

    # No connection could be made because the target machine actively refused it.
    WSAECONNREFUSED = 10061

    # Cannot translate name.
    WSAELOOP = 10062

    # Name component or name was too long.
    WSAENAMETOOLONG = 10063

    # A socket operation failed because the destination host was down.
    WSAEHOSTDOWN = 10064

    # A socket operation was attempted to an unreachable host.
    WSAEHOSTUNREACH = 10065

    # Cannot remove a directory that is not empty.
    WSAENOTEMPTY = 10066

    # A Windows Sockets implementation may have a limit on the number of applications that may use it simultaneously.
    WSAEPROCLIM = 10067

    # Ran out of quota.
    WSAEUSERS = 10068

    # Ran out of disk quota.
    WSAEDQUOT = 10069

    # File handle reference is no longer available.
    WSAESTALE = 10070

    # Item is not available locally.
    WSAEREMOTE = 10071

    # WSAStartup cannot function at this time because the underlying system it uses to provide network services is currently unavailable.
    WSASYSNOTREADY = 10091

    # The Windows Sockets version requested is not supported.
    WSAVERNOTSUPPORTED = 10092

    # Either the application has not called WSAStartup, or WSAStartup failed.
    WSANOTINITIALISED = 10093

    # Returned by WSARecv or WSARecvFrom to indicate the remote party has initiated a graceful shutdown sequence.
    WSAEDISCON = 10101

    # No more results can be returned by WSALookupServiceNext.
    WSAENOMORE = 10102

    # A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.
    WSAECANCELLED = 10103

    # The procedure call table is invalid.
    WSAEINVALIDPROCTABLE = 10104

    # The requested service provider is invalid.
    WSAEINVALIDPROVIDER = 10105

    # The requested service provider could not be loaded or initialized.
    WSAEPROVIDERFAILEDINIT = 10106

    # A system call that should never fail has failed.
    WSASYSCALLFAILURE = 10107

    # No such service is known. The service cannot be found in the specified name space.
    WSASERVICE_NOT_FOUND = 10108

    # The specified class was not found.
    WSATYPE_NOT_FOUND = 10109

    # No more results can be returned by WSALookupServiceNext.
    WSA_E_NO_MORE = 10110

    # A call to WSALookupServiceEnd was made while this call was still processing. The call has been canceled.
    WSA_E_CANCELLED = 10111

    # A database query failed because it was actively refused.
    WSAEREFUSED = 10112

    # No such host is known.
    WSAHOST_NOT_FOUND = 11001

    # This is usually a temporary error during hostname resolution and means that the local server did not receive a response from an authoritative server.
    WSATRY_AGAIN = 11002

    # A non-recoverable error occurred during a database lookup.
    WSANO_RECOVERY = 11003

    # The requested name is valid and was found in the database, but it does not have the correct associated data being resolved for.
    WSANO_DATA = 11004

    # At least one reserve has arrived.
    WSA_QOS_RECEIVERS = 11005

    # At least one path has arrived.
    WSA_QOS_SENDERS = 11006

    # There are no senders.
    WSA_QOS_NO_SENDERS = 11007

    # There are no receivers.
    WSA_QOS_NO_RECEIVERS = 11008

    # Reserve has been confirmed.
    WSA_QOS_REQUEST_CONFIRMED = 11009

    # Error due to lack of resources.
    WSA_QOS_ADMISSION_FAILURE = 11010

    # Rejected for administrative reasons - bad credentials.
    WSA_QOS_POLICY_FAILURE = 11011

    # Unknown or conflicting style.
    WSA_QOS_BAD_STYLE = 11012

    # Problem with some part of the filterspec or providerspecific buffer in general.
    WSA_QOS_BAD_OBJECT = 11013

    # Problem with some part of the flowspec.
    WSA_QOS_TRAFFIC_CTRL_ERROR = 11014

    # General QOS error.
    WSA_QOS_GENERIC_ERROR = 11015

    # An invalid or unrecognized service type was found in the flowspec.
    WSA_QOS_ESERVICETYPE = 11016

    # An invalid or inconsistent flowspec was found in the QOS structure.
    WSA_QOS_EFLOWSPEC = 11017

    # Invalid QOS provider-specific buffer.
    WSA_QOS_EPROVSPECBUF = 11018

    # An invalid QOS filter style was used.
    WSA_QOS_EFILTERSTYLE = 11019

    # An invalid QOS filter type was used.
    WSA_QOS_EFILTERTYPE = 11020

    # An incorrect number of QOS FILTERSPECs were specified in the FLOWDESCRIPTOR.
    WSA_QOS_EFILTERCOUNT = 11021

    # An object with an invalid ObjectLength field was specified in the QOS provider-specific buffer.
    WSA_QOS_EOBJLENGTH = 11022

    # An incorrect number of flow descriptors was specified in the QOS structure.
    WSA_QOS_EFLOWCOUNT = 11023

    # An unrecognized object was found in the QOS provider-specific buffer.
    WSA_QOS_EUNKOWNPSOBJ = 11024

    # An invalid policy object was found in the QOS provider-specific buffer.
    WSA_QOS_EPOLICYOBJ = 11025

    # An invalid QOS flow descriptor was found in the flow descriptor list.
    WSA_QOS_EFLOWDESC = 11026

    # An invalid or inconsistent flowspec was found in the QOS provider specific buffer.
    WSA_QOS_EPSFLOWSPEC = 11027

    # An invalid FILTERSPEC was found in the QOS provider-specific buffer.
    WSA_QOS_EPSFILTERSPEC = 11028

    # An invalid shape discard mode object was found in the QOS provider specific buffer.
    WSA_QOS_ESDMODEOBJ = 11029

    # An invalid shaping rate object was found in the QOS provider-specific buffer.
    WSA_QOS_ESHAPERATEOBJ = 11030

    # A reserved policy element was found in the QOS provider-specific buffer.
    WSA_QOS_RESERVED_PETYPE = 11031

    # The requested section was not present in the activation context.
    SXS_SECTION_NOT_FOUND = 14000

    # This application has failed to start because the application configuration is incorrect. Reinstalling the application may fix this problem.
    SXS_CANT_GEN_ACTCTX = 14001

    # The application binding data format is invalid.
    SXS_INVALID_ACTCTXDATA_FORMAT = 14002

    # The referenced assembly is not installed on your system.
    SXS_ASSEMBLY_NOT_FOUND = 14003

    # The manifest file does not begin with the required tag and format information.
    SXS_MANIFEST_FORMAT_ERROR = 14004

    # The manifest file contains one or more syntax errors.
    SXS_MANIFEST_PARSE_ERROR = 14005

    # The application attempted to activate a disabled activation context.
    SXS_ACTIVATION_CONTEXT_DISABLED = 14006

    # The requested lookup key was not found in any active activation context.
    SXS_KEY_NOT_FOUND = 14007

    # A component version required by the application conflicts with another component version already active.
    SXS_VERSION_CONFLICT = 14008

    # The type requested activation context section does not match the query API used.
    SXS_WRONG_SECTION_TYPE = 14009

    # Lack of system resources has required isolated activation to be disabled for the current thread of execution.
    SXS_THREAD_QUERIES_DISABLED = 14010

    # An attempt to set the process default activation context failed because the process default activation context was already set.
    SXS_PROCESS_DEFAULT_ALREADY_SET = 14011

    # The encoding group identifier specified is not recognized.
    SXS_UNKNOWN_ENCODING_GROUP = 14012

    # The encoding requested is not recognized.
    SXS_UNKNOWN_ENCODING = 14013

    # The manifest contains a reference to an invalid URI.
    SXS_INVALID_XML_NAMESPACE_URI = 14014

    # The application manifest contains a reference to a dependent assembly which is not installed
    SXS_ROOT_MANIFEST_DEPENDENCY_NOT_INSTALLED = 14015

    # The manifest for an assembly used by the application has a reference to a dependent assembly which is not installed
    SXS_LEAF_MANIFEST_DEPENDENCY_NOT_INSTALLED = 14016

    # The manifest contains an attribute for the assembly identity which is not valid.
    SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE = 14017

    # The manifest is missing the required default namespace specification on the assembly element.
    SXS_MANIFEST_MISSING_REQUIRED_DEFAULT_NAMESPACE = 14018

    # The manifest has a default namespace specified on the assembly element but its value is not "urn:schemas-microsoft-com:asm.v1".
    SXS_MANIFEST_INVALID_REQUIRED_DEFAULT_NAMESPACE = 14019

    # The private manifest probed has crossed reparse-point-associated path
    SXS_PRIVATE_MANIFEST_CROSS_PATH_WITH_REPARSE_POINT = 14020

    # Two or more components referenced directly or indirectly by the application manifest have files by the same name.
    SXS_DUPLICATE_DLL_NAME = 14021

    # Two or more components referenced directly or indirectly by the application manifest have window classes with the same name.
    SXS_DUPLICATE_WINDOWCLASS_NAME = 14022

    # Two or more components referenced directly or indirectly by the application manifest have the same COM server CLSIDs.
    SXS_DUPLICATE_CLSID = 14023

    # Two or more components referenced directly or indirectly by the application manifest have proxies for the same COM interface IIDs.
    SXS_DUPLICATE_IID = 14024

    # Two or more components referenced directly or indirectly by the application manifest have the same COM type library TLBIDs.
    SXS_DUPLICATE_TLBID = 14025

    # Two or more components referenced directly or indirectly by the application manifest have the same COM ProgIDs.
    SXS_DUPLICATE_PROGID = 14026

    # Two or more components referenced directly or indirectly by the application manifest are different versions of the same component which is not permitted.
    SXS_DUPLICATE_ASSEMBLY_NAME = 14027

    # A component's file does not match the verification information present in the
    # component manifest.
    SXS_FILE_HASH_MISMATCH = 14028

    # The policy manifest contains one or more syntax errors.
    SXS_POLICY_PARSE_ERROR = 14029

    # Manifest Parse Error : A string literal was expected, but no opening quote character was found.
    SXS_XML_E_MISSINGQUOTE = 14030

    # Manifest Parse Error : Incorrect syntax was used in a comment.
    SXS_XML_E_COMMENTSYNTAX = 14031

    # Manifest Parse Error : A name was started with an invalid character.
    SXS_XML_E_BADSTARTNAMECHAR = 14032

    # Manifest Parse Error : A name contained an invalid character.
    SXS_XML_E_BADNAMECHAR = 14033

    # Manifest Parse Error : A string literal contained an invalid character.
    SXS_XML_E_BADCHARINSTRING = 14034

    # Manifest Parse Error : Invalid syntax for an xml declaration.
    SXS_XML_E_XMLDECLSYNTAX = 14035

    # Manifest Parse Error : An Invalid character was found in text content.
    SXS_XML_E_BADCHARDATA = 14036

    # Manifest Parse Error : Required white space was missing.
    SXS_XML_E_MISSINGWHITESPACE = 14037

    # Manifest Parse Error : The character '>' was expected.
    SXS_XML_E_EXPECTINGTAGEND = 14038

    # Manifest Parse Error : A semi colon character was expected.
    SXS_XML_E_MISSINGSEMICOLON = 14039

    # Manifest Parse Error : Unbalanced parentheses.
    SXS_XML_E_UNBALANCEDPAREN = 14040

    # Manifest Parse Error : Internal error.
    SXS_XML_E_INTERNALERROR = 14041

    # Manifest Parse Error : Whitespace is not allowed at this location.
    SXS_XML_E_UNEXPECTED_WHITESPACE = 14042

    # Manifest Parse Error : End of file reached in invalid state for current encoding.
    SXS_XML_E_INCOMPLETE_ENCODING = 14043

    # Manifest Parse Error : Missing parenthesis.
    SXS_XML_E_MISSING_PAREN = 14044

    # Manifest Parse Error : A single or double closing quote character (\' or \") is missing.
    SXS_XML_E_EXPECTINGCLOSEQUOTE = 14045

    # Manifest Parse Error : Multiple colons are not allowed in a name.
    SXS_XML_E_MULTIPLE_COLONS = 14046

    # Manifest Parse Error : Invalid character for decimal digit.
    SXS_XML_E_INVALID_DECIMAL = 14047

    # Manifest Parse Error : Invalid character for hexidecimal digit.
    SXS_XML_E_INVALID_HEXIDECIMAL = 14048

    # Manifest Parse Error : Invalid unicode character value for this platform.
    SXS_XML_E_INVALID_UNICODE = 14049

    # Manifest Parse Error : Expecting whitespace or '?'.
    SXS_XML_E_WHITESPACEORQUESTIONMARK = 14050

    # Manifest Parse Error : End tag was not expected at this location.
    SXS_XML_E_UNEXPECTEDENDTAG = 14051

    # Manifest Parse Error : The following tags were not closed: %1.
    SXS_XML_E_UNCLOSEDTAG = 14052

    # Manifest Parse Error : Duplicate attribute.
    SXS_XML_E_DUPLICATEATTRIBUTE = 14053

    # Manifest Parse Error : Only one top level element is allowed in an XML document.
    SXS_XML_E_MULTIPLEROOTS = 14054

    # Manifest Parse Error : Invalid at the top level of the document.
    SXS_XML_E_INVALIDATROOTLEVEL = 14055

    # Manifest Parse Error : Invalid xml declaration.
    SXS_XML_E_BADXMLDECL = 14056

    # Manifest Parse Error : XML document must have a top level element.
    SXS_XML_E_MISSINGROOT = 14057

    # Manifest Parse Error : Unexpected end of file.
    SXS_XML_E_UNEXPECTEDEOF = 14058

    # Manifest Parse Error : Parameter entities cannot be used inside markup declarations in an internal subset.
    SXS_XML_E_BADPEREFINSUBSET = 14059

    # Manifest Parse Error : Element was not closed.
    SXS_XML_E_UNCLOSEDSTARTTAG = 14060

    # Manifest Parse Error : End element was missing the character '>'.
    SXS_XML_E_UNCLOSEDENDTAG = 14061

    # Manifest Parse Error : A string literal was not closed.
    SXS_XML_E_UNCLOSEDSTRING = 14062

    # Manifest Parse Error : A comment was not closed.
    SXS_XML_E_UNCLOSEDCOMMENT = 14063

    # Manifest Parse Error : A declaration was not closed.
    SXS_XML_E_UNCLOSEDDECL = 14064

    # Manifest Parse Error : A CDATA section was not closed.
    SXS_XML_E_UNCLOSEDCDATA = 14065

    # Manifest Parse Error : The namespace prefix is not allowed to start with the reserved string "xml".
    SXS_XML_E_RESERVEDNAMESPACE = 14066

    # Manifest Parse Error : System does not support the specified encoding.
    SXS_XML_E_INVALIDENCODING = 14067

    # Manifest Parse Error : Switch from current encoding to specified encoding not supported.
    SXS_XML_E_INVALIDSWITCH = 14068

    # Manifest Parse Error : The name 'xml' is reserved and must be lower case.
    SXS_XML_E_BADXMLCASE = 14069

    # Manifest Parse Error : The standalone attribute must have the value 'yes' or 'no'.
    SXS_XML_E_INVALID_STANDALONE = 14070

    # Manifest Parse Error : The standalone attribute cannot be used in external entities.
    SXS_XML_E_UNEXPECTED_STANDALONE = 14071

    # Manifest Parse Error : Invalid version number.
    SXS_XML_E_INVALID_VERSION = 14072

    # Manifest Parse Error : Missing equals sign between attribute and attribute value.
    SXS_XML_E_MISSINGEQUALS = 14073

    # Assembly Protection Error : Unable to recover the specified assembly.
    SXS_PROTECTION_RECOVERY_FAILED = 14074

    # Assembly Protection Error : The public key for an assembly was too short to be allowed.
    SXS_PROTECTION_PUBLIC_KEY_TOO_LONG = 14075

    # Assembly Protection Error : The catalog for an assembly is not valid, or does not match the assembly's manifest.
    SXS_PROTECTION_CATALOG_NOT_VALID = 14076

    # An HRESULT could not be translated to a corresponding Win32 error code.
    SXS_UNTRANSLATABLE_HRESULT = 14077

    # Assembly Protection Error : The catalog for an assembly is missing.
    SXS_PROTECTION_CATALOG_FILE_MISSING = 14078

    # The supplied assembly identity is missing one or more attributes which must be present in this context.
    SXS_MISSING_ASSEMBLY_IDENTITY_ATTRIBUTE = 14079

    # The supplied assembly identity has one or more attribute names that contain characters not permitted in XML names.
    SXS_INVALID_ASSEMBLY_IDENTITY_ATTRIBUTE_NAME = 14080

    # The specified quick mode policy already exists.
    IPSEC_QM_POLICY_EXISTS = 13000

    # The specified quick mode policy was not found.
    IPSEC_QM_POLICY_NOT_FOUND = 13001

    # The specified quick mode policy is being used.
    IPSEC_QM_POLICY_IN_USE = 13002

    # The specified main mode policy already exists.
    IPSEC_MM_POLICY_EXISTS = 13003

    # The specified main mode policy was not found
    IPSEC_MM_POLICY_NOT_FOUND = 13004

    # The specified main mode policy is being used.
    IPSEC_MM_POLICY_IN_USE = 13005

    # The specified main mode filter already exists.
    IPSEC_MM_FILTER_EXISTS = 13006

    # The specified main mode filter was not found.
    IPSEC_MM_FILTER_NOT_FOUND = 13007

    # The specified transport mode filter already exists.
    IPSEC_TRANSPORT_FILTER_EXISTS = 13008

    # The specified transport mode filter does not exist.
    IPSEC_TRANSPORT_FILTER_NOT_FOUND = 13009

    # The specified main mode authentication list exists.
    IPSEC_MM_AUTH_EXISTS = 13010

    # The specified main mode authentication list was not found.
    IPSEC_MM_AUTH_NOT_FOUND = 13011

    # The specified quick mode policy is being used.
    IPSEC_MM_AUTH_IN_USE = 13012

    # The specified main mode policy was not found.
    IPSEC_DEFAULT_MM_POLICY_NOT_FOUND = 13013

    # The specified quick mode policy was not found
    IPSEC_DEFAULT_MM_AUTH_NOT_FOUND = 13014

    # The manifest file contains one or more syntax errors.
    IPSEC_DEFAULT_QM_POLICY_NOT_FOUND = 13015

    # The application attempted to activate a disabled activation context.
    IPSEC_TUNNEL_FILTER_EXISTS = 13016

    # The requested lookup key was not found in any active activation context.
    IPSEC_TUNNEL_FILTER_NOT_FOUND = 13017

    # The Main Mode filter is pending deletion.
    IPSEC_MM_FILTER_PENDING_DELETION = 13018

    # The transport filter is pending deletion.
    IPSEC_TRANSPORT_FILTER_PENDING_DELETION = 13019

    # The tunnel filter is pending deletion.
    IPSEC_TUNNEL_FILTER_PENDING_DELETION = 13020

    # The Main Mode policy is pending deletion.
    IPSEC_MM_POLICY_PENDING_DELETION = 13021

    # The Main Mode authentication bundle is pending deletion.
    IPSEC_MM_AUTH_PENDING_DELETION = 13022

    # The Quick Mode policy is pending deletion.
    IPSEC_QM_POLICY_PENDING_DELETION = 13023

    # No information avialable.
    WARNING_IPSEC_MM_POLICY_PRUNED = 13024

    # No information avialable.
    WARNING_IPSEC_QM_POLICY_PRUNED = 13025

    # ERROR_IPSEC_IKE_NEG_STATUS_BEGIN
    IPSEC_IKE_NEG_STATUS_BEGIN = 13800

    # IKE authentication credentials are unacceptable
    IPSEC_IKE_AUTH_FAIL = 13801

    # IKE security attributes are unacceptable
    IPSEC_IKE_ATTRIB_FAIL = 13802

    # IKE Negotiation in progress
    IPSEC_IKE_NEGOTIATION_PENDING = 13803

    # General processing error
    IPSEC_IKE_GENERAL_PROCESSING_ERROR = 13804

    # Negotiation timed out
    IPSEC_IKE_TIMED_OUT = 13805

    # IKE failed to find valid machine certificate
    IPSEC_IKE_NO_CERT = 13806

    # IKE SA deleted by peer before establishment completed
    IPSEC_IKE_SA_DELETED = 13807

    # IKE SA deleted before establishment completed
    IPSEC_IKE_SA_REAPED = 13808

    # Negotiation request sat in Queue too long
    IPSEC_IKE_MM_ACQUIRE_DROP = 13809

    # Negotiation request sat in Queue too long
    IPSEC_IKE_QM_ACQUIRE_DROP = 13810

    # Negotiation request sat in Queue too long
    IPSEC_IKE_QUEUE_DROP_MM = 13811

    # Negotiation request sat in Queue too long
    IPSEC_IKE_QUEUE_DROP_NO_MM = 13812

    # No response from peer
    IPSEC_IKE_DROP_NO_RESPONSE = 13813

    # Negotiation took too long
    IPSEC_IKE_MM_DELAY_DROP = 13814

    # Negotiation took too long
    IPSEC_IKE_QM_DELAY_DROP = 13815

    # Unknown error occurred
    IPSEC_IKE_ERROR = 13816

    # Certificate Revocation Check failed
    IPSEC_IKE_CRL_FAILED = 13817

    # Invalid certificate key usage
    IPSEC_IKE_INVALID_KEY_USAGE = 13818

    # Invalid certificate type
    IPSEC_IKE_INVALID_CERT_TYPE = 13819

    # No private key associated with machine certificate
    IPSEC_IKE_NO_PRIVATE_KEY = 13820

    # Failure in Diffie-Helman computation
    IPSEC_IKE_DH_FAIL = 13822

    # Invalid header
    IPSEC_IKE_INVALID_HEADER = 13824

    # No policy configured
    IPSEC_IKE_NO_POLICY = 13825

    # Failed to verify signature
    IPSEC_IKE_INVALID_SIGNATURE = 13826

    # Failed to authenticate using kerberos
    IPSEC_IKE_KERBEROS_ERROR = 13827

    # Peer's certificate did not have a public key
    IPSEC_IKE_NO_PUBLIC_KEY = 13828

    # Error processing error payload
    IPSEC_IKE_PROCESS_ERR = 13829

    # Error processing SA payload
    IPSEC_IKE_PROCESS_ERR_SA = 13830

    # Error processing Proposal payload
    IPSEC_IKE_PROCESS_ERR_PROP = 13831

    # Error processing Transform payload
    IPSEC_IKE_PROCESS_ERR_TRANS = 13832

    # Error processing KE payload
    IPSEC_IKE_PROCESS_ERR_KE = 13833

    # Error processing ID payload
    IPSEC_IKE_PROCESS_ERR_ID = 13834

    # Error processing Cert payload
    IPSEC_IKE_PROCESS_ERR_CERT = 13835

    # Error processing Certificate Request payload
    IPSEC_IKE_PROCESS_ERR_CERT_REQ = 13836

    # Error processing Hash payload
    IPSEC_IKE_PROCESS_ERR_HASH = 13837

    # Error processing Signature payload
    IPSEC_IKE_PROCESS_ERR_SIG = 13838

    # Error processing Nonce payload
    IPSEC_IKE_PROCESS_ERR_NONCE = 13839

    # Error processing Notify payload
    IPSEC_IKE_PROCESS_ERR_NOTIFY = 13840

    # Error processing Delete Payload
    IPSEC_IKE_PROCESS_ERR_DELETE = 13841

    # Error processing VendorId payload
    IPSEC_IKE_PROCESS_ERR_VENDOR = 13842

    # Invalid payload received
    IPSEC_IKE_INVALID_PAYLOAD = 13843

    # Soft SA loaded
    IPSEC_IKE_LOAD_SOFT_SA = 13844

    # Soft SA torn down
    IPSEC_IKE_SOFT_SA_TORN_DOWN = 13845

    # Invalid cookie received.
    IPSEC_IKE_INVALID_COOKIE = 13846

    # Peer failed to send valid machine certificate
    IPSEC_IKE_NO_PEER_CERT = 13847

    # Certification Revocation check of peer's certificate failed
    IPSEC_IKE_PEER_CRL_FAILED = 13848

    # New policy invalidated SAs formed with old policy
    IPSEC_IKE_POLICY_CHANGE = 13849

    # There is no available Main Mode IKE policy.
    IPSEC_IKE_NO_MM_POLICY = 13850

    # Failed to enabled TCB privilege.
    IPSEC_IKE_NOTCBPRIV = 13851

    # Failed to load SECURITY.DLL.
    IPSEC_IKE_SECLOADFAIL = 13852

    # Failed to obtain security function table dispatch address from SSPI.
    IPSEC_IKE_FAILSSPINIT = 13853

    # Failed to query Kerberos package to obtain max token size.
    IPSEC_IKE_FAILQUERYSSP = 13854

    # Failed to obtain Kerberos server credentials for ISAKMP/ERROR_IPSEC_IKE service.  Kerberos authentication will not function.  The most likely reason for this is lack of domain membership.  This is normal if your computer is a member of a workgroup.
    IPSEC_IKE_SRVACQFAIL = 13855

    # Failed to determine SSPI principal name for ISAKMP/ERROR_IPSEC_IKE service (QueryCredentialsAttributes).
    IPSEC_IKE_SRVQUERYCRED = 13856

    # Failed to obtain new SPI for the inbound SA from Ipsec driver.  The most common cause for this is that the driver does not have the correct filter.  Check your policy to verify the filters.
    IPSEC_IKE_GETSPIFAIL = 13857

    # Given filter is invalid
    IPSEC_IKE_INVALID_FILTER = 13858

    # Memory allocation failed.
    IPSEC_IKE_OUT_OF_MEMORY = 13859

    # Failed to add Security Association to IPSec Driver.  The most common cause for this is if the IKE negotiation took too long to complete.  If the problem persists, reduce the load on the faulting machine.
    IPSEC_IKE_ADD_UPDATE_KEY_FAILED = 13860

    # Invalid policy
    IPSEC_IKE_INVALID_POLICY = 13861

    # Invalid DOI
    IPSEC_IKE_UNKNOWN_DOI = 13862

    # Invalid situation
    IPSEC_IKE_INVALID_SITUATION = 13863

    # Diffie-Hellman failure
    IPSEC_IKE_DH_FAILURE = 13864

    # Invalid Diffie-Hellman group
    IPSEC_IKE_INVALID_GROUP = 13865

    # Error encrypting payload
    IPSEC_IKE_ENCRYPT = 13866

    # Error decrypting payload
    IPSEC_IKE_DECRYPT = 13867

    # Policy match error
    IPSEC_IKE_POLICY_MATCH = 13868

    # Unsupported ID
    IPSEC_IKE_UNSUPPORTED_ID = 13869

    # Hash verification failed
    IPSEC_IKE_INVALID_HASH = 13870

    # Invalid hash algorithm
    IPSEC_IKE_INVALID_HASH_ALG = 13871

    # Invalid hash size
    IPSEC_IKE_INVALID_HASH_SIZE = 13872

    # Invalid encryption algorithm
    IPSEC_IKE_INVALID_ENCRYPT_ALG = 13873

    # Invalid authentication algorithm
    IPSEC_IKE_INVALID_AUTH_ALG = 13874

    # Invalid certificate signature
    IPSEC_IKE_INVALID_SIG = 13875

    # Load failed
    IPSEC_IKE_LOAD_FAILED = 13876

    # Deleted via RPC call
    IPSEC_IKE_RPC_DELETE = 13877

    # Temporary state created to perform reinit. This is not a real failure.
    IPSEC_IKE_BENIGN_REINIT = 13878

    # The lifetime value received in the Responder Lifetime Notify is below the Windows 2000 configured minimum value.  Please fix the policy on the peer machine.
    IPSEC_IKE_INVALID_RESPONDER_LIFETIME_NOTIFY = 13879

    # Key length in certificate is too small for configured security requirements.
    IPSEC_IKE_INVALID_CERT_KEYLEN = 13881

    # Max number of established MM SAs to peer exceeded.
    IPSEC_IKE_MM_LIMIT = 13882

    # IKE received a policy that disables negotiation.
    IPSEC_IKE_NEGOTIATION_DISABLED = 13883

    # ERROR_IPSEC_IKE_NEG_STATUS_END
    IPSEC_IKE_NEG_STATUS_END = 13884
