#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_ERRCAT.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum

# The error category. The hierarchy is as follows:
#
# JET_errcatError
#   |
#   |-- JET_errcatOperation
#   |    |-- JET_errcatFatal
#   |    |-- JET_errcatIO               //      bad IO issues, may or may not be transient.
#   |    |-- JET_errcatResource
#   |         |-- JET_errcatMemory      //      out of memory (all variants)
#   |         |-- JET_errcatQuota
#   |         |-- JET_errcatDisk        //      out of disk space (all variants)
#   |-- JET_errcatData
#   |     |-- JET_errcatCorruption
#   |     |-- JET_errcatInconsistent    //      typically caused by user Mishandling
#   |     |-- JET_errcatFragmentation
#   |-- JET_errcatApi
#         |-- JET_errcatUsage
#         |-- JET_errcatState
#         |-- JET_errcatObsolete


class JET_ERRCAT(Enum):
    """
    JET_ERRCAT
    """

    # Unknown category.
    Unknown = 0

    # A generic category.
    Error = 1

    # Errors that can usually happen any time due to uncontrollable
    # conditions.  Frequently temporary, but not always.
    #
    # Recovery: Probably retry, or eventually inform the operator.
    Operation = 2

    # This sort error happens only when ESE encounters an error condition
    # so grave, that we can not continue on in a safe (often transactional)
    # way, and rather than corrupt data we throw errors of this category.
    #
    # Recovery: Restart the instance or process. If the problem persists
    # inform the operator.
    Fatal = 3

    # O errors come from the OS, and are out of ESE's control, this sort
    # of error is possibly temporary, possibly not.
    #
    # Recovery: Retry.  If not resolved, ask operator about disk issue.
    IO = 4

    # This is a category that indicates one of many potential out-of-resource
    # conditions.
    Resource = 5

    # Classic out of memory condition.
    #
    # Recovery: Wait a while and retry, free up memory, or quit.
    Memory = 6

    # Certain "specialty" resources are in pools of a certain size, making
    # it easier to detect leaks of these resources.
    #
    # Recovery: Bug fix, generally the application should Assert() on these
    # conditions so as to detect these issues during development.  However,
    # in retail code, the best to hope for is to treat like Memory.
    Quota = 7

    # Out of disk conditions.
    #
    # Recovery: Can retry later in the hope more space is available, or
    # ask the operator to free some disk space.
    Disk = 8

    # A data-related error.
    Data = 9

    # My hard drive ate my homework. Classic corruption issues, frequently
    # permanent without corrective action.
    #
    # Recovery: Restore from backup, perhaps the ese utilities repair
    # operation (which only salvages what data is left / lossy) .Also
    # in the case of recovery(JetInit) perhaps recovery can be performed
    # by allowing data loss.
    Corruption = 10

    # This is similar to Corruption in that the database and/or log files
    # are in a state that is inconsistent and unreconcilable with each
    # other. Often this is caused by application/administrator mishandling.
    # Recovery: Restore from backup, perhaps the ese utilities repair
    # operation (which only salvages what data is left / lossy). Also
    # in the case of recovery(JetInit) perhaps recovery can be performed
    # by allowing data loss.
    Inconsistent = 11

    # This is a class of errors where some persisted internal resource ran
    # out.
    #
    # Recovery: For database errors, offline defragmentation will rectify
    # the problem, for the log files _first_ recover all attached databases
    # to a clean shutdown, and then delete all the log files and checkpoint.
    Fragmentation = 12

    # A container for <see cref="Usage"/> and <see cref="State"/>.
    Api = 13

    # Classic usage error, this means the client code did not pass correct
    # arguments to the JET API.  This error will likely not go away with
    # retry.
    #
    # Recovery: Generally speaking client code should Assert() this class
    # of errors is not returned, so issues can be caught during development.
    # In retail, the app will probably have little option but to return
    # the issue up to the operator.
    Usage = 14

    # This is the classification for different signals the API could return
    # describe the state of the database, a classic case is JET_errRecordNotFound
    # which can be returned by JetSeek() when the record you asked for
    # was not found.
    #
    # Recovery: Not really relevant, depends greatly on the API.
    State = 15

    # The error is recognized as a valid error, but is not expected to be
    # returned by this version of the API.
    Obsolete = 16

    # The maximum value for the enum. This should not be used.
    Max = 17
