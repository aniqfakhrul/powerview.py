#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_prep.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_prep(Enum):
    """
    JET_prep
    
    Update types for JetPrepareUpdate.
    """

    # This flag causes the cursor to prepare for an insert of a new record.
    # All the data is initialized to the default state for the record.
    # If the table has an auto-increment column, then a new value is
    # assigned to this record regardless of whether the update ultimately
    # succeeds, fails or is cancelled.
    Insert = 0

    # This flag causes the cursor to prepare for a replace of the current
    # record. If the table has a version column, then the version column
    # is set to the next value in its sequence. If this update does not
    # complete, then the version value in the record will be unaffected.
    # An update lock is taken on the record to prevent other sessions
    # from updating this record before this session completes.
    Replace = 2

    # This flag causes JetPrepareUpdate to cancel the update for this cursor.
    Cancel = 3

    # This flag is similar to JET_prepReplace, but no lock is taken to prevent
    # other sessions from updating this record. Instead, this session may receive
    # JET_errWriteConflict when it calls JetUpdate to complete the update.
    ReplaceNoLock = 4

    # This flag causes the cursor to prepare for an insert of a copy of the
    # existing record. There must be a current record if this option is used.
    # The initial state of the new record is copied from the current record.
    # Long values that are stored off-record are virtually copied.
    InsertCopy = 5

    # This flag causes the cursor to prepare for an insert of the same record,
    # and a delete or the original record. It is used in cases in which the
    # primary key has changed.
    InsertCopyDeleteOriginal = 7
