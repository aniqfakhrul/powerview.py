#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_DbInfo.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_DbInfo(Enum):
    """
    JET_DbInfo

    Info levels for retrieving database info.
    """

    # Returns the path to the database file (string).
    Filename = 0

    # Returns the locale identifier (LCID) associated with this database (Int32).
    LCID = 3

    # Returns a <see cref="OpenDatabaseGrbit"/>. This indicates whether the
    # database is opened in exclusive mode. If the database is in exclusive mode then
    # <see cref="OpenDatabaseGrbit.Exclusive"/> will be returned, otherwise zero is
    # returned. Other database grbit options for JetAttachDatabase and JetOpenDatabase
    # are not returned.
    Options = 6

    # Returns a number one greater than the maximum level to which transactions can be
    # nested. If <see cref="Api.JetBeginTransaction"/> is called (in a nesting fashion, that is, on the
    # same session, without a commit or rollback) as many times as this value, on the
    # last call <see cref="JET_err.TransTooDeep"/> will be returned (Int32).
    Transactions = 7

    # Returns the major version of the database engine (Int32).
    Version = 8

    # Returns the filesize of the database, in pages (Int32).
    Filesize = 10

    # Returns the owned space of the database, in pages (Int32).
    SpaceOwned = 11

    # Returns the available space in the database, in pages (Int32).
    SpaceAvailable = 12

    # Returns a <see cref="JET_DBINFOMISC"/> object.
    Misc = 14

    # Returns a boolean indicating whether the database is attached (boolean).
    DBInUse = 15

    # Returns the page size of the database (Int32).
    PageSize = 17

    # Returns the type of the database (<see cref="JET_filetype"/>).
    FileType = 19
