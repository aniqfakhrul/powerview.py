#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_cbtyp.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_cbtyp(Enum):
    """
    JET_cbtyp

    Type of progress being reported.
    """

    # This callback is reserved and always considered invalid.
    Null = 0

    # A finalizable column has gone to zero.
    Finalize = 0x1

    # This callback will occur just before a new record is inserted into
    # a table by a call to JetUpdate.
    BeforeInsert = 0x2

    # This callback will occur just after a new record has been inserted
    # into a table by a call to JetUpdate but before JetUpdate returns.
    AfterInsert = 0x4

    # This callback will occur just prior to an existing record in a table
    # being changed by a call to JetUpdate.
    BeforeReplace = 0x8

    # This callback will occur just after an existing record in a table
    # has been changed by a call to JetUpdate but prior to JetUpdate returning.
    AfterReplace = 0x10

    # This callback will occur just before an existing record in a table
    # is deleted by a call to JetDelete.
    BeforeDelete = 0x20

    # This callback will occur just after an existing record in a table
    # is deleted by a call to JetDelete.
    AfterDelete = 0x40

    # This callback will occur when the engine needs to retrieve the
    # user defined default value of a column from the application.
    # This callback is essentially a limited implementation of
    # JetRetrieveColumn that is evaluated by the application. A maximum
    # of one column value can be returned for a user defined default value.
    UserDefinedDefaultValue = 0x80

    # This callback will occur when the online defragmentation of a
    # database as initiated by JetDefragment has stopped due to either the
    # process being completed or the time limit being reached.
    OnlineDefragCompleted = 0x100

    # This callback will occur when the application needs to clean up
    # the context handle for the Local Storage associated with a cursor
    # that is being released by the database engine. For more information,
    # see JetSetLS. The delegate for this callback reason is
    # configured by means of JetSetSystemParameter with JET_paramRuntimeCallback.
    FreeCursorLS = 0x200

    # This callback will occur as the result of the need for the application
    # to cleanup the context handle for the Local Storage associated with
    # a table that is being released by the database engine. For more information,
    # see JetSetLS. The delegate for this callback reason is configured
    # by means of JetSetSystemParameter with JET_paramRuntimeCallback.
    FreeTableLS = 0x400