#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_ExceptionAction.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_ExceptionAction(Enum):
    """
    JET_ExceptionAction

    Constants to be used with JET_paramExceptionAction.
    """

    # Display message box on exception.
    MsgBox = 0x00000001

    # Do not handle exceptions. Throw them to the caller.
    NONE = 0x00000002
