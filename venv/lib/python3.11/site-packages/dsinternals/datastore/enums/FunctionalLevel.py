#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : FunctionalLevel.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class FunctionalLevel(Enum):
    """
    FunctionalLevel

    Domain, forest or DC functional level.
    We do not want to be dependent on System.DirectoryServices.ActiveDirectory, so we implement our own enum.

    See: https://msdn.microsoft.com/en-us/library/cc223743.aspx
    """

    Win2000 = 0
    Win2003Mixed = 1
    Win2003 = 2
    Win2008 = 3
    Win2008R2 = 4
    Win2012 = 5
    Win2012R2 = 6
    WinThreshold = 7
