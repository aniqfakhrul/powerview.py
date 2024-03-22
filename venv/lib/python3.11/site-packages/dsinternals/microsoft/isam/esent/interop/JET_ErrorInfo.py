#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_ErrorInfo.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_ErrorInfo(Enum):
    """
    JET_ErrorInfo
    """

    # Retrieve information about the specific error passed in pvContext.
    SpecificErr = 1,
