#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : KeySource.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021

from enum import Enum


class KeySource(Enum):
    """
    Key Source

    See: https://msdn.microsoft.com/en-us/library/mt220501.aspx
    """
    # On Premises Key Trust
    AD = 0x00

    # Hybrid Azure AD Key Trust
    AzureAD = 0x01
