#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : InstanceType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class InstanceType(Enum):
    """
    InstanceType
    
    A bit field that dictates how the object is instantiated on a particular domain controller.
    The value of this attribute can differ on different replicas even if the replicas are in sync.
    This attribute can be zero or a combination of one or more of the following bit flags.
    See: https://msdn.microsoft.com/en-us/library/cc219986.aspx
    """

    # The object is not writable on this directory and is not a naming context.
    NONE = 0

    # The head of naming context.
    NamingContextHead = 0x00000001

    # This replica is not instantiated.
    NotInstantiated = 0x00000002

    # The object is writable on this directory.
    Writable = 0x00000004

    # The naming context above this one on this directory is held.
    NamingContextAbove = 0x00000008

    # The naming context is being constructed for the first time via replication.
    Constructing = 0x00000010

    # The naming context is being removed from the local directory system agent (DSA).
    Removing = 0x00000020

