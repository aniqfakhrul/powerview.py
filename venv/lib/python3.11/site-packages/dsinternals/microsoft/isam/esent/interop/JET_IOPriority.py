#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : JET_IOPriority.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class JET_IOPriority(Enum):
    """
    JET_IOPriority
    
    Values for use with <see cref="VistaParam.IOPriority"/>.
    """

    # This is the default I/O priority level.
    Normal = 0x0

    # Subsequent I/Os issued will be issued at Low priority.
    Low = 0x1

    # Subsequent I/Os issued for checkpoint advancement will be issued at Low priority.
    # Available on Windows 8.1 and later.
    LowForCheckpoint = 0x2

    # Subsequent I/Os issued for scavenging buffers will be issued at Low priority.
    # Available on Windows 8.1 and later.
    LowForScavenge = 0x4

    # Subsequent I/Os issued for shrinking the database cache will be issued at Low priority.
    # Available on Windows 8.1 and later.
    LowForCacheShrink = 0x8
