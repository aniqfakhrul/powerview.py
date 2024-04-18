#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : NetResourceDisplayType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class NetResourceDisplayType(Enum):
    """
    NetResourceDisplayType
    
    The display options for the network object in a network browsing user interface.
    
    See: https://msdn.microsoft.com/library/windows/desktop/aa385353.aspx
    """

    # The method used to display the object does not matter.
    Generic = 0x00000000

    # The object should be displayed as a domain.
    Domain = 0x00000001

    # The object should be displayed as a server.
    Server = 0x00000002

    # The object should be displayed as a share.
    Share = 0x00000003

    # The object should be displayed as a file.
    File = 0x00000004

    # The object should be displayed as a group.
    Group = 0x00000005

    # The object should be displayed as a network.
    Network = 0x00000006

    # The object should be displayed as a logical root for the entire network.
    Root = 0x00000007

    # The object should be displayed as a administrative share.
    ShareAdmin = 0x00000008

    # The object should be displayed as a directory.
    Directory = 0x00000009

    # The object should be displayed as a tree. This display type was used for a NetWare Directory Service (NDS)
    # tree by the NetWare Workstation service supported on Windows XP and earlier.
    Tree = 0x0000000A

    # The object should be displayed as a Netware Directory Service container. This display type was used by
    # the NetWare Workstation service supported on Windows XP and earlier.
    NDSContainer = 0x0000000B
