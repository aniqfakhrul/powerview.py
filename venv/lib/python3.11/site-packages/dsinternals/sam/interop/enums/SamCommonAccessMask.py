#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : samcommonaccessmask.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum

    
class SamCommonAccessMask(Enum):
    """
    SamCommonAccessMask

    These values specify an access control that is applicable to all object types exposed by this protocol.
    See: https://msdn.microsoft.com/en-us/library/cc245511.aspx
    """

    # Indicates that the caller is requesting the most access possible to the object.
    MaximumAllowed = 0x02000000

    # Specifies access to the system security portion of the security descriptor.
    AccessSystemSecurity = 0x01000000

    # Specifies the ability to update the Owner field of the security descriptor.
    WriteOwner = 0x00080000

    # Specifies the ability to update the discretionary access control list (DACL) of the security descriptor.
    WriteDacl = 0x00040000

    # Specifies the ability to read the security descriptor.
    ReadControl = 0x00020000

    # Specifies the ability to delete the object.
    Delete = 0x00010000
