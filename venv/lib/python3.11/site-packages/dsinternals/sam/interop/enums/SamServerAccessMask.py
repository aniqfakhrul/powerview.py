#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamServerAccessMask.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamServerAccessMask(Enum):
    # Server Access Mask
    # 
    # These are the specific values available to describe the access control on a server object.
    #
    # See: https://msdn.microsoft.com/en-us/library/cc245521.aspx
    
    # Specifies access control to obtain a server handle.
    Connect = 0x00000001
    
    # Does not specify any access control.
    Shutdown = 0x00000002
    
    # Does not specify any access control.
    Initialize = 0x00000004
    
    # Does not specify any access control.
    CreateDomain = 0x00000008
    
    # Specifies access control to view domain objects.
    EnumerateDomains = 0x00000010
    
    # Specifies access control to perform SID-to-name translation.
    LookupDomain = 0x00000020
    
    # The specified accesses for a GENERIC_ALL request.
    AllAccess = 0x000F003F
    
    # The specified accesses for a GENERIC_READ request.
    Read = 0x00020010
    
    # The specified accesses for a GENERIC_WRITE request.
    Write = 0x0002000E
    
    # The specified accesses for a GENERIC_EXECUTE request.
    Execute = 0x00020021
    
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
