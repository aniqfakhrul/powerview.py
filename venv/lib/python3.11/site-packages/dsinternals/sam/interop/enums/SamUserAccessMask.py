#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamUserAccessMask.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamUserAccessMask(Enum):
    """
    User Access Mask
    These are the specific values available to describe the access control on a user object.
    
    See: https://msdn.microsoft.com/en-us/library/cc245525.aspx
    """

    # Specifies the ability to read sundry attributes.
    ReadGeneral = 0x00000001

    # Specifies the ability to read general information attributes.
    ReadPreferences = 0x00000002

    # Specifies the ability to write general information attributes.
    WritePreferences = 0x00000004

    # Specifies the ability to read attributes related to logon statistics.
    ReadLogon = 0x00000008

    # Specifies the ability to read attributes related to the administration of the user object.
    ReadAccount = 0x00000010

    # Specifies the ability to write attributes related to the administration of the user object.
    WriteAccount = 0x00000020

    # Specifies the ability to change the user's password.
    ChangePassword = 0x00000040

    # Specifies the ability to set the user's password.
    ForcePasswordChange = 0x00000080

    # Specifies the ability to query the membership of the user object.
    ListGroups = 0x00000100

    # Does not specify any access control.
    ReadGroupInformation = 0x00000200

    # Does not specify any access control.
    WriteGroupInformation = 0x00000400

    # The specified accesses for a GENERIC_ALL request.
    AllAccess = 0x000F07FF

    # The specified accesses for a GENERIC_READ request.
    Read = 0x0002031A

    # The specified accesses for a GENERIC_WRITE request.
    Write = 0x00020044

    # The specified accesses for a GENERIC_EXECUTE request.
    Execute = 0x00020041

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
