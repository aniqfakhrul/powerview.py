#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamDomainAccessMask.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamDomainAccessMask(Enum):
    """
    SamDomainAccessMask

    These are the specific values available to describe the access control on a domain object.
    See: https://msdn.microsoft.com/en-us/library/cc245522.aspx
    """

    # Specifies access control to read password policy.
    ReadPasswordParameters = 0x00000001

    # Specifies access control to write password policy.
    WritePasswordParameters = 0x00000002

    # Specifies access control to read attributes not related to password policy.
    ReadOtherParameters = 0x00000004

    # Specifies access control to write attributes not related to password policy.
    WriteOtherParameters = 0x00000008

    # Specifies access control to create a user object.
    CreateUser = 0x00000010

    # Specifies access control to create a group object.
    CreateGroup = 0x00000020

    # Specifies access control to create an alias object.
    CreateAlias = 0x00000040

    # Specifies access control to read the alias membership of a set of SIDs.
    GetAliasMembership = 0x00000080

    # Specifies access control to enumerate objects.
    ListAccounts = 0x00000100

    # Specifies access control to look up objects by name and SID.
    Lookup = 0x00000200

    # Specifies access control to various administrative operations on the server.
    AdministerServer = 0x00000400

    # The specified accesses for a GENERIC_ALL request.
    AllAccess = 0x000F07FF

    # The specified accesses for a GENERIC_READ request.
    Read = 0x00020084

    # The specified accesses for a GENERIC_WRITE request.
    Write = 0x0002047A

    # The specified accesses for a GENERIC_EXECUTE request.
    Execute = 0x00020301

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
