#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RegistryKeyRights.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class RegistryKeyRights(Enum):
    """
    RegistryKeyRights

    Access rights for registry key objects.
    """

    # Combines the STANDARD_RIGHTS_REQUIRED, KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_CREATE_SUB_KEY, KEY_ENUMERATE_SUB_KEYS, KEY_NOTIFY, and KEY_CREATE_LINK access rights.
    AllAccess = 0xF003F

    # Reserved for system use.
    CreateLink = 0x0020

    # Required to create a subkey of a registry key.
    CreateSubKey = 0x0004

    # Required to enumerate the subkeys of a registry key.
    EnumerateSubKeys = 0x0008

    # Required to request change notifications for a registry key or for subkeys of a registry key.
    Notify = 0x0010

    # Required to query the values of a registry key.
    QueryValue = 0x0001

    # Combines the STANDARD_RIGHTS_READ, KEY_QUERY_VALUE, KEY_ENUMERATE_SUB_KEYS, and KEY_NOTIFY values.
    Read = 0x20019

    # Equivalent to KEY_READ.
    Execute = Read

    # Required to create, delete, or set a registry value.
    SetValue = 0x0002

    # Indicates that an application on 64-bit Windows should operate on the 32-bit registry view. This flag is ignored by 32-bit Windows.
    Wow6432Key = 0x0200

    # Indicates that an application on 64-bit Windows should operate on the 64-bit registry view. This flag is ignored by 32-bit Windows.
    Wow6464Key = 0x0100

    # Combines the STANDARD_RIGHTS_WRITE, KEY_SET_VALUE, and KEY_CREATE_SUB_KEY access rights.
    Write = 0x20006
