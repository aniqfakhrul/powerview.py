#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamDomainPasswordProperties.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamDomainPasswordProperties(Enum):
    """
    SamDomainPasswordProperties

    Flags that describe the password properties.
    """

    # No flags are set.
    NONE = 0

    # The password must have a mix of at least two of the following types of characters: Uppercase characters, Lowercase characters, Numerals
    PasswordComplexity = 0x00000001

    # The password cannot be changed without logging on. Otherwise, if your password has expired, you can change your password and then log on.
    RequireLogonToChangePassword = 0x00000002

    # Forces the client to use a protocol that does not allow the domain controller to get the plaintext password.
    NoClearChange = 0x00000004

    # Allows the built-in administrator account to be locked out from network logons.
    LockoutAdmins = 0x00000008

    # The directory service is storing a plaintext password for all users instead of a hash function of the password.
    ClearTextPassword = 0x00000010

    # Removes the requirement that the machine account password be automatically changed every week.
    # This value should not be used as it can weaken security.
    RefuseMachinePasswordChange = 0x00000020
