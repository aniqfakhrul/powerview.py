#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamAccountType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamAccountType(Enum):
    """
    Account type values are associated with accounts and indicate the type of account.

    https://msdn.microsoft.com/en-us/library/cc245527.aspx
    """

    # Represents a domain object.
    Domain = 0x0

    # Represents a group object.
    SecurityGroup = 0x10000000

    # Represents a group object that is not used for authorization context generation.
    DistributuionGroup = 0x10000001

    # Represents an alias object or a domain local group object.
    Alias = 0x20000000

    # Represents an alias object that is not used for authorization context generation.
    NonSecurityAlias = 0x20000001

    # Represents a user object.
    User = 0x30000000

    # Represents a computer object.
    Computer = 0x30000001

    # Represents a user object that is used for domain trusts.
    Trust = 0x30000002

    # Represents an application-defined group.
    ApplicationBasicGroup = 0x40000000

    # Represents an application-defined group whose members are determined by the results of a query.
    ApplicationQueryGroup = 0x40000001
