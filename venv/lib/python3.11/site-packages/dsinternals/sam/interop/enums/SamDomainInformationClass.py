#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamDomainInformationClass.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamDomainInformationClass(Enum):
    """
    SamDomainInformationClass

    The DOMAIN_INFORMATION_CLASS enumeration indicates how to interpret the Buffer
    parameter for SamrSetInformationDomain and SamrQueryInformationDomain.

    See: https://msdn.microsoft.com/en-us/library/cc245570.aspx
    """

    PasswordInformation = 1
    GeneralInformation = 2
    LogoffInformation = 3
    OemInformation = 4
    NameInformation = 5
    ReplicationInformation = 6
    ServerRoleInformation = 7
    ModifiedInformation = 8
    StateInformation = 9
    GeneralInformation2 = 11
    LockoutInformation = 12
    ModifiedInformation2 = 13
