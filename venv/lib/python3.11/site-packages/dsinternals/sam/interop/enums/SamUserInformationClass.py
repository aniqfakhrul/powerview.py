#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : SamUserInformationClass.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class SamUserInformationClass(Enum):
    """User Information Class

    The USER_INFORMATION_CLASS enumeration indicates how to interpret the Buffer parameter
    for SamrSetInformationUser, SamrQueryInformationUser, SamrSetInformationUser2,
    and SamrQueryInformationUser2.

    See: https://msdn.microsoft.com/en-us/library/cc245617.aspx

    """

    GeneralInformation = 1
    PreferencesInformation = 2
    LogonInformation = 3
    LogonHoursInformation = 4
    AccountInformation = 5
    NameInformation = 6
    AccountNameInformation = 7
    FullNameInformation = 8
    PrimaryGroupInformation = 9
    HomeInformation = 10
    ScriptInformation = 11
    ProfileInformation = 12
    AdminCommentInformation = 13
    WorkStationsInformation = 14
    ControlInformation = 16
    ExpiresInformation = 17
    Internal1Information = 18
    ParametersInformation = 20
    AllInformation = 21
    Internal4Information = 23
    Internal5Information = 24
    Internal4InformationNew = 25
    Internal5InformationNew = 26
