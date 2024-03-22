#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : LsaPolicyInformationClass.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class LsaPolicyInformationClass(Enum):
    """
    LsaPolicyInformationClass

    Defines values that indicate the type of information to set or query in a Policy object.

    See : https://docs.microsoft.com/en-us/windows/desktop/api/ntsecapi/ne-ntsecapi-_policy_information_class
    """

    # Information about audit log.
    AuditLogInformation = 1

    # Query or set the auditing rules of the system.
    AuditEventsInformation = 2

    # Primary domain information.
    PrimaryDomainInformation = 3

    PdAccountInformation = 4

    # Query or set the name and SID of the account domain of the system.
    AccountDomainInformation = 5

    # Query or set the role of an LSA server.
    LsaServerRoleInformation = 6

    ReplicaSourceInformation = 7

    DefaultQuotaInformation = 8

    # Query or set information about the creation time and last modification of the LSA database.
    ModificationInformation = 9

    AuditFullSetInformation = 10

    #  Audit log state.
    AuditFullQueryInformation = 11

    # Query or set Domain Name System (DNS) information about the account domain associated with a Policy object.
    DnsDomainInformation = 12

    # DNS domain information.
    DnsDomainInformationInt = 13

    # Local account domain information.
    LocalAccountDomainInformation = 14

    # Machine account information.
    MachineAccountInformation = 15
