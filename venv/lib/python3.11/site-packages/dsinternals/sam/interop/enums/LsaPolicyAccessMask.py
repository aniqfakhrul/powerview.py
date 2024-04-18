#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : LsaPolicyAccessMask.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class LsaPolicyAccessMask(Enum):
    """
    LsaPolicyAccessMask

    """

    # This access type is needed to read the target system's miscellaneous security policy information.
    # This includes the default quota, auditing, server state and role information, and trust information.
    # This access type is also needed to enumerate trusted domains, accounts, and privileges.
    ViewLocalInformation = 0x00000001

    # This access type is needed to view audit trail or audit requirements information.
    ViewAuditInformation = 0x00000002

    # This access type is needed to view sensitive information, such as the names of accounts established
    # for trusted domain relationships.
    GetPrivateInformation = 0x00000004

    # This access type is needed to change the account domain or primary domain information.
    TrustAdmin = 0x00000008

    # This access type is needed to create a new Account object.
    CreateAccount = 0x00000010

    # This access type is needed to create a new Private Data object.
    CreateSecret = 0x00000020

    # Not yet supported.
    CreatePrivilege = 0x00000040

    # Set the default system quotas that are applied to user accounts.
    SetDefaultQuotaLimits = 0x00000080

    # This access type is needed to update the auditing requirements of the system.
    SetAuditRequirements = 0x00000100

    # This access type is needed to change the characteristics of the audit trail such as its maximum size
    # or the retention period for audit records, or to clear the log.
    AuditLogAdmin = 0x00000200

    # This access type is needed to modify the server state or role (master/replica) information.It is also
    # needed to change the replica source and account name information.
    ServerAdmin = 0x00000400

    # This access type is needed to translate between names and SIDs.
    LookupNames = 0x00000800

    Notification = 0x00001000
