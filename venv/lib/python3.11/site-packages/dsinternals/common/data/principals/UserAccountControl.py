#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : UserAccountControl.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum

class UserAccountControl(Enum):
    """
    UserAccountControl
    
    Flags that control the behavior of the user account.
    """

    # The logon script is executed.
    Script = 0x00000001

    # The user account is disabled.
    Disabled = 0x00000002

    # The home directory is required.
    HomeDirRequired = 0x00000008

    # The account is currently locked out.
    LockedOut = 0x00000010

    # No password is required.
    PasswordNotRequired = 0x00000020

    # The user cannot change the password.
    PasswordCantChange = 0x00000040

    # The user can send an encrypted password.
    PlaintextPasswordAllowed = 0x00000080

    # This is an account for users whose primary account is in another domain. This account provides user access
    # to this domain, but not to any domain that trusts this domain. Also known as a local user account.
    TempDuplicateAccount = 0x00000100

    # This is a default account type that represents a typical user.
    NormalAccount = 0x00000200

    # This is a permit to trust account for a system domain that trusts other domains.
    TrustAccount = 0x00000800

    # This is a computer account for a computer that is a member of this domain.
    WorkstationAccount = 0x00001000

    # This is a computer account for a system backup domain controller that is a member of this domain.
    ServerAccount = 0x00002000

    # The password for this account will never expire.
    PasswordNeverExpires = 0x00010000

    # This is an Majority Node Set (MNS) logon account. With MNS, you can configure a multi-node Windows cluster
    # without using a common shared disk.
    MNSAccount = 0x00020000

    # The user must log on using a smart card.
    SmartCardRequired = 0x00040000

    # The service account (user or computer account), under which a service runs, is trusted for Kerberos delegation.
    # Any such service can impersonate a client requesting the service.
    TrustedForDelegation = 0x00080000

    # The security context of the user will not be delegated to a service even if the service account is set as trusted
    # for Kerberos delegation.
    NotDelegated = 0x00100000

    # Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
    UseDesKeyOnly = 0x00200000

    # This account does not require Kerberos pre-authentication for logon.
    PreAuthNotRequired = 0x00400000

    # The user password has expired. This flag is created by the system using data from the Pwd-Last-Set attribute
    # and the domain policy.
    PasswordExpired = 0x00800000

    # The account is enabled for delegation. This is a security-sensitive setting; accounts with this option enabled
    # should be strictly controlled. This setting enables a service running under the account to assume a client identity
    # and authenticate as that user to other remote servers on the network.
    TrustedToAuthenticateForDelegation = 0x01000000
