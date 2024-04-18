#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : fidoauthenticatorflags.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class AuthenticatorFlags(Enum):
    """
    Authenticator data flags

    <see cref="https://www.w3.org/TR/webauthn/#flags"/>
    """

    # User Present indicates that the user presence test has completed successfully.
    # <see cref="https://www.w3.org/TR/webauthn/#up"/>
    UserPresent = 0x1

    # Reserved for future use (RFU1)
    RFU1 = 0x2

    # User Verified indicates that the user verification process has completed successfully.
    # <see cref="https://www.w3.org/TR/webauthn/#uv"/>
    UserVerified = 0x4

    # Reserved for future use (RFU2)
    RFU2 = 0x8

    # Reserved for future use (RFU3)
    RFU3 = 0x10

    # Reserved for future use (RFU4)
    RFU4 = 0x20

    # Attested credential data included indicates that the authenticator added attested credential data to the authenticator data.
    # <see cref="https://www.w3.org/TR/webauthn/#attested-credential-data"/>
    AttestationData = 0x40

    # Extension data included indicates that the authenticator added extension data to the authenticator data.
    # <see cref="https://www.w3.org/TR/webauthn/#authdataextensions"/>
    ExtensionData = 0x80