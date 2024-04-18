#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : RoamedCredentialType.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class RoamedCredentialType(Enum):
    """
    RoamedCredentialType
    """

    # DPAPI Master Key
    DPAPIMasterKey = 0

    # CAPI RSA Private Key
    RSAPrivateKey = 1

    # CAPI DSA Private Key
    DSAPrivateKey = 2

    # CAPI Certificate
    CryptoApiCertificate = 3

    # CAPI Certificate Signing Request
    CryptoApiRequest = 4

    # CNG Certificate
    CNGCertificate = 7

    # CNG Certificate Signing Request
    CNGRequest = 8

    # CNG Private Key
    CNGPrivateKey = 9
