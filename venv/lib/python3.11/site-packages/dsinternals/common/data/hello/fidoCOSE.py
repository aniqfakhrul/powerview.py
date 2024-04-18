#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : fidocose.py
# Author             : Podalirius (@podalirius_)
# Date created       : 31 Jul 2021

from enum import Enum


class COSE(object):
    """
    COSE

    CBOR Object Signing and Encryption RFC8152 https://tools.ietf.org/html/rfc8152
    """

    class Algorithm(Enum):
        """
        Algorithm

        COSE Algorithms https://www.iana.org/assignments/cose/cose.xhtml#algorithms
        """

        # RSASSA-PKCS1-v1_5 w/ SHA-1
        RS1 = -65535

        # RSASSA-PKCS1-v1_5 w/ SHA-512
        RS512 = -259

        # RSASSA-PKCS1-v1_5 w/ SHA-384
        RS384 = -258

        # RSASSA-PKCS1-v1_5 w/ SHA-256
        RS256 = -257

        # RSASSA-PSS w/ SHA-512
        PS512 = -39

        # RSASSA-PSS w/ SHA-384
        PS384 = -38

        # RSASSA-PSS w/ SHA-256
        PS256 = -37

        # ECDSA w/ SHA-512
        ES512 = -36

        # ECDSA w/ SHA-384
        ES384 = -35

        # EdDSA
        EdDSA = -8

        # ECDSA w/ SHA-256
        ES256 = -7

    class KeyCommonParameter(Enum):
        """
        KeyCommonParameter

        COSE Key Common Parameters https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters
        """

        # This value is reserved
        Reserved = 0

        # Identification of the key type
        KeyType = 1

        # Key identification value - match to kid in message
        KeyId = 2

        # Key usage restriction to this algorithm
        Alg = 3

        # Restrict set of permissible operations
        KeyOps = 4

        # Base IV to be XORed with Partial IVs
        BaseIV = 5

    class KeyTypeParameter(Enum):
        """
        KeyTypeParameter

        COSE Key Type Parameters https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters
        """

        # EC identifier
        Crv = -1

        # Key Value
        K = -1

        # x-coordinate
        X = -2

        # y-coordinate
        Y = -3

        # the RSA modulus n
        N = -1

        # the RSA public exponent e
        E = -2

    class KeyType(Enum):
        """
        KeyType

        COSE Key Types https://www.iana.org/assignments/cose/cose.xhtml#key-type
        """

        # This value is reserved
        Reserved = 0

        # Octet Key Pair
        OKP = 1

        # Elliptic Curve Keys w/ x- and y-coordinate pair
        EC2 = 2

        # RSA Key
        RSA = 3

        # Symmetric Keys
        Symmetric = 4

    class EllipticCurve(Enum):
        """
        EllipticCurve

        COSE Elliptic Curves https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
        """

        # This value is reserved
        Reserved = 0

        # NIST P-256 also known as secp256r1
        P256 = 1

        # NIST P-384 also known as secp384r1
        P384 = 2

        # NIST P-521 also known as secp521r1
        P521 = 3

        # X25519 for use w/ ECDH only
        X25519 = 4

        # X448 for use w/ ECDH only
        X448 = 5

        # Ed25519 for use w/ EdDSA only
        Ed25519 = 6

        # Ed448 for use w/ EdDSA only
        Ed448 = 7

        # secp256k1 (pending IANA - requested assignment 8)
        P256K = 8
