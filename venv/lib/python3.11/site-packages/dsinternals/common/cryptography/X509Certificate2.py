#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : X509Certificate2.py
# Author             : Podalirius (@podalirius_)
# Date created       : 28 Jul 2021
import os

import OpenSSL
from Cryptodome.PublicKey import RSA
from dsinternals.common.cryptography.RSAKeyMaterial import RSAKeyMaterial


class X509Certificate2(object):
    """
    class X509Certificate2
    """

    def __init__(self, subject, keySize=2048, notBefore=0, notAfter=365):
        self.key = None

        # create rsa key pair object
        self.key = OpenSSL.crypto.PKey()
        # generate key pair or 2048 of length
        self.key.generate_key(OpenSSL.crypto.TYPE_RSA, keySize)
        # create x509 certificate object
        self.certificate = OpenSSL.crypto.X509()

        # set cert params
        self.certificate.get_subject().CN = subject
        self.certificate.set_issuer(self.certificate.get_subject())
        # Validity
        self.certificate.gmtime_adj_notBefore(notBefore * 24 * 60 * 60)
        self.certificate.gmtime_adj_notAfter(notAfter * 24 * 60 * 60)

        self.certificate.set_pubkey(self.key)

        # self-sign certificate with SHA256 digest and PKCS1 padding scheme
        self.certificate.sign(self.key, "sha256")

        pem_key = OpenSSL.crypto.dump_publickey(OpenSSL.crypto.FILETYPE_PEM, self.key)
        pubkey = RSA.importKey(pem_key)
        self.publicKey = RSAKeyMaterial(
            modulus=pubkey.n,
            exponent=pubkey.e,
            keySize=pubkey.size_in_bits(),
            prime1=0,
            prime2=0
        )

    def ExportPFX(self, path_to_file, password):
        if len(os.path.dirname(path_to_file)) != 0:
            if not os.path.exists(os.path.dirname(path_to_file)):
                os.makedirs(os.path.dirname(path_to_file), exist_ok=True)
        pk = OpenSSL.crypto.PKCS12()
        pk.set_privatekey(self.key)
        pk.set_certificate(self.certificate)
        with open(path_to_file + ".pfx", "wb") as f:
            f.write(pk.export(passphrase=password))

    def ExportPEM(self, path_to_files):
        if len(os.path.dirname(path_to_files)) != 0:
            if not os.path.exists(os.path.dirname(path_to_files)):
                os.makedirs(os.path.dirname(path_to_files), exist_ok=True)
        cert = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate)
        with open(path_to_files + "_cert.pem", "wb") as f:
            f.write(cert)
        privpem = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.key)
        with open(path_to_files + "_priv.pem", "wb") as f:
            f.write(privpem)

    def ExportRSAPublicKeyDER(self):
        raise NotImplementedError("")

    def ExportRSAPublicKeyBCrypt(self):
        return self.publicKey
