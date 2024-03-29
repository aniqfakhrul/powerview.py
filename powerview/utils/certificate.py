#!/usr/bin/env python3
# codes taken from https://github.com/ly4k/Certipy/blob/main/certipy/lib/certificate.py
from cryptography import x509
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    pkcs12
)

def load_pfx(
    pfx: bytes, password: bytes = None
) -> Tuple[rsa.RSAPrivateKey, x509.Certificate, None]:
    return pkcs12.load_key_and_certificates(pfx, password)[:-1]

def key_to_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, encryption_algorithm=NoEncryption()
    )

def cert_to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(Encoding.PEM)
