"""
Vulnerable Demo App for ECDAT Cryptographic Discovery Evaluation.
Contains deliberately planted legacy and quantum-vulnerable cryptography.
"""

import hashlib
import ssl
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from Crypto.Cipher import AES

# Planted Artefact 1: Hardcoded private key PEM
HARDCODED_RSA_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAz8Z7K7c6Qx3f8K...FAKE...KEY...EXAMPLE...
-----END RSA PRIVATE KEY-----"""

# Planted Artefact 2: Hardcoded secret key
jwt_secret = "4f8b9e6c2a1d0f5e8b7a6c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f"


def insecure_hash_md5(data: bytes) -> str:
    # Planted Artefact 3: MD5 hash (classically broken)
    return hashlib.md5(data).hexdigest()


def insecure_hash_sha1(data: bytes) -> str:
    # Planted Artefact 4: SHA-1 hash (classically broken)
    return hashlib.sha1(data).hexdigest()


def vulnerable_aes_ecb_encrypt(key: bytes, plaintext: bytes) -> bytes:
    # Planted Artefact 5: AES in insecure ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)


def generate_quantum_vulnerable_rsa():
    # Planted Artefact 6: RSA 1024-bit key (vulnerable to Shor's algorithm + weak key size)
    return rsa.generate_private_key(public_exponent=65537, key_size=1024)


def generate_quantum_vulnerable_ec():
    # Planted Artefact 7: ECDSA SECP256R1 (vulnerable to Shor's algorithm)
    return ec.generate_private_key(ec.SECP256R1())


def get_legacy_ssl_context():
    # Planted Artefact 8: Deprecated TLSv1 protocol
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    return context
