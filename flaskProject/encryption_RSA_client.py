# -*- coding: utf-8 -*-
import base64
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from encryption_AES import encrypt_data
from encryption_RSA_server import load_private_key

# Load RSA public key for encryption
def load_public_key(filename):
    """Load public key from a PEM file."""
    with open(filename, "rb") as public_key_file:
        public_key = serialization.load_pem_public_key(
            public_key_file.read(),
            backend=default_backend()
        )
    return public_key

# Encrypt message with RSA
def encrypt_with_rsa(public_key, data):
    """Encrypt data using RSA public key."""
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

