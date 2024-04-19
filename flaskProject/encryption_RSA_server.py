from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import flask
import base64


# Load RSA private key for decryption
def load_private_key(filename):
    """Load private key from a PEM file."""
    with open(filename, "rb") as private_key_file:
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None,
            backend=default_backend()
        )
    return private_key


# Decrypt message with RSA
def decrypt_with_rsa(private_key, ciphertext):
    """Decrypt ciphertext using RSA private key."""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext  # Return decrypted bytes



