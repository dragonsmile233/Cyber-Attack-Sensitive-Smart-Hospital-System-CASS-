# -*- coding: utf-8 -*-
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


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

def encrypt_message(public_key, message):
    encrypted_fragments = []
    chunk_size = 50  # 设置每个片段的大小

    for i in range(0, len(message), chunk_size):
        chunk = message[i:i + chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_fragments.append(encrypted_chunk)

    return encrypted_fragments

# 解密消息
def decrypt_message(private_key, encrypted_fragments):
    decrypted_chunks = []

    for encrypted_fragment in encrypted_fragments:
        encrypted_chunk = encrypted_fragment
        decrypted_chunk = private_key.decrypt(
            encrypted_chunk,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_chunks.append(decrypted_chunk)

    return b''.join(decrypted_chunks)

if __name__ == "__main__":
    public_key = load_public_key("public_key.pem")
    from encryption_RSA_server import load_private_key
    private_key = load_private_key("private_key.pem")
    with open('packet.txt', 'rb') as file:
        data = file.read()

    data2=b'helow word'
    a=encrypt_message(public_key,data)
    decrypted_data = decrypt_message(private_key,a)
    print(decrypted_data)
