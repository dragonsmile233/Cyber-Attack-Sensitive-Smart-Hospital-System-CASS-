import sqlite3
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64


# Fixed encryption key
key = b'000102030405060708090a0b0c0d0e0f'  # Ensure key is a bytes object

# Initialize AES cipher with the fixed key
cipher = AES.new(key, AES.MODE_ECB)

# Encrypt data using AES cipher
def encrypt_data(data):
    padded_data = pad(data.encode(), AES.block_size)
    return cipher.encrypt(padded_data)

# Decrypt data using AES cipher
def decrypt_data(encrypted_data):
    decrypted_data = cipher.decrypt(encrypted_data)
    return unpad(decrypted_data, AES.block_size).decode()
