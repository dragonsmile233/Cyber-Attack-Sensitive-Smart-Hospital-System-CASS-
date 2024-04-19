from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Generate RSA private key
def generate_private_key(filename):
    """Generate RSA private key and store it as a PEM file."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    with open(filename, "wb") as private_key_file:
        private_key_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    return private_key

# Generate RSA public key from private key
def generate_public_key(private_key, filename):
    """Generate RSA public key from private key and store it as a PEM file."""
    public_key = private_key.public_key()
    with open(filename, "wb") as public_key_file:
        public_key_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

# Example usage
if __name__ == "__main__":
    private_key = generate_private_key("private_key.pem")
    generate_public_key(private_key, "public_key.pem")
