import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import secrets


# Constants
PRIVATE_KEY_FILE = "private_key.pem.enc"  # Encrypted private key file
PUBLIC_KEY_FILE = "public_key.pem"        # Public key file


def generate_rsa_keys():
    """Generate an RSA key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def derive_key(password: str, salt: bytes):
    """Derive a key from the master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())


def encrypt_private_key(private_key, password: str):
    """Encrypt the private key using the master password."""
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)

    # Serialize the private key
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key),
    )

    # Store the salt and encrypted private key
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(salt + pem)


def save_public_key(public_key):
    """Save the public key to a file."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(pem)


def main():
    print("Generating RSA key pair...")
    private_key, public_key = generate_rsa_keys()

    while True:
        password = input("Enter a master password to encrypt the private key: ")
        confirm_password = input("Confirm master password: ")

        if password != confirm_password:
            print("Error: Passwords do not match. Please try again.")
            continue

        # Encrypt and save the private key
        encrypt_private_key(private_key, password)
        print(f"Private key encrypted and saved to '{PRIVATE_KEY_FILE}'.")

        # Save the public key
        save_public_key(public_key)
        print(f"Public key saved to '{PUBLIC_KEY_FILE}'.")

        break

    print("Setup complete!")


if __name__ == "__main__":
    main()