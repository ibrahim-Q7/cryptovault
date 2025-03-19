import os
import json
import getpass
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import base64

# Constants
VAULT_FILE = "vault.json"
PRIVATE_KEY_FILE = "private_key.pem.enc"
PUBLIC_KEY_FILE = "public_key.pem"


def load_public_key():
    """Load the public key from the file."""
    if not os.path.exists(PUBLIC_KEY_FILE):
        raise FileNotFoundError(f"File '{PUBLIC_KEY_FILE}' not found. Run 'setup.py' first.")

    with open(PUBLIC_KEY_FILE, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key


def load_private_key(password: str):
    """Load and decrypt the private key."""
    if not os.path.exists(PRIVATE_KEY_FILE):
        raise FileNotFoundError(f"File '{PRIVATE_KEY_FILE}' not found. Run 'setup.py' first.")

    with open(PRIVATE_KEY_FILE, "rb") as f:
        data = f.read()
        salt = data[:16]
        encrypted_pem = data[16:]

    try:
        key = derive_key(password, salt)
        private_key = serialization.load_pem_private_key(
            encrypted_pem,
            password=key,
        )
        return private_key
    except Exception as e:
        print("Error: Failed to decrypt the private key.")
        print("Possible causes:")
        print("- Incorrect master password.")
        print("- Corrupted private key file.")
        print("- Mismatched salt between encryption and decryption.")
        exit(1)


def derive_key(password: str, salt: bytes):
    """Derive a key from the master password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode())


def encrypt_data(data: str, public_key):
    """Encrypt data using the public key."""
    encrypted = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(encrypted).decode()


def decrypt_data(encrypted_data: str, private_key):
    """Decrypt data using the private key."""
    encrypted_data = base64.b64decode(encrypted_data)
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted.decode()


def load_vault(password: str):
    """Load the encrypted vault and decrypt it."""
    if not os.path.exists(VAULT_FILE):
        return {}

    with open(VAULT_FILE, "r") as f:
        encrypted_vault = json.load(f)

    private_key = load_private_key(password)
    vault = {}
    for account, entry in encrypted_vault.items():
        username = decrypt_data(entry["username"], private_key)
        password = decrypt_data(entry["password"], private_key)
        vault[account] = {"username": username, "password": password}
    return vault


def save_vault(vault: dict, password: str):
    """Encrypt and save the vault."""
    public_key = load_public_key()
    encrypted_vault = {}
    for account, entry in vault.items():
        encrypted_username = encrypt_data(entry["username"], public_key)
        encrypted_password = encrypt_data(entry["password"], public_key)
        encrypted_vault[account] = {"username": encrypted_username, "password": encrypted_password}

    with open(VAULT_FILE, "w") as f:
        json.dump(encrypted_vault, f)


def initialize_vault():
    """Initialize the vault with a master password."""
    print("Initializing EncryptoVault...")
    password = getpass.getpass("Enter a master password: ")
    confirm_password = getpass.getpass("Confirm master password: ")

    if password != confirm_password:
        print("Error: Passwords do not match.")
        exit(1)

    save_vault({}, password)
    print("Vault initialized successfully!")


def add_entry(vault: dict, account: str, username: str, password: str):
    """Add a new entry to the vault."""
    vault[account] = {"username": username, "password": password}
    print(f"Added entry for '{account}'.")


def get_entry(vault: dict, account: str):
    """Retrieve an entry from the vault."""
    if account not in vault:
        print(f"Error: No entry found for '{account}'.")
        return

    entry = vault[account]
    print(f"Username: {entry['username']}")
    print(f"Password: {entry['password']}")


def list_entries(vault: dict):
    """List all entries in the vault."""
    if not vault:
        print("No entries found.")
        return

    print("Stored Accounts:")
    for account in vault:
        print(f"- {account}")


def delete_entry(vault: dict, account: str):
    """Delete an entry from the vault."""
    if account not in vault:
        print(f"Error: No entry found for '{account}'.")
        return

    del vault[account]
    print(f"Deleted entry for '{account}'.")


def main():
    if not os.path.exists(VAULT_FILE):
        initialize_vault()

    password = getpass.getpass("Enter your master password: ")
    try:
        vault = load_vault(password)
    except Exception as e:
        print("Error: Incorrect password or corrupted vault.")
        exit(1)

    while True:
        print("\nEncryptoVault CLI")
        print("1. Add Entry")
        print("2. Get Entry")
        print("3. List Entries")
        print("4. Delete Entry")
        print("5. Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            account = input("Account name: ").strip()
            username = input("Username: ").strip()
            password = getpass.getpass("Password: ").strip()
            add_entry(vault, account, username, password)
            save_vault(vault, password)

        elif choice == "2":
            account = input("Account name: ").strip()
            get_entry(vault, account)

        elif choice == "3":
            list_entries(vault)

        elif choice == "4":
            account = input("Account name: ").strip()
            delete_entry(vault, account)
            save_vault(vault, password)

        elif choice == "5":
            print("Exiting EncryptoVault CLI...")
            break

        else:
            print("Invalid option. Please try again.")


if __name__ == "__main__":
    main()