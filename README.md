# EncryptoVault - Secure Password Manager

EncryptoVault is a secure password manager that uses RSA encryption to store and manage sensitive credentials. It provides both a command-line interface (CLI) and a graphical user interface (GUI) for ease of use.

## Features

- **Secure Encryption**: Uses RSA asymmetric encryption to securely store passwords.
- **Master Password Protection**: The vault is encrypted and can only be accessed with a master password.
- **User-Friendly Interfaces**:
  - CLI tool for managing credentials via the terminal.
  - GUI tool for a more interactive experience.
- **Cross-Platform**: Works on any platform where Python is supported.

## Installation

### Prerequisites

- Python 3.8 or higher
- `pip` package manager

### Steps

1. Clone the repository or download the source code.

   ```bash
   git clone https://github.com/your-repo/encrypto-vault.git
   cd encrypto-vault
   ```
2. Install the required dependencies.
```bash
pip install -r requirements.txt
```
3. Run the setup.py script to generate the RSA key pair.
```bash
python3 setup.py
```
