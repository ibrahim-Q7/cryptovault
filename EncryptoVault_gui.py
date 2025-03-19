import os
import json
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import secrets

# Constants
VAULT_FILE = "vault.json"
PRIVATE_KEY_FILE = "private_key.pem.enc"  # Encrypted private key file
PUBLIC_KEY_FILE = "public_key.pem"        # Public key file


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
    key = derive_key(password, salt)
    private_key = serialization.load_pem_private_key(
        encrypted_pem,
        password=key,
    )
    return private_key


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


class EncryptoVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("EncryptoVault - Password Manager")
        self.root.geometry("600x400")  # Set window size
        self.root.resizable(False, False)  # Disable resizing
        self.vault = {}
        self.master_password = None

        # Modern Color Scheme
        self.style = ttk.Style()
        self.style.theme_use("clam")  # Use a sleek theme

        # Define colors
        self.primary_color = "#1E3A8A"  # Deep blue
        self.accent_color = "#4361EE"   # Bright blue
        self.bg_color = "#0F172A"       # Dark background
        self.text_color = "#FFFFFF"     # White text
        self.entry_bg_color = "#1E293B" # Darker entry background

        # Configure styles
        self.style.configure("TButton", padding=5, relief="flat", background=self.accent_color, foreground=self.text_color, font=("Arial", 12))
        self.style.map("TButton", background=[("active", self.primary_color)])  # Hover effect
        self.style.configure("TLabel", padding=5, font=("Arial", 12), background=self.bg_color, foreground=self.text_color)
        self.style.configure("TEntry", padding=5, font=("Arial", 12), fieldbackground=self.entry_bg_color, foreground=self.text_color)
        self.style.configure("TFrame", background=self.bg_color)

        # Add logo
        try:
            self.logo_image = tk.PhotoImage(file="logo.png")  # Ensure "logo.png" exists in the same directory
        except Exception:
            self.logo_image = None

        if self.logo_image:
            self.logo_label = ttk.Label(self.root, image=self.logo_image, background=self.bg_color)
            self.logo_label.pack(pady=10)

        # Initialize UI components
        self.init_ui()

    def init_ui(self):
        """Initialize the GUI components."""
        # Welcome Frame
        welcome_frame = ttk.Frame(self.root, padding=20, style="TFrame")
        welcome_frame.pack(fill="both", expand=True)

        ttk.Label(welcome_frame, text="Welcome to EncryptoVault", font=("Arial", 18, "bold"), foreground=self.accent_color).pack(pady=10)
        ttk.Label(welcome_frame, text="Your secure password manager.", font=("Arial", 12), foreground=self.text_color).pack(pady=5)

        # Check if the vault exists
        if os.path.exists(VAULT_FILE):
            unlock_button = ttk.Button(welcome_frame, text="Unlock Vault", command=self.unlock_vault)
            unlock_button.pack(pady=20)
        else:
            initialize_button = ttk.Button(welcome_frame, text="Initialize Vault", command=self.initialize_vault)
            initialize_button.pack(pady=20)

    def initialize_vault(self):
        """Initialize the vault with a master password."""
        while True:
            password = simpledialog.askstring("Master Password", "Enter a master password:", show="*")
            if not password:
                messagebox.showwarning("Warning", "Master password cannot be empty.")
                continue
            confirm_password = simpledialog.askstring("Confirm Password", "Confirm master password:", show="*")
            if not confirm_password:
                messagebox.showwarning("Warning", "Confirm password cannot be empty.")
                continue
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match. Please try again.")
                continue
            # Passwords match, proceed with vault initialization
            self.master_password = password
            try:
                save_vault({}, password)
                messagebox.showinfo("Success", "Vault initialized successfully!")
                break
            except Exception as e:
                messagebox.showerror("Error", "Failed to initialize vault.")
                break
        # Transition to the main UI
        self.main_ui()

    def unlock_vault(self):
        """Unlock the vault with the master password."""
        while True:
            password = simpledialog.askstring("Master Password", "Enter your master password:", show="*")
            if not password:
                messagebox.showwarning("Warning", "Master password cannot be empty.")
                continue
            try:
                self.master_password = password
                self.vault = load_vault(password)
                messagebox.showinfo("Success", "Vault unlocked successfully!")
                break
            except Exception as e:
                messagebox.showerror("Error", "Incorrect password or corrupted vault.")
                continue
        # Transition to the main UI
        self.main_ui()

    def main_ui(self):
        """Display the main UI with tabs for managing vault entries."""
        # Clear existing widgets
        for widget in self.root.winfo_children():
            widget.destroy()

        # Add logo
        if self.logo_image:
            self.logo_label = ttk.Label(self.root, image=self.logo_image, background=self.bg_color)
            self.logo_label.pack(pady=10)

        # Create Notebook (Tabbed Interface)
        notebook = ttk.Notebook(self.root, style="TNotebook")
        notebook.pack(fill="both", expand=True, padx=20, pady=20)

        # Add Entry Tab
        add_tab = ttk.Frame(notebook, padding=10, style="TFrame")
        notebook.add(add_tab, text="Add Entry")

        ttk.Label(add_tab, text="Account Name:", font=("Arial", 12), foreground=self.text_color).grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.account_entry = ttk.Entry(add_tab, width=30)
        self.account_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        ttk.Label(add_tab, text="Username:", font=("Arial", 12), foreground=self.text_color).grid(row=1, column=0, padx=10, pady=5, sticky="e")
        self.username_entry = ttk.Entry(add_tab, width=30)
        self.username_entry.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        ttk.Label(add_tab, text="Password:", font=("Arial", 12), foreground=self.text_color).grid(row=2, column=0, padx=10, pady=5, sticky="e")
        self.password_add_entry = ttk.Entry(add_tab, show="*", width=30)
        self.password_add_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")

        add_button = ttk.Button(add_tab, text="Add Entry", command=self.clear_and_add_entry, style="TButton")
        add_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Retrieve Entry Tab
        retrieve_tab = ttk.Frame(notebook, padding=10, style="TFrame")
        notebook.add(retrieve_tab, text="Retrieve Entry")

        ttk.Label(retrieve_tab, text="Account Name:", font=("Arial", 12), foreground=self.text_color).grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.retrieve_account_entry = ttk.Entry(retrieve_tab, width=30)
        self.retrieve_account_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        get_button = ttk.Button(retrieve_tab, text="Get Password", command=self.clear_and_get_password, style="TButton")
        get_button.grid(row=1, column=0, columnspan=2, pady=10)

        # List Entries Tab
        list_tab = ttk.Frame(notebook, padding=10, style="TFrame")
        notebook.add(list_tab, text="List Entries")

        list_button = ttk.Button(list_tab, text="List All Entries", command=self.list_entries, style="TButton")
        list_button.pack(pady=20)

        # Delete Entry Tab
        delete_tab = ttk.Frame(notebook, padding=10, style="TFrame")
        notebook.add(delete_tab, text="Delete Entry")

        ttk.Label(delete_tab, text="Account Name:", font=("Arial", 12), foreground=self.text_color).grid(row=0, column=0, padx=10, pady=5, sticky="e")
        self.delete_account_entry = ttk.Entry(delete_tab, width=30)
        self.delete_account_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        delete_button = ttk.Button(delete_tab, text="Delete Entry", command=self.clear_and_delete_entry, style="TButton")
        delete_button.grid(row=1, column=0, columnspan=2, pady=10)

        # Bind tab change event to clear inputs
        notebook.bind("<<NotebookTabChanged>>", self.clear_inputs_on_tab_change)

    def clear_inputs_on_tab_change(self, event=None):
        """Clear all input fields when switching tabs."""
        self.account_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_add_entry.delete(0, tk.END)
        self.retrieve_account_entry.delete(0, tk.END)
        self.delete_account_entry.delete(0, tk.END)

    def clear_and_add_entry(self):
        """Clear inputs after adding an entry."""
        self.add_entry()
        self.account_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_add_entry.delete(0, tk.END)

    def clear_and_get_password(self):
        """Clear inputs after retrieving a password."""
        self.get_password()
        self.retrieve_account_entry.delete(0, tk.END)

    def clear_and_delete_entry(self):
        """Clear inputs after deleting an entry."""
        self.delete_entry()
        self.delete_account_entry.delete(0, tk.END)

    def add_entry(self):
        """Add a new entry to the vault."""
        if not self.master_password:
            messagebox.showwarning("Warning", "Please unlock the vault first.")
            return
        account = self.account_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_add_entry.get().strip()
        if not account or not username or not password:
            messagebox.showwarning("Warning", "All fields are required.")
            return
        self.vault[account] = {"username": username, "password": password}
        save_vault(self.vault, self.master_password)
        messagebox.showinfo("Success", f"Entry for '{account}' added successfully!")

    def get_password(self):
        """Retrieve a password for an account."""
        if not self.master_password:
            messagebox.showwarning("Warning", "Please unlock the vault first.")
            return
        account = self.retrieve_account_entry.get().strip()
        if account not in self.vault:
            messagebox.showerror("Error", f"No entry found for '{account}'.")
            return
        password = self.vault[account]["password"]
        messagebox.showinfo("Success", f"Password for '{account}': {password}")

    def list_entries(self):
        """List all entries in the vault."""
        if not self.master_password:
            messagebox.showwarning("Warning", "Please unlock the vault first.")
            return
        if not self.vault:
            messagebox.showinfo("Info", "No entries found.")
            return
        entries = "\n".join([f"- {account}" for account in self.vault])
        messagebox.showinfo("Stored Accounts", f"Stored Accounts:\n{entries}")

    def delete_entry(self):
        """Delete an entry from the vault."""
        if not self.master_password:
            messagebox.showwarning("Warning", "Please unlock the vault first.")
            return
        account = self.delete_account_entry.get().strip()
        if account not in self.vault:
            messagebox.showerror("Error", f"No entry found for '{account}'.")
            return
        del self.vault[account]
        save_vault(self.vault, self.master_password)
        messagebox.showinfo("Success", f"Entry for '{account}' deleted successfully!")


if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptoVaultApp(root)
    root.mainloop()