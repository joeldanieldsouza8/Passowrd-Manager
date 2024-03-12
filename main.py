import tkinter as tk
from tkinter import simpledialog, messagebox
from cryptography.fernet import Fernet
import os
from tkinter import messagebox 

def write_or_load_key() -> bytes:
    if not os.path.exists("key.key"):
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    return key

def verify_master_password(fer: Fernet, master_password: str) -> bool:
    if not os.path.exists("master_password.key"):
        messagebox.showinfo("Setup", "Setting up a new master password.")  # type: ignore
        encrypted_master_password = fer.encrypt(master_password.encode())
        with open("master_password.key", "wb") as master_password_file:
            master_password_file.write(encrypted_master_password)
        return True
    else:
        with open("master_password.key", "rb") as master_password_file:
            stored_master_password = fer.decrypt(master_password_file.read()).decode()
            return master_password == stored_master_password

def encrypt_password(password: str, fer: Fernet) -> str:
    return fer.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password: str, fer: Fernet) -> str:
    return fer.decrypt(encrypted_password.encode()).decode()

def add_password_gui(fer: Fernet):
    account_name = simpledialog.askstring("Account Name", "Enter the account name:")
    password = simpledialog.askstring("Password", "Enter the password:", show="*")
    if account_name and password:  # Check if the user did not cancel the dialog
        encrypted_password = encrypt_password(password, fer)
        with open("passwords.txt", "a") as file:
            file.write(account_name + " | " + encrypted_password + "\n")
        messagebox.showwarning("Cancelled", "Operation cancelled by user.")  # type: ignore
    else:
        messagebox.showwarning("Cancelled", "Operation cancelled by user.") # type: ignore

def view_password_gui(fer: Fernet):
    try:
        with open("passwords.txt", "r") as file:
            passwords = [decrypt_password(line.strip().split(" | ")[1], fer) for line in file.readlines()]
            passwords_str = "\n".join(passwords)
            messagebox.showinfo("Stored Passwords", passwords_str) # type: ignore
    except FileNotFoundError:
        messagebox.showwarning("Error", "No passwords stored yet.") # type: ignore

def gui():
    key = write_or_load_key()
    fer = Fernet(key)

    master_password = simpledialog.askstring("Master Password", "Enter the master password:", show="*")
    if master_password and verify_master_password(fer, master_password):
        root = tk.Tk()
        root.title("Password Manager")

        add_btn = tk.Button(root, text="Add Password", command=lambda: add_password_gui(fer))
        add_btn.pack(fill=tk.X, padx=50, pady=5)

        view_btn = tk.Button(root, text="View Passwords", command=lambda: view_password_gui(fer))
        view_btn.pack(fill=tk.X, padx=50, pady=5)

        root.mainloop()
    else:
        messagebox.showwarning("Access Denied", "Incorrect master password or cancelled operation.") # type: ignore

if __name__ == "__main__":
    gui()
