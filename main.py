import tkinter as tk
from tkinter import ttk, simpledialog, messagebox
from cryptography.fernet import Fernet
import json, base64, os, hashlib
import ttkbootstrap as tb

import os
import sys

def resource_path(relative_path):
    """ Get absolute path to resource (icon) for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS  # PyInstaller temp folder
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)




root = tb.Window(themename="darkly")  # or "flatly", "cosmo", "solar", etc.

VAULT_FILE = "vault.json"
KEY_FILE = "key.hash"

def show_password_input_dialog(title, fields):
    dialog = tk.Toplevel()
    dialog.title(title)
    dialog.grab_set()
    inputs = {}

    def toggle(entry, var):
        entry.config(show='' if var.get() else '*')

    for i, field in enumerate(fields):
        tk.Label(dialog, text=field + ":").grid(row=i, column=0, padx=5, pady=5, sticky='e')
        var = tk.BooleanVar(value=False)
        entry = tk.Entry(dialog, show='*', width=30)
        entry.grid(row=i, column=1, padx=5, pady=5)
        inputs[field] = entry
        if 'password' in field.lower():
            tk.Checkbutton(dialog, text="Show", variable=var,
                           command=lambda e=entry, v=var: toggle(e, v)).grid(row=i, column=2, padx=5)

    result = {}

    def on_ok():
        for field in fields:
            val = inputs[field].get()
            if not val:
                messagebox.showerror("Error", f"{field} cannot be empty.")
                return
            result[field] = val
        dialog.destroy()

    tk.Button(dialog, text="OK", command=on_ok).grid(row=len(fields), column=0, columnspan=3, pady=10)
    dialog.wait_window()
    return result if result else None

# ========== UTILS ==========
def derive_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_data(data: str, fernet: Fernet) -> str:
    return fernet.encrypt(data.encode()).decode()

def decrypt_data(data: str, fernet: Fernet) -> str:
    return fernet.decrypt(data.encode()).decode()

def save_key_hash(password: str):
    try:
        hashed = hashlib.sha256(password.encode()).hexdigest()
        with open(KEY_FILE, "w") as f:
            f.write(hashed)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save key: {str(e)}")
        exit()

def check_key_hash(password: str) -> bool:
    try:
        if not os.path.exists(KEY_FILE):
            return False
        with open(KEY_FILE, "r") as f:
            return f.read() == hashlib.sha256(password.encode()).hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Error checking key hash: {str(e)}")
        return False
def save_vault(vault: dict, fernet: Fernet):
    try:
        encrypted = encrypt_data(json.dumps(vault), fernet)
        with open(VAULT_FILE, "w") as f:
            f.write(encrypted)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save vault: {str(e)}")

def load_vault(fernet: Fernet) -> dict:
    if not os.path.exists(VAULT_FILE):
        return {}
    try:
        with open(VAULT_FILE, "r") as f:
            encrypted = f.read()
        decrypted = decrypt_data(encrypted, fernet)
        return json.loads(decrypted)
    except FileNotFoundError:
        messagebox.showerror("Error", "Vault file not found.")
        return {}
    except json.JSONDecodeError:
        messagebox.showerror("Error", "Vault data is corrupted.")
        return {}
    except Exception as e:
        messagebox.showerror("Error", f"Could not load vault: {str(e)}")
        exit()

# ========== MAIN APP ==========
class PasswordManager:
    def __init__(self, master, password):
        self.master = master
        self.fernet = Fernet(derive_key(password))
        self.vault = load_vault(self.fernet)

        self.master.title("Password Manager")
        self.master.geometry("500x400")

        # Treeview
        self.tree = ttk.Treeview(master, columns=("Username", "Password"), show="headings")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        self.tree.pack(fill="both", expand=True)

        # Buttons
        btn_frame = tk.Frame(master)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Add Entry", command=self.add_entry).grid(row=0, column=0, padx=5)
        tk.Button(btn_frame, text="Delete Entry", command=self.delete_entry).grid(row=0, column=1, padx=5)
        tk.Button(btn_frame, text="Change Master Password", command=self.change_master_password).grid(row=0, column=2, padx=5)
        tk.Button(btn_frame, text="Save & Exit", command=self.save_and_exit).grid(row=0, column=3, padx=5)

        self.refresh()

    def refresh(self):
        self.tree.delete(*self.tree.get_children())
        for site, creds in self.vault.items():
            self.tree.insert("", "end", text=site, values=(creds["username"], creds["password"]))

    def add_entry(self):
        dialog = tk.Toplevel(self.master)
        dialog.title("Add New Entry")
        dialog.geometry("340x260")
        dialog.resizable(False, False)
        dialog.configure(bg="#1e1e1e")  # Dark background
        dialog.grab_set()

        # Common label style
        label_style = {'bg': '#1e1e1e', 'fg': 'white', 'font': ('Segoe UI', 10)}

        tk.Label(dialog, text="Site:", **label_style).pack(pady=(10, 0))
        site_entry = tk.Entry(dialog, width=30, bg="#333", fg="white", insertbackground='white')
        site_entry.pack()

        tk.Label(dialog, text="Username:", **label_style).pack(pady=(10, 0))
        username_entry = tk.Entry(dialog, width=30, bg="#333", fg="white", insertbackground='white')
        username_entry.pack()

        tk.Label(dialog, text="Password:", **label_style).pack(pady=(10, 0))
        password_frame = tk.Frame(dialog, bg="#1e1e1e")
        password_frame.pack()

        password_entry = tk.Entry(password_frame, width=26, show="*", bg="#333", fg="white", insertbackground='white')
        password_entry.pack(side=tk.LEFT)

        show_pw = tk.BooleanVar()
        show_button = tk.Checkbutton(password_frame, text="Show", variable=show_pw,
                                    command=lambda: password_entry.config(show="" if show_pw.get() else "*"),
                                    bg="#1e1e1e", fg="white", selectcolor="#1e1e1e", activebackground="#1e1e1e")
        show_button.pack(side=tk.LEFT, padx=5)

        def submit():
            try:
                site = site_entry.get()
                username = username_entry.get()
                password = password_entry.get()
                if not site or not username or not password:
                    messagebox.showerror("Error", "All fields are required.")
                    return
                self.vault[site] = {"username": username, "password": password}
                self.refresh()
                dialog.destroy()
                messagebox.showinfo("Success", f"Entry for '{site}' added.")
            except Exception as e:
                messagebox.showerror("Error", f"Something went wrong: {str(e)}")
        tk.Button(dialog, text="Add Entry", command=submit, bg="#444", fg="white", activebackground="#555", activeforeground="white").pack(pady=15)


    def delete_entry(self):
        selected = self.tree.selection()
        for item in selected:
            site = self.tree.item(item, "text")
            if site in self.vault:
                del self.vault[site]
        self.refresh()

    def change_master_password(self):
        current_pw = simpledialog.askstring("Current Password", "Enter current master password:", show="*")
        if not current_pw or not check_key_hash(current_pw):
            messagebox.showerror("Error", "Incorrect current password.")
            return

        dialog = tk.Toplevel(self.master)
        dialog.title("Change Master Password")
        dialog.geometry("300x220")
        dialog.grab_set()
        dialog.resizable(False, False)

        tk.Label(dialog, text="New Password:").pack(pady=(10, 0))
        new_pw_entry = tk.Entry(dialog, show="*")
        new_pw_entry.pack()

        tk.Label(dialog, text="Confirm Password:").pack(pady=(10, 0))
        confirm_pw_entry = tk.Entry(dialog, show="*")
        confirm_pw_entry.pack()

        def toggle_pw():
            if show_var.get():
                new_pw_entry.config(show="")
                confirm_pw_entry.config(show="")
            else:
                new_pw_entry.config(show="*")
                confirm_pw_entry.config(show="*")

        show_var = tk.BooleanVar()
        tk.Checkbutton(dialog, text="Show Password", variable=show_var, command=toggle_pw).pack()

        def submit():
            try:
                new_pw = new_pw_entry.get()
                confirm_pw = confirm_pw_entry.get()
                if not new_pw or not confirm_pw:
                    messagebox.showerror("Error", "Fields cannot be empty.")
                    return
                if new_pw != confirm_pw:
                    messagebox.showerror("Error", "Passwords do not match.")
                    return

                new_fernet = Fernet(derive_key(new_pw))
                save_key_hash(new_pw)
                encrypted_data = encrypt_data(json.dumps(self.vault), new_fernet)
                with open(VAULT_FILE, "w") as f:
                    f.write(encrypted_data)

                self.fernet = new_fernet
                dialog.destroy()
                messagebox.showinfo("Success", "Master password changed successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Something went wrong: {str(e)}")
        
        tk.Button(dialog, text="Change Password", command=submit).pack(pady=12)


    def save_and_exit(self):
        save_vault(self.vault, self.fernet)
        self.master.destroy()

# ========== MASTER PW DIALOG ==========
def prompt_master_password():
    try:
        if not os.path.exists(KEY_FILE):
            pw = simpledialog.askstring("Set Master Password", "Create a master password:", show="*")
            if not pw:
                exit()
            save_key_hash(pw)
            return pw
        else:
            for _ in range(3):
                pw = simpledialog.askstring("Enter Master Password", "Enter master password:", show="*")
                if pw and check_key_hash(pw):
                    return pw
                messagebox.showerror("Error", "Incorrect master password.")
            exit()
    except Exception as e:
        messagebox.showerror("Error", f"Password prompt failed: {str(e)}")
        exit()

# ========== MAIN ==========
if __name__ == "__main__":
    root.withdraw()              # Hide it before dialogs
    # Usage
    icon_path = resource_path("icon.ico")
    root.iconbitmap(icon_path)
    # Style after creating root
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TLabel", font=("Segoe UI", 10))
    style.configure("TEntry", font=("Segoe UI", 10))
    style.configure("TButton", font=("Segoe UI", 10), padding=6)
    style.configure("TCheckbutton", font=("Segoe UI", 9))

    # Prompt for password (uses the same root)
    master_pw = prompt_master_password()

    root.deiconify()             # Now show main window
    app = PasswordManager(root, master_pw)
    root.mainloop()
