# 🔐 Password Manager App (Python + EXE)

This is a secure and user-friendly Password Manager built using Python and Tkinter, with AES encryption using the `cryptography` library. You can also run it as a standalone Windows `.exe` — no need to install Python for users.

---

## 📦 Features

- Master password protected vault
- Add, edit, and delete saved site credentials
- Show/hide password toggle
- Ability to change master password
- Fully encrypted storage (AES)
- Modern UI with ttk and optional Bootstrap style
- One-click `.exe` distribution (no Python needed)

---

## 🖥️ For End Users (EXE)

### ✅ How to Use

1. **Download the `.exe` file** from the Releases tab or shared location.
2. Double-click the `.exe` to launch the app.
3. First time? You'll be asked to set a master password.
4. Save and manage your credentials securely!

> ℹ️ **You do NOT need to install Python** or any libraries to run the `.exe`.

---

## 🛠️ For Developers

### 🔧 Setup Instructions

#### Requirements

- Python 3.10+ (recommended)
- `pip` (Python package manager)

#### Installation

```bash
git clone https://github.com/your-username/password-manager.git
cd password-manager
pip install -r requirements.txt
python main.py
