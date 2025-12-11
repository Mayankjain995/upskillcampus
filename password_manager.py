import os
import sqlite3
import string
import secrets
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet

# -------------------- Encryption Setup --------------------
KEY_FILE = "key.key"

def load_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key

cipher = Fernet(load_key())

# -------------------- Database Setup --------------------
DB_FILE = "passwords.db"

def setup_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL,
            username TEXT,
            password BLOB NOT NULL
        )
    """)
    conn.commit()
    return conn

conn = setup_db()
cur = conn.cursor()

# -------------------- Core Functions --------------------
def encrypt_text(text):
    return cipher.encrypt(text.encode())

def decrypt_text(enc_text):
    try:
        return cipher.decrypt(enc_text).decode()
    except:
        return "<Error>"

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%&*?"
    return "".join(secrets.choice(chars) for _ in range(length))

def add_entry(account, username, password):
    cur.execute(
        "INSERT INTO passwords (account, username, password) VALUES (?, ?, ?)",
        (account, username, encrypt_text(password))
    )
    conn.commit()

def get_all_entries():
    cur.execute("SELECT * FROM passwords ORDER BY account")
    return cur.fetchall()

def delete_entry(entry_id):
    cur.execute("DELETE FROM passwords WHERE id=?", (entry_id,))
    conn.commit()

# -------------------- GUI --------------------
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Password Manager")
        self.root.geometry("950x600")
        self.root.minsize(800, 500)
        self.root.config(bg="#f0f4f7")
        self.password_visible = False
        self.create_widgets()
        self.load_entries()

    def create_widgets(self):
        # Header
        header = tk.Frame(self.root, bg="#0D47A1", height=70)
        header.pack(fill="x")
        tk.Label(header, text="🔐 PASSWORD MANAGER", bg="#0D47A1", fg="white",
                 font=("Segoe UI", 24, "bold")).pack(pady=15)

        # Input Frame
        frame = tk.LabelFrame(self.root, text="Add / Update Entry", bg="#f0f4f7",
                              font=("Segoe UI", 12, "bold"), padx=15, pady=15)
        frame.pack(fill="x", padx=20, pady=10)

        tk.Label(frame, text="Account:", bg="#f0f4f7", font=("Segoe UI", 11)).grid(row=0, column=0, sticky="w", pady=5)
        self.account_entry = tk.Entry(frame, font=("Segoe UI", 11))
        self.account_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")

        tk.Label(frame, text="Username:", bg="#f0f4f7", font=("Segoe UI", 11)).grid(row=1, column=0, sticky="w", pady=5)
        self.username_entry = tk.Entry(frame, font=("Segoe UI", 11))
        self.username_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")

        tk.Label(frame, text="Password:", bg="#f0f4f7", font=("Segoe UI", 11)).grid(row=2, column=0, sticky="w", pady=5)
        self.password_entry = tk.Entry(frame, font=("Segoe UI", 11), show="*")
        self.password_entry.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        # Buttons in input frame
        btn_style = {"font": ("Segoe UI", 10, "bold"), "width": 15}
        tk.Button(frame, text="👁️ Show/Hide", command=self.toggle_password, **btn_style, bg="#1565C0", fg="white").grid(row=2, column=2, padx=5)
        tk.Button(frame, text="Generate Password", command=self.generate_password_ui, **btn_style, bg="#0288D1", fg="white").grid(row=2, column=3, padx=5)
        tk.Button(frame, text="Save Entry", command=self.save_entry, **btn_style, bg="#2E7D32", fg="white").grid(row=3, column=1, pady=10)

        # Make entry fields expand when resizing
        frame.grid_columnconfigure(1, weight=1)

        # Treeview Frame
        tree_frame = tk.Frame(self.root)
        tree_frame.pack(fill="both", expand=True, padx=20, pady=5)

        style = ttk.Style()
        style.configure("Treeview", font=("Segoe UI", 11), rowheight=28)
        style.configure("Treeview.Heading", font=("Segoe UI", 12, "bold"), background="#1976D2", foreground="white")
        style.map("Treeview", background=[("selected", "#90CAF9")])

        self.tree = ttk.Treeview(tree_frame, columns=("ID", "Account", "Username"), show="headings")
        for col in ("ID", "Account", "Username"):
            self.tree.heading(col, text=col)
            self.tree.column(col, anchor="center")
        self.tree.pack(fill="both", expand=True)

        # Bottom Buttons below Treeview
        btn_frame = tk.Frame(self.root, bg="#f0f4f7")
        btn_frame.pack(fill="x", padx=20, pady=10)

        tk.Button(btn_frame, text="View Password", command=self.view_password, **btn_style, bg="#0288D1", fg="white").pack(side="left", padx=5, expand=True, fill="x")
        tk.Button(btn_frame, text="Copy Password", command=self.copy_password, **btn_style, bg="#F57C00", fg="white").pack(side="left", padx=5, expand=True, fill="x")
        tk.Button(btn_frame, text="Delete Entry", command=self.delete_selected, **btn_style, bg="#C62828", fg="white").pack(side="left", padx=5, expand=True, fill="x")
        tk.Button(btn_frame, text="Refresh", command=self.load_entries, **btn_style, bg="#1976D2", fg="white").pack(side="left", padx=5, expand=True, fill="x")

    # -------------------- Functionality --------------------
    def toggle_password(self):
        self.password_entry.config(show="" if not self.password_visible else "*")
        self.password_visible = not self.password_visible

    def generate_password_ui(self):
        length = simpledialog.askinteger("Password Length", "Enter length (8–32):", minvalue=8, maxvalue=32)
        if length:
            new_pass = generate_password(length)
            self.password_entry.delete(0, tk.END)
            self.password_entry.insert(0, new_pass)
            messagebox.showinfo("Success", "Strong password generated!")

    def save_entry(self):
        acc = self.account_entry.get().strip()
        user = self.username_entry.get().strip()
        pwd = self.password_entry.get().strip()
        if not acc or not pwd:
            messagebox.showwarning("Error", "Account and Password are required.")
            return
        add_entry(acc, user, pwd)
        self.clear_entries()
        self.load_entries()
        messagebox.showinfo("Saved", f"Password saved for {acc}")

    def load_entries(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        entries = get_all_entries()
        for idx, row in enumerate(entries):
            tag = "evenrow" if idx % 2 == 0 else "oddrow"
            self.tree.insert("", "end", values=(row[0], row[1], row[2]), tags=(tag,))
        self.tree.tag_configure("evenrow", background="#E3F2FD")
        self.tree.tag_configure("oddrow", background="#BBDEFB")

    def get_selected_id(self):
        selected = self.tree.selection()
        return self.tree.item(selected[0])["values"][0] if selected else None

    def view_password(self):
        entry_id = self.get_selected_id()
        if entry_id:
            cur.execute("SELECT password FROM passwords WHERE id=?", (entry_id,))
            enc = cur.fetchone()
            if enc:
                messagebox.showinfo("Password", decrypt_text(enc[0]))
        else:
            messagebox.showwarning("Select Entry", "Please select a record first.")

    def copy_password(self):
        entry_id = self.get_selected_id()
        if entry_id:
            cur.execute("SELECT password FROM passwords WHERE id=?", (entry_id,))
            enc = cur.fetchone()
            if enc:
                dec = decrypt_text(enc[0])
                self.root.clipboard_clear()
                self.root.clipboard_append(dec)
                messagebox.showinfo("Copied", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Select Entry", "Please select a record first.")

    def delete_selected(self):
        entry_id = self.get_selected_id()
        if entry_id and messagebox.askyesno("Confirm", "Delete this record?"):
            delete_entry(entry_id)
            self.load_entries()
            messagebox.showinfo("Deleted", "Entry deleted successfully!")
        else:
            messagebox.showwarning("Select Entry", "Please select an entry to delete.")

    def clear_entries(self):
        self.account_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        self.password_entry.config(show="*")
        self.password_visible = False

# -------------------- Run App --------------------
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
