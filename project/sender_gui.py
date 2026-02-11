# sender_gui.py
import os
import hashlib
from pathlib import Path
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from ecdsa import VerifyingKey, SECP256k1
from encryption_system import load_input_data, generate_ecc_keys
from secure_package import create_secure_package, save_secure_package_txt

BASE_DIR = Path(__file__).parent.resolve()
DEFAULT_RECIPIENT_PUB = BASE_DIR / "recipient_public.pem"

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

class SenderGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("(Sender) Quantum-Resilient Encryptor")
        # Sender keypair created silently on start (in-memory)
        self.sender_priv, self.sender_pub = generate_ecc_keys()
        self.recipient_pub = None
        self._build_ui()

    def _build_ui(self):
        self.root.geometry("720x480")
        self.root.minsize(640, 420)
        for i in range(6):
            self.root.rowconfigure(i, weight=0)
        self.root.rowconfigure(4, weight=1)  # text area grows
        self.root.rowconfigure(5, weight=0)  # status
        self.root.columnconfigure(0, weight=1)

        tk.Label(self.root, text="Encrypt & Save Secure Package (.txt)",
                 font=("Arial", 12, "bold")).grid(row=0, column=0, pady=10, padx=12, sticky="ew")

        # File row (Browse stays on this row)
        fr = tk.Frame(self.root)
        fr.grid(row=1, column=0, sticky="ew", padx=12, pady=6)
        fr.columnconfigure(1, weight=1)
        tk.Label(fr, text="File to encrypt:").grid(row=0, column=0, sticky="w")
        self.file_entry = tk.Entry(fr)
        self.file_entry.grid(row=0, column=1, sticky="ew", padx=6)
        tk.Button(fr, text="Browse", command=self.select_file).grid(row=0, column=2)

        # Centered buttons (everything except Browse)
        btns = tk.Frame(self.root)
        btns.grid(row=2, column=0, pady=6, sticky="ew")
        btns.columnconfigure(0, weight=1)  # center
        mid = tk.Frame(btns); mid.grid(row=0, column=0)

        tk.Button(mid, text="Load Recipient Public Key",
                  command=self.load_recipient_pub).pack(side="left", padx=6)
        tk.Button(mid, text="🔒 Encrypt & Save (.txt)",
                  command=self.encrypt_and_save, bg="#4CAF50", fg="white").pack(side="left", padx=6)
        tk.Button(mid, text="🗑️ Clear",
                  command=self.clear_all, bg="#f44336", fg="white").pack(side="left", padx=6)

        # Output
        tk.Label(self.root, text="Encryption Details:", font=("Arial", 10, "bold"))\
            .grid(row=3, column=0, sticky="w", padx=12)
        self.out = scrolledtext.ScrolledText(self.root, height=14, state="disabled")
        self.out.grid(row=4, column=0, sticky="nsew", padx=12, pady=6)

        # Status
        self.status = tk.Label(self.root, text="Ready", bd=1, relief="sunken", anchor="w")
        self.status.grid(row=5, column=0, sticky="ew")

        self.root.bind("<Configure>", lambda e: self.out.config(wrap="word"))

    def _out(self, text: str):
        self.out.config(state="normal")
        self.out.delete("1.0", tk.END)
        self.out.insert(tk.END, text)
        self.out.config(state="disabled")

    def select_file(self):
        p = filedialog.askopenfilename(title="Select File", filetypes=[("All Files", "*.*")])
        if p:
            self.file_entry.delete(0, tk.END)
            self.file_entry.insert(0, p)

    def load_recipient_pub(self):
        # First try the default file path automatically
        try_path = DEFAULT_RECIPIENT_PUB
        if try_path.exists():
            try:
                with open(try_path, "rb") as f:
                    self.recipient_pub = VerifyingKey.from_pem(f.read())
                self.status.config(text=f"Loaded recipient public key: {try_path.name}")
                messagebox.showinfo("OK", f"Loaded recipient public key:\n{try_path}")
                return
            except Exception:
                pass
        # Fallback to manual file dialog
        p = filedialog.askopenfilename(title="Load Recipient Public Key (PEM)",
                                       filetypes=[("PEM files", "*.pem"), ("All Files", "*.*")])
        if not p:
            return
        try:
            with open(p, "rb") as f:
                self.recipient_pub = VerifyingKey.from_pem(f.read())
            self.status.config(text=f"Loaded recipient public key: {Path(p).name}")
            messagebox.showinfo("OK", f"Loaded recipient public key:\n{p}")
        except Exception as e:
            self.recipient_pub = None
            messagebox.showerror("Error", f"Failed to load recipient public key:\n{e}")

    def clear_all(self):
        self.file_entry.delete(0, tk.END)
        self._out("")
        self.status.config(text="Cleared")

    def encrypt_and_save(self):
        try:
            path = (self.file_entry.get() or "").strip()
            if not path or not os.path.isfile(path):
                messagebox.showerror("Error", "Select a valid file first.")
                return
            if self.recipient_pub is None:
                messagebox.showerror("Error", "Load recipient public key first.")
                return

            data = load_input_data(path)
            pkg = create_secure_package(
                data_bytes=data,
                recipient_public_key=self.recipient_pub,
                sender_private_key=self.sender_priv,
                sender_public_key=self.sender_pub
            )

            suggested = os.path.splitext(os.path.basename(path))[0] + "_secure.txt"
            save_path = filedialog.asksaveasfilename(
                initialfile=suggested, defaultextension=".txt",
                filetypes=[("Secure Package", "*.txt"), ("All Files", "*.*")]
            )
            if not save_path:
                self.status.config(text="Cancelled")
                return

            save_secure_package_txt(pkg, save_path)
            self.status.config(text=f"✅ Encryption complete. Saved to {save_path}")

            # Show sender keys (raw forms; demo visibility)
            sender_priv_b64 = b64e(self.sender_priv.to_string())  # 32 bytes
            sender_pub_b64 = b64e(self.sender_pub.to_string())    # 64 bytes

            display = (
                "=== ENCRYPTION DETAILS (Display Only) ===\n"
                f"AES-256 Key (base64): {pkg['aes_key']}\n"
                f"IV (base64): {pkg['iv']}\n"
                f"Ciphertext (base64): {pkg['ciphertext']}\n"
                f"SHA1(ciphertext) (hex): {pkg['ciphertext_sha1']}\n"
                f"Sender Private (base64 raw 32B): {sender_priv_b64}\n"
                f"Sender Public  (base64 raw 64B): {sender_pub_b64}\n"
                f"Sender FP (sha256): {pkg['fingerprints']['sender_fp']}\n"
                f"Recipient FP (sha256): {pkg['fingerprints']['recipient_fp']}\n"
            )
            self._out(display)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.status.config(text="Failed")

if __name__ == "__main__":
    root = tk.Tk()
    SenderGUI(root)
    root.mainloop()
