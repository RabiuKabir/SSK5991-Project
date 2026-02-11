# recipient_gui.py
import base64
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from encryption_system import verify_signature, decapsulate_aes_key, decrypt_aes
from secure_package import load_secure_package_txt

BASE_DIR = Path(__file__).parent.resolve()
PRIV_PEM = BASE_DIR / "recipient_private.pem"
PUB_PEM  = BASE_DIR / "recipient_public.pem"

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

class RecipientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("(Recipient) Quantum-Resilient Decryptor")
        self.recipient_priv: SigningKey | None = None
        self.loaded_pkg: dict | None = None
        self._build_ui()

    def _build_ui(self):
        self.root.geometry("720x520")
        self.root.minsize(640, 420)
        for i in range(6):
            self.root.rowconfigure(i, weight=0)
        self.root.rowconfigure(4, weight=1)  # text grows
        self.root.rowconfigure(5, weight=0)  # status
        self.root.columnconfigure(0, weight=1)

        tk.Label(self.root, text="Decrypt Secure Package (.txt)",
                 font=("Arial", 12, "bold")).grid(row=0, column=0, pady=10, sticky="ew")

        # Centered buttons
        bar = tk.Frame(self.root); bar.grid(row=1, column=0, sticky="ew")
        bar.columnconfigure(0, weight=1)
        mid = tk.Frame(bar); mid.grid(row=0, column=0)

        tk.Button(mid, text="Generate Keypair (auto-save)", command=self.generate_keypair)\
            .pack(side="left", padx=6)
        tk.Button(mid, text="Load Private Key (PEM)", command=self.load_private_key)\
            .pack(side="left", padx=6)
        tk.Button(mid, text="Load Package (.txt)", command=self.load_package)\
            .pack(side="left", padx=6)
        tk.Button(mid, text="Decrypt", command=self.decrypt_now, bg="#4CAF50", fg="white")\
            .pack(side="left", padx=6)

        tk.Label(self.root, text="Output:", font=("Arial", 10, "bold"))\
            .grid(row=3, column=0, sticky="w", padx=12, pady=(6, 2))
        self.output = scrolledtext.ScrolledText(self.root, height=18, state="disabled")
        self.output.grid(row=4, column=0, sticky="nsew", padx=12, pady=6)

        self.status = tk.Label(self.root, text="Ready", bd=1, relief="sunken", anchor="w")
        self.status.grid(row=5, column=0, sticky="ew")

        self.root.bind("<Configure>", lambda e: self.output.config(wrap="word"))

    def log(self, msg: str):
        self.output.config(state="normal")
        self.output.insert(tk.END, msg + "\n")
        self.output.config(state="disabled")
        self.output.see(tk.END)

    # --- Keys ---
    def generate_keypair(self):
        try:
            sk = SigningKey.generate(curve=SECP256k1)
            vk = sk.get_verifying_key()
            PRIV_PEM.write_bytes(sk.to_pem())
            PUB_PEM.write_bytes(vk.to_pem())
            self.recipient_priv = sk  # auto-load
            self.status.config(text=f"✅ Keypair generated & saved.")
            self.log(f"Saved {PRIV_PEM.name} and {PUB_PEM.name} in project folder.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate/save keys: {e}")

    def load_private_key(self):
        p = PRIV_PEM if PRIV_PEM.exists() else filedialog.askopenfilename(
            title="Open recipient private key (PEM)", filetypes=[("PEM","*.pem"), ("All Files","*.*")]
        )
        if not p:
            return
        try:
            data = Path(p).read_bytes() if isinstance(p, (str, Path)) else p
            self.recipient_priv = SigningKey.from_pem(data)
            self.status.config(text=f"✅ Loaded private key: {Path(p).name}")
            self.log(f"Loaded private key from {p}")
        except Exception as e:
            self.recipient_priv = None
            messagebox.showerror("Error", f"Failed to load private key: {e}")

    # --- Package ---
    def load_package(self):
        p = filedialog.askopenfilename(title="Open secure package (.txt)",
                                       filetypes=[("Secure Package","*.txt"), ("All Files","*.*")])
        if not p: return
        try:
            self.loaded_pkg = load_secure_package_txt(p)
            self.status.config(text=f"✅ Package loaded: {Path(p).name}")
            # Optional pre-check
            try:
                sender_pub = VerifyingKey.from_string(b64d(self.loaded_pkg["sender_public_key"]), curve=SECP256k1)
                ok = verify_signature(b64d(self.loaded_pkg["ciphertext"]), b64d(self.loaded_pkg["signature"]), sender_pub)
                self.log("Signature valid (pre-check)." if ok else "Signature invalid (pre-check).")
            except Exception:
                self.log("Could not pre-check signature.")
        except Exception as e:
            self.loaded_pkg = None
            messagebox.showerror("Error", str(e))

    def decrypt_now(self):
        try:
            if self.loaded_pkg is None:
                messagebox.showerror("Error", "Load a package first."); return
            if self.recipient_priv is None:
                messagebox.showerror("Error", "Load or generate your private key first."); return

            pkg = self.loaded_pkg
            ciphertext = b64d(pkg["ciphertext"])
            iv = b64d(pkg["iv"])
            enc_aes_key = b64d(pkg["encrypted_aes_key"])
            nonce = b64d(pkg["nonce"])
            tag = b64d(pkg["tag"])
            eph_pub = VerifyingKey.from_string(b64d(pkg["ephemeral_public_key"]), curve=SECP256k1)
            sender_pub = VerifyingKey.from_string(b64d(pkg["sender_public_key"]), curve=SECP256k1)
            sig = b64d(pkg["signature"])

            # Verify, decapsulate, decrypt
            ok = verify_signature(ciphertext, sig, sender_pub)
            self.log("✅ Signature valid." if ok else "❌ Signature invalid!")
            aes_key = decapsulate_aes_key(enc_aes_key, self.recipient_priv, eph_pub, nonce, tag)
            plaintext = decrypt_aes(aes_key, iv, ciphertext)

            # Ask where to save the decrypted file
            save_path = filedialog.asksaveasfilename(
                title="Save decrypted file as...",
                initialfile="decrypted_output",
                defaultextension="",
                filetypes=[("All Files","*.*")]
            )
            if save_path:
                Path(save_path).write_bytes(plaintext)
                self.log(f"💾 Decrypted file saved to: {save_path}")

            self.status.config(text="✅ Decryption complete.")
            self.log("✅ AES key recovered.")
            self.log("✅ Decryption successful.")

            # Show preview (text or hex)
            try:
                self.log("📄 Decrypted text (preview):\n" + plaintext.decode("utf-8"))
            except UnicodeDecodeError:
                self.log("🧩 Decrypted binary (hex preview):\n" + plaintext.hex())

        except Exception as e:
            messagebox.showerror("Decrypt Error", str(e))
            self.status.config(text="Failed")
            self.log("❌ " + str(e))

if __name__ == "__main__":
    root = tk.Tk()
    RecipientGUI(root)
    root.mainloop()
