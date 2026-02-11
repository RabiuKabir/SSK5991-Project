# secure_package.py
import base64
import hashlib
from pathlib import Path
from typing import Dict, Any
from ecdsa import VerifyingKey, SigningKey
from encryption_system import encrypt_aes, encapsulate_aes_key, sign_data

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s)

def create_secure_package(
    data_bytes: bytes,
    recipient_public_key: VerifyingKey,
    sender_private_key: SigningKey,
    sender_public_key: VerifyingKey,
) -> Dict[str, Any]:
    # AES-256-CBC for payload
    enc = encrypt_aes(data_bytes)
    aes_key = enc["key"]
    iv = enc["iv"]
    ciphertext = enc["ciphertext"]

    # ECDH + scrypt -> AES-GCM to wrap AES key
    kaps = encapsulate_aes_key(aes_key, recipient_public_key)

    # ECDSA(SHA-1) over ciphertext
    signature = sign_data(ciphertext, sender_private_key)

    # metadata
    sender_fp = hashlib.sha256(sender_public_key.to_string()).hexdigest()
    recipient_fp = hashlib.sha256(recipient_public_key.to_string()).hexdigest()
    ciphertext_sha1 = hashlib.sha1(ciphertext).hexdigest()

    # We RETURN aes_key (for Sender UI display), but we DO NOT write it to file
    return {
        "ciphertext": b64e(ciphertext),
        "ciphertext_sha1": ciphertext_sha1,
        "iv": b64e(iv),
        "encrypted_aes_key": b64e(kaps["encrypted_aes_key"]),
        "nonce": b64e(kaps["nonce"]),
        "tag": b64e(kaps["tag"]),
        "ephemeral_public_key": b64e(kaps["ephemeral_public_key"].to_string()),
        "sender_public_key": b64e(sender_public_key.to_string()),
        "signature": b64e(signature),
        "fingerprints": {
            "sender_fp": sender_fp,
            "recipient_fp": recipient_fp
        },
        # display-only (kept in memory; NOT serialized)
        "aes_key": b64e(aes_key),
    }

def save_secure_package_txt(pkg: Dict[str, Any], output_path: str | Path) -> None:
    """
    Save as readable .txt with a blank line between entries.
    IMPORTANT: We intentionally DO NOT serialize 'aes_key'.
    """
    lines = ["# Secure Package (realistic demo)\n\n"]

    def add(k: str, v: str):
        lines.append(f"{k}: {v}\n\n")  # <-- extra blank line between entries

    # top-level simple fields (skip aes_key)
    for k in ("ciphertext", "ciphertext_sha1", "iv",
              "encrypted_aes_key", "nonce", "tag",
              "ephemeral_public_key", "sender_public_key", "signature"):
        add(k, pkg[k])

    # nested fingerprints
    fps = pkg.get("fingerprints", {})
    for kk in ("sender_fp", "recipient_fp"):
        if kk in fps:
            add(kk, fps[kk])

    Path(output_path).write_text("".join(lines), encoding="utf-8")

def load_secure_package_txt(path: str | Path) -> Dict[str, str]:
    text = Path(path).read_text(encoding="utf-8")
    kv: Dict[str, str] = {}
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        k, v = s.split(":", 1)
        kv[k.strip()] = v.strip()
    required = [
        "ciphertext", "ciphertext_sha1", "iv",
        "encrypted_aes_key", "nonce", "tag",
        "ephemeral_public_key", "sender_public_key", "signature"
    ]
    missing = [r for r in required if r not in kv]
    if missing:
        raise ValueError(f"Missing fields in package: {missing}")
    return kv
