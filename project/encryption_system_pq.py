# encryption_system_pq.py
# Enhanced system using ML-KEM-768 (Kyber768) via pqcrypto + HKDF-SHA256 + ECDSA(secp256k1, SHA-256)
# IMPORTANT: run with Python 3.10 where pqcrypto is installed, e.g.:
#   py -3.10 cli_bench_pq.py ...

import os, hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from ecdsa import SECP256k1, SigningKey, VerifyingKey, util

# ---- ML-KEM-768 (Kyber768) from pqcrypto (FIPS 203 naming) ----
from pqcrypto.kem.ml_kem_768 import generate_keypair as mlkem_keygen
from pqcrypto.kem.ml_kem_768 import encrypt as mlkem_encaps
from pqcrypto.kem.ml_kem_768 import decrypt as mlkem_decaps

# ---------- IO helper ----------
def load_input_data(input_source):
    if isinstance(input_source, bytes):
        return input_source
    if isinstance(input_source, str):
            # file path or plaintext
        if os.path.isfile(input_source):
            with open(input_source, "rb") as f:
                return f.read()
        return input_source.encode("utf-8")
    raise ValueError("Input must be a string (text or file path) or bytes.")

# ---------- AES-256-CBC payload ----------
def encrypt_aes(data_bytes: bytes):
    key = get_random_bytes(32)
    iv = get_random_bytes(16)
    ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(data_bytes, AES.block_size))
    return {"key": key, "iv": iv, "ciphertext": ct}

def decrypt_aes(aes_key: bytes, iv: bytes, ct: bytes):
    return unpad(AES.new(aes_key, AES.MODE_CBC, iv).decrypt(ct), AES.block_size)

# ---------- ECDSA (SHA-256) ----------
def generate_ecc_keys():
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    return sk, vk

def sha256_digest(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def sign_digest_sha256(digest: bytes, sk: SigningKey) -> bytes:
    return sk.sign_digest_deterministic(digest, hashfunc=hashlib.sha256, sigencode=util.sigencode_string)

def verify_digest_sha256(sig: bytes, digest: bytes, vk: VerifyingKey) -> bool:
    try:
        return vk.verify_digest(sig, digest, sigdecode=util.sigdecode_string)
    except Exception:
        return False

# ---------- ML-KEM-768 KEM (pqcrypto) ----------
def kyber_generate_keys():
    # returns (public_key: bytes, private_key: bytes)
    pk, sk = mlkem_keygen()
    return pk, sk

def kyber_encapsulate(recipient_public: bytes):
    # returns (kem_ciphertext: bytes, shared_secret: bytes)
    ct, ss = mlkem_encaps(recipient_public)
    return ct, ss

def kyber_decapsulate(kem_ciphertext: bytes, recipient_secret: bytes):
    # returns shared_secret: bytes
    # OLD (wrong): ss = mlkem_decaps(kem_ciphertext, recipient_secret)
    ss = mlkem_decaps(recipient_secret, kem_ciphertext)   # <-- correct order
    return ss


# ---------- HKDF-SHA256 to derive 32B wrap key ----------
def hkdf_sha256(secret: bytes, info: bytes = b"wrap-aes-key", length: int = 32) -> bytes:
    return HKDF(master=secret, key_len=length, salt=None, hashmod=SHA256, context=info)

# ---------- AES-GCM to wrap/unwrap the AES key ----------
def wrap_aes_key_with_gcm(aes_key: bytes, wrap_key: bytes):
    cipher = AES.new(wrap_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(aes_key)
    return {"encrypted_aes_key": ct, "nonce": cipher.nonce, "tag": tag}

def unwrap_aes_key_with_gcm(enc_key: bytes, wrap_key: bytes, nonce: bytes, tag: bytes):
    cipher = AES.new(wrap_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(enc_key, tag)
