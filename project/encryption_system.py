# encryption_system.py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from ecdsa import SECP256k1, SigningKey, VerifyingKey, util
import hashlib
import os

# ---- Tunables for benchmarking (can adjust in CLI) ----
SCRYPT_N = 2**14
SCRYPT_r = 8
SCRYPT_p = 1
SCRYPT_SALT = b"salt"  # demo constant; OK for benchmarking (not for prod)

def set_scrypt_params(N=None, r=None, p=None, salt=None):
    global SCRYPT_N, SCRYPT_r, SCRYPT_p, SCRYPT_SALT
    if N is not None: SCRYPT_N = int(N)
    if r is not None: SCRYPT_r = int(r)
    if p is not None: SCRYPT_p = int(p)
    if salt is not None: SCRYPT_SALT = salt

def load_input_data(input_source):
    if isinstance(input_source, bytes):
        return input_source
    if isinstance(input_source, str):
        if os.path.isfile(input_source):
            with open(input_source, 'rb') as f:
                return f.read()
        return input_source.encode('utf-8')
    raise ValueError("Input must be a string (text or file path) or bytes.")

# --- AES-256-CBC payload ---
def encrypt_aes(data_bytes: bytes):
    aes_key_bytes = get_random_bytes(32)
    iv = get_random_bytes(16)
    cipher = AES.new(aes_key_bytes, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
    return {'key': aes_key_bytes, 'iv': iv, 'ciphertext': ciphertext}

def decrypt_aes(aes_key_bytes: bytes, iv_bytes: bytes, ciphertext_bytes: bytes):
    cipher = AES.new(aes_key_bytes, AES.MODE_CBC, iv_bytes)
    return unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)

# --- ECC key material ---
def generate_ecc_keys():
    priv = SigningKey.generate(curve=SECP256k1)
    pub = priv.get_verifying_key()
    return priv, pub

# --- ECDH ---
def perform_ecdh(privkey: SigningKey, pubkey: VerifyingKey) -> bytes:
    shared_point = privkey.privkey.secret_multiplier * pubkey.pubkey.point
    return shared_point.x().to_bytes(32, 'big')

# --- KEM wrap: ECDH + scrypt -> AES-GCM ---
def encapsulate_aes_key(aes_key_bytes: bytes, recipient_public_key_obj: VerifyingKey):
    ephemeral_private = SigningKey.generate(curve=SECP256k1)
    ephemeral_public = ephemeral_private.get_verifying_key()
    shared_secret = perform_ecdh(ephemeral_private, recipient_public_key_obj)
    derived_key = scrypt(shared_secret, SCRYPT_SALT, 32, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p)
    cipher = AES.new(derived_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(aes_key_bytes)
    return {
        'encrypted_aes_key': ciphertext,
        'nonce': cipher.nonce,
        'tag': tag,
        'ephemeral_public_key': ephemeral_public
    }

def decapsulate_aes_key(encrypted_aes_key_bytes: bytes, recipient_private_key_obj: SigningKey,
                        ephemeral_public_key: VerifyingKey, nonce: bytes, tag: bytes) -> bytes:
    shared_secret = perform_ecdh(recipient_private_key_obj, ephemeral_public_key)
    derived_key = scrypt(shared_secret, SCRYPT_SALT, 32, N=SCRYPT_N, r=SCRYPT_r, p=SCRYPT_p)
    cipher = AES.new(derived_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted_aes_key_bytes, tag)

# --- Hash/Sign helpers (so you can time them separately) ---
def sha1_digest(data_bytes: bytes) -> bytes:
    return hashlib.sha1(data_bytes).digest()

def sign_digest(digest_bytes: bytes, sender_private_key_obj: SigningKey) -> bytes:
    return sender_private_key_obj.sign_digest_deterministic(
        digest_bytes, hashfunc=hashlib.sha1, sigencode=util.sigencode_string
    )

def verify_digest(signature_bytes: bytes, digest_bytes: bytes, sender_public_key_obj: VerifyingKey) -> bool:
    try:
        return sender_public_key_obj.verify_digest(signature_bytes, digest_bytes, sigdecode=util.sigdecode_string)
    except Exception:
        return False

# Back-compat (used in GUI): sign/verify that do the hashing inside
def sign_data(data_bytes: bytes, sender_private_key_obj: SigningKey) -> bytes:
    return sign_digest(sha1_digest(data_bytes), sender_private_key_obj)

def verify_signature(data_bytes: bytes, signature_bytes: bytes, sender_public_key_obj: VerifyingKey) -> bool:
    return verify_digest(signature_bytes, sha1_digest(data_bytes), sender_public_key_obj)
