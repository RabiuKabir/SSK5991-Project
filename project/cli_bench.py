# cli_bench.py
import argparse, base64, csv, json, os, time
from pathlib import Path
from ecdsa import SigningKey, VerifyingKey, SECP256k1

from encryption_system import (
    load_input_data, generate_ecc_keys,
    encrypt_aes, decrypt_aes,
    encapsulate_aes_key, decapsulate_aes_key,
    sha1_digest, sign_digest, verify_digest,
    set_scrypt_params
)
from secure_package import create_secure_package, save_secure_package_txt, load_secure_package_txt

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s)

def now():
    return time.perf_counter()

def bench_once(data_bytes: bytes,
               sender_priv: SigningKey, sender_pub: VerifyingKey,
               recipient_priv: SigningKey, recipient_pub: VerifyingKey,
               include_io: bool, tmp_pkg_path: Path):

    # ---- Encrypt path ----
    t0 = now()
    # AES encrypt
    t = now(); enc = encrypt_aes(data_bytes); aes_encrypt_ms = (now()-t)*1000
    # KEM wrap
    t = now(); kaps = encapsulate_aes_key(enc["key"], recipient_pub); kem_encaps_ms = (now()-t)*1000
    # Sign (hash + sign separately)
    t = now(); dig = sha1_digest(enc["ciphertext"]); hash_ms = (now()-t)*1000
    t = now(); sig = sign_digest(dig, sender_priv); sign_ms = (now()-t)*1000

    # Build package (in-memory)
    pkg = {
        "ciphertext": b64e(enc["ciphertext"]),
        "ciphertext_sha1": base64.b16encode(dig).decode("ascii").lower(),
        "iv": b64e(enc["iv"]),
        "encrypted_aes_key": b64e(kaps["encrypted_aes_key"]),
        "nonce": b64e(kaps["nonce"]),
        "tag": b64e(kaps["tag"]),
        "ephemeral_public_key": b64e(kaps["ephemeral_public_key"].to_string()),
        "sender_public_key": b64e(sender_pub.to_string()),
        "signature": b64e(sig),
        "fingerprints": {
            "sender_fp": "", "recipient_fp": ""
        },
        # aes_key intentionally NOT serialized
        "aes_key": b64e(enc["key"]),
    }

    serialize_ms = parse_ms = 0.0
    if include_io:
        # Write to disk
        from secure_package import save_secure_package_txt, load_secure_package_txt
        t = now(); save_secure_package_txt(pkg, tmp_pkg_path); serialize_ms = (now()-t)*1000
        # Read back
        t = now(); pkg = load_secure_package_txt(tmp_pkg_path); parse_ms = (now()-t)*1000

    enc_total_ms = (now()-t0)*1000

    # ---- Decrypt path ----
    t1 = now()
    # Reconstruct objects from 'pkg' (whether in mem or reloaded)
    ciphertext = b64d(pkg["ciphertext"])
    iv = b64d(pkg["iv"])
    enc_key = b64d(pkg["encrypted_aes_key"])
    nonce = b64d(pkg["nonce"])
    tag = b64d(pkg["tag"])
    eph_pub = VerifyingKey.from_string(b64d(pkg["ephemeral_public_key"]), curve=SECP256k1)
    sender_pub_re = VerifyingKey.from_string(b64d(pkg["sender_public_key"]), curve=SECP256k1)
    sig_re = b64d(pkg["signature"])

    # Verify (hash + verify separately)
    t = now(); dig2 = sha1_digest(ciphertext); verify_hash_ms = (now()-t)*1000
    t = now(); verify_ms = (now()-t)*1000 if not verify_digest(sig_re, dig2, sender_pub_re) else (now()-t)*1000

    # KEM decap
    t = now(); aes_key2 = decapsulate_aes_key(enc_key, recipient_priv, eph_pub, nonce, tag); kem_decaps_ms = (now()-t)*1000
    # AES decrypt
    t = now(); plain2 = decrypt_aes(aes_key2, iv, ciphertext); aes_decrypt_ms = (now()-t)*1000

    dec_total_ms = (now()-t1)*1000

    return {
        "aes_encrypt_ms": aes_encrypt_ms,
        "kem_encaps_ms": kem_encaps_ms,
        "hash_ms": hash_ms,
        "sign_ms": sign_ms,
        "serialize_ms": serialize_ms,
        "parse_ms": parse_ms,
        "enc_total_ms": enc_total_ms,
        "verify_hash_ms": verify_hash_ms,
        "verify_ms": verify_ms,
        "kem_decaps_ms": kem_decaps_ms,
        "aes_decrypt_ms": aes_decrypt_ms,
        "dec_total_ms": dec_total_ms,
        "input_bytes": len(data_bytes),
        "ciphertext_bytes": len(ciphertext),
        "enc_aes_key_bytes": len(enc_key),
        "tag_bytes": len(tag),
        "nonce_bytes": len(nonce),
    }

def main():
    ap = argparse.ArgumentParser(description="Benchmark hybrid crypto CLI")
    ap.add_argument("--input", required=True, help="Path to input file to encrypt")
    ap.add_argument("--recipient-private", default="recipient_private.pem", help="Recipient private key PEM")
    ap.add_argument("--recipient-public",  default="recipient_public.pem",  help="Recipient public key PEM")
    ap.add_argument("--iterations", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--include-io", action="store_true", help="Include serialize/parse (disk I/O) in timings")
    ap.add_argument("--csv", default="results.csv")
    ap.add_argument("--jsonl", default=None)
    ap.add_argument("--scrypt-N", type=int, default=None)
    ap.add_argument("--scrypt-r", type=int, default=None)
    ap.add_argument("--scrypt-p", type=int, default=None)
    args = ap.parse_args()

    # scrypt tunables (optional)
    set_scrypt_params(args.scrypt_N, args.scrypt_r, args.scrypt_p, None)

    # Keys: load or generate recipient
    priv_path = Path(args.recipient_private)
    pub_path  = Path(args.recipient_public)
    if priv_path.exists() and pub_path.exists():
        recipient_priv = SigningKey.from_pem(priv_path.read_bytes())
        recipient_pub  = VerifyingKey.from_pem(pub_path.read_bytes())
    else:
        recipient_priv = SigningKey.generate(curve=SECP256k1)
        recipient_pub  = recipient_priv.get_verifying_key()
        priv_path.write_bytes(recipient_priv.to_pem())
        pub_path.write_bytes(recipient_pub.to_pem())

    # Sender keys (fresh each run, to mimic GUI behavior)
    sender_priv, sender_pub = generate_ecc_keys()

    data = load_input_data(args.input)
    tmp_pkg = Path("tmp_pkg.txt")

    # Warmup (not recorded)
    for _ in range(max(0, args.warmup)):
        bench_once(data, sender_priv, sender_pub, recipient_priv, recipient_pub, args.include_io, tmp_pkg)

    # Benchmark iterations (record)
    rows = []
    for _ in range(args.iterations):
        rows.append(
            bench_once(data, sender_priv, sender_pub, recipient_priv, recipient_pub, args.include_io, tmp_pkg)
        )

    # Context columns
    context = {
        "curve": "secp256k1",
        "aes_payload": "AES-256-CBC",
        "kem_wrap": "ECDH+scrypt -> AES-GCM",
        "hash": "SHA-1",
        "scrypt_N": os.getenv("SCRYPT_N") or "",
        "scrypt_r": os.getenv("SCRYPT_r") or "",
        "scrypt_p": os.getenv("SCRYPT_p") or "",
        "file": Path(args.input).name,
        "include_io": args.include_io,
        "iterations": args.iterations,
    }

    # Write CSV
    fieldnames = (
        list(context.keys()) +
        ["aes_encrypt_ms","kem_encaps_ms","hash_ms","sign_ms","serialize_ms","parse_ms","enc_total_ms",
         "verify_hash_ms","verify_ms","kem_decaps_ms","aes_decrypt_ms","dec_total_ms",
         "input_bytes","ciphertext_bytes","enc_aes_key_bytes","tag_bytes","nonce_bytes"]
    )
    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({**context, **r})

    # Optional JSONL
    if args.jsonl:
        with open(args.jsonl, "w") as f:
            for r in rows:
                f.write(json.dumps({**context, **r}) + "\n")

    print(f"Saved CSV: {args.csv}")
    if args.jsonl:
        print(f"Saved JSONL: {args.jsonl}")
    if tmp_pkg.exists():
        tmp_pkg.unlink()

if __name__ == "__main__":
    main()
