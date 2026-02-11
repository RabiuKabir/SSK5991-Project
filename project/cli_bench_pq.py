# cli_bench_pq.py
import argparse, base64, csv, json, os, time
from pathlib import Path
from ecdsa import VerifyingKey, SECP256k1, SigningKey

from encryption_system_pq import (
    load_input_data, encrypt_aes, decrypt_aes,
    generate_ecc_keys,
    kyber_generate_keys, kyber_encapsulate, kyber_decapsulate,
    hkdf_sha256, wrap_aes_key_with_gcm, unwrap_aes_key_with_gcm,
    sha256_digest, sign_digest_sha256, verify_digest_sha256
)

def b64e(b: bytes) -> str: return base64.b64encode(b).decode("ascii")
def b64d(s: str) -> bytes: return base64.b64decode(s)
def now(): return time.perf_counter()

def save_package_pq(pkg: dict, path: Path):
    lines = ["# Secure Package (PQ / ML-KEM-768 via pqcrypto)\n\n"]
    def add(k, v): lines.append(f"{k}: {v}\n\n")
    for k in ("ciphertext","ciphertext_sha256","iv",
              "encrypted_aes_key","nonce","tag",
              "kem_ciphertext","sender_public_key","signature"):
        add(k, pkg[k])
    Path(path).write_text("".join(lines), encoding="utf-8")

def load_package_pq(path: Path) -> dict:
    kv = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if not s or s.startswith("#") or ":" not in s: continue
        k, v = s.split(":", 1)
        kv[k.strip()] = v.strip()
    required = ["ciphertext","ciphertext_sha256","iv",
                "encrypted_aes_key","nonce","tag",
                "kem_ciphertext","sender_public_key","signature"]
    missing = [r for r in required if r not in kv]
    if missing: raise ValueError(f"Missing fields: {missing}")
    return kv

def bench_once(idx:int, data: bytes,
               sender_priv: SigningKey, sender_pub: VerifyingKey,
               recip_pub: bytes, recip_sec: bytes,
               include_io: bool, tmp_path: Path,
               keep_packages: bool, outdir: Path):

    # --- Encrypt path ---
    t0 = now()
    t = now(); enc = encrypt_aes(data); aes_encrypt_ms = (now()-t)*1000

    t = now(); kem_ct, ss = kyber_encapsulate(recip_pub); kem_encaps_ms = (now()-t)*1000
    wrap_key = hkdf_sha256(ss, info=b"wrap-aes-key")
    wrapped = wrap_aes_key_with_gcm(enc["key"], wrap_key)

    t = now(); dig = sha256_digest(enc["ciphertext"]); hash_ms = (now()-t)*1000
    t = now(); sig = sign_digest_sha256(dig, sender_priv); sign_ms = (now()-t)*1000

    pkg = {
        "ciphertext": b64e(enc["ciphertext"]),
        "ciphertext_sha256": dig.hex(),
        "iv": b64e(enc["iv"]),
        "encrypted_aes_key": b64e(wrapped["encrypted_aes_key"]),
        "nonce": b64e(wrapped["nonce"]),
        "tag": b64e(wrapped["tag"]),
        "kem_ciphertext": b64e(kem_ct),
        "sender_public_key": b64e(sender_pub.to_string()),
        "signature": b64e(sig),
    }

    serialize_ms = parse_ms = 0.0
    if include_io:
        if keep_packages:
            outdir.mkdir(parents=True, exist_ok=True)
            tmp_path = outdir / f"pkg_pq_{idx:04d}.txt"
        t = now(); save_package_pq(pkg, tmp_path); serialize_ms = (now()-t)*1000
        t = now(); pkg = load_package_pq(tmp_path); parse_ms = (now()-t)*1000

    enc_total_ms = (now()-t0)*1000

    # --- Decrypt path ---
    t1 = now()
    ciphertext = b64d(pkg["ciphertext"])
    iv = b64d(pkg["iv"])
    enc_key = b64d(pkg["encrypted_aes_key"])
    nonce = b64d(pkg["nonce"])
    tag = b64d(pkg["tag"])
    kem_ct_re = b64d(pkg["kem_ciphertext"])
    sender_pub_re = VerifyingKey.from_string(b64d(pkg["sender_public_key"]), curve=SECP256k1)
    sig_re = b64d(pkg["signature"])

    t = now(); dig2 = sha256_digest(ciphertext); verify_hash_ms = (now()-t)*1000
    t = now(); ok = verify_digest_sha256(sig_re, dig2, sender_pub_re); verify_ms = (now()-t)*1000

    t = now(); ss2 = kyber_decapsulate(kem_ct_re, recip_sec); kem_decaps_ms = (now()-t)*1000
    wrap_key2 = hkdf_sha256(ss2, info=b"wrap-aes-key")
    aes_key2 = unwrap_aes_key_with_gcm(enc_key, wrap_key2, nonce, tag)
    t = now(); _ = decrypt_aes(aes_key2, iv, ciphertext); aes_decrypt_ms = (now()-t)*1000

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
        "input_bytes": len(data),
        "ciphertext_bytes": len(ciphertext),
        "enc_aes_key_bytes": len(enc_key),
        "tag_bytes": len(tag),
        "nonce_bytes": len(nonce),
        "verify_ok": int(ok),
        "enc_throughput_MBps": (len(data) / (enc_total_ms/1000.0)) / (1024*1024),
        "dec_throughput_MBps": (len(data) / (dec_total_ms/1000.0)) / (1024*1024),
    }

def main():
    ap = argparse.ArgumentParser(description="Benchmark enhanced PQ (ML-KEM-768 via pqcrypto)")
    ap.add_argument("--input", required=True)
    ap.add_argument("--iterations", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=1)
    ap.add_argument("--include-io", action="store_true")
    ap.add_argument("--keep-packages", action="store_true")
    ap.add_argument("--outdir", default="bench_out_pq")
    ap.add_argument("--csv", default="results_pq.csv")
    ap.add_argument("--jsonl", default=None)
    args = ap.parse_args()

    data = load_input_data(args.input)

    # Recipient ML-KEM keys (one pair for the whole run)
    recip_pub, recip_sec = kyber_generate_keys()

    # Sender ECDSA keys (fresh per run)
    sender_priv, sender_pub = generate_ecc_keys()

    tmp_path = Path("tmp_pkg_pq.txt")
    outdir = Path(args.outdir)

    # Warmup
    for _ in range(max(0, args.warmup)):
        bench_once(0, data, sender_priv, sender_pub, recip_pub, recip_sec,
                   args.include_io, tmp_path, args.keep_packages, outdir)

    # Iterations
    rows = []
    for i in range(1, args.iterations+1):
        rows.append(
            bench_once(i, data, sender_priv, sender_pub, recip_pub, recip_sec,
                       args.include_io, tmp_path, args.keep_packages, outdir)
        )

    # Context
    context = {
        "kem": "ML-KEM-768 (Kyber768) via pqcrypto",
        "kem_wrap_kdf": "HKDF-SHA256",
        "aes_payload": "AES-256-CBC",
        "sign_alg": "ECDSA(secp256k1)",
        "sign_hash": "SHA-256",
        "file": Path(args.input).name,
        "include_io": args.include_io,
        "iterations": args.iterations,
    }

    fieldnames = (
        list(context.keys()) +
        ["aes_encrypt_ms","kem_encaps_ms","hash_ms","sign_ms","serialize_ms","parse_ms","enc_total_ms",
         "verify_hash_ms","verify_ms","kem_decaps_ms","aes_decrypt_ms","dec_total_ms",
         "input_bytes","ciphertext_bytes","enc_aes_key_bytes","tag_bytes","nonce_bytes","verify_ok",
         "enc_throughput_MBps","dec_throughput_MBps"]
    )

    with open(args.csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({**context, **r})

    if args.jsonl:
        with open(args.jsonl, "w") as f:
            for r in rows:
                f.write(json.dumps({**context, **r}) + "\n")

    print(f"Saved CSV: {args.csv}")
    if args.keep_packages:
        print(f"Kept packages in: {outdir.resolve()}")
    elif args.include_io and tmp_path.exists():
        try: tmp_path.unlink()
        except Exception: pass

if __name__ == "__main__":
    main()
