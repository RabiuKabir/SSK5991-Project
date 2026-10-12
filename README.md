# PQEF — Post-Quantum Encryption Framework for Secure Data Exchange

Source code and benchmark data for the paper
**"PQEF: Post-Quantum Encryption Framework for Secure Data Exchange"** (Kabir & Md Yasin), derived from the first author's master's thesis, *PQEF: Post-Quantum Encryption Framework for Secure Data Storage*, Universiti Putra Malaysia, 2026 (course code SSK5991).

The repository contains two complete hybrid encryption systems and the command-line tools used to benchmark them:

| | Original system (baseline) | PQEF (enhanced system) |
|---|---|---|
| Payload encryption | AES-256-CBC (PKCS#7 padding) | AES-256-CBC (PKCS#7 padding) |
| Session-key protection | Ephemeral ECDH (secp256k1) + scrypt → AES-GCM key wrap | **Kyber768 / ML-KEM-768** + HKDF-SHA-256 → AES-GCM key wrap |
| Digital signature | Deterministic ECDSA (secp256k1) over a **SHA-1** digest of the ciphertext | Deterministic ECDSA (secp256k1) over a **SHA-256** digest of the ciphertext |
| Source files | `encryption_system.py`, `secure_package.py`, `cli.py`, `sender_gui.py`, `recipient_gui.py`, `cli_bench.py` | `encryption_system_pq.py`, `cli_bench_pq.py` |
| Benchmark data | `os_*.csv` | `es_*.csv` |

The baseline is a re-implementation of the AES–ECC–SHA-1 hybrid scheme of Li and Huang (2024), *Egyptian Informatics Journal*, 28, 100569. The PQEF replaces the ECDH + scrypt key-encapsulation stage with Kyber768 (ML-KEM-768) + HKDF-SHA-256 and the SHA-1 digest with SHA-256; the AES layer and the ECDSA signature layer are unchanged.

---

## 1. Repository layout

```
project/
├── encryption_system.py      # Original system: AES-256-CBC, ECDH+scrypt key wrap, SHA-1 + ECDSA
├── encryption_system_pq.py   # PQEF: AES-256-CBC, Kyber768 (ML-KEM-768) + HKDF-SHA256 key wrap, SHA-256 + ECDSA
├── secure_package.py         # Builds / saves / loads the secure package (.txt) for the original system
├── cli.py                    # Interactive step-by-step demo of the original system (verbose)
├── sender_gui.py             # Tkinter GUI – encrypt a file with the original system
├── recipient_gui.py          # Tkinter GUI – decrypt a package with the original system
├── cli_bench.py              # Benchmark tool – original system
├── cli_bench_pq.py           # Benchmark tool – PQEF
├── file_sizes.py             # Generates test files of exact sizes
├── recipient_public.pem      # Demo recipient key pair for the original system (see §6)
├── recipient_private.pem     #   (regenerate your own – do not reuse these)
├── os_file_<size>.csv        # Benchmark results, original system, crypto only (no I/O)
├── os_io_file_<size>.csv     # Benchmark results, original system, including serialize/parse I/O
├── es_file_<size>.csv        # Benchmark results, PQEF, crypto only (no I/O)
├── es_io_file_<size>.csv     # Benchmark results, PQEF, including serialize/parse I/O
├── test_data_pqc_1MB.csv     # Additional PQEF run on the 1 MB file
├── file.txt, file_1MB.txt, file_15MB.txt, text files/, files/   # Sample inputs and packages
└── pycryptodome-3.23.0-...whl  # Convenience wheel (Linux x86-64 only; use pip normally)
```

`<size>` is one of `1kb, 10kb, 100kb, 500kb, 1mb, 5mb, 10mb, 25mb, 50mb, 75mb, 100mb` (the I/O runs cover 1 KB – 10 MB). The paper reports the crypto-only runs from 1 KB to 25 MB.

---

## 2. Requirements

* Python 3.10 (the experiments in the paper were run on Python 3.10, Windows 11, Intel Core i7 2.8 GHz, 16 GB RAM)
* [`pycryptodome`](https://pypi.org/project/pycryptodome/) — AES, AES-GCM, scrypt, HKDF, SHA-256, CSPRNG
* [`ecdsa`](https://pypi.org/project/ecdsa/) — secp256k1 keys, ECDH, deterministic ECDSA
* [`pqcrypto`](https://pypi.org/project/pqcrypto/) — ML-KEM-768 (Kyber768) key encapsulation (`pqcrypto.kem.ml_kem_768`)
* `tkinter` — standard library, needed only for the two GUI scripts

```bash
python -m venv .venv
# Windows:  .venv\Scripts\activate      Linux/macOS:  source .venv/bin/activate
pip install pycryptodome ecdsa pqcrypto
```

> `pqcrypto` ships pre-built wheels for common platforms. If `pip` tries to compile it and fails, install a C compiler (on Windows, the Visual Studio Build Tools) or use a platform for which a wheel exists.

All commands below are run from inside the `project/` directory:

```bash
cd project
```

---

## 3. Generating test files

`file_sizes.py` writes plain-ASCII text files of an exact byte length (the pattern `This is a test file. ` repeated and trimmed). Edit the `SIZES` dictionary to the sizes you need, then run:

```bash
python file_sizes.py
# -> file_1MB.txt, file_15MB.txt (as configured)
```

The files used in the paper were 1 KB, 10 KB, 100 KB, 500 KB, 1 MB, 5 MB, 10 MB and 25 MB, where 1 KB = 1,024 bytes and 1 MB = 1,048,576 bytes. Any file can be used as input; the benchmark tools read it as raw bytes.

---

## 4. Running the benchmarks

Both benchmark tools perform, for every iteration, the complete sender pipeline (AES encryption → key encapsulation/wrapping → hashing → signing) followed by the complete recipient pipeline (signature verification → key decapsulation/unwrapping → AES decryption), time each step with `time.perf_counter()`, check that the plaintext round-trips, and write one CSV row per measured iteration. Warm-up iterations are executed but not recorded.

### 4.1 Original system — `cli_bench.py`

```bash
python cli_bench.py --input file_1kb.txt --iterations 20 --warmup 3 --csv micro_1KB.csv
python cli_bench.py --input sample_50MB.bin --iterations 20 --warmup 3 --csv micro_50MB.csv
```

| Option | Default | Meaning |
|---|---|---|
| `--input PATH` | *(required)* | File to encrypt |
| `--iterations N` | 5 | Number of measured iterations |
| `--warmup N` | 1 | Un-recorded warm-up iterations run first |
| `--csv PATH` | `results.csv` | Output CSV |
| `--jsonl PATH` | – | Optional JSON-lines copy of the results |
| `--include-io` | off | Also time serialising the package to disk and parsing it back (`serialize_ms`, `parse_ms` are then non-zero and included in the totals) |
| `--recipient-private PATH` | `recipient_private.pem` | Recipient ECC private key; generated and saved if the file does not exist |
| `--recipient-public PATH` | `recipient_public.pem` | Recipient ECC public key |
| `--scrypt-N`, `--scrypt-r`, `--scrypt-p` | library defaults (N = 2¹⁴, r = 8, p = 1) | Override the scrypt parameters used to derive the key-wrapping key |

A fresh sender key pair is generated for every run; the recipient key pair is loaded from the PEM files (or created on first use).

### 4.2 PQEF — `cli_bench_pq.py`

```bash
python cli_bench_pq.py --input sample_1MB.bin --iterations 20 --warmup 3 --csv pq_micro_1MB.csv
```

| Option | Default | Meaning |
|---|---|---|
| `--input PATH` | *(required)* | File to encrypt |
| `--iterations N` | 5 | Number of measured iterations |
| `--warmup N` | 1 | Un-recorded warm-up iterations |
| `--csv PATH` | `results_pq.csv` | Output CSV |
| `--jsonl PATH` | – | Optional JSON-lines copy |
| `--include-io` | off | Also time serialising/parsing the package |
| `--keep-packages` | off | Keep every generated package file instead of deleting it |
| `--outdir DIR` | `bench_out_pq` | Where kept packages are written |

A recipient ML-KEM-768 key pair is generated once per run and a fresh sender ECDSA key pair per run; no key files are written.

### 4.3 Reproducing the paper's protocol

The results in the paper were obtained as follows: the machine was restarted and Wi-Fi disabled, only a PowerShell window was kept open, and each file was run through both tools with `--iterations 20 --warmup 3` and **without** `--include-io`. Per-file means of the 20 measured iterations give the values in the paper's tables; throughput is the mean of the per-iteration `enc_throughput_MBps` column. Aggregate percentages in the paper's text are Σ(original − PQEF) / Σ(original) over the eight file sizes.

To repeat the full sweep:

```bash
for f in file_1KB.txt file_10KB.txt file_100KB.txt file_500KB.txt file_1MB.txt file_5MB.txt file_10MB.txt file_25MB.txt
do
  python cli_bench.py    --input $f --iterations 20 --warmup 3 --csv os_$f.csv
  python cli_bench_pq.py --input $f --iterations 20 --warmup 3 --csv es_$f.csv
done
```

(On Windows PowerShell use `foreach ($f in @(...)) { ... }`.)

---

## 5. CSV format

Every row is one measured iteration. All times are milliseconds; sizes are bytes.

**Context columns** (identical in every row of a file)

| Original system | PQEF |
|---|---|
| `curve`, `aes_payload`, `kem_wrap`, `hash`, `scrypt_N`, `scrypt_r`, `scrypt_p` | `kem`, `kem_wrap_kdf`, `aes_payload`, `sign_alg`, `sign_hash` |
| `file`, `include_io`, `iterations` | `file`, `include_io`, `iterations` |

**Timing columns** (both systems)

| Column | Sender / recipient | What is timed |
|---|---|---|
| `aes_encrypt_ms` | sender | AES-256-CBC encryption of the payload |
| `kem_encaps_ms` | sender | Original: ECDH + scrypt + AES-GCM wrap. PQEF: ML-KEM-768 encapsulation + HKDF + AES-GCM wrap |
| `hash_ms` | sender | SHA-1 (original) or SHA-256 (PQEF) digest of the ciphertext |
| `sign_ms` | sender | ECDSA signing of the digest |
| `serialize_ms` | sender | Writing the package to disk (0 unless `--include-io`) |
| `enc_total_ms` | sender | End-to-end encryption time (sum of the sender steps) |
| `parse_ms` | recipient | Reading the package back (0 unless `--include-io`) |
| `verify_hash_ms` | recipient | Re-hashing the ciphertext |
| `verify_ms` | recipient | ECDSA signature verification |
| `kem_decaps_ms` | recipient | Original: ECDH + scrypt + AES-GCM unwrap. PQEF: ML-KEM-768 decapsulation + HKDF + AES-GCM unwrap |
| `aes_decrypt_ms` | recipient | AES-256-CBC decryption of the payload |
| `dec_total_ms` | recipient | End-to-end decryption time (sum of the recipient steps) |

**Size columns** (both systems): `input_bytes`, `ciphertext_bytes`, `enc_aes_key_bytes`, `tag_bytes`, `nonce_bytes`.

**PQEF only**: `verify_ok` (1 if signature verification and AES-GCM authentication succeeded and the plaintext round-tripped), `enc_throughput_MBps` = `input_bytes` / 1,048,576 ÷ (`enc_total_ms` / 1000), `dec_throughput_MBps` likewise with `dec_total_ms`.

File naming: `os_` = original system, `es_` = enhanced system (PQEF); `_io_` = run with `--include-io`; the suffix is the input size.

---

## 6. Interactive demo and GUI (original system only)

These demonstrate the classical AES–ECC–SHA-1 pipeline. The PQEF is exercised through `cli_bench_pq.py` only.

**Step-by-step console demo**

```bash
python cli.py
```
Choose a text message or a file path; the script prints every intermediate value (keys, IV, ciphertext, encrypted session key, digest, signature) and verifies the round trip.

**GUI**

```bash
python recipient_gui.py   # 1. "Generate Keypair (auto-save)" -> writes recipient_private.pem / recipient_public.pem
python sender_gui.py      # 2. Browse to a file, load recipient_public.pem, "Encrypt & Save (.txt)"
                          # 3. Back in the recipient window: load the private key, load the package, "Decrypt"
```

The package is a readable `.txt` file containing, Base64-encoded: `ciphertext`, `ciphertext_sha1`, `iv`, `encrypted_aes_key`, `nonce`, `tag`, `ephemeral_public_key`, `sender_public_key`, `signature`, and key fingerprints. The AES session key itself is never written to disk.

**Keys.** The `recipient_*.pem` files in the repository are demonstration keys for the GUI/benchmark and should be regenerated before any real use (delete them and run `recipient_gui.py` → *Generate Keypair*, or let `cli_bench.py` create a new pair).

---

## 7. Security notes

* This is research code written to compare two cryptographic pipelines under identical conditions. It has not been audited and is not intended for production use.
* Public keys are exchanged through the local file system; key distribution over a network is out of scope.
* The signature layer in both systems is classical ECDSA. Replacing it with a post-quantum signature scheme (e.g., ML-DSA/Dilithium or Falcon) is listed as future work in the paper.
* Both pipelines sign the ciphertext (verification happens before decryption). The original Li and Huang design signs the plaintext hash before encryption; this is a documented deviation of the re-implementation.

---

## 8. Citing

If you use this code or data, please cite the paper and the repository:

```
Kabir, R. I., & Md Yasin, S. (2026). PQEF: Post-Quantum Encryption Framework for Secure Data Exchange.
Pertanika Journal of Science & Technology. [volume/issue/DOI to be added on publication]

Kabir, R. I. (2026). SSK5991-Project: PQEF source code and benchmark data [Computer software and data set].
GitHub. https://github.com/RabiuKabir/SSK5991-Project
```
