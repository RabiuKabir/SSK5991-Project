# make_test_files.py
from pathlib import Path

# Sizes in bytes (exact)
SIZES = {
    "1MB":   1 * 1024 * 1024,
    "15MB":   15 * 1024 * 1024,
}

# Your repeated text pattern (ASCII so 1 char = 1 byte). Keep it short for precision.
PATTERN = b"This is a test file. This is a test file. "

def make_exact_text_file(path: Path, target_bytes: int, pattern: bytes = PATTERN):
    """Write repeated ASCII text and trim to exact byte length (binary mode avoids CRLF surprises)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        remaining = target_bytes
        # Write in chunks for speed
        chunk = pattern * (max(1, 64 * 1024 // len(pattern)))  # ~64KB chunk
        while remaining > 0:
            to_write = chunk if len(chunk) <= remaining else pattern
            if len(to_write) > remaining:
                # Write only the slice needed to hit the exact size
                f.write(pattern[:remaining])
                remaining = 0
            else:
                f.write(to_write)
                remaining -= len(to_write)

if __name__ == "__main__":
    outdir = Path(".")
    for label, nbytes in SIZES.items():
        fname = f"file_{label}.txt"
        make_exact_text_file(outdir / fname, nbytes)
        print(f"✅ Created {fname} ({nbytes} bytes)")
