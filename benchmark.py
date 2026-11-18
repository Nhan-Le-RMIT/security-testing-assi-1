"""Crypto benchmark using hashlib + pycryptodome.

Hashing:    MD5, SHA-256, SHA3-256            (hashlib)
Symmetric:  AES-256-CBC, DES-CBC, ChaCha20    (Crypto.Cipher)
Asymmetric: RSA-2048, ECC P-256, ElGamal      (Crypto.PublicKey)

Variable: input size (bytes). Output: results.csv (opens in Excel / loads in pandas).

Setup:  pip install pycryptodome pandas matplotlib seaborn psutil
Usage:
    python crypto_benchmark.py            # synthetic random data, 1 KB .. 50 MB
    python crypto_benchmark.py dataset    # every file in a folder (from make_dataset.py)
    python crypto_benchmark.py somefile   # synthetic sizes + one extra file

Notes:
  * ElGamal key generation is slow (safe-prime search). Default is 1024 bits so the run
    finishes; set the env var ELGAMAL_BITS=2048 for a realistic size (can take minutes).
  * pycryptodome has no ECC encryption (no ECIES), so ECC is benchmarked for
    key generation and ECDSA sign/verify only.
  * IVs/nonces are fixed per run: fine for timing, never do that in real systems.
"""

import hashlib
import os
import statistics
import sys
import time

import pandas as pd
import psutil

try:
    from Crypto.Cipher import AES, DES, PKCS1_OAEP, ChaCha20
    from Crypto.Hash import SHA256
    from Crypto.PublicKey import ECC, RSA, ElGamal
    from Crypto.Random import get_random_bytes
    from Crypto.Signature import DSS, pss
    from Crypto.Util.number import GCD, getRandomRange
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    sys.exit("pycryptodome is not installed. Run: pip install pycryptodome")

SIZES = [
    1_024,
    10_240,
    102_400,
    1_048_576,
    10_485_760,
    52_428_800,
]  # 1KB .. 50MB
REPEATS = 5
ELGAMAL_BITS = int(os.environ.get("ELGAMAL_BITS", "1024"))

# Approximate security strength in bits (NIST SP 800-57 / SP 800-131A style estimates).
# MD5 and DES are broken/legacy; the figure is the theoretical value.
SECURITY_BITS = {
    "MD5": 64,
    "SHA-256": 128,
    "SHA3-256": 128,
    "AES-256-CBC": 256,
    "DES-CBC": 56,
    "ChaCha20": 256,
    "RSA-2048": 112,
    "ECC-P256": 128,
    f"ElGamal-{ELGAMAL_BITS}": {1024: 80, 2048: 112, 3072: 128}.get(ELGAMAL_BITS, ""),
}

proc = psutil.Process()
rows = []


def timed(fn, repeats=REPEATS):
    """Return (median wall-clock seconds, result of the last run)."""
    runs, result = [], None
    for _ in range(repeats):
        t0 = time.perf_counter()
        result = fn()
        runs.append(time.perf_counter() - t0)
    return statistics.median(runs), result


def add(category, algo, op, source, nbytes, secs, out_bytes="", notes=""):
    mbs = ""
    if category in ("hash", "symmetric") and nbytes and secs > 0:
        mbs = round((nbytes / 2**20) / secs, 2)
    rows.append(
        {
            "category": category,
            "algorithm": algo,
            "operation": op,
            "data_source": source,
            "input_bytes": nbytes,
            "median_seconds": secs,
            "throughput_mb_s": mbs,
            "output_bytes": out_bytes,
            "rss_mb": round(proc.memory_info().rss / 2**20, 1),
            "security_bits": SECURITY_BITS.get(algo, ""),
            "notes": notes,
        }
    )


# ---------------- Hashing ----------------
HASHES = {
    "MD5": hashlib.md5,
    "SHA-256": hashlib.sha256,
    "SHA3-256": hashlib.sha3_256,
}


def bench_hashes(data, source):
    for name, fn in HASHES.items():
        secs, digest = timed(lambda: fn(data).digest())
        add("hash", name, "digest", source, len(data), secs, len(digest))


# ---------------- Symmetric ----------------
def bench_symmetric(data, source):
    aes_key, des_key = get_random_bytes(32), get_random_bytes(8)
    cc_key = get_random_bytes(32)
    iv16, iv8, nonce = (
        get_random_bytes(16),
        get_random_bytes(8),
        get_random_bytes(12),
    )

    # (name, encrypt fn, decrypt fn)
    suites = [
        (
            "AES-256-CBC",
            lambda: AES.new(aes_key, AES.MODE_CBC, iv=iv16).encrypt(pad(data, 16)),
            lambda ct: unpad(AES.new(aes_key, AES.MODE_CBC, iv=iv16).decrypt(ct), 16),
        ),
        (
            "DES-CBC",
            lambda: DES.new(des_key, DES.MODE_CBC, iv=iv8).encrypt(pad(data, 8)),
            lambda ct: unpad(DES.new(des_key, DES.MODE_CBC, iv=iv8).decrypt(ct), 8),
        ),
        (
            "ChaCha20",
            lambda: ChaCha20.new(key=cc_key, nonce=nonce).encrypt(data),
            lambda ct: ChaCha20.new(key=cc_key, nonce=nonce).decrypt(ct),
        ),
    ]
    for name, enc, dec in suites:
        enc_t, ct = timed(enc)
        dec_t, pt = timed(lambda: dec(ct))
        assert pt == data, f"{name} round-trip failed"
        add("symmetric", name, "encrypt", source, len(data), enc_t, len(ct))
        add("symmetric", name, "decrypt", source, len(data), dec_t, len(data))


# ---------------- Asymmetric ----------------
def rand_coprime(n):
    """Random k in [2, n) with gcd(k, n) == 1 (needed by ElGamal signing)."""
    while True:
        k = getRandomRange(2, n)
        if GCD(k, n) == 1:
            return k


def make_keys():
    keys = {}
    print("Generating keys (ElGamal can take a while)...")
    secs, keys["rsa"] = timed(lambda: RSA.generate(2048), 3)
    add("asymmetric", "RSA-2048", "keygen", "-", 0, secs)
    secs, keys["ecc"] = timed(lambda: ECC.generate(curve="P-256"), 20)
    add("asymmetric", "ECC-P256", "keygen", "-", 0, secs)
    secs, keys["eg"] = timed(
        lambda: ElGamal.generate(ELGAMAL_BITS, get_random_bytes), 1
    )
    add(
        "asymmetric",
        f"ElGamal-{ELGAMAL_BITS}",
        "keygen",
        "-",
        0,
        secs,
        notes="1 run only (slow)",
    )
    return keys


def bench_small_block_encryption(keys):
    """Public-key encryption only fits tiny messages, so test the maximum block."""
    # RSA-OAEP (SHA-256): max message = 256 - 2*32 - 2 = 190 bytes
    rsa_key = keys["rsa"]
    max_len = 2048 // 8 - 2 * 32 - 2
    msg = get_random_bytes(max_len)
    enc_t, ct = timed(
        lambda: PKCS1_OAEP.new(rsa_key.publickey(), hashAlgo=SHA256).encrypt(msg)
    )
    dec_t, pt = timed(lambda: PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256).decrypt(ct))
    assert pt == msg
    add(
        "asymmetric",
        "RSA-2048",
        "encrypt (OAEP)",
        "max-block",
        max_len,
        enc_t,
        len(ct),
    )
    add(
        "asymmetric",
        "RSA-2048",
        "decrypt (OAEP)",
        "max-block",
        max_len,
        dec_t,
        max_len,
    )

    # ElGamal: textbook scheme on an integer < p (no padding: for benchmarking only).
    # pycryptodome only exposes it through the key's private-named helpers.
    eg = keys["eg"]
    algo = f"ElGamal-{ELGAMAL_BITS}"
    try:
        m = getRandomRange(2, int(eg.p) - 1)
        block = ELGAMAL_BITS // 8 - 1
        enc_t, ct = timed(lambda: eg._encrypt(m, rand_coprime(int(eg.p) - 1)))
        dec_t, pt = timed(lambda: eg._decrypt(ct))
        assert pt == m
        add(
            "asymmetric",
            algo,
            "encrypt (textbook)",
            "max-block",
            block,
            enc_t,
            2 * ELGAMAL_BITS // 8,
        )
        add(
            "asymmetric",
            algo,
            "decrypt (textbook)",
            "max-block",
            block,
            dec_t,
            block,
        )
    except (AttributeError, TypeError, AssertionError) as e:
        print(f"ElGamal encrypt/decrypt skipped: {e}")


def bench_signatures(data, source, keys):
    """Hash + sign / verify. Cost is dominated by hashing, so it grows with data size."""
    rsa_key, ecc_key, eg = keys["rsa"], keys["ecc"], keys["eg"]

    # RSA-PSS
    sign_t, sig = timed(lambda: pss.new(rsa_key).sign(SHA256.new(data)))
    ver_t, _ = timed(lambda: pss.new(rsa_key.publickey()).verify(SHA256.new(data), sig))
    add(
        "asymmetric",
        "RSA-2048",
        "sign (PSS)",
        source,
        len(data),
        sign_t,
        len(sig),
    )
    add("asymmetric", "RSA-2048", "verify (PSS)", source, len(data), ver_t)

    # ECDSA P-256
    sign_t, sig = timed(lambda: DSS.new(ecc_key, "fips-186-3").sign(SHA256.new(data)))
    ver_t, _ = timed(
        lambda: DSS.new(ecc_key.public_key(), "fips-186-3").verify(
            SHA256.new(data), sig
        )
    )
    add(
        "asymmetric",
        "ECC-P256",
        "sign (ECDSA)",
        source,
        len(data),
        sign_t,
        len(sig),
    )
    add("asymmetric", "ECC-P256", "verify (ECDSA)", source, len(data), ver_t)

    # ElGamal signature over the SHA-256 digest (textbook, benchmarking only)
    algo = f"ElGamal-{ELGAMAL_BITS}"
    try:

        def eg_sign():
            m = int.from_bytes(SHA256.new(data).digest(), "big")
            return m, eg._sign(m, rand_coprime(int(eg.p) - 1))

        sign_t, (m, sig) = timed(eg_sign)
        ver_t, ok = timed(
            lambda: eg._verify(int.from_bytes(SHA256.new(data).digest(), "big"), sig)
        )
        assert ok
        add(
            "asymmetric",
            algo,
            "sign (textbook)",
            source,
            len(data),
            sign_t,
            2 * ELGAMAL_BITS // 8,
        )
        add("asymmetric", algo, "verify (textbook)", source, len(data), ver_t)
    except (AttributeError, TypeError, AssertionError) as e:
        print(f"ElGamal sign/verify skipped: {e}")


# ---------------- Main ----------------
def load_datasets():
    arg = sys.argv[1] if len(sys.argv) > 1 else None
    if arg and os.path.isdir(arg):
        out = []
        for name in sorted(os.listdir(arg)):
            with open(os.path.join(arg, name), "rb") as f:
                out.append((f.read(), name))
        return out
    out = [(os.urandom(n), "random") for n in SIZES]
    if arg:
        with open(arg, "rb") as f:
            out.append((f.read(), os.path.basename(arg)))
    return out


def main():
    datasets = load_datasets()
    keys = make_keys()
    bench_small_block_encryption(keys)

    for data, source in datasets:
        print(f"Benchmarking {len(data):,} bytes ({source})...")
        bench_hashes(data, source)
        bench_symmetric(data, source)
        bench_signatures(data, source, keys)

    df = pd.DataFrame(rows)
    df.to_csv("results.csv", index=False)
    print(f"Done. Wrote results.csv ({len(df)} rows)")


if __name__ == "__main__":
    main()
