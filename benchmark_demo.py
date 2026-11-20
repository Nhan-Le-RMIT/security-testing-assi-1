import hashlib
import time
from base64 import b64encode

from Crypto.Cipher import AES, DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


def hash_sha256(data):
    digest = hashlib.sha256(data.encode("utf-8"))

    return f"SHA-256({data}): {digest.hexdigest()}"


def hash_md5(data):
    digest = hashlib.md5(data.encode("utf-8"))

    return f"MD5({data}): {digest.hexdigest()}"


def hash_sha3_256(data):
    digest = hashlib.sha3_256(data.encode("utf-8"))

    return f"SHA3-256({data}): {digest.hexdigest()}"


def encrypt_aes256(plaintext: bytes):
    key = get_random_bytes(32)  # 256-bit key
    padded = pad(plaintext, AES.block_size)

    start = time.perf_counter()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(padded)
    elapsed = time.perf_counter() - start

    return {
        "total_s": elapsed,
        "throughput_MBps": len(plaintext) / elapsed / 1e6,
        "ciphertext_bytes": len(ct_bytes),
    }


def encrypt_des(plaintext):
    plaintext = plaintext.encode("utf-8")
    key = get_random_bytes(8)  # key size: 54 bits
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = bytes(cipher.iv) + cipher.encrypt(pad(plaintext, DES.block_size))  # type: ignore[attr-defined]
    ct = b64encode(ct_bytes).decode("utf-8")

    return f"DES({plaintext}): {ct}"


def encrypt_des3(plaintext):
    while True:
        try:
            key = DES3.adjust_key_parity(get_random_bytes(24))
            break
        except ValueError:
            pass
    plaintext = plaintext.encode("utf-8")
    iv = get_random_bytes(8)  # 3DES block size is 8 bytes
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext, DES3.block_size))
    ct = b64encode(ct_bytes).decode("utf-8")

    return f"3DES({plaintext}): {ct}"


def load_entries(path):
    with open(path, "rb") as f:
        return [line.strip() for line in f if line.strip()]


times = []

BASE = r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset"

datasets = {
    "1KB": load_entries(rf"{BASE}\transaction_1KB.jsonl"),
    "1MB": load_entries(rf"{BASE}\transaction_1MB.jsonl"),
    "10MB": load_entries(rf"{BASE}\transaction_10MB.jsonl"),
}

ATTEMPTS = 10

for size, entries in datasets.items():
    encrypt_aes256(entries)  # warm-up run, discarded

    totals = []
    for _ in range(RUNS):
        result = encrypt_aes256(entries)
        totals.append(result["total_s"])

    print(f"{name}: avg total over {RUNS} runs = {sum(totals) / RUNS:.6f} s")
