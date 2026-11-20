from base64 import b64encode
import hashlib
import time

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
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


def encrypt_aes256(entries):
    times = []
    total_bytes = 0

    for entry in entries:
        plaintext = entry.encode("utf-8")
        total_bytes += len(plaintext)
        key = get_random_bytes(32)

        start = time.perf_counter()
        cipher = AES.new(key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
        times.append(time.perf_counter() - start)

    total = sum(times)
    return {
        "avg_per_entry_s": total / len(times),
        "total_s": total,
        "throughput_MBps": total_bytes / total / 1e6,
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
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]


print(
    encrypt_aes256(
        load_entries(
            r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset\transaction_1KB.jsonl"
        )
    )
)


print(
    encrypt_aes256(
        load_entries(
            r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset\transaction_1MB.jsonl"
        )
    )
)


print(
    encrypt_aes256(
        load_entries(
            r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset\transaction_10MB.jsonl"
        )
    )
)
