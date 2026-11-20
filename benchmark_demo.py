from base64 import b64encode
from functools import wraps
import hashlib
from pathlib import Path
import time

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


class Cipher:
    def __init__(self, message: str) -> None:
        self.message = message.encode("utf-8")
        self.aes_key = get_random_bytes(32)
        self.des_key = get_random_bytes(8)
        while True:
            try:
                self.des3_key = DES3.adjust_key_parity(get_random_bytes(24))
                break
            except ValueError:
                pass

    @staticmethod
    def timer(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ATTEMPTS = 10
            totals = 0.0
            result = None

            for _ in range(ATTEMPTS):
                start_time = time.perf_counter()
                result = func(*args, **kwargs)
                end_time = time.perf_counter()
                totals += end_time - start_time

            avg_time = totals / ATTEMPTS
            print(
                f"{func.__name__} took an average of {avg_time:.2f} seconds over {ATTEMPTS} runs"
            )

            return result

        return wrapper

    # Hashing
    @timer
    def hash_sha256(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        digest = hashlib.sha256(data)

        return f"SHA-256({data}): {digest.hexdigest()}"

    @timer
    def hash_md5(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        digest = hashlib.md5(data)

        return f"MD5({data}): {digest.hexdigest()}"

    @timer
    def hash_sha3_256(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        digest = hashlib.sha3_256(data)

        return f"SHA3-256({data}): {digest.hexdigest()}"

    # Symmetric Encryptions
    @timer
    def encrypt_aes256(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        padded = pad(data, AES.block_size)

        cipher = AES.new(self.aes_key, AES.MODE_CBC)
        ct_bytes = cipher.encrypt(padded)
        ct = b64encode(ct_bytes).decode("utf-8")

        return f"AES256 ({data}): {ct}"

    @timer
    def encrypt_des(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        iv = get_random_bytes(DES.block_size)  # 8 bytes
        padded = pad(data, DES.block_size)

        cipher = DES.new(self.des_key, DES.MODE_CBC)
        ct_bytes = bytes(iv) + cipher.encrypt(padded)
        ct = b64encode(ct_bytes).decode("utf-8")

        return f"DES({data}): {ct}"

    @timer
    def encrypt_des3(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        iv = get_random_bytes(8)  # 3DES block size is 8 bytes

        cipher = DES3.new(self.des3_key, DES3.MODE_CBC, iv)
        padded = pad(data, DES3.block_size)
        ct_bytes = cipher.encrypt(padded)
        ct = b64encode(ct_bytes).decode("utf-8")

        return f"3DES({data}): {ct}"

    # Helper

    def _prepare_data(self, message: str | bytes | None) -> bytes:
        if message is None:
            return self.message
        if isinstance(message, str):
            return message.encode("utf-8")
        return message

    def load_entries(self, path: Path) -> list:
        with open(path, "rb") as f:
            return [line.strip() for line in f if line.strip()]

    def main(self) -> None:
        BASE = Path(
            r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset"
        )

        datasets = {
            "1KB": self.load_entries(BASE / "transaction_1KB.jsonl"),
            # "1MB": self.load_entries(BASE / "transaction_1MB.jsonl"),
            # "10MB": self.load_entries(BASE / "transaction_10MB.jsonl"),
        }

        for name, entries in datasets.items():
            messages = b"\n".join(entries)
            messages = messages.split(b"\n")
            # self.encrypt_aes256(messages)


if __name__ == "__main__":
    cp = Cipher("hello world")
    cp.hash_md5()
    cp.main()
