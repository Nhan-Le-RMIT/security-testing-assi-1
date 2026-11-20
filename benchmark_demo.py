from base64 import b64encode
from functools import wraps
import hashlib
import os
from pathlib import Path
import time

from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher as CryptoCipher
from cryptography.hazmat.primitives.ciphers import algorithms
from cryptography.hazmat.primitives.ciphers import modes


class Cipher:
    def __init__(self, message: str = "hello world") -> None:
        self.message = message.encode("utf-8")
        self.aes_key = os.urandom(32)
        self.des_key = os.urandom(8)
        self.des3_key = os.urandom(24)

    @staticmethod
    def timer(func):
        @wraps(func)
        def wrapper(
            self, records: list[bytes] | str | bytes | None = None
        ) -> list[str] | str:
            ATTEMPTS = 10
            totals = 0.0

            # Handle single input (e.g., cp.hash_md5() or cp.hash_md5("test"))
            if not isinstance(records, list):
                result = ""
                for _ in range(ATTEMPTS):
                    start_time = time.perf_counter()
                    result = func(self, records)
                    end_time = time.perf_counter()
                    totals += end_time - start_time

                avg_us = (totals / ATTEMPTS) * 1_000_000
                print(
                    f"{func.__name__:<16} | Single run avg: {avg_us:.2f} µs ({ATTEMPTS} runs)"
                )
                return result

            # Handle batch of records (list[bytes] from .jsonl dataset)
            results: list[str] = []
            for _ in range(ATTEMPTS):
                start_time = time.perf_counter()
                results = [func(self, record) for record in records]
                end_time = time.perf_counter()
                totals += end_time - start_time

            avg_total = totals / ATTEMPTS
            avg_per_record_us = (avg_total / len(records)) * 1_000_000

            print(
                f"{func.__name__:<16} | "
                f"Batch ({len(records):,} records): {avg_total:.6f}s | "
                f"Per record: {avg_per_record_us:.2f} µs"
            )
            return results

        return wrapper

    # Hashing
    @timer
    def hash_sha256(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        return hashlib.sha256(data).hexdigest()

    @timer
    def hash_md5(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        return hashlib.md5(data).hexdigest()

    @timer
    def hash_sha3_256(self, message: str | bytes | None = None) -> str:
        data = self._prepare_data(message)
        return hashlib.sha3_256(data).hexdigest()

    # Symmetric Encryptions (with IV prepended so each record is decryptable)
    def _cbc(self, algorithm, block_bits: int, data: bytes) -> bytes:
        iv = os.urandom(block_bits // 8)
        padder = padding.PKCS7(block_bits).padder()
        padded = padder.update(data) + padder.finalize()
        enc = CryptoCipher(algorithm, modes.CBC(iv)).encryptor()
        return iv + enc.update(padded) + enc.finalize()

    @timer
    def encrypt_aes256(self, message=None) -> str:
        data = self._prepare_data(message)
        return b64encode(
            self._cbc(algorithms.AES(self.aes_key), 128, data)
        ).decode()

    @timer
    def encrypt_des(self, message=None) -> str:
        data = self._prepare_data(message)
        return b64encode(
            self._cbc(TripleDES(self.des_key * 3), 64, data)
        ).decode()

    @timer
    def encrypt_des3(self, message=None) -> str:
        data = self._prepare_data(message)
        return b64encode(self._cbc(TripleDES(self.des3_key), 64, data)).decode()

    # Helpers
    def _prepare_data(self, message: str | bytes | None) -> bytes:
        if message is None:
            return self.message
        if isinstance(message, str):
            return message.encode("utf-8")
        return message

    def load_entries(self, path: Path) -> list[bytes]:
        with open(path, "rb") as f:
            return [line.strip() for line in f if line.strip()]

    def main(self) -> None:
        BASE = Path(
            r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset"
        )

        datasets = {
            "1KB": self.load_entries(BASE / "transaction_1KB.jsonl"),
            "1MB": self.load_entries(BASE / "transaction_1MB.jsonl"),
            "10MB": self.load_entries(BASE / "transaction_10MB.jsonl"),
        }

        for name, entries in datasets.items():
            title = f"Dataset: {name} ({len(entries):,} records)"
            print(title.center(40, "-") + "\n")
            self.hash_md5(entries)  # type: ignore
            self.hash_sha256(entries)
            self.hash_sha3_256(entries)
            self.encrypt_aes256(entries)
            self.encrypt_des(entries)
            self.encrypt_des3(entries)


if __name__ == "__main__":
    cp = Cipher("hello world")
    cp.main()
