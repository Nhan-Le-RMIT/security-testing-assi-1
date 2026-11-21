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
        self.message: bytes = message.encode("utf-8")
        self.aes_key: bytes = os.urandom(32)
        self.des_key: bytes = os.urandom(8)
        self.des3_key: bytes = os.urandom(24)

    @staticmethod
    def timer(func):
        @wraps(func)
        def wrapper(
            self, records: list[bytes] | str | bytes | None = None
        ) -> list[str] | str:
            ATTEMPTS: int = 10
            totals: float = 0.0

            if not isinstance(records, list):
                data_len = len(
                    self._prepare_data(records)
                )  # bytes in one message
                result = ""
                for _ in range(ATTEMPTS):
                    start_time = time.perf_counter()
                    result = func(self, records)
                    totals += time.perf_counter() - start_time

                avg = totals / ATTEMPTS
                print(
                    f"{func.__name__:<16} | Single run avg: {avg * 1e6:.2f} µs "
                    f"| {data_len / avg / 1e6:.2f} MB/s ({ATTEMPTS} runs)"
                )
                return result

            total_bytes = sum(len(r) for r in records)  # computed once, untimed
            results = []
            for _ in range(ATTEMPTS):
                start_time = time.perf_counter()
                results = [func(self, record) for record in records]
                totals += time.perf_counter() - start_time

            avg_total = totals / ATTEMPTS
            print(
                f"{func.__name__:<16} | "
                f"Batch ({len(records):,} records): {avg_total:.6f}s | "
                f"Per record: {(avg_total / len(records)) * 1e6:.2f} µs | "
                f"Throughput: {total_bytes / avg_total / 1e6:.2f} MB/s"
            )
            return results

        return wrapper

    # Hashing
    @timer
    def hash_sha_256(self, message: str | bytes | None = None) -> str:
        data: str | bytes = self._prepare_data(message)
        return hashlib.sha256(data).hexdigest()

    @timer
    def hash_md5(self, message: str | bytes | None = None) -> str:
        data: str | bytes = self._prepare_data(message)
        return hashlib.md5(data).hexdigest()

    @timer
    def hash_sha3_256(self, message: str | bytes | None = None) -> str:
        data: str | bytes = self._prepare_data(message)
        return hashlib.sha3_256(data).hexdigest()

    # Symmetric Encryptions
    def _cbc(self, algorithm, block_bits: int, data: bytes) -> bytes:
        iv: bytes = os.urandom(block_bits // 8)
        padder = padding.PKCS7(block_bits).padder()
        padded = padder.update(data) + padder.finalize()
        enc = CryptoCipher(algorithm, modes.CBC(iv)).encryptor()
        return iv + enc.update(padded) + enc.finalize()

    @timer
    def encrypt_aes256(self, message=None) -> str:
        data: str | bytes = self._prepare_data(message)
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
        data: str | bytes = self._prepare_data(message)
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

    # Main
    def main(self) -> None:
        BASE = Path(
            r"C:\Users\admin\Devs\RMIT\Security Testing\security-testing-assi-1\dataset"
        )

        datasets = {
            "1KB": self.load_entries(BASE / "transaction_1KB.jsonl"),
            "1MB": self.load_entries(BASE / "transaction_1MB.jsonl"),
            "10MB": self.load_entries(BASE / "transaction_10MB.jsonl"),
            "100MB": self.load_entries(BASE / "transaction_100MB.jsonl"),
        }

        for name, payload in datasets.items():
            title = f"Dataset: {name} ({len(payload):,} records)"
            print("\n" + title.center(40, "-") + "\n")
            self.hash_md5(payload)  # type: ignore
            self.hash_sha_256(payload)
            self.hash_sha3_256(payload)
            self.encrypt_des(payload)
            self.encrypt_des3(payload)
            self.encrypt_aes256(payload)


if __name__ == "__main__":
    cp = Cipher("hello world")
    cp.main()
