from base64 import b64encode
import hashlib
import json

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


def encrypt_aes256(plaintext):
    plaintext = plaintext.encode("utf-8")
    key = get_random_bytes(32)  # key size: 256 bits
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = b64encode(cipher.iv).decode("utf-8")
    ct = b64encode(ct_bytes).decode("utf-8")

    return f"AES-256({plaintext}): {ct}"


def encrypt_des(plaintext):
    plaintext = plaintext.encode("utf-8")
    key = get_random_bytes(8)  # key size: 54 bits
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.iv + cipher.encrypt(pad(plaintext, DES.block_size))
    ct = b64encode(ct_bytes).decode("utf-8")

    return f"DES({plaintext}): {ct}"


def encrypt_des3(plaintext):
    while True:
        try:
            key = DES3.adjust_key_parity(get_random_bytes(24))  # avoid option 3
            break
        except ValueError:
            pass
    plaintext = plaintext.encode("utf-8")
    iv = get_random_bytes(8)  # 3DES block size is 8 bytes
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plaintext, DES3.block_size))
    ct = b64encode(ct_bytes).decode("utf-8")

    return f"3DES({plaintext}): {ct}"


aes_ct = encrypt_aes256("hello world")
des_ct = encrypt_des("hello world")
des3_ct = encrypt_des3("hello world")
print(aes_ct)
print(des_ct)
print(des3_ct)
