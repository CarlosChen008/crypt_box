"""Passphrase-based symmetric encryption built on the from-scratch primitives.

AES uses counter mode with encrypt-then-MAC (HMAC-SHA256), while DES and
Triple-DES use CBC and are provided for legacy study only.
"""

import os

from . import aes, des
from .hmac_sha256 import hmac_sha256
from .pbkdf2 import pbkdf2_hmac_sha256

SALT_LEN = 16
_DEFAULT_ITER = 4096


def _derive(passphrase, salt: bytes, length: int, iterations: int) -> bytes:
    return pbkdf2_hmac_sha256(passphrase, salt, iterations, length)


def _constant_time_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


def encrypt_aes(passphrase, data: bytes, mode: str = "CTR", iterations: int = _DEFAULT_ITER) -> bytes:
    salt = os.urandom(SALT_LEN)
    if mode == "CBC":
        key = _derive(passphrase, salt, 32, iterations)
        iv = os.urandom(16)
        return salt + iv + aes.aes_cbc_encrypt(key, data, iv)
    material = _derive(passphrase, salt, 64, iterations)
    enc_key, mac_key = material[:32], material[32:]
    nonce = os.urandom(16)
    ciphertext = aes.aes_ctr_crypt(enc_key, data, nonce)
    tag = hmac_sha256(mac_key, salt + nonce + ciphertext)
    return salt + nonce + ciphertext + tag


def decrypt_aes(passphrase, blob: bytes, mode: str = "CTR", iterations: int = _DEFAULT_ITER) -> bytes:
    if mode == "CBC":
        if len(blob) < SALT_LEN + 16:
            raise ValueError("ciphertext too short")
        salt, iv, ciphertext = blob[:SALT_LEN], blob[SALT_LEN:SALT_LEN + 16], blob[SALT_LEN + 16:]
        key = _derive(passphrase, salt, 32, iterations)
        return aes.aes_cbc_decrypt(key, ciphertext, iv)
    if len(blob) < SALT_LEN + 16 + 32:
        raise ValueError("ciphertext too short")
    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + 16]
    ciphertext = blob[SALT_LEN + 16:-32]
    tag = blob[-32:]
    material = _derive(passphrase, salt, 64, iterations)
    enc_key, mac_key = material[:32], material[32:]
    expected = hmac_sha256(mac_key, salt + nonce + ciphertext)
    if not _constant_time_eq(tag, expected):
        raise ValueError("authentication failed (wrong passphrase or corrupted data)")
    return aes.aes_ctr_crypt(enc_key, ciphertext, nonce)


def encrypt_des(passphrase, data: bytes, iterations: int = _DEFAULT_ITER) -> bytes:
    salt = os.urandom(8)
    key = _derive(passphrase, salt, 8, iterations)
    iv = os.urandom(8)
    return salt + iv + des.des_encrypt(key, data, iv)


def decrypt_des(passphrase, blob: bytes, iterations: int = _DEFAULT_ITER) -> bytes:
    if len(blob) < 16:
        raise ValueError("ciphertext too short")
    salt, iv, ciphertext = blob[:8], blob[8:16], blob[16:]
    key = _derive(passphrase, salt, 8, iterations)
    return des.des_decrypt(key, ciphertext, iv)


def encrypt_3des(passphrase, data: bytes, iterations: int = _DEFAULT_ITER) -> bytes:
    salt = os.urandom(8)
    key = _derive(passphrase, salt, 24, iterations)
    iv = os.urandom(8)
    return salt + iv + des.tdes_encrypt(key, data, iv)


def decrypt_3des(passphrase, blob: bytes, iterations: int = _DEFAULT_ITER) -> bytes:
    if len(blob) < 16:
        raise ValueError("ciphertext too short")
    salt, iv, ciphertext = blob[:8], blob[8:16], blob[16:]
    key = _derive(passphrase, salt, 24, iterations)
    return des.tdes_decrypt(key, ciphertext, iv)
