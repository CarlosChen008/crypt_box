"""PBKDF2-HMAC-SHA256 (RFC 8018), implemented from scratch.

Pure Python makes a high iteration count slow, so the default is intentionally
modest. It can be raised for production-like use.
"""

from .hmac_sha256 import hmac_sha256

DEFAULT_ITERATIONS = 4096
_HASH_LEN = 32


def pbkdf2_hmac_sha256(password, salt: bytes, iterations: int = DEFAULT_ITERATIONS,
                       dklen: int = 32) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    if iterations < 1:
        raise ValueError("iterations must be >= 1")

    blocks = (dklen + _HASH_LEN - 1) // _HASH_LEN
    derived = bytearray()
    for block_index in range(1, blocks + 1):
        u = hmac_sha256(password, salt + block_index.to_bytes(4, "big"))
        t = bytearray(u)
        for _ in range(iterations - 1):
            u = hmac_sha256(password, u)
            for i in range(_HASH_LEN):
                t[i] ^= u[i]
        derived += t
    return bytes(derived[:dklen])
