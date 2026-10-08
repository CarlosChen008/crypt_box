"""HMAC-SHA256 (RFC 2104), built on the local SHA-256 implementation."""

from .sha256 import sha256

BLOCK_SIZE = 64


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    if len(key) > BLOCK_SIZE:
        key = sha256(key)
    key = key + b"\x00" * (BLOCK_SIZE - len(key))
    outer = bytes(b ^ 0x5C for b in key)
    inner = bytes(b ^ 0x36 for b in key)
    return sha256(outer + sha256(inner + message))
