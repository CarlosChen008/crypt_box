"""Byte/string encoding helpers (base64 and hex)."""

import base64


def encode(data: bytes, fmt: str = "BASE64") -> str:
    if fmt.upper() == "HEX":
        return data.hex()
    return base64.b64encode(data).decode("ascii")


def decode(text: str, fmt: str = "BASE64") -> bytes:
    cleaned = "".join(text.split())
    if fmt.upper() == "HEX":
        return bytes.fromhex(cleaned)
    return base64.b64decode(cleaned, validate=True)
