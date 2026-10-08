"""Registry of self-implemented hash algorithms."""

from . import md5 as _md5
from . import sha1 as _sha1
from . import sha256 as _sha256

ALGORITHMS = {
    "MD5": _md5.md5,
    "SHA1": _sha1.sha1,
    "SHA256": _sha256.sha256,
}

DIGEST_SIZE = {
    "MD5": 16,
    "SHA1": 20,
    "SHA256": 32,
}


def supported():
    return list(ALGORITHMS.keys())


def digest(name: str, data: bytes) -> bytes:
    key = name.upper()
    if key not in ALGORITHMS:
        raise ValueError("unsupported hash algorithm: %s" % name)
    return ALGORITHMS[key](data)


def digest_hex(name: str, data: bytes) -> str:
    return digest(name, data).hex()


def hash_file(name: str, path: str):
    with open(path, "rb") as f:
        return digest_hex(name, f.read())
