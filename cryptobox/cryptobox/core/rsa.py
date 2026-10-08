"""RSA, implemented from scratch (Miller-Rabin primes, modpow, PKCS#1 v1.5, OAEP).

Keys are serialised in a small self-contained PEM-like format so the toolbox
does not depend on any external crypto library.
"""

import secrets

from .sha256 import sha256

_SMALL_PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149,
    151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229,
    233, 239, 241, 251,
]


def mod_pow(base: int, exponent: int, modulus: int) -> int:
    result = 1
    base %= modulus
    while exponent > 0:
        if exponent & 1:
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent >>= 1
    return result


def _egcd(a: int, b: int):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y


def mod_inverse(a: int, m: int) -> int:
    g, x, _ = _egcd(a % m, m)
    if g != 1:
        raise ValueError("inverse does not exist")
    return x % m


def is_probable_prime(n: int, rounds: int = 24) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = 2 + secrets.randbelow(n - 3)
        x = mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = mod_pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits)
        candidate |= (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


class RSAKey:
    def __init__(self, n, e, d=None, p=None, q=None):
        self.n = n
        self.e = e
        self.d = d
        self.p = p
        self.q = q

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def size_bytes(self) -> int:
        return (self.n.bit_length() + 7) // 8


def generate_keypair(bits: int = 1024, e: int = 65537) -> RSAKey:
    if bits < 512:
        raise ValueError("key size must be at least 512 bits")
    half = bits // 2
    while True:
        p = generate_prime(half)
        q = generate_prime(bits - half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        phi = (p - 1) * (q - 1)
        try:
            d = mod_inverse(e, phi)
        except ValueError:
            continue
        return RSAKey(n, e, d, p, q)


def mgf1(seed: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += sha256(seed + counter.to_bytes(4, "big"))
        counter += 1
    return bytes(out[:length])


def oaep_encrypt(public, message: bytes) -> bytes:
    n, e = public
    k = (n.bit_length() + 7) // 8
    hlen = 32
    if len(message) > k - 2 * hlen - 2:
        raise ValueError("message too long for OAEP")
    lhash = sha256(b"")
    ps = b"\x00" * (k - len(message) - 2 * hlen - 2)
    db = lhash + ps + b"\x01" + message
    seed = secrets.token_bytes(hlen)
    db_mask = mgf1(seed, k - hlen - 1)
    masked_db = bytes(a ^ b for a, b in zip(db, db_mask))
    seed_mask = mgf1(masked_db, hlen)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    em = b"\x00" + masked_seed + masked_db
    c = mod_pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "big")


def oaep_decrypt(private: RSAKey, ciphertext: bytes) -> bytes:
    n, d = private.n, private.d
    k = private.size_bytes
    hlen = 32
    if len(ciphertext) != k:
        raise ValueError("ciphertext has wrong length")
    m = mod_pow(int.from_bytes(ciphertext, "big"), d, n)
    em = m.to_bytes(k, "big")
    if em[0] != 0:
        raise ValueError("decryption error")
    masked_seed = em[1:1 + hlen]
    masked_db = em[1 + hlen:]
    seed_mask = mgf1(masked_db, hlen)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    db_mask = mgf1(seed, k - hlen - 1)
    db = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    lhash = sha256(b"")
    if db[:hlen] != lhash:
        raise ValueError("decryption error")
    idx = db.find(b"\x01", hlen)
    if idx < 0:
        raise ValueError("decryption error")
    return db[idx + 1:]


def pkcs1v15_encrypt(public, message: bytes) -> bytes:
    n, e = public
    k = (n.bit_length() + 7) // 8
    if len(message) > k - 11:
        raise ValueError("message too long for PKCS#1 v1.5")
    ps = bytes((b % 255) + 1 for b in secrets.token_bytes(k - len(message) - 3))
    em = b"\x00\x02" + ps + b"\x00" + message
    c = mod_pow(int.from_bytes(em, "big"), e, n)
    return c.to_bytes(k, "big")


def pkcs1v15_decrypt(private: RSAKey, ciphertext: bytes) -> bytes:
    n, d = private.n, private.d
    k = private.size_bytes
    if len(ciphertext) != k:
        raise ValueError("ciphertext has wrong length")
    m = mod_pow(int.from_bytes(ciphertext, "big"), d, n)
    em = m.to_bytes(k, "big")
    if not em.startswith(b"\x00\x02"):
        raise ValueError("decryption error")
    idx = em.find(b"\x00", 2)
    if idx < 0:
        raise ValueError("decryption error")
    return em[idx + 1:]


_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def sign(private: RSAKey, message: bytes) -> bytes:
    k = private.size_bytes
    digest_info = _SHA256_DIGEST_INFO + sha256(message)
    if k < len(digest_info) + 11:
        raise ValueError("key too small for signing")
    padding = b"\xff" * (k - len(digest_info) - 3)
    em = b"\x00\x01" + padding + b"\x00" + digest_info
    s = mod_pow(int.from_bytes(em, "big"), private.d, private.n)
    return s.to_bytes(k, "big")


def verify(public, message: bytes, signature: bytes) -> bool:
    n, e = public
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    m = mod_pow(int.from_bytes(signature, "big"), e, n)
    em = m.to_bytes(k, "big")
    expected = _SHA256_DIGEST_INFO + sha256(message)
    padding_len = k - len(expected) - 3
    if padding_len < 8:
        return False
    expected_em = b"\x00\x01" + b"\xff" * padding_len + b"\x00" + expected
    return em == expected_em


def format_public(public) -> str:
    n, e = public
    return ("-----BEGIN CRYPTOBOX PUBLIC KEY-----\n"
            "n=%x\n"
            "e=%x\n"
            "-----END CRYPTOBOX PUBLIC KEY-----\n") % (n, e)


def format_private(private: RSAKey) -> str:
    return ("-----BEGIN CRYPTOBOX PRIVATE KEY-----\n"
            "n=%x\n"
            "e=%x\n"
            "d=%x\n"
            "-----END CRYPTOBOX PRIVATE KEY-----\n") % (private.n, private.e, private.d)


def parse_public(text: str):
    fields = _parse_fields(text, "PUBLIC")
    return int(fields["n"], 16), int(fields["e"], 16)


def parse_private(text: str) -> RSAKey:
    fields = _parse_fields(text, "PRIVATE")
    return RSAKey(int(fields["n"], 16), int(fields["e"], 16), int(fields["d"], 16))


def _parse_fields(text: str, kind: str):
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("-----"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key.strip()] = value.strip()
    if "n" not in fields or "e" not in fields:
        raise ValueError("invalid key data")
    if kind == "PRIVATE" and "d" not in fields:
        raise ValueError("invalid private key data")
    return fields
