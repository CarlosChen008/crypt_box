"""AES (FIPS 197), implemented from scratch for study purposes."""


def _gf_mul(a: int, b: int) -> int:
    product = 0
    for _ in range(8):
        if b & 1:
            product ^= a
        high = a & 0x80
        a = (a << 1) & 0xFF
        if high:
            a ^= 0x1B
        b >>= 1
    return product


def _gf_inv(a: int) -> int:
    if a == 0:
        return 0
    for x in range(1, 256):
        if _gf_mul(a, x) == 1:
            return x
    return 0


def _rotl8(x: int, n: int) -> int:
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_sbox():
    sbox = [0] * 256
    for b in range(256):
        inv = _gf_inv(b)
        sbox[b] = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * 256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36,
        0x6C, 0xD8, 0xAB, 0x4D]


def _key_expansion(key: bytes):
    nk = len(key) // 4
    if nk not in (4, 6, 8):
        raise ValueError("AES key must be 16, 24 or 32 bytes")
    nr = nk + 6
    w = [list(key[4 * i:4 * i + 4]) for i in range(nk)]
    rcon_index = 0
    for i in range(nk, 4 * (nr + 1)):
        temp = list(w[i - 1])
        if i % nk == 0:
            temp = temp[1:] + temp[:1]
            temp = [SBOX[b] for b in temp]
            temp[0] ^= RCON[rcon_index]
            rcon_index += 1
        elif nk > 6 and i % nk == 4:
            temp = [SBOX[b] for b in temp]
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(nr + 1):
        rk = []
        for c in range(4):
            rk += w[r * 4 + c]
        round_keys.append(rk)
    return round_keys, nr


def _add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]


def _sub_bytes(state, box):
    return [box[b] for b in state]


def _shift_rows(state):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = state[4 * ((c + r) % 4) + r]
    return out


def _inv_shift_rows(state):
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[4 * c + r] = state[4 * ((c - r) % 4) + r]
    return out


def _mix_columns(state):
    out = [0] * 16
    for c in range(4):
        s = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gf_mul(s[0], 2) ^ _gf_mul(s[1], 3) ^ s[2] ^ s[3]
        out[4 * c + 1] = s[0] ^ _gf_mul(s[1], 2) ^ _gf_mul(s[2], 3) ^ s[3]
        out[4 * c + 2] = s[0] ^ s[1] ^ _gf_mul(s[2], 2) ^ _gf_mul(s[3], 3)
        out[4 * c + 3] = _gf_mul(s[0], 3) ^ s[1] ^ s[2] ^ _gf_mul(s[3], 2)
    return out


def _inv_mix_columns(state):
    out = [0] * 16
    for c in range(4):
        s = state[4 * c:4 * c + 4]
        out[4 * c + 0] = _gf_mul(s[0], 14) ^ _gf_mul(s[1], 11) ^ _gf_mul(s[2], 13) ^ _gf_mul(s[3], 9)
        out[4 * c + 1] = _gf_mul(s[0], 9) ^ _gf_mul(s[1], 14) ^ _gf_mul(s[2], 11) ^ _gf_mul(s[3], 13)
        out[4 * c + 2] = _gf_mul(s[0], 13) ^ _gf_mul(s[1], 9) ^ _gf_mul(s[2], 14) ^ _gf_mul(s[3], 11)
        out[4 * c + 3] = _gf_mul(s[0], 11) ^ _gf_mul(s[1], 13) ^ _gf_mul(s[2], 9) ^ _gf_mul(s[3], 14)
    return out


def aes_encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys, nr = _key_expansion(key)
    state = list(block)
    state = _add_round_key(state, round_keys[0])
    for r in range(1, nr):
        state = _sub_bytes(state, SBOX)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, round_keys[r])
    state = _sub_bytes(state, SBOX)
    state = _shift_rows(state)
    state = _add_round_key(state, round_keys[nr])
    return bytes(state)


def aes_decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    round_keys, nr = _key_expansion(key)
    state = list(block)
    state = _add_round_key(state, round_keys[nr])
    for r in range(nr - 1, 0, -1):
        state = _inv_shift_rows(state)
        state = _sub_bytes(state, INV_SBOX)
        state = _add_round_key(state, round_keys[r])
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _sub_bytes(state, INV_SBOX)
    state = _add_round_key(state, round_keys[0])
    return bytes(state)


def _pkcs7_pad(data: bytes, block: int) -> bytes:
    pad = block - len(data) % block
    return data + bytes([pad]) * pad


def _pkcs7_unpad(data: bytes, block: int) -> bytes:
    if not data or len(data) % block != 0:
        raise ValueError("invalid padded data length")
    pad = data[-1]
    if pad < 1 or pad > block or data[-pad:] != bytes([pad]) * pad:
        raise ValueError("invalid padding")
    return data[:-pad]


def aes_cbc_encrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("AES IV must be 16 bytes")
    data = _pkcs7_pad(data, 16)
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = bytes(a ^ b for a, b in zip(data[i:i + 16], prev))
        prev = aes_encrypt_block(key, block)
        out += prev
    return bytes(out)


def aes_cbc_decrypt(key: bytes, data: bytes, iv: bytes) -> bytes:
    if len(iv) != 16:
        raise ValueError("AES IV must be 16 bytes")
    if len(data) % 16 != 0:
        raise ValueError("ciphertext length must be a multiple of 16")
    out = bytearray()
    prev = iv
    for i in range(0, len(data), 16):
        block = data[i:i + 16]
        plain = bytes(a ^ b for a, b in zip(aes_decrypt_block(key, block), prev))
        out += plain
        prev = block
    return _pkcs7_unpad(bytes(out), 16)


def aes_ctr_crypt(key: bytes, data: bytes, nonce: bytes) -> bytes:
    if len(nonce) != 16:
        raise ValueError("CTR nonce/counter block must be 16 bytes")
    out = bytearray()
    counter = int.from_bytes(nonce, "big")
    for i in range(0, len(data), 16):
        keystream = aes_encrypt_block(key, counter.to_bytes(16, "big"))
        chunk = data[i:i + 16]
        out += bytes(a ^ b for a, b in zip(chunk, keystream))
        counter = (counter + 1) % (1 << 128)
    return bytes(out)
