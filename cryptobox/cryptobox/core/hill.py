"""Hill cipher over the 26-letter alphabet, implemented from scratch.

The key is a square matrix whose determinant is coprime with 26. Letters only
are processed (case is ignored); other characters are dropped. Plaintext is
padded with 'X' and trailing 'X' is stripped on decryption, which is the usual
textbook behaviour.
"""

import random

_MOD = 26


def _isqrt(n: int) -> int:
    r = 0
    while (r + 1) * (r + 1) <= n:
        r += 1
    return r


def _det(matrix) -> int:
    n = len(matrix)
    if n == 1:
        return matrix[0][0]
    if n == 2:
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0]
    total = 0
    for j in range(n):
        sign = 1 if j % 2 == 0 else -1
        total += sign * matrix[0][j] * _det(_minor(matrix, 0, j))
    return total


def _minor(matrix, row, col):
    return [[matrix[i][j] for j in range(len(matrix)) if j != col]
            for i in range(len(matrix)) if i != row]


def _mod_inverse(value: int) -> int:
    value %= _MOD
    for x in range(_MOD):
        if (value * x) % _MOD == 1:
            return x
    raise ValueError("matrix is not invertible modulo 26")


def parse_key(text: str):
    fields = [f for f in text.replace(",", " ").replace(";", " ").split() if f]
    if not fields:
        raise ValueError("empty key")
    numbers = [int(f) % _MOD for f in fields]
    size = _isqrt(len(numbers))
    if size * size != len(numbers) or size < 2:
        raise ValueError("key must contain 4, 9, 16, ... numbers (a square matrix)")
    matrix = [numbers[i * size:(i + 1) * size] for i in range(size)]
    validate_key(matrix)
    return matrix


def validate_key(matrix):
    n = len(matrix)
    if n == 0 or any(len(row) != n for row in matrix):
        raise ValueError("key matrix must be square")
    from math import gcd
    if gcd(_det(matrix) % _MOD, _MOD) != 1:
        raise ValueError("key determinant is not coprime with 26; matrix is not invertible")


def key_string(matrix) -> str:
    return " ".join(str(v % _MOD) for row in matrix for v in row)


def _inverse_matrix(matrix):
    n = len(matrix)
    validate_key(matrix)
    det_inv = _mod_inverse(_det(matrix) % _MOD)
    adjugate = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            cofactor = _det(_minor(matrix, j, i)) % _MOD
            if (i + j) % 2 == 1:
                cofactor = (-cofactor) % _MOD
            adjugate[i][j] = cofactor
    return [[(det_inv * adjugate[i][j]) % _MOD for j in range(n)] for i in range(n)]


def _transform(text: str, matrix) -> str:
    validate_key(matrix)
    letters = [ord(ch) - ord('A') for ch in text.upper() if 'A' <= ch <= 'Z']
    n = len(matrix)
    if not letters:
        return ""
    while len(letters) % n != 0:
        letters.append(ord('X') - ord('A'))
    out = []
    for i in range(0, len(letters), n):
        vector = letters[i:i + n]
        for row in range(n):
            total = sum(matrix[row][k] * vector[k] for k in range(n))
            out.append(chr(ord('A') + total % _MOD))
    return "".join(out)


def encrypt(text: str, key) -> str:
    return _transform(text, key)


def decrypt(text: str, key) -> str:
    plain = _transform(text, _inverse_matrix(key))
    return plain.rstrip("X")


def random_key(n: int = 2):
    if n < 2:
        raise ValueError("dimension must be at least 2")
    while True:
        matrix = [[random.randrange(_MOD) for _ in range(n)] for _ in range(n)]
        try:
            validate_key(matrix)
            return matrix
        except ValueError:
            continue
