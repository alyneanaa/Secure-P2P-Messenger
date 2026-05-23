"""
EDUCATIONAL KYBER-STYLE POST-QUANTUM KEM
========================================

This module implements a compact Module-LWE key encapsulation mechanism inspired
by Kyber / ML-KEM. It is intentionally small and readable for coursework:

  - Ring:      R_q = Z_q[x] / (x^n + 1)
  - Public key: matrix A and vector t = A*s + e
  - Ciphertext: u = A^T*r + e1, v = t^T*r + e2 + encode(m)
  - Shared key: toy KDF(m || ciphertext)

Important: this is NOT production cryptography and is NOT a drop-in
replacement for standardized ML-KEM. It is a from-scratch educational
demonstration of the lattice/KEM idea using only Python built-ins.
"""

from __future__ import annotations

import os
import random
from typing import Any


KYBER_EDU_N = 128
KYBER_EDU_Q = 3329
KYBER_EDU_K = 2
KYBER_EDU_ETA = 1
KYBER_MESSAGE_BYTES = KYBER_EDU_N // 8


Polynomial = list[int]
PolyVector = list[Polynomial]
PolyMatrix = list[PolyVector]


# =====================================================================
# BASIC HELPERS
# =====================================================================

def _mod_q(value: int, q: int = KYBER_EDU_Q) -> int:
    return value % q


def _centered_binomial(eta: int = KYBER_EDU_ETA) -> int:
    """Tiny centered noise distribution in [-eta, eta]."""
    return sum(random.getrandbits(1) for _ in range(eta)) - sum(
        random.getrandbits(1) for _ in range(eta)
    )


def _random_poly_uniform(n: int, q: int) -> Polynomial:
    return [random.randrange(q) for _ in range(n)]


def _random_poly_small(n: int, eta: int) -> Polynomial:
    return [_centered_binomial(eta) for _ in range(n)]


def _poly_add(a: Polynomial, b: Polynomial, q: int = KYBER_EDU_Q) -> Polynomial:
    return [(x + y) % q for x, y in zip(a, b)]


def _poly_sub(a: Polynomial, b: Polynomial, q: int = KYBER_EDU_Q) -> Polynomial:
    return [(x - y) % q for x, y in zip(a, b)]


def _poly_mul(a: Polynomial, b: Polynomial, q: int = KYBER_EDU_Q) -> Polynomial:
    """
    Multiply two polynomials modulo x^n + 1.

    For this small educational parameter set, the simple O(n^2) version is much
    easier to audit than an NTT implementation.
    """
    n = len(a)
    result = [0] * n
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            idx = i + j
            if idx >= n:
                result[idx - n] -= ai * bj
            else:
                result[idx] += ai * bj
    return [value % q for value in result]


def _poly_dot(a: PolyVector, b: PolyVector, q: int = KYBER_EDU_Q) -> Polynomial:
    n = len(a[0])
    total = [0] * n
    for left, right in zip(a, b):
        total = _poly_add(total, _poly_mul(left, right, q), q)
    return total


def _matrix_vector_mul(matrix: PolyMatrix, vector: PolyVector, q: int) -> PolyVector:
    return [_poly_dot(row, vector, q) for row in matrix]


def _transpose_matrix_vector_mul(matrix: PolyMatrix, vector: PolyVector, q: int) -> PolyVector:
    k = len(matrix)
    result = []
    for col in range(k):
        column = [matrix[row][col] for row in range(k)]
        result.append(_poly_dot(column, vector, q))
    return result


def _bytes_to_poly(message: bytes, n: int, q: int) -> Polynomial:
    if len(message) * 8 > n:
        raise ValueError(f"Message must fit in {n} bits")

    high = q // 2
    coeffs = [0] * n
    bit_index = 0
    for byte in message:
        for bit in range(8):
            coeffs[bit_index] = high if ((byte >> bit) & 1) else 0
            bit_index += 1
    return coeffs


def _poly_to_bytes(poly: Polynomial, byte_count: int, q: int) -> bytes:
    output = []
    for byte_index in range(byte_count):
        value = 0
        for bit in range(8):
            coeff = poly[byte_index * 8 + bit] % q
            # Decode by distance to 0 versus q/2. This mirrors the Kyber idea
            # without compression, making the demo reliable and inspectable.
            is_one = q // 4 <= coeff <= (3 * q) // 4
            if is_one:
                value |= 1 << bit
        output.append(value)
    return bytes(output)


def _int_to_le_bytes(value: int, length: int = 2) -> bytes:
    return int(value).to_bytes(length, "little", signed=False)


def _serialize_poly(poly: Polynomial) -> bytes:
    return b"".join(_int_to_le_bytes(value % KYBER_EDU_Q) for value in poly)


def _serialize_vector(vector: PolyVector) -> bytes:
    return b"".join(_serialize_poly(poly) for poly in vector)


def _toy_hash(data: bytes, out_len: int = 32) -> bytes:
    """
    Small deterministic hash/KDF for the coursework demo.

    It is deliberately not advertised as a secure hash; it keeps the "no crypto
    libraries" constraint while giving both KEM sides identical key material.
    """
    state = [
        0x243F6A88,
        0x85A308D3,
        0x13198A2E,
        0x03707344,
        0xA4093822,
        0x299F31D0,
        0x082EFA98,
        0xEC4E6C89,
    ]
    for index, byte in enumerate(data):
        slot = index % len(state)
        state[slot] ^= byte + 0x9E3779B9 + ((state[(slot - 1) % 8] << 6) & 0xFFFFFFFF)
        state[slot] = ((state[slot] << 7) | (state[slot] >> 25)) & 0xFFFFFFFF
        state[slot] = (state[slot] * 0x85EBCA6B + 0xC2B2AE35) & 0xFFFFFFFF

    output = bytearray()
    counter = 0
    while len(output) < out_len:
        for i in range(len(state)):
            state[i] ^= (counter + i * 0x9E3779B1) & 0xFFFFFFFF
            state[i] = ((state[i] << 11) | (state[i] >> 21)) & 0xFFFFFFFF
            output.extend(state[i].to_bytes(4, "little"))
        counter += 1
    return bytes(output[:out_len])


# =====================================================================
# PUBLIC KYBER-STYLE KEM API
# =====================================================================

def generate_kyber_keys(
    n: int = KYBER_EDU_N,
    q: int = KYBER_EDU_Q,
    k: int = KYBER_EDU_K,
    eta: int = KYBER_EDU_ETA,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Generate a Kyber-style public/private key pair."""
    matrix_a = [
        [_random_poly_uniform(n, q) for _ in range(k)]
        for _ in range(k)
    ]
    #t=AS+e
    secret = [_random_poly_small(n, eta) for _ in range(k)]
    error = [_random_poly_small(n, eta) for _ in range(k)]
    public_t = _matrix_vector_mul(matrix_a, secret, q)
    public_t = [_poly_add(poly, err, q) for poly, err in zip(public_t, error)]

    public_key = {
        "algorithm": "Kyber-Edu Module-LWE KEM",
        "n": n,
        "q": q,
        "k": k,
        "eta": eta,
        "A": matrix_a, 
        "t": public_t,
    }
    private_key = {
        "algorithm": "Kyber-Edu Module-LWE KEM",
        "n": n,
        "q": q,
        "k": k,
        "eta": eta,
        "s": secret,
    }
    return public_key, private_key


def kyber_encapsulate(public_key: dict[str, Any]) -> tuple[dict[str, Any], bytes]:
    """
    Encapsulate a fresh shared secret to a public key.

    Returns (ciphertext, shared_secret).
    """
    n = public_key["n"]
    q = public_key["q"]
    k = public_key["k"]
    eta = public_key["eta"]
    matrix_a = public_key["A"]
    public_t = public_key["t"]

    message = os.urandom(n // 8)
    message_poly = _bytes_to_poly(message, n, q)
    r = [_random_poly_small(n, eta) for _ in range(k)]
    e1 = [_random_poly_small(n, eta) for _ in range(k)]
    e2 = _random_poly_small(n, eta)

    u = _transpose_matrix_vector_mul(matrix_a, r, q)
    u = [_poly_add(poly, err, q) for poly, err in zip(u, e1)]
    v = _poly_dot(public_t, r, q)
    v = _poly_add(v, e2, q)
    v = _poly_add(v, message_poly, q)

    ciphertext = {
        "algorithm": "Kyber-Edu Module-LWE KEM",
        "n": n,
        "q": q,
        "k": k,
        "u": u,
        "v": v,
    }
    shared_secret = _derive_shared_secret(message, ciphertext)
    return ciphertext, shared_secret


def kyber_decapsulate(ciphertext: dict[str, Any], private_key: dict[str, Any]) -> bytes:
    """Recover the shared secret from a ciphertext and private key."""
    q = ciphertext["q"]
    s = private_key["s"]
    u = ciphertext["u"]
    v = ciphertext["v"]

    noisy_message = _poly_sub(v, _poly_dot(s, u, q), q)
    message = _poly_to_bytes(noisy_message, ciphertext["n"] // 8, q)
    return _derive_shared_secret(message, ciphertext)


def _derive_shared_secret(message: bytes, ciphertext: dict[str, Any]) -> bytes:
    transcript = (
        b"KYBER-EDU-KEM"
        + message
        + _serialize_vector(ciphertext["u"])
        + _serialize_poly(ciphertext["v"])
    )
    return _toy_hash(transcript, out_len=32)


def ciphertext_size_bytes(ciphertext: dict[str, Any]) -> int:
    """Return the serialized polynomial payload size for quick comparison."""
    return len(_serialize_vector(ciphertext["u"])) + len(_serialize_poly(ciphertext["v"]))


def public_key_size_bytes(public_key: dict[str, Any]) -> int:
    """Return the serialized public polynomial payload size for quick comparison."""
    matrix_bytes = sum(
        len(_serialize_poly(poly))
        for row in public_key["A"]
        for poly in row
    )
    return matrix_bytes + len(_serialize_vector(public_key["t"]))
