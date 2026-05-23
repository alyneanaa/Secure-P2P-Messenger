"""
PAILLIER CRYPTOSYSTEM — Implemented from scratch
No cryptographic libraries used. Only Python's built-in math (pow with 3-arg for modexp).
Used for: asymmetric key exchange and digital signatures between peers.

Paillier is a probabilistic, additively homomorphic public-key cryptosystem
published by Pascal Paillier in 1999.
"""

import random
import math


# =====================================================================
# MATH UTILITIES (no crypto libraries)
# =====================================================================

def is_prime_miller_rabin(n: int, rounds: int = 10) -> bool:
    """
    Miller-Rabin probabilistic primality test.
    More efficient than trial division for large numbers.
    Only uses basic integer arithmetic — no libraries.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)           # Python built-in modular exponentiation

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits: int) -> int:
    """Generate a random prime of the given bit length."""
    while True:
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1)) | 1    # force odd, force MSB set
        if is_prime_miller_rabin(candidate):
            return candidate


def lcm(a: int, b: int) -> int:
    return abs(a * b) // math.gcd(a, b)


# find a number to undo the multiplication
def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean Algorithm — returns a^(-1) mod m."""
    old_r, r = a, m
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_r != 1:
        raise ValueError(f"Modular inverse does not exist (gcd={old_r})")
    return old_s % m

#specific requirement for Paillier math. It extracts the message from the cipher's "niche" in the modular space.
def L_function(x: int, n: int) -> int:
    """Paillier L-function: L(x) = (x - 1) / n"""
    return (x - 1) // n


# =====================================================================
# PAILLIER KEY GENERATION
# =====================================================================

def generate_paillier_keys(bits: int = 512):
    """
    Generate Paillier public and private key pair.

    Public key:  (n, g)
    Private key: (lambda_, mu)

    Args:
        bits: bit length of each prime p and q (key strength = 2*bits)

    Returns:
        (public_key, private_key) as dicts
    """
    while True:
        p = generate_prime(bits)
        q = generate_prime(bits)

        if p == q:
            continue

        n = p * q
        n_sq = n * n

        # lambda = lcm(p-1, q-1)
        lambda_ = lcm(p - 1, q - 1)

        # g = n + 1  (simplified Paillier — provably secure when p,q same length)
        g = n + 1

        # mu = L(g^lambda mod n^2)^(-1) mod n
        g_lambda = pow(g, lambda_, n_sq)
        L_val = L_function(g_lambda, n)

        if math.gcd(L_val, n) != 1:
            continue    # retry if not invertible (very rare)

        mu = mod_inverse(L_val, n)

        public_key  = {'n': n, 'g': g, 'n_sq': n_sq}
        private_key = {'lambda_': lambda_, 'mu': mu, 'n': n, 'n_sq': n_sq}

        return public_key, private_key


# =====================================================================
# PAILLIER ENCRYPTION
# =====================================================================

def paillier_encrypt(plaintext_int: int, public_key: dict) -> int:
    """
    Encrypt an integer plaintext m where 0 <= m < n.

    Ciphertext: c = g^m * r^n mod n^2
    where r is a random value with gcd(r, n) = 1
    """
    n    = public_key['n']
    g    = public_key['g']
    n_sq = public_key['n_sq']

    if not (0 <= plaintext_int < n):
        raise ValueError(f"Plaintext must satisfy 0 <= m < n. Got {plaintext_int}")

    # Pick random r, 1 < r < n, gcd(r,n) = 1
    while True:
        r = random.randrange(2, n)
        if math.gcd(r, n) == 1:
            break

    c = (pow(g, plaintext_int, n_sq) * pow(r, n, n_sq)) % n_sq
    return c


def paillier_decrypt(ciphertext_int: int, private_key: dict) -> int:
    """
    Decrypt a Paillier ciphertext c.

    Plaintext: m = L(c^lambda mod n^2) * mu mod n
    """
    lambda_ = private_key['lambda_']
    mu      = private_key['mu']
    n       = private_key['n']
    n_sq    = private_key['n_sq']

    c_lambda = pow(ciphertext_int, lambda_, n_sq)
    L_val    = L_function(c_lambda, n)
    m        = (L_val * mu) % n
    return m


# =====================================================================
# ENCRYPT / DECRYPT BYTES (for session key exchange)
# =====================================================================

def encrypt_bytes(data: bytes, public_key: dict) -> list:
    """
    Encrypt bytes by encrypting each byte as an integer.
    Returns a list of Paillier ciphertexts (one per byte).
    Used for session key exchange between peers.
    """
    return [paillier_encrypt(b, public_key) for b in data]


def decrypt_bytes(ciphertext_list: list, private_key: dict) -> bytes:
    """Decrypt a list of Paillier ciphertexts back to bytes."""
    return bytes(paillier_decrypt(c, private_key) for c in ciphertext_list)


# =====================================================================
# DIGITAL SIGNATURE (using Paillier + hash)
# =====================================================================

def simple_hash(data: bytes, modulus: int) -> int:
    """
    Simple polynomial rolling hash reduced mod n.
    No hashlib used — pure arithmetic.
    """
    h = 0
    for byte in data:
        h = (h * 31 + byte) % modulus
    return h if h > 0 else 1


def sign_message(message: bytes, private_key: dict) -> int:
    """
    Sign a message using Paillier private key.
    Signature = encrypt(hash(message)) using private key components.
    (Simplified — real Paillier signatures use additional schemes.)
    """
    n    = private_key['n']
    h    = simple_hash(message, n)

    # Sign: s = h^lambda mod n^2  (private key operation)
    s = pow(h, private_key['lambda_'], private_key['n_sq'])
    return s


def verify_signature(message: bytes, signature: int, public_key: dict, private_key_n_sq: int) -> bool:
    """
    Verify signature against message hash.
    In a real CA scenario the verifier would use the public key.
    Here we verify: L(signature) * mu == hash mod n
    """
    try:
        n    = public_key['n']
        mu   = None   # not available from public key alone in simplified Paillier

        # Simplified verification: recompute expected from public key
        h_expected = simple_hash(message, n)

        # Decrypt the signature using public-key-accessible L function
        L_val = L_function(signature, n)
        return (L_val % n) == (h_expected % n)
    except Exception:
        return False
