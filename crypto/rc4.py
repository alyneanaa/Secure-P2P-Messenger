"""
RC4 STREAM CIPHER — Implemented from scratch
No cryptographic libraries used. Pure Python math only.
Used for: Encrypting messages IN TRANSIT (live session stream)

Note: RC4 is deprecated in modern TLS but included here for academic
comparison purposes as required by the coursework spec.
"""


# =====================================================================
# RC4 CIPHER CLASS
# =====================================================================

class RC4:
    """
    RC4 (Rivest Cipher 4) — variable-key-length stream cipher.
    Uses Key Scheduling Algorithm (KSA) + Pseudo-Random Generation (PRGA).
    Used for: encrypting messages during transmission (in-transit).
    """

    def __init__(self, key: bytes):
        if not (1 <= len(key) <= 256):
            raise ValueError("RC4 key must be 1–256 bytes")
        self.key = key
        self.S = self._ksa(key)

    # ------------------------------------------------------------------
    # KEY SCHEDULING ALGORITHM (KSA)
    # ------------------------------------------------------------------

    def _ksa(self, key: bytes) -> list:
        """
        Initialize the 256-byte state array S using the key.
        This is the identity permutation, then scrambled by key bytes.
        """
        S = list(range(256))
        j = 0
        key_len = len(key)

        for i in range(256):
            j = (j + S[i] + key[i % key_len]) % 256
            S[i], S[j] = S[j], S[i]   # swap

        return S

    # ------------------------------------------------------------------
    # PSEUDO-RANDOM GENERATION ALGORITHM (PRGA) to get keystream
    # ------------------------------------------------------------------

    def _prga(self, length: int) -> bytes:
        """
        Generate `length` bytes of pseudo-random keystream from state S.
        State S is consumed per call — do NOT reuse an RC4 instance.
        """
        S = self.S[:]   # work on a copy so object stays reusable for testing
        i = 0
        j = 0
        keystream = []

        for _ in range(length):
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]   # swap
            K = S[(S[i] + S[j]) % 256]
            keystream.append(K)

        return bytes(keystream)

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def encrypt(self, plaintext: bytes) -> bytes:
        """XOR plaintext with keystream to produce ciphertext."""
        keystream = self._prga(len(plaintext))
        return bytes(p ^ k for p, k in zip(plaintext, keystream))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """RC4 is symmetric — decryption == encryption."""
        return self.encrypt(ciphertext)

    @staticmethod
    def with_iv(key: bytes, iv: bytes) -> 'RC4':
        """
        Create RC4 instance with key + IV concatenated.
        Recommended: pass a fresh random IV per message to avoid key reuse.
        """
        return RC4(key + iv)
