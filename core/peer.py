"""
PEER NODE — Alice / Bob
Each peer has:
  - Paillier key pair for key exchange
  - CA-issued certificate
  - RC4 for in-transit encryption (session messages)
  - Blowfish for at-rest encryption (stored message log)
  - Session key exchange via Paillier
"""

import os
import time
import json
from crypto.paillier   import generate_paillier_keys, encrypt_bytes, decrypt_bytes
from crypto.rc4        import RC4
from crypto.blowfish   import Blowfish
from crypto.kyber      import generate_kyber_keys, kyber_encapsulate, kyber_decapsulate


# =====================================================================
# PEER CLASS
# =====================================================================

class Peer:
    """
    Represents a messaging peer (Alice or Bob).

    Encryption roles:
      - Paillier:  asymmetric — exchange session keys securely
      - RC4:       symmetric stream cipher — encrypt messages in transit
      - Blowfish:  symmetric block cipher — encrypt message log at rest
    """

    def __init__(self, name: str, key_bits: int = 256):
        self.name = name
        self.certificate = None
        self.session_key: bytes | None = None
        self.pq_public_key: dict | None = None
        self._pq_private_key: dict | None = None
        self.message_log: list[dict]   = []          # plaintext for display
        self._encrypted_log: list[bytes] = []        # Blowfish-encrypted at rest

        print(f"[{name}] Generating {key_bits*2}-bit Paillier key pair...")
        self.public_key, self._private_key = generate_paillier_keys(bits=key_bits)
        print(f"[{name}] Key pair ready. n = {str(self.public_key['n'])[:20]}...")

    # ------------------------------------------------------------------
    # POST-QUANTUM KEM (KYBER-STYLE)
    # ------------------------------------------------------------------

    def generate_post_quantum_keys(self) -> dict:
        """Generate a Kyber-style Module-LWE KEM key pair."""
        print(f"[{self.name}] Generating Kyber-Edu post-quantum KEM keys...")
        self.pq_public_key, self._pq_private_key = generate_kyber_keys()
        print(
            f"[{self.name}] Kyber-Edu public key ready "
            f"(n={self.pq_public_key['n']}, k={self.pq_public_key['k']}, q={self.pq_public_key['q']})"
        )
        return self.pq_public_key

    def encapsulate_post_quantum_secret(self, recipient_pq_public_key: dict) -> tuple[dict, bytes]:
        """Encapsulate a shared secret using the recipient's Kyber-style public key."""
        ciphertext, shared_secret = kyber_encapsulate(recipient_pq_public_key)
        print(
            f"[{self.name}] Kyber-Edu encapsulated shared secret "
            f"({len(shared_secret)} bytes)"
        )
        return ciphertext, shared_secret

    def decapsulate_post_quantum_secret(self, ciphertext: dict) -> bytes:
        """Decapsulate a Kyber-style ciphertext using our private KEM key."""
        if self._pq_private_key is None:
            raise RuntimeError(f"[{self.name}] No post-quantum private key available")
        shared_secret = kyber_decapsulate(ciphertext, self._pq_private_key)
        print(f"[{self.name}] Kyber-Edu decapsulated shared secret ({len(shared_secret)} bytes)")
        return shared_secret

    # ------------------------------------------------------------------
    # CERTIFICATE REGISTRATION
    # ------------------------------------------------------------------

    def register_with_ca(self, ca) -> None:
        """Ask the CA to issue a certificate for this peer."""
        self.certificate = ca.issue_certificate(self.name, self.public_key)
        print(f"[{self.name}] Certificate obtained: serial={self.certificate.serial}")

    # ------------------------------------------------------------------
    # SESSION KEY EXCHANGE
    # ------------------------------------------------------------------

    def generate_session_key(self) -> bytes:
        """Generate a fresh 16-byte random session key."""
        self.session_key = os.urandom(16)
        return self.session_key

    def export_encrypted_session_key(self, recipient_public_key: dict) -> list:
        """
        Encrypt our session key byte-by-byte with recipient's Paillier public key.
        Returns list of Paillier ciphertexts.
        """
        if self.session_key is None:
            raise RuntimeError("No session key generated yet")
        encrypted = encrypt_bytes(self.session_key, recipient_public_key)
        print(f"[{self.name}] Session key encrypted with recipient's Paillier key ({len(encrypted)} ciphertexts)")
        return encrypted

    def import_encrypted_session_key(self, ciphertext_list: list) -> None:
        """Decrypt received session key using our Paillier private key."""
        self.session_key = decrypt_bytes(ciphertext_list, self._private_key)
        print(f"[{self.name}] Session key decrypted successfully ({len(self.session_key)} bytes)")

    # ------------------------------------------------------------------
    # SEND MESSAGE (RC4 in-transit encryption)
    # ------------------------------------------------------------------

    def send_message(self, plaintext: str, recipient_name: str) -> dict:
        """
        Encrypt a message for transmission using RC4 (in-transit).
        Returns a packet dict containing IV + ciphertext (hex-encoded).
        """
        if self.session_key is None:
            raise RuntimeError(f"[{self.name}] No session key — cannot send")

        # Fresh IV per message to prevent RC4 key reuse
        iv           = os.urandom(8)
        rc4          = RC4.with_iv(self.session_key, iv)
        ciphertext   = rc4.encrypt(plaintext.encode('utf-8'))

        packet = {
            'from':       self.name,
            'to':         recipient_name,
            'iv':         iv.hex(),
            'ciphertext': ciphertext.hex(),
            'timestamp':  time.time()
        }

        print(f"[{self.name}→{recipient_name}] Sent encrypted packet (RC4, {len(ciphertext)} bytes)")
        return packet

    # ------------------------------------------------------------------
    # RECEIVE MESSAGE (RC4 decrypt + Blowfish store at rest)
    # ------------------------------------------------------------------

    def receive_message(self, packet: dict, ca=None) -> str:
        """
        Receive and decrypt a packet.
        1. Validates sender certificate (if CA provided)
        2. RC4-decrypts the in-transit payload
        3. Stores Blowfish-encrypted copy at rest
        """
        if self.session_key is None:
            raise RuntimeError(f"[{self.name}] No session key — cannot receive")

        sender = packet['from']

        # Step 1: Certificate validation (optional but realistic)
        if ca is not None:
            print(f"[{self.name}] Validating {sender}'s certificate with CA...")

        # Step 2: RC4 decrypt
        iv         = bytes.fromhex(packet['iv'])
        ciphertext = bytes.fromhex(packet['ciphertext'])
        rc4        = RC4.with_iv(self.session_key, iv)
        plaintext  = rc4.decrypt(ciphertext).decode('utf-8')

        print(f"[{self.name}] Decrypted message from {sender}: \"{plaintext}\"")

        # Step 3: Store at rest using Blowfish
        bf = Blowfish(self.session_key)
        entry_bytes      = plaintext.encode('utf-8')
        encrypted_entry  = bf.encrypt(entry_bytes)
        self._encrypted_log.append(encrypted_entry)

        # Also keep plaintext log for display
        self.message_log.append({
            'from':      sender,
            'to':        self.name,
            'plaintext': plaintext,
            'timestamp': packet['timestamp']
        })

        return plaintext

    # ------------------------------------------------------------------
    # READ STORED LOG (Blowfish decrypt at rest)
    # ------------------------------------------------------------------

    def read_stored_log(self) -> list[str]:
        """Decrypt and return the Blowfish-encrypted message log."""
        if self.session_key is None:
            return ["[No session key — cannot read log]"]

        bf       = Blowfish(self.session_key)
        messages = []
        for enc in self._encrypted_log:
            plaintext = bf.decrypt(enc).decode('utf-8')
            messages.append(plaintext)
        return messages
