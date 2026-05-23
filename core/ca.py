"""
CERTIFICATE AUTHORITY (CA) — Simulation
Implements certificate issuance, validation, and revocation.
No crypto libraries — uses Paillier keys for signing certificates.
"""

import time
import json
from crypto.paillier import (
    generate_paillier_keys,
    simple_hash,
    paillier_encrypt,
    paillier_decrypt
)


# =====================================================================
# CERTIFICATE STRUCTURE
# =====================================================================

class Certificate:
    """Represents a digital certificate issued by the CA."""

    def __init__(self, owner_id: str, owner_public_key: dict,
                 issued_at: float, expires_at: float,
                 serial: int, ca_signature: int):
        self.owner_id       = owner_id
        self.owner_public_key = owner_public_key
        self.issued_at      = issued_at
        self.expires_at     = expires_at
        self.serial         = serial
        self.ca_signature   = ca_signature
        self.revoked        = False

    def is_valid(self) -> bool:
        return not self.revoked and time.time() < self.expires_at

    def to_dict(self) -> dict:
        return {
            'owner_id': self.owner_id,
            'owner_public_key': {k: str(v) for k, v in self.owner_public_key.items()},
            'issued_at': self.issued_at,
            'expires_at': self.expires_at,
            'serial': self.serial,
            'ca_signature': self.ca_signature,
            'revoked': self.revoked
        }

    def __repr__(self):
        status = "VALID" if self.is_valid() else ("REVOKED" if self.revoked else "EXPIRED")
        return f"<Certificate owner={self.owner_id} serial={self.serial} status={status}>"


# =====================================================================
# CERTIFICATE AUTHORITY
# =====================================================================

class CertificateAuthority:
    """
    Simulated Certificate Authority.
    - Generates its own Paillier key pair (CA root keys)
    - Issues certificates to peers (Alice, Bob)
    - Validates and revokes certificates
    - Maintains a certificate registry and revocation list
    """

    def __init__(self, name: str = "TrustNet CA", key_bits: int = 256):
        self.name = name
        print(f"[CA] Initializing {name}...")
        print(f"[CA] Generating {key_bits*2}-bit Paillier root keys...")

        self.public_key, self.private_key = generate_paillier_keys(bits=key_bits)
        self._serial_counter = 1000
        self._registry: dict[int, Certificate] = {}     # serial → cert
        self._revocation_list: set[int] = set()          # revoked serials

        print(f"[CA] Root key generated. CA n = {str(self.public_key['n'])[:20]}...")

    # ------------------------------------------------------------------
    # ISSUE CERTIFICATE
    # ------------------------------------------------------------------

    def issue_certificate(self, owner_id: str, owner_public_key: dict,
                           validity_seconds: int = 3600) -> Certificate:
        """Issue a certificate for a peer."""

        serial     = self._serial_counter
        self._serial_counter += 1
        issued_at  = time.time()
        expires_at = issued_at + validity_seconds

        # Build the data to sign
        cert_data = (
            f"{owner_id}|{serial}|{owner_public_key['n']}|"
            f"{issued_at}|{expires_at}"
        ).encode()

        # CA signs the cert data using its private key
        ca_signature = self._sign(cert_data)

        cert = Certificate(
            owner_id=owner_id,
            owner_public_key=owner_public_key,
            issued_at=issued_at,
            expires_at=expires_at,
            serial=serial,
            ca_signature=ca_signature
        )

        self._registry[serial] = cert

        print(f"[CA] Certificate issued: serial={serial}, owner={owner_id}")
        return cert

    # ------------------------------------------------------------------
    # VALIDATE CERTIFICATE
    # ------------------------------------------------------------------

    def validate_certificate(self, cert: Certificate) -> tuple[bool, str]:
        """Check if a certificate is genuine, unexpired, and not revoked."""

        # 1. Check expiry
        if time.time() > cert.expires_at:
            return False, "Certificate expired"

        # 2. Check revocation
        if cert.serial in self._revocation_list:
            return False, "Certificate revoked"

        # 3. Verify CA signature
        cert_data = (
            f"{cert.owner_id}|{cert.serial}|{cert.owner_public_key['n']}|"
            f"{cert.issued_at}|{cert.expires_at}"
        ).encode()

        if not self._verify(cert_data, cert.ca_signature):
            return False, "Invalid CA signature"

        return True, "Certificate valid"

    # ------------------------------------------------------------------
    # REVOKE CERTIFICATE
    # ------------------------------------------------------------------

    def revoke_certificate(self, serial: int):
        """Add a certificate serial to the revocation list."""
        self._revocation_list.add(serial)
        if serial in self._registry:
            self._registry[serial].revoked = True
        print(f"[CA] Certificate serial={serial} REVOKED")

    # ------------------------------------------------------------------
    # SIGNING (internal — uses CA private key)
    # ------------------------------------------------------------------

    def _sign(self, data: bytes) -> int:
        """Sign data using CA private key. Returns integer signature."""
        h = simple_hash(data, self.private_key['n'])
        # Encrypt hash with CA private key components (signature)
        signature = pow(h, self.private_key['lambda_'], self.private_key['n_sq'])
        return signature

    def _verify(self, data: bytes, signature: int) -> bool:
        """Verify a CA signature against data."""
        try:
            n    = self.private_key['n']
            n_sq = self.private_key['n_sq']
            h_expected = simple_hash(data, n)
            # Recompute signature from h_expected and compare
            expected_sig = pow(h_expected, self.private_key['lambda_'], n_sq)
            return expected_sig == signature
        except Exception:
            return False
