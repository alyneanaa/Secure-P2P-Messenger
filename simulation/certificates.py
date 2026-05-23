"""
Certificate issuing for the multi-party simulation.

The CA uses the existing Paillier implementation for its root key pair and
signature operation. Validation is performed by the CA service in this
educational project because the existing coursework Paillier signature helper is
not a standards-compliant public signature scheme.
"""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Any

from core.ca import CertificateAuthority
from simulation.protocol import canonical_json


@dataclass
class SimulationCertificate:
    username: str
    public_key: dict[str, Any]
    signature: int
    timestamp: float
    serial: int
    expires_at: float
    ca_name: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "username": self.username,
            "public_key": self.public_key,
            "signature": self.signature,
            "timestamp": self.timestamp,
            "serial": self.serial,
            "expires_at": self.expires_at,
            "ca_name": self.ca_name,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "SimulationCertificate":
        return SimulationCertificate(
            username=data["username"],
            public_key=data["public_key"],
            signature=int(data["signature"]),
            timestamp=float(data["timestamp"]),
            serial=int(data["serial"]),
            expires_at=float(data["expires_at"]),
            ca_name=data["ca_name"],
        )


class SimulationCA:
    """CA facade that issues certificates containing both classical and PQ keys."""

    def __init__(self, name: str = "TrustNet CA", key_bits: int = 128) -> None:
        self._ca = CertificateAuthority(name=name, key_bits=key_bits)
        self.name = name
        self.public_key = self._ca.public_key
        self._serial = 5000
        self._revoked: set[int] = set()
        self._issued: dict[int, SimulationCertificate] = {}
        self._lock = threading.Lock()

    def issue_certificate(
        self,
        username: str,
        public_key: dict[str, Any],
        validity_seconds: int = 3600,
    ) -> SimulationCertificate:
        with self._lock:
            serial = self._serial
            self._serial += 1

        timestamp = time.time()
        expires_at = timestamp + validity_seconds
        payload = self._payload(username, public_key, timestamp, serial, expires_at)
        signature = self._ca._sign(canonical_json(payload).encode("utf-8"))
        cert = SimulationCertificate(
            username=username,
            public_key=public_key,
            signature=signature,
            timestamp=timestamp,
            serial=serial,
            expires_at=expires_at,
            ca_name=self.name,
        )
        self._issued[serial] = cert
        return cert

    def validate_certificate(self, cert_data: dict[str, Any]) -> tuple[bool, str]:
        cert = SimulationCertificate.from_dict(cert_data)
        if cert.serial in self._revoked:
            return False, "Certificate revoked"
        if time.time() > cert.expires_at:
            return False, "Certificate expired"
        if cert.ca_name != self.name:
            return False, "Unknown CA"

        payload = self._payload(
            cert.username,
            cert.public_key,
            cert.timestamp,
            cert.serial,
            cert.expires_at,
        )
        valid_signature = self._ca._verify(
            canonical_json(payload).encode("utf-8"),
            cert.signature,
        )
        if not valid_signature:
            return False, "Invalid CA signature"
        return True, "Certificate valid"

    def revoke(self, serial: int) -> None:
        self._revoked.add(serial)

    @staticmethod
    def _payload(
        username: str,
        public_key: dict[str, Any],
        timestamp: float,
        serial: int,
        expires_at: float,
    ) -> dict[str, Any]:
        return {
            "username": username,
            "public_key": public_key,
            "timestamp": timestamp,
            "serial": serial,
            "expires_at": expires_at,
        }
