"""
Structured message-transfer flow for the browser UI.

This module keeps the frontend honest: every visible artifact is produced by
the existing CA, Peer, Paillier, RC4, and Blowfish implementations.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import io
import time
import uuid
from typing import Any, Callable

from core.ca import CertificateAuthority
from core.peer import Peer
from crypto.kyber import ciphertext_size_bytes, public_key_size_bytes


DEFAULT_DEMO_MESSAGES = [
    ("Alice", "Hello Bob. This channel is end-to-end encrypted."),
    ("Bob", "Hi Alice. Certificate check passed and the session key matches."),
    ("Alice", "Transaction TXN-8842 for $5,000 is ready for approval."),
    ("Bob", "TXN-8842 approved. I stored the decrypted copy with Blowfish."),
]

_TEXT_REPLACEMENTS = {
    "â†’": "->",
    "â€”": "-",
    "âœ“": "OK",
    "âœ—": "FAIL",
    "â€“": "-",
}

_TEXT_REPLACEMENTS.update(
    {
        "\u2192": "->",
        "\u2014": "-",
        "\u2713": "OK",
        "\u2717": "FAIL",
        "\u2013": "-",
        "\u2022": "*",
    }
)


def _run_captured(fn: Callable[[], Any]) -> tuple[Any, float, list[str]]:
    """Run a noisy demo function and return result, elapsed ms, and print lines."""
    buffer = io.StringIO()
    start = time.perf_counter()
    with redirect_stdout(buffer):
        result = fn()
    elapsed_ms = (time.perf_counter() - start) * 1000
    lines = [_clean_line(line) for line in buffer.getvalue().splitlines() if line.strip()]
    return result, elapsed_ms, lines


def _clean_line(line: str) -> str:
    for old, new in _TEXT_REPLACEMENTS.items():
        line = line.replace(old, new)
    return line


def _short_int(value: int, size: int = 28) -> str:
    text = str(value)
    return text if len(text) <= size else f"{text[:size]}..."


def _short_hex(value: str, size: int = 72) -> str:
    return value if len(value) <= size else f"{value[:size]}..."


class SecureMessengerFlow:
    """A stateful, inspectable secure messaging session for the frontend."""

    def __init__(self, key_bits: int = 128):
        self.key_bits = key_bits
        self.session_id = uuid.uuid4().hex[:10]
        self.created_at = time.time()
        self.setup_phases: list[dict[str, Any]] = []
        self.messages: list[dict[str, Any]] = []
        self.trace: list[dict[str, Any]] = []

        self.ca: CertificateAuthority
        self.alice: Peer
        self.bob: Peer
        self.session_key: bytes
        self.paillier_session_key: bytes
        self.encrypted_session_key: list[int]
        self.pq_ciphertext: dict[str, Any]
        self.pq_shared_secret: bytes

        self._initialize()

    # ------------------------------------------------------------------
    # Initialization phases
    # ------------------------------------------------------------------

    def _initialize(self) -> None:
        self.ca, elapsed, lines = _run_captured(
            lambda: CertificateAuthority(name="TrustNet CA", key_bits=self.key_bits)
        )
        self._add_phase(
            "ca",
            "Certificate Authority",
            "TrustNet CA generated its Paillier root key pair.",
            elapsed,
            lines,
            {
                "Algorithm": "Paillier root key",
                "Public n": _short_int(self.ca.public_key["n"]),
                "Key size": f"{self.key_bits * 2}-bit demo key",
            },
        )

        def register_peers() -> tuple[Peer, Peer]:
            alice = Peer("Alice", key_bits=self.key_bits)
            bob = Peer("Bob", key_bits=self.key_bits)
            alice.register_with_ca(self.ca)
            bob.register_with_ca(self.ca)
            return alice, bob

        (self.alice, self.bob), elapsed, lines = _run_captured(register_peers)
        cert_results = {
            peer.name: self.ca.validate_certificate(peer.certificate)
            for peer in (self.alice, self.bob)
        }
        self._add_phase(
            "registration",
            "Peer Registration",
            "Alice and Bob generated Paillier key pairs and received CA certificates.",
            elapsed,
            lines,
            {
                "Alice cert": self._cert_status_text(self.alice),
                "Bob cert": self._cert_status_text(self.bob),
                "Validation": ", ".join(
                    f"{name}: {reason}" for name, (_, reason) in cert_results.items()
                ),
            },
        )

        def exchange_session_key() -> tuple[bytes, list[int], bytes]:
            session_key = self.alice.generate_session_key()
            encrypted_key = self.alice.export_encrypted_session_key(self.bob.public_key)
            self.bob.import_encrypted_session_key(encrypted_key)
            return session_key, encrypted_key, self.bob.session_key or b""

        (self.paillier_session_key, self.encrypted_session_key, bob_key), elapsed, lines = _run_captured(
            exchange_session_key
        )
        self.session_key = self.paillier_session_key
        self._add_phase(
            "key-exchange",
            "Paillier Key Exchange",
            "Alice encrypted a fresh session key with Bob's public key; Bob recovered it.",
            elapsed,
            lines,
            {
                "Session key": self.paillier_session_key.hex(),
                "Paillier ciphertexts": str(len(self.encrypted_session_key)),
                "Agreement": "MATCH" if self.paillier_session_key == bob_key else "MISMATCH",
            },
        )

        def exchange_post_quantum_secret() -> tuple[dict[str, Any], bytes, bytes]:
            self.bob.generate_post_quantum_keys()
            ciphertext, alice_secret = self.alice.encapsulate_post_quantum_secret(
                self.bob.pq_public_key
            )
            bob_secret = self.bob.decapsulate_post_quantum_secret(ciphertext)
            return ciphertext, alice_secret, bob_secret

        (self.pq_ciphertext, self.pq_shared_secret, bob_pq_secret), elapsed, lines = _run_captured(
            exchange_post_quantum_secret
        )
        self.session_key = bytes(
            a ^ b for a, b in zip(self.paillier_session_key, self.pq_shared_secret[:16])
        )
        self.alice.session_key = self.session_key
        self.bob.session_key = self.session_key
        self._add_phase(
            "post-quantum-kem",
            "Kyber-Edu Post-Quantum KEM",
            "Alice encapsulated a lattice-based secret to Bob and both sides hybridized it with Paillier.",
            elapsed,
            lines,
            {
                "Algorithm": "Module-LWE KEM",
                "PQ ciphertext": f"{ciphertext_size_bytes(self.pq_ciphertext)} bytes",
                "PQ public key": f"{public_key_size_bytes(self.bob.pq_public_key)} bytes",
                "Agreement": "MATCH" if self.pq_shared_secret == bob_pq_secret else "MISMATCH",
            },
        )

    def _add_phase(
        self,
        phase_id: str,
        title: str,
        summary: str,
        elapsed_ms: float,
        terminal: list[str],
        facts: dict[str, str],
    ) -> None:
        phase = {
            "id": phase_id,
            "title": title,
            "summary": summary,
            "elapsed_ms": round(elapsed_ms, 3),
            "terminal": terminal,
            "facts": facts,
        }
        self.setup_phases.append(phase)
        self.trace.append(
            {
                "kind": "setup",
                "title": title,
                "elapsed_ms": round(elapsed_ms, 3),
                "lines": terminal,
            }
        )

    # ------------------------------------------------------------------
    # Message transfer
    # ------------------------------------------------------------------

    def run_scripted_demo(self) -> None:
        for sender, message in DEFAULT_DEMO_MESSAGES:
            self.send_message(sender, message)

    def send_message(self, sender_name: str, plaintext: str) -> dict[str, Any]:
        sender = self._peer(sender_name)
        recipient = self.bob if sender.name == "Alice" else self.alice
        validation_ok, validation_reason = self.ca.validate_certificate(sender.certificate)

        base_event = {
            "id": len(self.messages) + 1,
            "from": sender.name,
            "to": recipient.name,
            "direction": f"{sender.name} -> {recipient.name}",
            "plaintext": plaintext,
            "created_at": time.time(),
            "certificate": {
                "checked_by": recipient.name,
                "serial": sender.certificate.serial,
                "valid": validation_ok,
                "reason": validation_reason,
            },
            "session_key": self.session_key.hex(),
        }

        if not validation_ok:
            event = {
                **base_event,
                "status": "blocked",
                "decrypted": "",
                "packet": None,
                "at_rest": None,
                "timing": {"send_ms": 0.0, "receive_ms": 0.0},
                "terminal": [],
                "stages": [
                    self._stage(
                        "Certificate validation",
                        "failed",
                        f"{recipient.name} rejected {sender.name}'s certificate: {validation_reason}.",
                    ),
                    self._stage("RC4 encryption", "skipped", "No packet was created."),
                    self._stage("Transmission", "skipped", "Transfer stopped before the channel."),
                    self._stage("Blowfish storage", "skipped", "Nothing was written at rest."),
                ],
            }
            self.messages.append(event)
            self._record_message_trace(event)
            return event

        packet, send_ms, send_lines = _run_captured(
            lambda: sender.send_message(plaintext, recipient.name)
        )
        decrypted, receive_ms, receive_lines = _run_captured(
            lambda: recipient.receive_message(packet, ca=self.ca)
        )

        encrypted_entry = recipient._encrypted_log[-1]
        packet_ciphertext = packet["ciphertext"]
        event = {
            **base_event,
            "status": "delivered",
            "decrypted": decrypted,
            "packet": {
                "iv": packet["iv"],
                "ciphertext": packet_ciphertext,
                "ciphertext_preview": _short_hex(packet_ciphertext),
                "ciphertext_bytes": len(bytes.fromhex(packet_ciphertext)),
                "timestamp": packet["timestamp"],
            },
            "at_rest": {
                "owner": recipient.name,
                "algorithm": "Blowfish",
                "ciphertext": encrypted_entry.hex(),
                "ciphertext_preview": _short_hex(encrypted_entry.hex()),
                "ciphertext_bytes": len(encrypted_entry),
            },
            "timing": {
                "send_ms": round(send_ms, 3),
                "receive_ms": round(receive_ms, 3),
            },
            "terminal": send_lines + receive_lines,
            "stages": [
                self._stage(
                    "Certificate validation",
                    "complete",
                    f"{recipient.name} accepted serial {sender.certificate.serial}: {validation_reason}.",
                ),
                self._stage(
                    "RC4 encryption",
                    "complete",
                    f"Plaintext became {len(bytes.fromhex(packet_ciphertext))} ciphertext bytes with IV {packet['iv']}.",
                ),
                self._stage(
                    "Transmission",
                    "complete",
                    f"Packet moved across the channel as hex ciphertext, not readable text.",
                ),
                self._stage(
                    "RC4 decryption",
                    "complete",
                    f"{recipient.name} recovered: \"{decrypted}\"",
                ),
                self._stage(
                    "Blowfish storage",
                    "complete",
                    f"{recipient.name} stored {len(encrypted_entry)} encrypted bytes at rest.",
                ),
            ],
        }
        self.messages.append(event)
        self._record_message_trace(event)
        return event

    def revoke_certificate(self, peer_name: str) -> dict[str, Any]:
        peer = self._peer(peer_name)
        _, elapsed_ms, lines = _run_captured(
            lambda: self.ca.revoke_certificate(peer.certificate.serial)
        )
        status = self._certificate_view(peer)
        self.trace.append(
            {
                "kind": "revocation",
                "title": f"{peer.name} certificate revoked",
                "elapsed_ms": round(elapsed_ms, 3),
                "lines": lines,
            }
        )
        return status

    # ------------------------------------------------------------------
    # Snapshot serialization
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        certs = {
            "Alice": self._certificate_view(self.alice),
            "Bob": self._certificate_view(self.bob),
        }
        delivered = sum(1 for message in self.messages if message["status"] == "delivered")
        blocked = sum(1 for message in self.messages if message["status"] == "blocked")
        revoked = sum(1 for cert in certs.values() if cert["revoked"])

        return {
            "session": {
                "id": self.session_id,
                "created_at": self.created_at,
                "key_bits": self.key_bits,
                "key_size": self.key_bits * 2,
            },
            "setup_phases": self.setup_phases,
            "certificates": certs,
            "key_exchange": {
                "algorithm": "Hybrid Paillier + Kyber-Edu",
                "paillier_session_key_hex": self.paillier_session_key.hex(),
                "session_key_hex": self.session_key.hex(),
                "ciphertext_count": len(self.encrypted_session_key),
                "ciphertext_preview": [
                    _short_int(value, 36) for value in self.encrypted_session_key[:4]
                ],
                "alice_key_matches_bob": self.alice.session_key == self.bob.session_key,
                "post_quantum": {
                    "algorithm": "Kyber-Edu Module-LWE KEM",
                    "shared_secret_preview": self.pq_shared_secret[:16].hex(),
                    "ciphertext_bytes": ciphertext_size_bytes(self.pq_ciphertext),
                    "public_key_bytes": public_key_size_bytes(self.bob.pq_public_key),
                    "n": self.pq_ciphertext["n"],
                    "q": self.pq_ciphertext["q"],
                    "k": self.pq_ciphertext["k"],
                },
            },
            "messages": self.messages,
            "logs": {
                "Alice": self._log_view(self.alice),
                "Bob": self._log_view(self.bob),
            },
            "metrics": {
                "delivered_messages": delivered,
                "blocked_messages": blocked,
                "revoked_certificates": revoked,
                "total_messages": len(self.messages),
            },
            "trace": self.trace[-18:],
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _peer(self, name: str) -> Peer:
        normalized = name.strip().lower()
        if normalized == "alice":
            return self.alice
        if normalized == "bob":
            return self.bob
        raise ValueError("Peer must be Alice or Bob")

    def _certificate_view(self, peer: Peer) -> dict[str, Any]:
        valid, reason = self.ca.validate_certificate(peer.certificate)
        cert = peer.certificate
        return {
            "owner": peer.name,
            "serial": cert.serial,
            "valid": valid,
            "reason": reason,
            "revoked": cert.revoked,
            "issued_at": cert.issued_at,
            "expires_at": cert.expires_at,
            "public_key_n": _short_int(cert.owner_public_key["n"]),
            "signature": _short_int(cert.ca_signature),
        }

    def _cert_status_text(self, peer: Peer) -> str:
        cert = self._certificate_view(peer)
        status = "valid" if cert["valid"] else cert["reason"].lower()
        return f"serial {cert['serial']} ({status})"

    def _log_view(self, peer: Peer) -> dict[str, Any]:
        encrypted_entries = [entry.hex() for entry in peer._encrypted_log]
        return {
            "decrypted": peer.read_stored_log(),
            "encrypted": encrypted_entries,
            "encrypted_preview": [_short_hex(entry) for entry in encrypted_entries],
            "count": len(encrypted_entries),
        }

    def _record_message_trace(self, event: dict[str, Any]) -> None:
        self.trace.append(
            {
                "kind": "message",
                "title": f"{event['direction']} #{event['id']} {event['status']}",
                "elapsed_ms": round(
                    event["timing"]["send_ms"] + event["timing"]["receive_ms"], 3
                ),
                "lines": event["terminal"],
            }
        )

    @staticmethod
    def _stage(label: str, state: str, detail: str) -> dict[str, str]:
        return {"label": label, "state": state, "detail": detail}
