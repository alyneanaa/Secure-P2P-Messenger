"""Alice/Bob actors for the TLS-style localhost simulation."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
import queue
import socket
import sys
import threading
import time
from typing import Any

from core.peer import Peer
from crypto.rc4 import RC4
from simulation.ca_service import CertificateAuthorityClient
from simulation.protocol import (
    DEFAULT_CA_HOST,
    DEFAULT_CA_PORT,
    DEFAULT_RELAY_HOST,
    DEFAULT_RELAY_PORT,
    ReplayWindow,
    derive_session_key,
    estimate_size,
    make_nonce,
    packet_mac,
    recv_packet,
    send_packet,
    short_hex,
    toy_hash,
)


@dataclass
class SimulationMetrics:
    key_generation_ms: float = 0.0
    handshake_ms: float = 0.0
    encryption_ms: float = 0.0
    decryption_ms: float = 0.0
    ciphertext_sizes: list[int] = field(default_factory=list)
    memory_bytes: dict[str, int] = field(default_factory=dict)


class SecurePeerNode:
    """
    Represents Alice or Bob as an independent localhost actor.

    Each node owns:
      - existing Paillier key pair via Peer
      - existing Kyber-Edu KEM key pair
      - CA-issued simulation certificate
      - relay socket connection
      - replay window and active session keys
    """

    def __init__(
        self,
        username: str,
        ca_host: str = DEFAULT_CA_HOST,
        ca_port: int = DEFAULT_CA_PORT,
        relay_host: str = DEFAULT_RELAY_HOST,
        relay_port: int = DEFAULT_RELAY_PORT,
        key_bits: int = 128,
        auto_respond: bool = False,
    ) -> None:
        self.username = username
        self.ca_client = CertificateAuthorityClient(ca_host, ca_port)
        self.relay_host = relay_host
        self.relay_port = relay_port
        self.key_bits = key_bits
        self.auto_respond = auto_respond
        self.metrics = SimulationMetrics()
        self.replay_window = ReplayWindow()
        self.sessions: dict[str, bytes] = {}
        self.certificates: dict[str, dict[str, Any]] = {}
        self.handshake_nonces: dict[str, dict[str, str]] = {}
        self._pending: queue.Queue[dict[str, Any]] = queue.Queue()
        self._running = threading.Event()
        self._sock: socket.socket | None = None
        self._receiver_thread: threading.Thread | None = None

        start = time.perf_counter()
        self.peer = Peer(username, key_bits=key_bits)
        self.peer.generate_post_quantum_keys()
        self.metrics.key_generation_ms = (time.perf_counter() - start) * 1000
        self.certificate = self._request_certificate()

    # ------------------------------------------------------------------
    # Network lifecycle
    # ------------------------------------------------------------------

    def connect(self) -> None:
        self._sock = socket.create_connection((self.relay_host, self.relay_port), timeout=10)
        # Keep socket in blocking mode for continuous listening
        self._sock.settimeout(None)
        send_packet(self._sock, {"type": "register", "username": self.username})
        file = self._sock.makefile("r", encoding="utf-8")
        response = recv_packet(file)
        if response is None or response.get("type") != "registered":
            raise RuntimeError(f"{self.username} could not register with relay")
        self._running.set()
        self._receiver_thread = threading.Thread(
            target=self._receive_loop,
            args=(file,),
            name=f"{self.username}-receiver",
            daemon=True,
        )
        self._receiver_thread.start()
        print(f"[{self.username} terminal] connected to relay")

    def close(self) -> None:
        self._running.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def route(self, recipient: str, payload: dict[str, Any]) -> None:
        if self._sock is None:
            raise RuntimeError(f"{self.username} is not connected to relay")
        send_packet(
            self._sock,
            {
                "type": "route",
                "from": self.username,
                "to": recipient,
                "payload": payload,
            },
        )

    # ------------------------------------------------------------------
    # Certificate and handshake
    # ------------------------------------------------------------------

    def _request_certificate(self) -> dict[str, Any]:
        public_key = {
            "paillier": self.peer.public_key,
            "kyber_edu": self.peer.pq_public_key,
        }
        response = self.ca_client.issue(self.username, public_key)
        cert = response["certificate"]
        print(f"[{self.username} terminal] received CA certificate serial={cert['serial']}")
        return cert

    def initiate_handshake(self, recipient: str) -> dict[str, Any]:
        start = time.perf_counter()
        client_nonce = make_nonce()
        print(f"[{self.username} terminal] -> {recipient}: Client Hello nonce={client_nonce}")
        self.route(
            recipient,
            {
                "type": "client_hello",
                "client_nonce": client_nonce,
                "supported": ["Paillier", "Kyber-Edu", "RC4", "Blowfish"],
            },
        )

        server_hello = self.wait_for("server_hello", sender=recipient)
        server_nonce = server_hello["payload"]["server_nonce"]
        certificate = server_hello["payload"]["certificate"]
        valid, reason = self.ca_client.validate(certificate)
        print(f"[{self.username} terminal] validated {recipient} certificate: {reason}")
        if not valid:
            raise RuntimeError(f"Certificate validation failed: {reason}")

        self.certificates[recipient] = certificate
        recipient_public = certificate["public_key"]

        classical_component = os.urandom(16)
        self.peer.session_key = classical_component
        encrypted_classical = self.peer.export_encrypted_session_key(
            recipient_public["paillier"]
        )
        pq_ciphertext, pq_secret = self.peer.encapsulate_post_quantum_secret(
            recipient_public["kyber_edu"]
        )
        session_key = derive_session_key(
            classical_component,
            pq_secret,
            client_nonce,
            server_nonce,
        )
        self.sessions[recipient] = session_key
        self.peer.session_key = session_key

        transcript = {
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "encrypted_classical": encrypted_classical,
            "pq_ciphertext": pq_ciphertext,
            "certificate_serial": certificate["serial"],
        }
        client_finished_mac = packet_mac(session_key, "client-finished", transcript)
        print(
            f"[{self.username} terminal] hybrid key ready "
            f"session={session_key.hex()} pq_ct={estimate_size(pq_ciphertext)}B"
        )
        self.route(
            recipient,
            {
                "type": "key_exchange",
                **transcript,
                "client_finished_mac": client_finished_mac,
            },
        )

        finished = self.wait_for("handshake_finished", sender=recipient)
        expected = packet_mac(session_key, "server-finished", transcript)
        if finished["payload"]["server_finished_mac"] != expected:
            raise RuntimeError("Server Finished MAC did not verify")

        self.metrics.handshake_ms = (time.perf_counter() - start) * 1000
        print(
            f"[{self.username} terminal] TLS-style handshake complete "
            f"({self.metrics.handshake_ms:.2f} ms)"
        )
        return {
            "session_key": session_key,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
            "classical_component": classical_component,
            "pq_secret": pq_secret,
            "pq_ciphertext": pq_ciphertext,
        }

    def _handle_client_hello(self, sender: str, payload: dict[str, Any]) -> None:
        server_nonce = make_nonce()
        client_nonce = payload["client_nonce"]
        self.handshake_nonces[sender] = {
            "client_nonce": client_nonce,
            "server_nonce": server_nonce,
        }
        print(f"[{self.username} terminal] <- {sender}: Client Hello")
        print(f"[{self.username} terminal] -> {sender}: Server Hello + certificate")
        self.route(
            sender,
            {
                "type": "server_hello",
                "server_nonce": server_nonce,
                "certificate": self.certificate,
                "selected": ["Paillier", "Kyber-Edu", "RC4", "Blowfish"],
            },
        )

    def _handle_key_exchange(self, sender: str, payload: dict[str, Any]) -> None:
        start = time.perf_counter()
        nonces = self.handshake_nonces.get(sender)
        if nonces is None:
            raise RuntimeError(f"{self.username} received key exchange before Client Hello")

        self.peer.import_encrypted_session_key(payload["encrypted_classical"])
        classical_component = self.peer.session_key or b""
        pq_secret = self.peer.decapsulate_post_quantum_secret(payload["pq_ciphertext"])
        session_key = derive_session_key(
            classical_component,
            pq_secret,
            payload["client_nonce"],
            payload["server_nonce"],
        )
        transcript = {
            "client_nonce": payload["client_nonce"],
            "server_nonce": payload["server_nonce"],
            "encrypted_classical": payload["encrypted_classical"],
            "pq_ciphertext": payload["pq_ciphertext"],
            "certificate_serial": payload["certificate_serial"],
        }
        expected = packet_mac(session_key, "client-finished", transcript)
        if payload["client_finished_mac"] != expected:
            raise RuntimeError("Client Finished MAC did not verify")

        self.sessions[sender] = session_key
        self.peer.session_key = session_key
        server_finished_mac = packet_mac(session_key, "server-finished", transcript)
        self.metrics.handshake_ms = (time.perf_counter() - start) * 1000
        print(
            f"[{self.username} terminal] hybrid key established with {sender} "
            f"session={session_key.hex()}"
        )
        self.route(
            sender,
            {
                "type": "handshake_finished",
                "server_finished_mac": server_finished_mac,
            },
        )

    # ------------------------------------------------------------------
    # Secure messaging and key rotation
    # ------------------------------------------------------------------

    def send_secure_message(self, recipient: str, plaintext: str) -> dict[str, Any]:
        key = self.sessions[recipient]
        nonce = make_nonce()
        iv = os.urandom(8)
        start = time.perf_counter()
        ciphertext = RC4.with_iv(key, iv).encrypt(plaintext.encode("utf-8"))
        self.metrics.encryption_ms = (time.perf_counter() - start) * 1000
        payload = {
            "type": "secure_message",
            "nonce": nonce,
            "iv": iv.hex(),
            "ciphertext": ciphertext.hex(),
            "ciphertext_size": len(ciphertext),
        }
        payload["integrity_tag"] = packet_mac(key, "secure-message", payload)
        self.metrics.ciphertext_sizes.append(len(ciphertext))
        self.metrics.memory_bytes["last_packet"] = sys.getsizeof(payload) + sys.getsizeof(
            payload["ciphertext"]
        )
        print(f"[{self.username} terminal] Plaintext : {plaintext}")
        print(f"[{self.username} terminal] Session key: {key.hex()}")
        print(f"[{self.username} terminal] Ciphertext: {short_hex(ciphertext.hex(), 72)}")
        self.route(recipient, payload)
        return payload

    def _handle_secure_message(self, sender: str, payload: dict[str, Any]) -> None:
        key = self.sessions[sender]
        if not self.replay_window.accept(payload["nonce"]):
            print(f"[{self.username} terminal] REPLAY DETECTED nonce={payload['nonce']}")
            return
        received_tag = payload["integrity_tag"]
        unsigned = dict(payload)
        del unsigned["integrity_tag"]
        expected = packet_mac(key, "secure-message", unsigned)
        if received_tag != expected:
            print(f"[{self.username} terminal] INTEGRITY FAILURE from {sender}")
            return

        start = time.perf_counter()
        plaintext = RC4.with_iv(key, bytes.fromhex(payload["iv"])).decrypt(
            bytes.fromhex(payload["ciphertext"])
        ).decode("utf-8")
        self.metrics.decryption_ms = (time.perf_counter() - start) * 1000
        print(f"[{self.username} terminal] Decrypted message from {sender}: {plaintext}")
        self._pending.put(
            {
                "from": sender,
                "payload": payload,
                "plaintext": plaintext,
            }
        )

    def rotate_session_key(self, recipient: str) -> bytes:
        old_key = self.sessions[recipient]
        rotation_nonce = make_nonce()
        new_key = toy_hash(
            b"SESSION-ROTATION" + old_key + bytes.fromhex(rotation_nonce),
            out_len=16,
        )
        payload = {
            "type": "key_rotation",
            "rotation_nonce": rotation_nonce,
            "integrity_tag": packet_mac(old_key, "key-rotation", {"rotation_nonce": rotation_nonce}),
        }
        self.sessions[recipient] = new_key
        self.peer.session_key = new_key
        print(f"[{self.username} terminal] rotating session key with {recipient}: {new_key.hex()}")
        self.route(recipient, payload)
        return new_key

    def _handle_key_rotation(self, sender: str, payload: dict[str, Any]) -> None:
        old_key = self.sessions[sender]
        expected = packet_mac(
            old_key,
            "key-rotation",
            {"rotation_nonce": payload["rotation_nonce"]},
        )
        if payload["integrity_tag"] != expected:
            print(f"[{self.username} terminal] rejected invalid key rotation from {sender}")
            return
        new_key = toy_hash(
            b"SESSION-ROTATION" + old_key + bytes.fromhex(payload["rotation_nonce"]),
            out_len=16,
        )
        self.sessions[sender] = new_key
        self.peer.session_key = new_key
        print(f"[{self.username} terminal] accepted key rotation from {sender}: {new_key.hex()}")

    # ------------------------------------------------------------------
    # Receiver helpers
    # ------------------------------------------------------------------

    def wait_for(
        self,
        payload_type: str,
        sender: str | None = None,
        timeout: float = 15.0,
    ) -> dict[str, Any]:
        deadline = time.time() + timeout
        skipped = []
        while time.time() < deadline:
            try:
                packet = self._pending.get(timeout=0.1)
            except queue.Empty:
                continue
            matches_type = packet.get("payload", {}).get("type") == payload_type
            matches_sender = sender is None or packet.get("from") == sender
            if matches_type and matches_sender:
                for item in skipped:
                    self._pending.put(item)
                return packet
            skipped.append(packet)
        for item in skipped:
            self._pending.put(item)
        raise TimeoutError(f"{self.username} timed out waiting for {payload_type}")

    def _receive_loop(self, file) -> None:
        while self._running.is_set():
            try:
                print(f"[{self.username} DEBUG] waiting for packet...")
                packet = recv_packet(file)
                print(f"[{self.username} DEBUG] received: {packet}")
            #except (OSError, ValueError):
            except Exception as e:
                print(f"[{self.username} receiver ERROR] {e}")
                break
            if packet is None:
                break
            if packet.get("type") != "deliver":
                continue
            sender = packet["from"]
            payload = packet["payload"]
            payload_type = payload.get("type")

            if self.auto_respond and payload_type == "client_hello":
                self._handle_client_hello(sender, payload)
            elif self.auto_respond and payload_type == "key_exchange":
                self._handle_key_exchange(sender, payload)
            elif payload_type == "secure_message":
                self._handle_secure_message(sender, payload)
            elif payload_type == "key_rotation":
                self._handle_key_rotation(sender, payload)
            else:
                self._pending.put(packet)
