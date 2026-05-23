"""Localhost Certificate Authority service for terminal and threaded demos."""

from __future__ import annotations

import socket
import threading
from typing import Any

from simulation.certificates import SimulationCA
from simulation.protocol import DEFAULT_CA_HOST, DEFAULT_CA_PORT, recv_packet, send_packet


class CertificateAuthorityServer:
    """Tiny JSON-over-TCP CA service."""

    def __init__(
        self,
        host: str = DEFAULT_CA_HOST,
        port: int = DEFAULT_CA_PORT,
        key_bits: int = 128,
    ) -> None:
        self.host = host
        self.port = port
        self.ca = SimulationCA(key_bits=key_bits)
        self._sock: socket.socket | None = None
        self._running = threading.Event()

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="ca-service", daemon=True)
        thread.start()
        return thread

    def serve_forever(self) -> None:
        self._running.set()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen()
            self._sock = server
            print(f"[CA terminal] {self.ca.name} listening on {self.host}:{self.port}")
            while self._running.is_set():
                try:
                    client, address = server.accept()
                except OSError:
                    break
                threading.Thread(
                    target=self._handle_client,
                    args=(client, address),
                    daemon=True,
                ).start()

    def stop(self) -> None:
        self._running.clear()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    def _handle_client(self, client: socket.socket, address) -> None:
        with client:
            file = client.makefile("r", encoding="utf-8")
            request = recv_packet(file)
            if request is None:
                return
            response = self._dispatch(request)
            send_packet(client, response)

    def _dispatch(self, request: dict[str, Any]) -> dict[str, Any]:
        request_type = request.get("type")
        if request_type == "issue":
            cert = self.ca.issue_certificate(
                username=request["username"],
                public_key=request["public_key"],
            )
            print(f"[CA terminal] issued certificate for {cert.username} serial={cert.serial}")
            return {
                "ok": True,
                "certificate": cert.to_dict(),
                "ca_public_key": self.ca.public_key,
            }

        if request_type == "validate":
            valid, reason = self.ca.validate_certificate(request["certificate"])
            username = request["certificate"].get("username", "unknown")
            print(f"[CA terminal] validated {username}: {reason}")
            return {
                "ok": True,
                "valid": valid,
                "reason": reason,
                "ca_public_key": self.ca.public_key,
            }

        if request_type == "revoke":
            serial = int(request["serial"])
            self.ca.revoke(serial)
            print(f"[CA terminal] revoked serial={serial}")
            return {"ok": True, "revoked": serial}

        return {"ok": False, "error": f"Unknown CA request type: {request_type}"}


class CertificateAuthorityClient:
    """Convenience client used by Alice and Bob."""

    def __init__(self, host: str = DEFAULT_CA_HOST, port: int = DEFAULT_CA_PORT) -> None:
        self.host = host
        self.port = port

    def issue(self, username: str, public_key: dict[str, Any]) -> dict[str, Any]:
        response = self._request(
            {
                "type": "issue",
                "username": username,
                "public_key": public_key,
            }
        )
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "CA issue failed"))
        return response

    def validate(self, certificate: dict[str, Any]) -> tuple[bool, str]:
        response = self._request({"type": "validate", "certificate": certificate})
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "CA validation failed"))
        return bool(response["valid"]), str(response["reason"])

    def _request(self, payload: dict[str, Any]) -> dict[str, Any]:
        with socket.create_connection((self.host, self.port), timeout=10) as sock:
            send_packet(sock, payload)
            file = sock.makefile("r", encoding="utf-8")
            response = recv_packet(file)
            if response is None:
                raise RuntimeError("CA closed connection without a response")
            return response
