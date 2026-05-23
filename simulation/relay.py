"""Messaging relay server with Blowfish-encrypted storage at rest."""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading
from typing import Any

from crypto.blowfish import Blowfish
from simulation.protocol import (
    DEFAULT_RELAY_HOST,
    DEFAULT_RELAY_PORT,
    canonical_json,
    estimate_size,
    now_ms,
    recv_packet,
    send_packet,
)


class EncryptedRelayLog:
    """Append-only Blowfish encrypted JSONL log."""

    def __init__(
        self,
        log_path: str | Path = "logs/relay_messages.enc.jsonl",
        key_path: str | Path = "logs/relay_storage.key",
    ) -> None:
        self.log_path = Path(log_path)
        self.key_path = Path(key_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        self.key = self._load_or_create_key()
        self._lock = threading.Lock()

    def append(self, record: dict[str, Any]) -> int:
        plaintext = canonical_json(record).encode("utf-8")
        ciphertext = Blowfish(self.key).encrypt(plaintext).hex()
        entry = {
            "stored_at": now_ms(),
            "algorithm": "Blowfish",
            "ciphertext": ciphertext,
            "plaintext_size": len(plaintext),
            "ciphertext_size": len(bytes.fromhex(ciphertext)),
        }
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as file:
                file.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry["ciphertext_size"]

    def decrypt_all(self) -> list[dict[str, Any]]:
        if not self.log_path.exists():
            return []
        messages = []
        bf = Blowfish(self.key)
        with self.log_path.open("r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                entry = json.loads(line)
                plaintext = bf.decrypt(bytes.fromhex(entry["ciphertext"]))
                messages.append(json.loads(plaintext.decode("utf-8")))
        return messages

    def clear(self) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text("", encoding="utf-8")

    def _load_or_create_key(self) -> bytes:
        if self.key_path.exists():
            return bytes.fromhex(self.key_path.read_text(encoding="utf-8").strip())
        key = os.urandom(16)
        self.key_path.write_text(key.hex(), encoding="utf-8")
        return key


class MessagingRelayServer:
    """Routes JSON packets between connected peers and stores encrypted logs."""

    def __init__(
        self,
        host: str = DEFAULT_RELAY_HOST,
        port: int = DEFAULT_RELAY_PORT,
        log_path: str | Path = "logs/relay_messages.enc.jsonl",
        key_path: str | Path = "logs/relay_storage.key",
        clear_logs: bool = False,
    ) -> None:
        self.host = host
        self.port = port
        self.log = EncryptedRelayLog(log_path=log_path, key_path=key_path)
        if clear_logs:
            self.log.clear()
        self._clients: dict[str, socket.socket] = {}
        self._queued: dict[str, list[dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._running = threading.Event()
        self._sock: socket.socket | None = None

    def start_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve_forever, name="relay-server", daemon=True)
        thread.start()
        return thread

    def serve_forever(self) -> None:
        self._running.set()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.host, self.port))
            server.listen()
            self._sock = server
            print(f"[Server terminal] relay listening on {self.host}:{self.port}")
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
        username = None
        try:
            file = client.makefile("r", encoding="utf-8")
            while self._running.is_set():
                packet = recv_packet(file)
                if packet is None:
                    break
                packet_type = packet.get("type")
                if packet_type == "register":
                    username = str(packet["username"])
                    self._register(username, client)
                    send_packet(client, {"type": "registered", "username": username})
                    print(f"[Server terminal] registered {username}")
                    self._flush_queue(username)
                elif packet_type == "route":
                    self._route(packet)
                else:
                    send_packet(client, {"type": "error", "error": f"Unknown packet: {packet_type}"})
        finally:
            if username is not None:
                with self._lock:
                    if self._clients.get(username) is client:
                        del self._clients[username]
            try:
                client.close()
            except OSError:
                pass

    def _register(self, username: str, client: socket.socket) -> None:
        with self._lock:
            self._clients[username] = client

    def _route(self, packet: dict[str, Any]) -> None:
        sender = str(packet["from"])
        recipient = str(packet["to"])
        payload = packet["payload"]
        record = {
            "from": sender,
            "to": recipient,
            "payload_type": payload.get("type"),
            "payload": payload,
            "wire_size": estimate_size(packet),
        }
        stored_size = self.log.append(record)
        delivery = {
            "type": "deliver",
            "from": sender,
            "to": recipient,
            "payload": payload,
            "relay": {
                "stored_at_rest": True,
                "storage_algorithm": "Blowfish",
                "stored_ciphertext_size": stored_size,
            },
        }
        print(
            f"[Server terminal] {sender} -> {recipient} "
            f"{payload.get('type')} stored={stored_size}B"
        )
        self._deliver_or_queue(recipient, delivery)

    def _deliver_or_queue(self, recipient: str, delivery: dict[str, Any]) -> None:
        with self._lock:
            client = self._clients.get(recipient)
            if client is None:
                self._queued.setdefault(recipient, []).append(delivery)
                return
        try:
            send_packet(client, delivery)
        except OSError:
            with self._lock:
                self._queued.setdefault(recipient, []).append(delivery)

    def _flush_queue(self, username: str) -> None:
        with self._lock:
            queued = self._queued.pop(username, [])
            client = self._clients.get(username)
        if client is None:
            return
        for packet in queued:
            try:
                send_packet(client, packet)
            except OSError:
                break
