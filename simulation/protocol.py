"""
Protocol helpers for the localhost multi-party simulation.

The project intentionally avoids cryptographic libraries. The helpers below
therefore provide educational framing utilities only: JSON-over-socket packets,
nonces, a toy KDF, and a toy MAC. They make the workflow look like a TLS-style
protocol without claiming production cryptographic strength.
"""

from __future__ import annotations
import json
import os
import socket
import time
from typing import Any


DEFAULT_CA_HOST = "127.0.0.1"
DEFAULT_CA_PORT = 9100
DEFAULT_RELAY_HOST = "127.0.0.1"
DEFAULT_RELAY_PORT = 9200


def now_ms() -> int:
    return int(time.time() * 1000)


def make_nonce(size: int = 16) -> str:
    return os.urandom(size).hex()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def encode_packet(data: dict[str, Any]) -> bytes:
    return (canonical_json(data) + "\n").encode("utf-8")


def send_packet(sock: socket.socket, data: dict[str, Any]) -> None:
    sock.sendall(encode_packet(data))


def recv_packet(sock_file) -> dict[str, Any] | None:
    line = sock_file.readline()
    if not line:
        return None
    if isinstance(line, bytes):
        line = line.decode("utf-8")
    return json.loads(line)


def toy_hash(data: bytes, out_len: int = 32) -> bytes:
    """
    Deterministic educational hash/KDF.

    This is not a production hash. It exists to keep the coursework constraint:
    no cryptographic libraries, only Python standard library modules.
    """
    state = [
        0x6A09E667,
        0xBB67AE85,
        0x3C6EF372,
        0xA54FF53A,
        0x510E527F,
        0x9B05688C,
        0x1F83D9AB,
        0x5BE0CD19,
    ]
    for index, byte in enumerate(data):
        slot = index % len(state)
        state[slot] ^= byte + index + 0x9E3779B9
        state[slot] = ((state[slot] << 9) | (state[slot] >> 23)) & 0xFFFFFFFF
        state[slot] = (state[slot] * 0x85EBCA6B + state[(slot - 1) % 8]) & 0xFFFFFFFF

    output = bytearray()
    counter = 0
    while len(output) < out_len:
        for i, value in enumerate(state):
            mixed = (value ^ counter ^ (i * 0xC2B2AE35)) & 0xFFFFFFFF
            mixed = ((mixed << 13) | (mixed >> 19)) & 0xFFFFFFFF
            state[i] = (mixed * 0x27D4EB2D + 0x165667B1) & 0xFFFFFFFF
            output.extend(state[i].to_bytes(4, "little"))
        counter += 1
    return bytes(output[:out_len])


# def derive_session_key(
#     classical_component: bytes,
#     post_quantum_component: bytes,
#     client_nonce: str,
#     server_nonce: str,
#     length: int = 16,
# ) -> bytes:
#     transcript = (
#         b"TLS-STYLE-HYBRID-SESSION"
#         + classical_component
#         + post_quantum_component
#         + bytes.fromhex(client_nonce)
#         + bytes.fromhex(server_nonce)
#     )
#     return toy_hash(transcript, out_len=length)

def derive_session_key(
    classical_secret: bytes,
    pq_secret: bytes,
    client_nonce: str,
    server_nonce: str,
) -> bytes:

    # Hybrid combine
    hybrid = bytes(
        a ^ b
        for a, b in zip(classical_secret[:16], pq_secret[:16])
    )

    # Add transcript binding
    context = (
        hybrid
        + bytes.fromhex(client_nonce)
        + bytes.fromhex(server_nonce)
    )

    # KDF using the toy hash function
    derived = toy_hash(context, out_len=32)

    # Return 16-byte RC4/Blowfish session key
    return derived[:16]


def packet_mac(key: bytes, purpose: str, data: dict[str, Any]) -> str:
    mac_input = b"|".join(
        [
            b"SIM-MAC",
            key,
            purpose.encode("utf-8"),
            canonical_json(data).encode("utf-8"),
        ]
    )
    return toy_hash(mac_input, out_len=16).hex()


def short_hex(value: str | bytes, size: int = 32) -> str:
    text = value.hex() if isinstance(value, bytes) else str(value)
    return text if len(text) <= size else f"{text[:size]}..."


def estimate_size(value: Any) -> int:
    return len(canonical_json(value).encode("utf-8"))


class ReplayWindow:
    """Tracks seen nonces to reject replayed packets."""

    def __init__(self) -> None:
        self._seen: set[str] = set()

    def accept(self, nonce: str) -> bool:
        if nonce in self._seen:
            return False
        self._seen.add(nonce)
        return True
