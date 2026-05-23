"""Runnable multi-party secure messaging simulation."""

from __future__ import annotations

import argparse
import time

from simulation.actors import SecurePeerNode
from simulation.ca_service import CertificateAuthorityServer
from simulation.protocol import (
    DEFAULT_CA_HOST,
    DEFAULT_CA_PORT,
    DEFAULT_RELAY_HOST,
    DEFAULT_RELAY_PORT,
)
from simulation.relay import MessagingRelayServer


def run_full_simulation(
    ca_host: str = DEFAULT_CA_HOST,
    ca_port: int = DEFAULT_CA_PORT,
    relay_host: str = DEFAULT_RELAY_HOST,
    relay_port: int = DEFAULT_RELAY_PORT,
    key_bits: int = 128,
) -> None:
    """Start CA, relay, Bob, and Alice locally in threads and run the demo."""
    print("\n" + "=" * 72)
    print("  MULTI-PARTY TLS-STYLE HYBRID CRYPTOGRAPHIC SIMULATION")
    print("=" * 72)

    ca_server = CertificateAuthorityServer(ca_host, ca_port, key_bits=key_bits)
    relay = MessagingRelayServer(relay_host, relay_port, clear_logs=True)
    ca_server.start_background()
    relay.start_background()
    time.sleep(0.25)

    bob = None
    alice = None
    try:
        print("\n[orchestrator] launching Bob terminal")
        bob = SecurePeerNode(
            "Bob",
            ca_host=ca_host,
            ca_port=ca_port,
            relay_host=relay_host,
            relay_port=relay_port,
            key_bits=key_bits,
            auto_respond=True,
        )
        bob.connect()

        print("\n[orchestrator] launching Alice terminal")
        alice = SecurePeerNode(
            "Alice",
            ca_host=ca_host,
            ca_port=ca_port,
            relay_host=relay_host,
            relay_port=relay_port,
            key_bits=key_bits,
            auto_respond=False,
        )
        alice.connect()

        print("\n--- STEP 1/2: Certificate issuing + TLS-style hybrid handshake ---")
        handshake = alice.initiate_handshake("Bob")

        print("\n--- STEP 3: Secure RC4 messaging ---")
        first_packet = alice.send_secure_message(
            "Bob",
            "Hello Bob, this is protected by a hybrid Paillier + Kyber-Edu session key.",
        )
        received = bob.wait_for("secure_message", sender="Alice")
        print(f"[orchestrator] Bob recovered plaintext: {received['plaintext']}")

        print("\n--- Bonus: replay attack detection ---")
        print("[orchestrator] replaying Alice's previous packet with the same nonce")
        alice.route("Bob", first_packet)
        time.sleep(0.3)

        print("\n--- Bonus: session key rotation ---")
        alice.rotate_session_key("Bob")
        time.sleep(0.3)
        alice.send_secure_message("Bob", "Second message after session key rotation.")
        received_after_rotation = bob.wait_for("secure_message", sender="Alice")
        print(f"[orchestrator] Bob recovered after rotation: {received_after_rotation['plaintext']}")

        print("\n--- STEP 4: Blowfish encrypted relay storage ---")
        decrypted_logs = relay.log.decrypt_all()
        for index, record in enumerate(decrypted_logs, 1):
            print(
                f"  log {index}: {record['from']} -> {record['to']} "
                f"{record['payload_type']} wire={record['wire_size']}B"
            )

        print("\n--- STEP 5: Performance and packet metrics ---")
        print(f"  Alice key generation: {alice.metrics.key_generation_ms:.3f} ms")
        print(f"  Bob key generation:   {bob.metrics.key_generation_ms:.3f} ms")
        print(f"  Handshake time:       {alice.metrics.handshake_ms:.3f} ms")
        print(f"  Alice encryption:     {alice.metrics.encryption_ms:.3f} ms")
        print(f"  Bob decryption:       {bob.metrics.decryption_ms:.3f} ms")
        print(f"  Ciphertext sizes:     {alice.metrics.ciphertext_sizes} bytes")
        print(f"  Last packet memory:   {alice.metrics.memory_bytes.get('last_packet', 0)} bytes")
        print(f"  PQ secret preview:    {handshake['pq_secret'][:8].hex()}...")
        print(f"  Final session key:    {handshake['session_key'].hex()}")

        print("\n[orchestrator] simulation complete")
    finally:
        if alice is not None:
            alice.close()
        if bob is not None:
            bob.close()
        relay.stop()
        ca_server.stop()


def run_ca_terminal(args: argparse.Namespace) -> None:
    server = CertificateAuthorityServer(args.host, args.port, key_bits=args.key_bits)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()


def run_server_terminal(args: argparse.Namespace) -> None:
    server = MessagingRelayServer(
        args.host,
        args.port,
        log_path=args.log_path,
        key_path=args.key_path,
        clear_logs=args.clear_logs,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.stop()


def run_bob_terminal(args: argparse.Namespace) -> None:
    bob = SecurePeerNode(
        "Bob",
        ca_host=args.ca_host,
        ca_port=args.ca_port,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
        key_bits=args.key_bits,
        auto_respond=True,
    )
    bob.connect()
    print("[Bob terminal] waiting for Alice. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        bob.close()


def run_alice_terminal(args: argparse.Namespace) -> None:
    alice = SecurePeerNode(
        "Alice",
        ca_host=args.ca_host,
        ca_port=args.ca_port,
        relay_host=args.relay_host,
        relay_port=args.relay_port,
        key_bits=args.key_bits,
        auto_respond=False,
    )
    alice.connect()
    try:
        alice.initiate_handshake("Bob")
        message = args.message or input("Message for Bob: ").strip()
        alice.send_secure_message("Bob", message)
        time.sleep(0.5)
    finally:
        alice.close()


def decrypt_relay_logs(args: argparse.Namespace) -> None:
    relay = MessagingRelayServer(
        host=args.relay_host,
        port=args.relay_port,
        log_path=args.log_path,
        key_path=args.key_path,
    )
    logs = relay.log.decrypt_all()
    print(f"Decrypted relay log entries: {len(logs)}")
    for index, record in enumerate(logs, 1):
        print(
            f"{index}. {record['from']} -> {record['to']} "
            f"{record['payload_type']} payload_keys={list(record['payload'].keys())}"
        )
