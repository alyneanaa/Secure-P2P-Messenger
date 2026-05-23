"""
SECURE P2P MESSENGER — Main Demo
=====================================
Scenario: Alice and Bob exchange encrypted messages
          through a Certificate Authority (TrustNet CA).

Encryption layers:
  1. Paillier    — asymmetric key exchange (Bob's session key → Alice)
  2. Kyber-Edu   — post-quantum KEM contribution (hybrid key exchange)
  3. RC4         — symmetric stream cipher for in-transit messages
  4. Blowfish    — symmetric block cipher for at-rest message logs

Run:
    python main.py          # full demo
    python main.py bench    # performance benchmarks only
    python main.py web      # browser frontend
    python main.py simulate # multi-party localhost simulation
"""

import sys
import os
import time
import argparse

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# Make sure imports work from project root
sys.path.insert(0, os.path.dirname(__file__))

from core.ca          import CertificateAuthority
from core.peer        import Peer
from core.performance import run_all_benchmarks
from crypto.kyber     import ciphertext_size_bytes


def _add_common_sim_args(parser):
    parser.add_argument("--ca-host", default="127.0.0.1")
    parser.add_argument("--ca-port", type=int, default=9100)
    parser.add_argument("--relay-host", default="127.0.0.1")
    parser.add_argument("--relay-port", type=int, default=9200)
    parser.add_argument("--key-bits", type=int, default=128)


def run_simulation_command(command: str, argv: list[str]) -> None:
    from simulation.demo import (
        decrypt_relay_logs,
        run_alice_terminal,
        run_bob_terminal,
        run_ca_terminal,
        run_full_simulation,
        run_server_terminal,
    )

    if command == "simulate":
        parser = argparse.ArgumentParser(description="Run full threaded localhost simulation.")
        _add_common_sim_args(parser)
        args = parser.parse_args(argv)
        run_full_simulation(
            ca_host=args.ca_host,
            ca_port=args.ca_port,
            relay_host=args.relay_host,
            relay_port=args.relay_port,
            key_bits=args.key_bits,
        )
        return

    if command == "ca-terminal":
        parser = argparse.ArgumentParser(description="Run the CA terminal/service.")
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=9100)
        parser.add_argument("--key-bits", type=int, default=128)
        run_ca_terminal(parser.parse_args(argv))
        return

    if command == "server-terminal":
        parser = argparse.ArgumentParser(description="Run the messaging relay terminal/service.")
        parser.add_argument("--host", default="127.0.0.1")
        parser.add_argument("--port", type=int, default=9200)
        parser.add_argument("--log-path", default="logs/relay_messages.enc.jsonl")
        parser.add_argument("--key-path", default="logs/relay_storage.key")
        parser.add_argument("--clear-logs", action="store_true")
        run_server_terminal(parser.parse_args(argv))
        return

    if command == "bob-terminal":
        parser = argparse.ArgumentParser(description="Run Bob as a terminal peer.")
        _add_common_sim_args(parser)
        run_bob_terminal(parser.parse_args(argv))
        return

    if command == "alice-terminal":
        parser = argparse.ArgumentParser(description="Run Alice as a terminal peer.")
        _add_common_sim_args(parser)
        parser.add_argument("--message", default="")
        run_alice_terminal(parser.parse_args(argv))
        return

    if command == "decrypt-logs":
        parser = argparse.ArgumentParser(description="Decrypt Blowfish-at-rest relay logs.")
        parser.add_argument("--relay-host", default="127.0.0.1")
        parser.add_argument("--relay-port", type=int, default=9200)
        parser.add_argument("--log-path", default="logs/relay_messages.enc.jsonl")
        parser.add_argument("--key-path", default="logs/relay_storage.key")
        decrypt_relay_logs(parser.parse_args(argv))
        return

    raise ValueError(f"Unknown simulation command: {command}")


# =====================================================================
# BANNER
# =====================================================================

def banner():
    print("""
╔══════════════════════════════════════════════════════╗
║         SECURE P2P MESSENGER — COURSEWORK DEMO       ║
║                                                      ║
║  Symmetric :  Blowfish (at rest) + RC4 (in transit)  ║
║  Classical :  Paillier (key exchange + certs)        ║
║  Post-Q    :  Kyber-Edu Module-LWE KEM               ║
╚══════════════════════════════════════════════════════╝
""")


# =====================================================================
# DEMO: FULL SECURE MESSAGING FLOW
# =====================================================================

def run_demo():
    banner()

    # ------------------------------------------------------------------
    # PHASE 1: Certificate Authority Setup
    # ------------------------------------------------------------------
    print("━"*54)
    print("  PHASE 1 — Certificate Authority Initialization")
    print("━"*54)
    ca = CertificateAuthority(name="TrustNet CA", key_bits=256)

    # ------------------------------------------------------------------
    # PHASE 2: Peer Registration
    # ------------------------------------------------------------------
    print("\n" + "━"*54)
    print("  PHASE 2 — Peer Key Generation & Registration")
    print("━"*54)

    alice = Peer("Alice", key_bits=256)
    bob   = Peer("Bob",   key_bits=256)

    alice.register_with_ca(ca)
    bob.register_with_ca(ca)

    # Validate certificates
    print()
    for peer in [alice, bob]:
        valid, reason = ca.validate_certificate(peer.certificate)
        status = "✓ VALID" if valid else f"✗ {reason}"
        print(f"  [{ca.name}] {peer.name}'s cert → {status}")

    # ------------------------------------------------------------------
    # PHASE 3: Paillier Session Key Exchange
    # ------------------------------------------------------------------
    print("\n" + "━"*54)
    print("  PHASE 3 — Paillier Session Key Exchange")
    print("━"*54)

    # Alice generates session key, encrypts it with Bob's public key
    session_key = alice.generate_session_key()
    print(f"[Alice] Session key (hex): {session_key.hex()}")

    encrypted_sk = alice.export_encrypted_session_key(bob.public_key)
    print(f"[Alice→Bob] Sending {len(encrypted_sk)} Paillier ciphertexts over channel")

    # Bob decrypts the session key
    bob.import_encrypted_session_key(encrypted_sk)
    bob_key = bob.session_key
    print(f"[Bob] Recovered session key (hex): {bob_key.hex()}")

    # Verify both have same key
    match = "✓ MATCH" if session_key == bob_key else "✗ MISMATCH"
    print(f"\n  Session key agreement: {match}")

    # ------------------------------------------------------------------
    # PHASE 3B: Post-Quantum Kyber-Style KEM Contribution
    # ------------------------------------------------------------------
    print("\n" + "━"*54)
    print("  PHASE 3B — Post-Quantum Kyber-Edu KEM")
    print("━"*54)

    # Bob owns the post-quantum KEM key pair. Alice encapsulates a fresh
    # shared secret to Bob; Bob decapsulates it with his private KEM key.
    bob.generate_post_quantum_keys()
    pq_ciphertext, alice_pq_secret = alice.encapsulate_post_quantum_secret(bob.pq_public_key)
    bob_pq_secret = bob.decapsulate_post_quantum_secret(pq_ciphertext)

    pq_match = "✓ MATCH" if alice_pq_secret == bob_pq_secret else "✗ MISMATCH"
    print(f"[Alice→Bob] Kyber-Edu ciphertext payload: {ciphertext_size_bytes(pq_ciphertext)} bytes")
    print(f"[Alice] PQ shared secret (hex): {alice_pq_secret[:16].hex()}...")
    print(f"[Bob]   PQ shared secret (hex): {bob_pq_secret[:16].hex()}...")
    print(f"\n  Post-quantum secret agreement: {pq_match}")

    # Hybridize: classical Paillier session key XOR post-quantum KEM secret.
    hybrid_key = bytes(a ^ b for a, b in zip(session_key, alice_pq_secret[:16]))
    alice.session_key = hybrid_key
    bob.session_key = hybrid_key
    print(f"  Hybrid RC4/Blowfish session key: {hybrid_key.hex()}")

    # ------------------------------------------------------------------
    # PHASE 4: RC4 Encrypted Messaging (in transit)
    # ------------------------------------------------------------------
    print("\n" + "━"*54)
    print("  PHASE 4 — RC4 Encrypted Messaging (in transit)")
    print("━"*54)

    messages_alice_to_bob = [
        "Hello Bob! This channel is end-to-end encrypted.",
        "Transaction ID: TXN-8842. Amount: $5,000. Approve?",
        "Meeting confirmed for Friday at 14:00 UTC."
    ]

    messages_bob_to_alice = [
        "Hi Alice! Confirmed — connection is secure.",
        "TXN-8842 approved. Forwarding to settlement system.",
        "Friday 14:00 UTC works. See you then."
    ]

    print()
    for i, msg in enumerate(messages_alice_to_bob):
        print(f"  [Alice→Bob #{i+1}]")
        print(f"   Plaintext : {msg}")
        packet = alice.send_message(msg, "Bob")
        print(f"   IV        : {packet['iv']}")
        print(f"   Ciphertext: {packet['ciphertext'][:48]}...")
        received = bob.receive_message(packet, ca=ca)
        print()

    print()
    for i, msg in enumerate(messages_bob_to_alice):
        print(f"  [Bob→Alice #{i+1}]")
        print(f"   Plaintext : {msg}")
        packet = bob.send_message(msg, "Alice")
        print(f"   IV        : {packet['iv']}")
        print(f"   Ciphertext: {packet['ciphertext'][:48]}...")
        received = alice.receive_message(packet, ca=ca)
        print()

    # ------------------------------------------------------------------
    # PHASE 5: Blowfish At-Rest Log Verification
    # ------------------------------------------------------------------
    print("━"*54)
    print("  PHASE 5 — Blowfish At-Rest Message Log")
    print("━"*54)

    print("\n  [Bob's stored log — Blowfish decrypted]")
    for i, entry in enumerate(bob.read_stored_log(), 1):
        print(f"   {i}. {entry}")

    print("\n  [Alice's stored log — Blowfish decrypted]")
    for i, entry in enumerate(alice.read_stored_log(), 1):
        print(f"   {i}. {entry}")

    # ------------------------------------------------------------------
    # PHASE 6: Certificate Revocation
    # ------------------------------------------------------------------
    print("\n" + "━"*54)
    print("  PHASE 6 — Certificate Revocation Demo")
    print("━"*54)

    ca.revoke_certificate(alice.certificate.serial)
    valid, reason = ca.validate_certificate(alice.certificate)
    print(f"  Alice's cert after revocation: {'✓' if valid else '✗'} {reason}")

    print("\n" + "═"*54)
    print("  DEMO COMPLETE — All phases executed successfully")
    print("═"*54)


# =====================================================================
# ENTRYPOINT
# =====================================================================

if __name__ == "__main__":
    command = sys.argv[1].lower() if len(sys.argv) > 1 else "demo"

    if command == "bench":
        run_all_benchmarks()
    elif command in {"web", "frontend", "ui"}:
        from web_app import main as run_web_frontend

        run_web_frontend(sys.argv[2:])
    elif command in {
        "simulate",
        "ca-terminal",
        "server-terminal",
        "bob-terminal",
        "alice-terminal",
        "decrypt-logs",
    }:
        run_simulation_command(command, sys.argv[2:])
    else:
        run_demo()
        print()
        run_all = input("Run performance benchmarks? (y/n): ").strip().lower()
        if run_all == 'y':
            run_all_benchmarks()
