# Secure P2P Messenger — Cryptography Coursework

## Overview

A fully implemented end-to-end encrypted peer-to-peer messaging system
simulating a realistic multi-party business scenario with a Certificate Authority.

**AI Usage Declaration**: Claude AI was used for code structure suggestions
and debugging assistance. All algorithm logic, mathematical formulations,
and implementation decisions were reviewed and understood by the team.

---

## Algorithms Implemented (all from scratch — no crypto libraries)

| Layer       | Algorithm  | Role                                          |
|-------------|------------|-----------------------------------------------|
| Symmetric 1 | **Blowfish** | 64-bit block cipher — encrypts stored logs (at rest) |
| Symmetric 2 | **RC4**      | Stream cipher — encrypts messages in transit  |
| Asymmetric  | **Paillier** | Probabilistic PKC — session key exchange + CA signing |
| Post-Quantum | **Kyber-Edu** | Module-LWE KEM — hybrid post-quantum session-key contribution |

---

## Project Structure

```
secure_messenger/
├── main.py                   ← Entry point (demo + benchmarks + frontend + simulation)
├── web_app.py                ← Browser frontend server (stdlib only)
├── frontend/                 ← HTML/CSS/JS transfer visualizer
├── crypto/
│   ├── blowfish.py           ← Blowfish cipher (from scratch)
│   ├── rc4.py                ← RC4 stream cipher (from scratch)
│   ├── paillier.py           ← Paillier cryptosystem (from scratch)
│   └── kyber.py              ← Educational Kyber-style PQ KEM
├── core/
│   ├── ca.py                 ← Certificate Authority simulation
│   ├── peer.py               ← Peer node (Alice / Bob)
│   └── performance.py        ← Benchmarking module
└── simulation/
    ├── protocol.py           ← JSON socket packets, nonces, toy KDF/MAC
    ├── certificates.py       ← CA-issued simulation certificates
    ├── ca_service.py         ← localhost CA terminal/service
    ├── relay.py              ← messaging relay + Blowfish-at-rest logs
    ├── actors.py             ← Alice/Bob socket actors
    └── demo.py               ← threaded orchestration + terminal commands
```

---

## How to Run

**Requirements**: Python 3.11+ (no external packages needed)

```bash
# Full demo (6-phase walkthrough)
python main.py

# Benchmarks only
python main.py bench

# Browser frontend (shows the full message-transfer process)
python main.py web

# Optional: choose host/port or avoid opening the browser automatically
python main.py web --port 8000 --no-browser

# Full localhost multi-party simulation in one process
python main.py simulate

# Or run the simulated parties in separate terminals
python main.py ca-terminal
python main.py server-terminal --clear-logs
python main.py bob-terminal
python main.py alice-terminal --message "Hello Bob from Alice"

# Decrypt relay logs stored with Blowfish at rest
python main.py decrypt-logs
```

---

## System Architecture

```
┌─────────┐    Paillier-encrypted     ┌─────────┐
│  Alice  │◄─── session key ─────────►│   Bob   │
│         │                           │         │
│ RC4 enc │──── encrypted msg ───────►│ RC4 dec │
│         │◄─── encrypted msg ────────│         │
│         │                           │         │
│ Blowfish│  stored log (at rest)     │ Blowfish│
└─────────┘                           └─────────┘
     │                                     │
     └──────────── TrustNet CA ────────────┘
                  (Paillier PKI)
```

## Multi-Party TLS-Style Simulation

The simulation layer runs four realistic actors on one machine:

| Actor | Role |
|-------|------|
| CA terminal | Issues and validates certificates over localhost TCP |
| Server terminal | Relays packets and stores every packet encrypted at rest |
| Bob terminal | Acts like the server-side TLS peer and message receiver |
| Alice terminal | Acts like the client-side TLS peer and message sender |

### Console Demo Workflow

```bash
python main.py simulate
```

This starts CA, relay server, Bob, and Alice in threads and performs:

1. CA creates a Paillier root key pair.
2. Alice and Bob generate Paillier + Kyber-Edu identities.
3. CA issues certificates containing username, public key material, signature, and timestamp.
4. Alice sends `Client Hello` with a nonce.
5. Bob replies with `Server Hello`, nonce, and certificate.
6. Alice validates Bob's certificate through the CA service.
7. Alice sends Paillier-encrypted classical key material and Kyber-Edu ciphertext.
8. Bob decrypts/decapsulates both components.
9. Both derive the final symmetric session key from both components and both nonces.
10. Alice sends RC4-encrypted packets with integrity tags.
11. Relay stores all packets as Blowfish ciphertext on disk.
12. Replay attack detection rejects repeated message nonces.
13. Session key rotation derives a fresh key and continues messaging.

### Separate Terminal Workflow

Open four terminals from the project directory:

```bash
# Terminal 1
python main.py ca-terminal

# Terminal 2
python main.py server-terminal --clear-logs

# Terminal 3
python main.py bob-terminal

# Terminal 4
python main.py alice-terminal --message "Hello Bob from Alice"
```

Then inspect encrypted-at-rest server logs:

```bash
python main.py decrypt-logs
```

### Sequence Diagram

```text
CA                Relay Server              Alice                    Bob
|                      |                       |                       |
|<-- issue Alice cert ------------------------ |                       |
|-- signed cert -----------------------------> |                       |
|<------------------------------------------------ issue Bob cert -----|
|------------------------------------------------ signed cert -------->|
|                      |<-- register Alice ----|                       |
|                      |<-------------------------------- register Bob -|
|                      |<-- Client Hello ------|                       |
|                      |----------------------- Client Hello --------->|
|                      |<-------------------------------- Server Hello -|
|                      |------ Server Hello + Bob certificate -------->|
|<---------------- validate Bob certificate ---|                       |
|---------------- validation result ---------> |                       |
|                      |<-- Paillier + Kyber-Edu key exchange --------|
|                      |----------------------- key exchange -------->|
|                      |<---------------------------- Finished MAC ----|
|                      |------ Finished MAC ------------------------->|
|                      |<-- RC4 ciphertext ----|                       |
|                      |-- Blowfish log write  |                       |
|                      |----------------------- RC4 ciphertext ------>|
|                      |                       |                 decrypt|
```

### Example Output

```text
[Alice terminal] -> Bob: Client Hello nonce=...
[Bob terminal] -> Alice: Server Hello + certificate
[Alice terminal] validated Bob certificate: Certificate valid
[Alice terminal] hybrid key ready session=... pq_ct=1862B
[Bob terminal] hybrid key established with Alice session=...
[Alice terminal] Plaintext : Hello Bob, this is protected by a hybrid Paillier + Kyber-Edu session key.
[Alice terminal] Ciphertext: 639e0082...
[Bob terminal] Decrypted message from Alice: Hello Bob, this is protected by a hybrid Paillier + Kyber-Edu session key.
[Bob terminal] REPLAY DETECTED nonce=...
[Alice terminal] rotating session key with Bob: ...
[Bob terminal] accepted key rotation from Alice: ...
```

### TLS-Style Hybrid Encryption Explanation

In a real TLS-style handshake, peers first agree on identity, nonces, algorithms, and key material. This simulation mirrors that shape:

- **Identity**: Bob sends a CA-issued certificate, and Alice validates it before trusting Bob's public keys.
- **Freshness**: Alice and Bob each contribute a nonce, preventing old handshakes from being reused directly.
- **Classical key exchange**: Paillier encrypts a random classical session component to Bob.
- **Post-quantum KEM**: Kyber-Edu encapsulates a lattice-based shared secret to Bob.
- **Hybrid key derivation**: Both components plus both nonces are mixed into the final RC4/Blowfish session key.
- **Finished MACs**: Alice and Bob verify transcript integrity before application data is sent.
- **Secure messaging**: RC4 encrypts in-transit plaintext, and a toy MAC detects tampering.
- **At-rest protection**: The relay stores packets only as Blowfish ciphertext on disk.
- **Replay defense**: Bob rejects repeated message nonces.
- **Key rotation**: Alice can rotate the session key and Bob derives the same replacement key.

The KDF/MAC are educational toy constructions because the coursework constraint forbids cryptographic libraries.

### Flow Phases
1. **CA Initialization** — CA generates its own Paillier root key pair
2. **Peer Registration** — Alice & Bob generate keys, CA issues certificates
3. **Key Exchange** — Alice encrypts a 16-byte session key with Bob's Paillier public key
4. **Post-Quantum KEM** — Alice encapsulates a Kyber-Edu shared secret to Bob
5. **Hybridization** — Paillier key material is XORed with the Kyber-Edu secret
6. **In-Transit (RC4)** — All messages encrypted with RC4 + fresh IV per message
7. **At-Rest (Blowfish)** — Received messages stored as Blowfish ciphertext on disk
8. **Revocation** — CA can revoke certificates; validation fails immediately

---

## Algorithm Details

### Blowfish
- 64-bit block size, 16-round Feistel network
- Variable key: 32–448 bits (we use 128 bits)
- F-function uses 4 S-boxes (256 entries each)
- PKCS#7 padding for non-block-aligned data
- Ciphertext overhead: +8 bytes per message (one extra block worst case)

### RC4
- Variable key stream cipher (Key Scheduling Algorithm + PRGA)
- Fresh 8-byte IV per message (IV prepended to derive unique stream)
- Zero ciphertext expansion (1:1 plaintext-to-ciphertext ratio)
- Symmetric: encrypt == decrypt

### Paillier
- Probabilistic, additively homomorphic public-key cryptosystem
- Miller-Rabin primality test (10 rounds) for prime generation
- Simplified form: g = n+1, lambda = lcm(p-1, q-1)
- Used for: encrypting session key bytes + CA certificate signing
- Key sizes: 512-bit (256-bit primes) for peers; 512-bit for CA

### Kyber-Edu
- Educational Kyber-style Module-LWE key encapsulation mechanism
- Ring: `Z_q[x] / (x^n + 1)` with demo parameters `n=128`, `q=3329`, `k=2`
- Public key: matrix `A` and vector `t = A*s + e`
- Ciphertext: `u = A^T*r + e1`, `v = t^T*r + e2 + encode(m)`
- Used as a post-quantum contribution to the final hybrid session key
- Not production ML-KEM; it is a readable coursework implementation

---

## Performance Summary (from benchmarks)

| Algorithm | 1KB enc (ms) | 100KB enc (ms) | CT overhead |
|-----------|-------------|----------------|-------------|
| Blowfish  | 6.4         | 160            | +8 bytes    |
| RC4       | 0.3         | 22             | 0 bytes     |
| Paillier  | 5.4 (16B)   | N/A (key only) | ~1.5 KB     |
| Kyber-Edu | KEM only    | N/A (key only) | 768B CT     |

RC4 is ~7× faster than Blowfish for bulk data.
Paillier and Kyber-Edu are used only once per session (hybrid key exchange), so their cost is amortized.

---

## Roles in the System

| Entity | Role |
|--------|------|
| Alice  | Peer — initiates session, generates session key |
| Bob    | Peer — receives and decrypts session key, responds |
| TrustNet CA | Issues & validates X.509-style certificates using Paillier |

---

## Academic Notes

- No encryption libraries used (OpenSSL, PyCryptodome, etc. are absent)
- Only Python built-ins: `os`, `time`, `struct`, `math`, `random`, `sys`
- `pow(base, exp, mod)` is Python's built-in modular exponentiation (not a crypto library)
- Blowfish and RC4 were not covered in lectures — chosen per coursework requirement
- Paillier was not covered in lectures — chosen per coursework requirement
- Kyber-Edu is an educational Kyber-style implementation, not standardized production ML-KEM
