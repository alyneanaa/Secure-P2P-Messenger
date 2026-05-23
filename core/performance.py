"""
PERFORMANCE ANALYSIS MODULE
Measures computation time, memory usage, and ciphertext size
for all three algorithms: Blowfish, RC4, Paillier.
"""

import time
import sys
import os

from crypto.blowfish import Blowfish
from crypto.rc4      import RC4
from crypto.paillier import (
    generate_paillier_keys,
    paillier_encrypt,
    paillier_decrypt,
    encrypt_bytes,
    decrypt_bytes
)
from crypto.kyber import (
    generate_kyber_keys,
    kyber_encapsulate,
    kyber_decapsulate,
    ciphertext_size_bytes,
    public_key_size_bytes
)


# =====================================================================
# HELPERS
# =====================================================================

def _measure(fn):
    """Return (result, elapsed_seconds)."""
    start  = time.perf_counter()
    result = fn()
    end    = time.perf_counter()
    return result, end - start


def size_of(obj) -> int:
    """Approximate memory size in bytes."""
    return sys.getsizeof(obj)


# =====================================================================
# BLOWFISH BENCHMARK
# =====================================================================

def benchmark_blowfish(data_sizes_kb=(1, 10, 100)):
    print("\n" + "="*55)
    print("  BLOWFISH BENCHMARK (at-rest encryption)")
    print("="*55)
    print(f"{'Size (KB)':<12} {'Enc (ms)':<14} {'Dec (ms)':<14} {'CT/PT ratio':<12}")
    print("-"*55)

    key = os.urandom(16)
    bf  = Blowfish(key)
    results = []

    for kb in data_sizes_kb:
        data = os.urandom(kb * 1024)

        ct, enc_time = _measure(lambda d=data: bf.encrypt(d))
        pt, dec_time = _measure(lambda c=ct: bf.decrypt(c))

        ratio = len(ct) / len(data)
        print(f"{kb:<12} {enc_time*1000:<14.3f} {dec_time*1000:<14.3f} {ratio:<12.4f}")
        results.append({
            'size_kb': kb,
            'enc_ms': enc_time * 1000,
            'dec_ms': dec_time * 1000,
            'ratio': ratio
        })

    return results


# =====================================================================
# RC4 BENCHMARK
# =====================================================================

def benchmark_rc4(data_sizes_kb=(1, 10, 100)):
    print("\n" + "="*55)
    print("  RC4 BENCHMARK (in-transit encryption)")
    print("="*55)
    print(f"{'Size (KB)':<12} {'Enc (ms)':<14} {'Dec (ms)':<14} {'CT/PT ratio':<12}")
    print("-"*55)

    key = os.urandom(16)
    results = []

    for kb in data_sizes_kb:
        data = os.urandom(kb * 1024)

        rc4_enc = RC4(key)
        ct, enc_time = _measure(lambda d=data: RC4(key).encrypt(d))

        rt, dec_time = _measure(lambda c=ct: RC4(key).decrypt(c))

        ratio = len(ct) / len(data)
        print(f"{kb:<12} {enc_time*1000:<14.3f} {dec_time*1000:<14.3f} {ratio:<12.4f}")
        results.append({
            'size_kb': kb,
            'enc_ms': enc_time * 1000,
            'dec_ms': dec_time * 1000,
            'ratio': ratio
        })

    return results


# =====================================================================
# PAILLIER BENCHMARK
# =====================================================================

def benchmark_paillier(key_bits=(128, 256)):
    print("\n" + "="*65)
    print("  PAILLIER BENCHMARK (key exchange / asymmetric)")
    print("="*65)
    print(f"{'Key bits':<12} {'KeyGen (ms)':<16} {'Enc/byte (ms)':<16} {'Dec/byte (ms)':<16}")
    print("-"*65)

    results = []

    for bits in key_bits:
        # Key generation
        (pub, priv), kg_time = _measure(lambda b=bits: generate_paillier_keys(b))

        # Encrypt 16 bytes (session key size)
        test_data = os.urandom(16)
        ct_list, enc_time = _measure(lambda d=test_data: encrypt_bytes(d, pub))
        pt,      dec_time = _measure(lambda c=ct_list:   decrypt_bytes(c, priv))

        enc_per_byte = enc_time * 1000 / 16
        dec_per_byte = dec_time * 1000 / 16

        print(f"{bits*2:<12} {kg_time*1000:<16.1f} {enc_per_byte:<16.3f} {dec_per_byte:<16.3f}")
        results.append({
            'key_bits': bits * 2,
            'keygen_ms': kg_time * 1000,
            'enc_per_byte_ms': enc_per_byte,
            'dec_per_byte_ms': dec_per_byte
        })

    return results


# =====================================================================
# KYBER-STYLE POST-QUANTUM KEM BENCHMARK
# =====================================================================

def benchmark_kyber_edu(rounds: int = 5):
    print("\n" + "="*68)
    print("  KYBER-EDU BENCHMARK (post-quantum KEM / hybrid key exchange)")
    print("="*68)
    print(f"{'Round':<10} {'KeyGen (ms)':<16} {'Encaps (ms)':<16} {'Decaps (ms)':<16} {'CT bytes':<10}")
    print("-"*68)

    results = []
    for i in range(1, rounds + 1):
        (pub, priv), kg_time = _measure(lambda: generate_kyber_keys())
        (ct, ss1), enc_time = _measure(lambda p=pub: kyber_encapsulate(p))
        ss2, dec_time = _measure(lambda c=ct, sk=priv: kyber_decapsulate(c, sk))
        ct_size = ciphertext_size_bytes(ct)

        print(
            f"{i:<10} {kg_time*1000:<16.3f} {enc_time*1000:<16.3f} "
            f"{dec_time*1000:<16.3f} {ct_size:<10}"
        )
        results.append({
            'round': i,
            'keygen_ms': kg_time * 1000,
            'encaps_ms': enc_time * 1000,
            'decaps_ms': dec_time * 1000,
            'ciphertext_bytes': ct_size,
            'public_key_bytes': public_key_size_bytes(pub),
            'shared_secret_match': ss1 == ss2
        })

    return results


# =====================================================================
# CIPHERTEXT SIZE COMPARISON
# =====================================================================

def benchmark_ciphertext_size():
    print("\n" + "="*55)
    print("  CIPHERTEXT SIZE COMPARISON (1 KB plaintext)")
    print("="*55)

    key  = os.urandom(16)
    data = os.urandom(1024)

    bf_ct = Blowfish(key).encrypt(data)
    rc4_ct = RC4(key).encrypt(data)

    # Paillier: only 16 bytes (session key)
    pub, _ = generate_paillier_keys(128)
    paillier_ct = encrypt_bytes(bytes(16), pub)
    paillier_size = sum(sys.getsizeof(c) for c in paillier_ct)
    kyber_pub, _ = generate_kyber_keys()
    kyber_ct, _ = kyber_encapsulate(kyber_pub)

    print(f"  Plaintext:           {len(data):>8} bytes")
    print(f"  Blowfish ciphertext: {len(bf_ct):>8} bytes  (overhead: {len(bf_ct)-len(data):+d})")
    print(f"  RC4 ciphertext:      {len(rc4_ct):>8} bytes  (overhead: {len(rc4_ct)-len(data):+d})")
    print(f"  Paillier (16B key):  {paillier_size:>8} bytes  (one-time key exchange)")
    print(f"  Kyber-Edu KEM:       {ciphertext_size_bytes(kyber_ct):>8} bytes  (post-quantum key exchange)")


# =====================================================================
# FULL BENCHMARK SUITE
# =====================================================================

def run_all_benchmarks():
    print("\n" + "★"*55)
    print("  SECURE MESSENGER — PERFORMANCE ANALYSIS")
    print("★"*55)

    bf_results      = benchmark_blowfish()
    rc4_results     = benchmark_rc4()
    paillier_results = benchmark_paillier()
    kyber_results    = benchmark_kyber_edu()
    benchmark_ciphertext_size()

    print("\n" + "="*55)
    print("  SUMMARY")
    print("="*55)
    print("  • Blowfish:  block cipher, slight overhead per block")
    print("  • RC4:       stream cipher, minimal overhead (1:1 ratio)")
    print("  • Paillier:  asymmetric, expensive per byte — used only")
    print("               for key exchange (16 bytes total)")
    print("  • Kyber-Edu: post-quantum lattice KEM used as a hybrid")
    print("               contribution to the final session key.")
    print("  • Trade-off: Paillier provides classical key exchange;")
    print("               Kyber-Edu adds PQ resistance; RC4/Blowfish")
    print("               handle bulk data.")
    print("="*55)

    return {
        'blowfish': bf_results,
        'rc4': rc4_results,
        'paillier': paillier_results,
        'kyber_edu': kyber_results
    }
