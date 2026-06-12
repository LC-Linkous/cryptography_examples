#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/merkle_damgard/hash_test.py'
#   Tests for the teaching Merkle-Damgard hash: determinism, avalanche,
#   and the structural properties (it is NOT checked against a standard,
#   because it is a teaching construction, not a standard hash).
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from hash import hashfn

print("=== Merkle-Damgard Teaching Hash Test ===\n")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))
h.show_hash_state()
print(f"\nStatistics:")
for k, v in h.get_cipher_stats().items():
    print(f"  {k}: {v}")

print(f"\n=== DETERMINISM (same input -> same digest) ===")
for v in ["", "hello", "hello world", "a" * 50]:
    d1 = h.hash_message(v); d2 = h.hash_message(v)
    print(f"  {v[:20]!r:22} -> {d1}  (stable: {d1 == d2})")

print(f"\n=== STEP-BY-STEP (watch the chaining) ===")
hs = hashfn(None, pd.DataFrame({'SHOW_STEPS': [True]}))
hs.hash_message("CHAIN")

print(f"\n=== AVALANCHE (single-bit input change) ===")
import random
base = "the quick brown fox jumps over the lazy dog"
d0 = h.hash_message(base)
total = 0; trials = 0
for i in range(len(base)):
    flipped = base[:i] + chr(ord(base[i]) ^ 1) + base[i+1:]
    d1 = h.hash_message(flipped)
    bits = bin(int(d0, 16) ^ int(d1, 16)).count('1')
    total += bits; trials += 1
print(f"  avg bits changed per single-bit flip: {total/trials:.1f}/32 "
      f"({100*total/trials/32:.0f}%)  (ideal ~50%)")
