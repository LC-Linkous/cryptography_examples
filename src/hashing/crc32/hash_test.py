#! /usr/bin/python3
##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/hashing/crc32/hash_test.py'
#   Verifies the from-scratch CRC32 against Python's zlib.crc32.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
import zlib
from hash import hashfn

print("=== CRC32 Test (verified against zlib) ===\n")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))
h.show_hash_state()
print(f"\nCRC32 Statistics:")
for k, v in h.get_cipher_stats().items():
    print(f"  {k}: {v}")

print(f"\n=== KNOWN-ANSWER TESTS (vs zlib) ===")
vectors = ["", "a", "abc", "123456789",
           "The quick brown fox jumps over the lazy dog"]
all_ok = True
for v in vectors:
    mine = h.hash_message(v)
    ref = f"{zlib.crc32(v.encode()) & 0xFFFFFFFF:08x}"
    ok = mine == ref
    all_ok = all_ok and ok
    print(f"  {'OK ' if ok else 'BAD'} CRC32({v[:30]!r:32}) = {mine}  (zlib {ref})")
# The canonical CRC-32 check value: '123456789' -> 0xCBF43926
print(f"\n  Canonical check '123456789' -> cbf43926: "
      f"{h.hash_message('123456789') == 'cbf43926'}")
print(f"ALL VECTORS MATCH zlib: {all_ok}")
