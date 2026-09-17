#! /usr/bin/python3
##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/hashing/md5/hash_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Verifies the from-scratch MD5 against Python's hashlib.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
import hashlib
from hash import hashfn

print("=== MD5 Hash Test (verified against hashlib) ===\n")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))
h.show_hash_state()
print(f"\nMD5 Statistics:")
for k, v in h.get_cipher_stats().items():
    print(f"  {k}: {v}")

print(f"\n=== KNOWN-ANSWER TESTS (RFC 1321 + hashlib) ===")
vectors = ["", "a", "abc", "message digest",
           "The quick brown fox jumps over the lazy dog",
           "abcdefghijklmnopqrstuvwxyz", "x" * 1000]
all_ok = True
for v in vectors:
    mine = h.hash_message(v)
    ref = hashlib.md5(v.encode()).hexdigest()
    ok = mine == ref
    all_ok = all_ok and ok
    label = (v[:33] + '...') if len(v) > 36 else v
    print(f"  {'OK ' if ok else 'BAD'} MD5({label!r})")
    print(f"       mine={mine}  ref={ref}")
print(f"\nALL VECTORS MATCH hashlib: {all_ok}")

print(f"\n=== AVALANCHE (one bit in -> ~half the bits out) ===")
a = h.hash_message("The quick brown fox jumps over the lazy dog")
b = h.hash_message("The quick brown fox jumps over the lazy cog")  # dog->cog
diff = bin(int(a, 16) ^ int(b, 16)).count('1')
print(f"  'dog' vs 'cog': {diff}/128 bits differ ({100*diff/128:.0f}%)")
