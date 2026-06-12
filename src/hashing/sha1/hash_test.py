#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/sha1/hash_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Verifies the from-scratch SHA-1 against Python's hashlib.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
import hashlib
from hash import hashfn

print("=== SHA-1 Hash Test (verified against hashlib) ===\n")
h = hashfn(None, pd.DataFrame({'SHOW_STEPS': [False]}))
h.show_hash_state()
print(f"\nSHA-1 Statistics:")
for k, v in h.get_cipher_stats().items():
    print(f"  {k}: {v}")

print(f"\n=== KNOWN-ANSWER TESTS (FIPS 180 + hashlib) ===")
vectors = ["", "abc", "The quick brown fox jumps over the lazy dog",
           "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq", "a" * 1000]
all_ok = True
for v in vectors:
    mine = h.hash_message(v)
    ref = hashlib.sha1(v.encode()).hexdigest()
    ok = mine == ref
    all_ok = all_ok and ok
    label = (v[:33] + '...') if len(v) > 36 else v
    print(f"  {'OK ' if ok else 'BAD'} SHA1({label!r})")
    print(f"        mine={mine}")
print(f"\nALL VECTORS MATCH hashlib: {all_ok}")

print(f"\n=== AVALANCHE ===")
a = h.hash_message("The quick brown fox jumps over the lazy dog")
b = h.hash_message("The quick brown fox jumps over the lazy cog")
diff = bin(int(a, 16) ^ int(b, 16)).count('1')
print(f"  'dog' vs 'cog': {diff}/160 bits differ ({100*diff/160:.0f}%)")
