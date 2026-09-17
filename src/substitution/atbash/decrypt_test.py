#! /usr/bin/python3
##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/atbash/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt

print("=== Atbash Decrypt Class Example ===")

print("\n=== CREATING TEST CASES ===")
msgs = ["HELLO", "ATTACK AT DAWN", "THE TREASURE IS BURIED HERE"]
enc = encrypt(None, pd.DataFrame({'SHOW_STEPS': [False]}))
cases = [(m, enc.encrypt_message(m)) for m in msgs]
for pt, ct in cases:
    print(f"  {pt!r:35} -> {ct}")

print(f"\n{'='*60}\nPART 1: DECRYPTION (= encryption; Atbash is self-inverse)\n{'='*60}")
dec = decrypt(None, pd.DataFrame({'SHOW_STEPS': [False]}))
for pt, ct in cases:
    r = dec.decrypt_message(ct)
    print(f"  {ct[:30]!r:32} -> {r!r:35} match: {r == pt}")

print(f"\n{'='*60}\nPART 2: THE 'ATTACK' (there is no key)\n{'='*60}")
dec.brute_force_decrypt(cases[2][1])

print(f"\n{'='*60}\nATBASH DECRYPT SUMMARY\n{'='*60}")
print("""
KEY INSIGHTS:
1. Atbash is an INVOLUTION: D = E, since 25 - (25 - x) = x. Decrypting is
   literally encrypting again.
2. There is no key, so there is no keyspace and no brute force -- knowing
   the algorithm IS knowing the plaintext. This is the cleanest example of
   Kerckhoffs's principle in the negative: security must live in the KEY,
   and Atbash has none.
""")
