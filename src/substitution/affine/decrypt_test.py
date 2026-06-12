#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/affine/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt

print("=== Affine Decrypt Class Example ===")

print("\n=== CREATING TEST CASES ===")
cases = [
    {'plaintext': 'AFFINECIPHER', 'a': 5, 'b': 8},
    {'plaintext': 'THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG', 'a': 7, 'b': 3},
    {'plaintext': 'ATTACK AT DAWN', 'a': 11, 'b': 15},
]
for c in cases:
    e = encrypt(None, pd.DataFrame({'A': [c['a']], 'B': [c['b']], 'SHOW_STEPS': [False]}))
    c['ciphertext'] = e.encrypt_message(c['plaintext'])
    print(f"  a={c['a']:2d} b={c['b']:2d}: {c['plaintext'][:30]!r} -> {c['ciphertext'][:30]}")

print(f"\n{'='*60}")
print("PART 1: LEGITIMATE DECRYPTION (keys known)")
print('='*60)
for c in cases:
    d = decrypt(None, pd.DataFrame({'A': [c['a']], 'B': [c['b']], 'SHOW_STEPS': [False]}))
    r = d.decrypt_message(c['ciphertext'])
    print(f"  a={c['a']:2d} b={c['b']:2d}: decrypts to {r[:30]!r}  match: {r == c['plaintext']}")

print(f"\n{'='*60}")
print("PART 2: BRUTE-FORCE ATTACK (keys unknown)")
print('='*60)
print("Only 312 keys, so just try them all and score by English frequency.\n")
target = cases[1]  # the long pangram - best for frequency scoring
attacker = decrypt(None, pd.DataFrame({'A': [1], 'B': [0], 'SHOW_STEPS': [False]}))
best = attacker.brute_force_decrypt(target['ciphertext'], top_n=3)
print(f"\n  Recovered a={best[0]}, b={best[1]} "
      f"(true a={target['a']}, b={target['b']}): "
      f"{best[0] == target['a'] and best[1] == target['b']}")

print(f"\n{'='*60}")
print("AFFINE DECRYPT SUMMARY")
print('='*60)
print("""
KEY INSIGHTS:
1. Decryption needs the MODULAR INVERSE of a: D(y) = a^-1 (y - b) mod 26.
   This is why a must be coprime with 26 -- otherwise no inverse exists.
2. The keyspace is tiny (312 keys), so brute force is the simplest break;
   frequency analysis works too, since the cipher is monoalphabetic.
3. A longer message gives the frequency scorer more signal -- short
   ciphertexts can yield ties between several plausible (a,b) pairs.
""")
