#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/affine/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt

print("=== Affine Cipher Educational Example ===")

configurations = [
    {'name': 'Affine Classic (a=5, b=8)', 'A': [5], 'B': [8], 'SHOW_STEPS': [False]},
    {'name': 'Affine Step-by-Step',       'A': [7], 'B': [3], 'SHOW_STEPS': [True]},
    {'name': 'Affine as Caesar (a=1, b=3)','A': [1], 'B': [3], 'SHOW_STEPS': [False]},
]
test_messages = ["AFFINECIPHER", "HELLO WORLD", "the quick brown fox"]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)
    cipher = encrypt(None, pd.DataFrame(config))
    cipher.show_affine_state()
    stats = cipher.get_cipher_stats()
    print(f"\nAffine Statistics:")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    print(f"\n=== Testing Messages ===")
    count = 1 if config['SHOW_STEPS'][0] else len(test_messages)
    for message in test_messages[:count]:
        print(f"'{message}' -> {cipher.encrypt_message(message)}")

print(f"\n{'='*70}")
print("KNOWN-ANSWER CHECK")
print('='*70)
v = encrypt(None, pd.DataFrame({'A': [5], 'B': [8], 'SHOW_STEPS': [False]}))
ct = v.encrypt_message("AFFINECIPHER")
print(f"  AFFINECIPHER with a=5,b=8 = {ct}  (expected IHHWVCSWFRCP)")
print(f"  MATCH: {ct == 'IHHWVCSWFRCP'}")
print(f"\n  Note: a=1 reduces the Affine cipher to a plain Caesar shift of b.")

print(f"\n{'='*70}")
print("AFFINE EDUCATIONAL SUMMARY")
print('='*70)
print("""
AFFINE OVERVIEW:
1. E(x) = (a*x + b) mod 26, decryption D(y) = a^-1 (y - b) mod 26.
2. 'a' MUST be coprime with 26 or the map is not invertible (two letters
   would collide). Valid a: 1,3,5,7,9,11,15,17,19,21,23,25 -- twelve values.
3. Caesar is the special case a=1; Atbash is a=25, b=25. So Affine unifies
   several classical ciphers under one modular-arithmetic formula.
4. Still MONOALPHABETIC (one fixed substitution), so frequency analysis
   breaks it -- and with only 312 keys, brute force is instant.
SECURITY STATUS: insecure; a teaching cipher that introduces modular
inverses and the coprimality requirement.
""")
