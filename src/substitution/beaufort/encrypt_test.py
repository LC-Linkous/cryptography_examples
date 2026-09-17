#! /usr/bin/python3
##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/beaufort/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt

print("=== Beaufort Cipher Educational Example ===")

configs = [
    {'name': 'Beaufort (FORTIFICATION)', 'KEYWORD': ['FORTIFICATION'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]},
    {'name': 'Beaufort Step-by-Step', 'KEYWORD': ['STORM'], 'KEEP_SPACES': [True], 'SHOW_STEPS': [True]},
]
msgs = ["DEFENDTHEEASTWALL", "HELLO WORLD", "the quick brown fox"]
for cfg in configs:
    print(f"\n{'='*70}\nCONFIGURATION: {cfg['name']}\n{'='*70}")
    c = encrypt(None, pd.DataFrame(cfg))
    c.show_beaufort_state()
    print(f"\nBeaufort Statistics:")
    for k, v in c.get_cipher_stats().items():
        print(f"  {k}: {v}")
    print(f"\n=== Testing Messages ===")
    for m in (msgs[:1] if cfg['SHOW_STEPS'][0] else msgs):
        print(f"'{m}' -> {c.encrypt_message(m)}")

print(f"\n{'='*70}\nKNOWN-ANSWER + RECIPROCITY CHECK\n{'='*70}")
v = encrypt(None, pd.DataFrame({'KEYWORD': ['FORTIFICATION'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]}))
ct = v.encrypt_message("DEFENDTHEEASTWALL")
print(f"  DEFENDTHEEASTWALL / FORTIFICATION = {ct}")
v2 = encrypt(None, pd.DataFrame({'KEYWORD': ['FORTIFICATION'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]}))
print(f"  Reciprocity (encrypt the ciphertext again -> plaintext): "
      f"{v2.encrypt_message(ct) == 'DEFENDTHEEASTWALL'}")

print(f"\n{'='*70}\nBEAUFORT EDUCATIONAL SUMMARY\n{'='*70}")
print("""
BEAUFORT OVERVIEW:
1. A polyalphabetic cipher (Sir Francis Beaufort) with C = (K - P) mod 26 --
   the key MINUS the plaintext, rather than Vigenere's key PLUS plaintext.
2. RECIPROCAL: the identical operation encrypts and decrypts, since
   P = (K - C) mod 26 has the same form. This made it ideal for mechanical
   machines (the Hagelin M-209 used Beaufort) -- no separate decrypt mode.
3. Do not confuse with 'variant Beaufort' (C = P - K), which is just
   Vigenere decryption-as-encryption. This is the TRUE Beaufort.
4. Same KEYSPACE and same WEAKNESS as Vigenere: a repeating key, so the
   index of coincidence + Kasiski break it identically (see decrypt.py).
SECURITY STATUS: insecure; a teaching cipher and a nice example of how a
sign flip yields a reciprocal cipher.
""")
