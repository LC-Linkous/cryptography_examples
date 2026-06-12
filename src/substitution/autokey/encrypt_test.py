#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/autokey/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt

print("=== Autokey Cipher Educational Example ===")

configs = [
    {'name': 'Autokey (primer QUEENLY)', 'PRIMER': ['QUEENLY'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]},
    {'name': 'Autokey Step-by-Step', 'PRIMER': ['CAT'], 'KEEP_SPACES': [True], 'SHOW_STEPS': [True]},
]
msgs = ["ATTACKATDAWN", "HELLO WORLD", "the quick brown fox"]
for cfg in configs:
    print(f"\n{'='*70}\nCONFIGURATION: {cfg['name']}\n{'='*70}")
    c = encrypt(None, pd.DataFrame(cfg))
    c.show_autokey_state()
    print(f"\nAutokey Statistics:")
    for k, v in c.get_cipher_stats().items():
        print(f"  {k}: {v}")
    print(f"\n=== Testing Messages ===")
    for m in (msgs[:1] if cfg['SHOW_STEPS'][0] else msgs):
        print(f"'{m}' -> {c.encrypt_message(m)}")

print(f"\n{'='*70}\nKNOWN-ANSWER CHECK (classic autokey example)\n{'='*70}")
v = encrypt(None, pd.DataFrame({'PRIMER': ['QUEENLY'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]}))
ct = v.encrypt_message("ATTACKATDAWN")
print(f"  ATTACKATDAWN with primer QUEENLY = {ct}  (expected QNXEPVYTWTWP)")
print(f"  MATCH: {ct == 'QNXEPVYTWTWP'}")

print(f"\n{'='*70}\nAUTOKEY EDUCATIONAL SUMMARY\n{'='*70}")
print("""
AUTOKEY OVERVIEW:
1. Vigenere's OWN 1586 invention -- ironically stronger than the repeating-
   key cipher now bearing his name. The key is a short PRIMER followed by the
   PLAINTEXT itself: key = PRIMER + PLAINTEXT. C = (P + K) mod 26.
2. THE BIG IDEA: the key never repeats. So there is no period -- the index of
   coincidence and Kasiski examination, which break Vigenere, find NOTHING.
   This is the historical 'fix' for Vigenere's fatal flaw.
3. Still breakable, but by a DIFFERENT and harder route: since the key stream
   is English plaintext, an attacker brute-forces the short primer and looks
   for the message to 'unzip' into English (see decrypt.py).
4. Two variants exist: plaintext-autokey (this one, stronger) and
   ciphertext-autokey (weaker). We implement the plaintext form.
SECURITY STATUS: insecure by modern standards, but a genuine improvement over
Vigenere and a great lesson in how removing structure defeats an attack.
""")
