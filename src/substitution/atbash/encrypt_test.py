#! /usr/bin/python3
##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/atbash/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt

print("=== Atbash Cipher Educational Example ===")

for cfg in [{'name': 'Atbash Standard', 'SHOW_STEPS': [False]},
            {'name': 'Atbash Step-by-Step', 'SHOW_STEPS': [True]}]:
    print(f"\n{'='*70}\nCONFIGURATION: {cfg['name']}\n{'='*70}")
    cipher = encrypt(None, pd.DataFrame(cfg))
    cipher.show_atbash_state()
    print(f"\nAtbash Statistics:")
    for k, v in cipher.get_cipher_stats().items():
        print(f"  {k}: {v}")
    print(f"\n=== Testing Messages ===")
    msgs = ["HELLO", "ATTACK AT DAWN", "the quick brown fox"]
    for m in (msgs[:1] if cfg['SHOW_STEPS'][0] else msgs):
        print(f"'{m}' -> {cipher.encrypt_message(m)}")

print(f"\n{'='*70}\nKNOWN-ANSWER CHECK\n{'='*70}")
v = encrypt(None, pd.DataFrame({'SHOW_STEPS': [False]}))
ct = v.encrypt_message("HELLO")
print(f"  HELLO -> {ct}  (expected SVOOL)   MATCH: {ct == 'SVOOL'}")
print(f"  Applying Atbash twice returns the original: "
      f"{v.encrypt_message(v.encrypt_message('HELLO')) == 'HELLO'}")

print(f"\n{'='*70}\nATBASH EDUCATIONAL SUMMARY\n{'='*70}")
print("""
ATBASH OVERVIEW:
1. One of the OLDEST ciphers (ancient Hebrew). Name = aleph-taw-beth-shin,
   the first/last/second/second-last Hebrew letters -- describing the
   reversal A<->Z, B<->Y, ... It appears in the Hebrew Bible (Jeremiah uses
   'Sheshach' as Atbash for 'Babel').
2. For Latin letters: E(x) = 25 - x. No key. Self-inverse (an involution):
   encrypting twice returns the plaintext.
3. It is exactly the Affine cipher with a=25, b=25 -- a tidy link to the
   affine family in this repo.
SECURITY STATUS: none. With no key, anyone who recognizes the method reads
the message instantly. Its value is purely historical and pedagogical: the
simplest possible substitution.
""")
