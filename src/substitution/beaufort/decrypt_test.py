#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/beaufort/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt

print("=== Beaufort Decrypt Class Example ===")

plaintext = ("the beaufort cipher is reciprocal which means the very same "
             "operation both conceals and reveals the message a property that "
             "made it convenient for mechanical cipher machines like the hagelin "
             "used widely in the middle of the twentieth century for field traffic")
keyword = "STORM"

print("\n=== CREATING TEST CASE ===")
enc = encrypt(None, pd.DataFrame({'KEYWORD': [keyword], 'KEEP_SPACES': [True], 'SHOW_STEPS': [False]}))
ct = enc.encrypt_message(plaintext)
print(f"  keyword   : {keyword}")
print(f"  ciphertext: {ct[:60]}...")

print(f"\n{'='*60}\nPART 1: LEGITIMATE DECRYPTION (reciprocal: same op as encrypt)\n{'='*60}")
dec = decrypt(None, pd.DataFrame({'KEYWORD': [keyword], 'SHOW_STEPS': [False]}))
r = dec.decrypt_message(ct)
print(f"  decrypted (first 60): {r[:60]}...")
print(f"  exact match: {r == plaintext}")

print(f"\n{'='*60}\nPART 2: THE ATTACK (same family as Vigenere)\n{'='*60}")
attacker = decrypt(None, pd.DataFrame({'KEYWORD': [''], 'SHOW_STEPS': [False]}))
k, pt = attacker.brute_force_decrypt(ct)
print(f"\n  recovered key '{k}' (true '{keyword}'): {k == keyword}")
print(f"  plaintext recovered: {pt == plaintext}")

print(f"\n{'='*60}\nBEAUFORT DECRYPT SUMMARY\n{'='*60}")
print("""
KEY INSIGHTS:
1. Decryption IS encryption (reciprocal): P = (K - C) mod 26. One routine
   serves both directions -- the property that made Beaufort attractive for
   hand and machine use.
2. The repeating key is the same Achilles' heel as Vigenere: index of
   coincidence finds the period, then each column falls to frequency
   analysis. The subtractive formula only changes the per-column solve, not
   the overall strategy.
3. Contrast with the AUTOKEY cipher (see src/substitution/autokey), which
   removes the period entirely and so resists this exact attack.
""")
