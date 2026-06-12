#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/autokey/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt

print("=== Autokey Decrypt Class Example ===")

plaintext = ("the autokey cipher uses the message itself as part of the key so "
             "there is no repeating period for kasiski to exploit which is why it "
             "is stronger than the ordinary vigenere cipher of the same key length")
primer = "CAT"

print("\n=== CREATING TEST CASE ===")
enc = encrypt(None, pd.DataFrame({'PRIMER': [primer], 'KEEP_SPACES': [True], 'SHOW_STEPS': [False]}))
ct = enc.encrypt_message(plaintext)
print(f"  primer    : {primer}")
print(f"  ciphertext: {ct[:60]}...")

print(f"\n{'='*60}\nPART 1: LEGITIMATE DECRYPTION (the self-unzipping key)\n{'='*60}")
dec = decrypt(None, pd.DataFrame({'PRIMER': [primer], 'SHOW_STEPS': [False]}))
r = dec.decrypt_message(ct)
print(f"  decrypted (first 60): {r[:60]}...")
print(f"  exact match: {r == plaintext}")
print(f"  (Each recovered plaintext letter becomes the next key letter --")
print(f"   the key stream unzips itself as decryption proceeds.)")

print(f"\n{'='*60}\nPART 2: WHY KASISKI FAILS, AND THE ATTACK THAT WORKS\n{'='*60}")
attacker = decrypt(None, pd.DataFrame({'PRIMER': [''], 'ATTACK_PRIMER_LEN': [3], 'SHOW_STEPS': [False]}))
best = attacker.brute_force_decrypt(ct, primer_len=3, top_n=3)
print(f"\n  recovered primer '{best[0]}' (true '{primer}'): {best[0] == primer}")
print(f"  plaintext recovered: {best[1] == plaintext}")

print(f"\n{'='*60}\nAUTOKEY DECRYPT SUMMARY\n{'='*60}")
print("""
KEY INSIGHTS:
1. THE SELF-UNZIPPING DECRYPTION: start with the primer; each plaintext
   letter you recover becomes the next key letter. The key reconstructs
   itself from the message as you go -- a small, elegant feedback loop.
2. KASISKI / INDEX OF COINCIDENCE DO NOT WORK. There is no repeating key, so
   no period exists to detect. This is the entire reason the autokey is
   stronger than Vigenere with the same primer length.
3. THE REAL ATTACK is different: brute force the SHORT primer (a few letters)
   and exploit that the key stream is English -- only the correct primer makes
   the whole message unzip into readable text. Longer primers raise the
   brute-force cost, but classic attacks also use probable-word 'cribs'
   propagated through the autokey feedback.
""")
