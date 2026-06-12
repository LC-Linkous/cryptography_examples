#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/vigenere/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#
#   Shows (1) legitimate decryption with the keyword, and (2) the historical
#   ATTACK: recover the key length by index of coincidence + Kasiski, then
#   solve each column as a Caesar cipher. Ciphertext is produced by the real
#   encrypt class.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt


print("=== Vigenere Decrypt Class Example ===")

# A longer passage so the statistical attack has enough data. Cryptanalysis
# of polyalphabetic ciphers NEEDS length -- that is itself a lesson.
plaintext = ("the index of coincidence is a statistical measure used in "
             "cryptanalysis to study the frequency of letters in a text and "
             "it helps reveal the length of the keyword used in a polyalphabetic "
             "cipher such as the vigenere cipher which resisted analysis for "
             "centuries until babbage and kasiski independently found the method "
             "to break it by exploiting the periodic nature of the repeating key")

print("\n=== CREATING TEST CASE ===")
keyword = "LEMON"
enc = encrypt(None, pd.DataFrame({
    'KEYWORD': [keyword], 'KEEP_SPACES': [True], 'SHOW_STEPS': [False]
}))
ciphertext = enc.encrypt_message(plaintext)
print(f"  keyword   : {keyword}")
print(f"  plaintext : {plaintext[:60]}...")
print(f"  ciphertext: {ciphertext[:60]}...")

print(f"\n{'='*60}")
print("PART 1: LEGITIMATE DECRYPTION (keyword known)")
print('='*60)
dec = decrypt(None, pd.DataFrame({'KEYWORD': [keyword], 'SHOW_STEPS': [False]}))
recovered = dec.decrypt_message(ciphertext)
print(f"  Decrypted (first 60): {recovered[:60]}...")
print(f"  Exact match: {recovered == plaintext}")

print(f"\n{'='*60}")
print("PART 2: THE ATTACK (keyword unknown - the historical break)")
print('='*60)
attacker = decrypt(None, pd.DataFrame({'KEYWORD': [''], 'SHOW_STEPS': [False]}))
key, pt = attacker.brute_force_decrypt(ciphertext)
print(f"\n  Recovered key '{key}' (true key was '{keyword}'): {key == keyword}")
print(f"  Recovered plaintext matches: {pt == plaintext}")

print(f"\n{'='*60}")
print("PART 3: WHY KEY LENGTH MATTERS")
print('='*60)
print("Short text + long key = not enough data per column to attack.")
short_text = "HELLO WORLD THIS IS SHORT"
for kw in ("AB", "SECRETKEYWORD"):
    e = encrypt(None, pd.DataFrame({'KEYWORD':[kw],'KEEP_SPACES':[True],'SHOW_STEPS':[False]}))
    ct = e.encrypt_message(short_text)
    a = decrypt(None, pd.DataFrame({'KEYWORD':[''],'SHOW_STEPS':[False]}))
    print(f"\n  key '{kw}' (len {len(kw)}) on a {len(short_text)}-char message:")
    ic = a.find_key_length_by_ic(ct, max_len=15)
    ranked = sorted(ic, key=lambda x: abs(x[1]-0.0667))[:3]
    print(f"    top IC candidates: {[(p, round(v,4)) for p,v in ranked]}")
    print(f"    (with little data, the IC signal is noisy -- attack is harder)")

print(f"\n{'='*60}")
print("VIGENERE DECRYPT SUMMARY")
print('='*60)
print("""
KEY INSIGHTS:

1. THE TWO-STAGE BREAK:
    - Stage 1: find the KEY LENGTH. The index of coincidence of each column
      jumps toward English's ~0.067 only at the true period (and multiples).
      Kasiski's repeated-substring spacings corroborate it.
    - Stage 2: each column is now a simple Caesar cipher -- solve all of them
      by frequency analysis, reusing the Caesar/RC4 scoring machinery.

2. WHY POLYALPHABETIC RESISTED SO LONG:
    - Spreading letters across cipher alphabets flattens single-letter
      frequency, defeating the naive attack that kills monoalphabetic ciphers.
    - The break needed a NEW idea (periodicity), not just more frequency
      counting -- which is why it took ~300 years.

3. THE DATA REQUIREMENT IS THE LESSON:
    - The attack is statistical, so it needs enough ciphertext: roughly,
      several times the key length per column. Longer keys need more data.
    - In the limit (key as long as the message, never reused) the statistics
      vanish entirely -- that is the one-time pad, and it is unbreakable.
""")
