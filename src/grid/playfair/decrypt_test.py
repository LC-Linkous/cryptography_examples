#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grids/playfair/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#
#   Shows (1) legitimate decryption with the keyword, and (2) the
#   keyword-dictionary attack scored by English frequency. Ciphertext is
#   produced by the real encrypt class, so it is genuine.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt


print("=== Playfair Decrypt Class Example ===")

print("\n=== CREATING TEST CASES ===")
cases = [
    {'name': 'MONARCHY', 'plaintext': 'MEET ME AT THE DOCK', 'keyword': 'MONARCHY'},
    {'name': 'SECRET',   'plaintext': 'ATTACK AT DAWN',      'keyword': 'SECRET'},
    {'name': 'CIPHER',   'plaintext': 'THE GOLD IS HIDDEN',  'keyword': 'CIPHER'},
]
for case in cases:
    enc = encrypt(None, pd.DataFrame({
        'KEYWORD': [case['keyword']], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [False]
    }))
    case['ciphertext'] = enc.encrypt_message(case['plaintext'])
    print(f"  {case['name']}: {case['plaintext']!r} -> {case['ciphertext']}")

print(f"\n{'='*60}")
print("PART 1: LEGITIMATE DECRYPTION (keyword known)")
print('='*60)
for case in cases:
    dec = decrypt(None, pd.DataFrame({
        'KEYWORD': [case['keyword']], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [False]
    }))
    result = dec.decrypt_message(case['ciphertext'])
    # Compare ignoring the pad letters that Playfair inserts.
    stripped_expected = case['plaintext'].upper().replace(' ', '').replace('J', 'I')
    print(f"\n--- {case['name']} ---")
    print(f"  Ciphertext: {case['ciphertext']}")
    print(f"  Decrypted : {result}")
    print(f"  Original  : {stripped_expected}")
    print(f"  (Pad letters may appear between doubled letters / at the end.)")

print(f"\n{'='*60}")
print("PART 2: KEYWORD-DICTIONARY ATTACK (keyword unknown)")
print('='*60)
print("The attacker does not know the keyword. Try a dictionary, score by")
print("English-likeness. (A full break would use digraph-frequency search.)\n")

# Attack the SECRET case using the dictionary that happens to include it.
target = cases[1]  # SECRET / ATTACK AT DAWN
attacker = decrypt(None, pd.DataFrame({
    'KEYWORD': [''], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [False]
}))
best = attacker.auto_decrypt(target['ciphertext'], top_n=5)
if best:
    print(f"\n  Top-scoring guess: keyword '{best[0]}' -> {best[1]}")
    print(f"  (True keyword was '{target['keyword']}'.)")
    print(f"  NOTE: on a short ciphertext, single-letter frequency scoring")
    print(f"  often does NOT pick the right keyword - which is exactly the")
    print(f"  point of Playfair. It encrypts PAIRS, so it flattens the very")
    print(f"  single-letter statistics this attack relies on. A real break")
    print(f"  needs DIGRAPH frequency analysis (a 'decrypt_improved' extension).")

print(f"\n{'='*60}")
print("PLAYFAIR DECRYPT SUMMARY")
print('='*60)
print("""
KEY INSIGHTS:

1. DECRYPTION REVERSES THE RULES:
    - same row -> shift LEFT;  same column -> shift UP
    - rectangle rule is its own inverse

2. THE PAD ARTIFACT:
    - Playfair inserts a pad (X) between doubled letters and to fill an
      odd final pair. Those survive decryption, so output may read e.g.
      'TREXESTUMP'. Readers fix this from context - part of the lesson.

3. WHY BRUTE FORCE IS NOT THE ATTACK:
    - 25! possible squares makes exhaustive search hopeless, yet Playfair
      is still broken in practice via digraph frequency analysis and key
      cribs. Large keyspace != secure (a recurring theme in this repo).

4. SCORING:
    - The dictionary attack scores candidates by English letter frequency,
      the same technique used against the substitution and RC4 ciphers.
""")
