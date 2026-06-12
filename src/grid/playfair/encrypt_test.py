#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grids/playfair/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Claude also added some additional commentary, which is neat.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== Playfair Cipher Educational Example ===")

configurations = [
    {'name': 'Playfair Classic (keyword MONARCHY)',
     'KEYWORD': ['MONARCHY'], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [False]},
    {'name': 'Playfair Step-by-Step',
     'KEYWORD': ['SECRET'], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [True]},
    {'name': 'Playfair Wikipedia Example',
     'KEYWORD': ['PLAYFAIR EXAMPLE'], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [False]},
]

test_messages = [
    "HELLO",
    "MEET ME AT NOON",
    "THE QUICK BROWN FOX",
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)

    options = pd.DataFrame(config)
    cipher = encrypt(None, options)
    cipher.show_playfair_state()

    stats = cipher.get_cipher_stats()
    print(f"\nPlayfair Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print(f"\n=== Testing Messages ===")
    count = 1 if config['SHOW_STEPS'][0] else len(test_messages)
    for message in test_messages[:count]:
        encrypted = cipher.encrypt_message(message)
        print(f"'{message}' -> {encrypted}")

print(f"\n{'='*70}")
print("KNOWN-ANSWER CHECK (the canonical Wikipedia example)")
print('='*70)
# Keyword 'playfair example' encrypting 'hide the gold in the tree stump'
# is the standard worked example, with a published ciphertext.
verify = encrypt(None, pd.DataFrame({
    'KEYWORD': ['playfair example'], 'COMBINE': ['J'], 'PAD': ['X'], 'SHOW_STEPS': [False]
}))
ct = verify.encrypt_message("hide the gold in the tree stump")
expected = "BMODZBXDNABEKUDMUIXMMOUVIF"
print(f"  Plaintext : 'hide the gold in the tree stump'")
print(f"  Ciphertext: {ct}")
print(f"  Expected  : {expected}")
print(f"  MATCH: {ct == expected}")

print(f"\n{'='*70}")
print("PLAYFAIR EDUCATIONAL SUMMARY")
print('='*70)
print("""
PLAYFAIR OVERVIEW:

1. WHAT IT IS:
    - A DIGRAPH substitution cipher (encrypts letter PAIRS)
    - Charles Wheatstone, 1854; championed by Lord Playfair
    - Used in the field through WWI and into WWII

2. HOW IT WORKS:
    - Build a 5x5 key square from a keyword (I/J share a cell)
    - Split the message into letter pairs, padding doubled letters
    - Apply three rules per pair:
        * same row    -> shift each letter right
        * same column -> shift each letter down
        * rectangle   -> swap to the other letter's column

3. WHY IT MATTERS HISTORICALLY:
    - Encrypting PAIRS flattens single-letter frequency, so the simple
      frequency analysis that breaks a monoalphabetic cipher does NOT
      directly work here. It is the natural 'next step up'.
    - It can still be broken: digraph frequency analysis, known cribs,
      and (for automation) simulated annealing on the key square.

SECURITY STATUS:
    - Insecure by modern standards; a teaching cipher only.
    - Keyspace is 25! squares, so brute force is infeasible - but that
      does NOT make it secure, since smarter attacks exist (a recurring
      theme: a big keyspace alone is not security).
""")
