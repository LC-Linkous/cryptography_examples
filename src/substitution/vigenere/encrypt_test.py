#! /usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/vigenere/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Claude also added some additional commentary, which is neat.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== Vigenere Cipher Educational Example ===")

configurations = [
    {'name': 'Vigenere Classic (LEMON)',
     'KEYWORD': ['LEMON'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]},
    {'name': 'Vigenere Step-by-Step',
     'KEYWORD': ['KEY'], 'KEEP_SPACES': [True], 'SHOW_STEPS': [True]},
    {'name': 'Vigenere Long Keyword',
     'KEYWORD': ['CRYPTOGRAPHY'], 'KEEP_SPACES': [True], 'SHOW_STEPS': [False]},
]

test_messages = [
    "ATTACKATDAWN",
    "HELLO WORLD",
    "the quick brown fox",
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)

    options = pd.DataFrame(config)
    cipher = encrypt(None, options)
    cipher.show_vigenere_state()

    stats = cipher.get_cipher_stats()
    print(f"\nVigenere Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print(f"\n=== Testing Messages ===")
    count = 1 if config['SHOW_STEPS'][0] else len(test_messages)
    for message in test_messages[:count]:
        encrypted = cipher.encrypt_message(message)
        print(f"'{message}' -> {encrypted}")
        if not config['SHOW_STEPS'][0]:
            # show the key alignment for the first config
            if config['name'].endswith('(LEMON)'):
                print(f"    key stream: {cipher.make_full_key(message)}")

print(f"\n{'='*70}")
print("KNOWN-ANSWER CHECK (the canonical Wikipedia example)")
print('='*70)
verify = encrypt(None, pd.DataFrame({
    'KEYWORD': ['LEMON'], 'KEEP_SPACES': [False], 'SHOW_STEPS': [False]
}))
ct = verify.encrypt_message("ATTACKATDAWN")
print(f"  ATTACKATDAWN + LEMON = {ct}  (expected LXFOPVEFRNHR)")
print(f"  MATCH: {ct == 'LXFOPVEFRNHR'}")

print(f"\n{'='*70}")
print("VIGENERE EDUCATIONAL SUMMARY")
print('='*70)
print("""
VIGENERE OVERVIEW:

1. WHAT IT IS:
    - A POLYALPHABETIC substitution cipher (Bellaso 1553; misattributed to
      Vigenere). A keyword selects a different Caesar shift for each letter,
      cycling through the keyword.

2. HOW IT WORKS:
    - Write the keyword repeatedly under the plaintext.
    - Each plaintext letter is Caesar-shifted by its keyword letter
      (A=0, B=1, ...). Decryption subtracts the same shifts.

3. WHY IT MATTERS HISTORICALLY:
    - Called 'le chiffre indechiffrable' for ~300 years. By spreading each
      letter across multiple cipher alphabets, it FLATTENS the single-letter
      frequency signature that breaks the monoalphabetic cipher.
    - Broken by Babbage (c.1854) and Kasiski (1863) via the periodicity of
      the repeating key -- see decrypt.py for the full method.

4. THE KEY-LENGTH LESSON:
    - Security grows with keyword length: a longer key means more cipher
      alphabets and less data per column for the attacker. A key as long as
      the message, used once, IS the one-time pad (provably unbreakable).

SECURITY STATUS:
    - Insecure; a teaching cipher. But it is the conceptual bridge from the
      breakable monoalphabetic world to the (in its limit) unbreakable
      one-time pad.
""")
