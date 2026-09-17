#! /usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/asymmetric/rsa/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Claude also added some additional commentary, which is neat.
#
#   NOTE: this is the first ASYMMETRIC example, so the test reads a little
#   differently from the symmetric ones - there are now two keys.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== RSA Public-Key Cipher Educational Example ===")
print("(TEXTBOOK RSA - educational only, NOT secure for real use)")

# Different RSA configurations. Primes kept small ON PURPOSE so the
# decrypt attack files can actually factor them in front of a class.
configurations = [
    {
        'name': 'RSA Classic Textbook (p=61, q=53)',
        'P': [61],
        'Q': [53],
        'E': [17],
        'OUTPUT_FORMAT': ['INT'],
        'SHOW_STEPS': [False]
    },
    {
        'name': 'RSA Step-by-Step Keygen',
        'P': [61],
        'Q': [53],
        'E': [17],
        'OUTPUT_FORMAT': ['INT'],
        'SHOW_STEPS': [True]
    },
    {
        'name': 'RSA Larger Teaching Primes',
        'P': [10007],
        'Q': [10037],
        'E': [17],
        'OUTPUT_FORMAT': ['INT'],
        'SHOW_STEPS': [False]
    },
    {
        'name': 'RSA Hex Output',
        'P': [101],
        'Q': [113],
        'E': [13],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    }
]

# Short messages: textbook RSA here encrypts one character at a time, and
# each character's code point must be smaller than n.
test_messages = [
    "HI",
    "RSA",
    "HELLO",
    "KEYS"
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)

    options = pd.DataFrame(config)
    cipher = encrypt(None, options)

    # Show cipher state
    cipher.show_rsa_state()

    # Show statistics
    stats = cipher.get_cipher_stats()
    print(f"\nRSA Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Test encryption
    print(f"\n=== Testing Messages ===")
    test_count = 2 if config['SHOW_STEPS'][0] else 4
    for message in test_messages[:test_count]:
        try:
            encrypted = cipher.encrypt_message(message)
            print(f"'{message}' -> {encrypted}")
        except Exception as e:
            print(f"'{message}' -> ERROR: {e}")

print(f"\n{'='*70}")
print("RSA EDUCATIONAL DEMONSTRATIONS")
print('='*70)

# Determinism demo - the headline weakness of textbook RSA
demo_options = pd.DataFrame({
    'P': [61], 'Q': [53], 'E': [17],
    'OUTPUT_FORMAT': ['INT'], 'SHOW_STEPS': [False]
})
demo_cipher = encrypt(None, demo_options)

print("\n1. Determinism Weakness:")
demo_cipher.demonstrate_determinism("HELLO")

print(f"\n{'='*70}")
print("RSA EDUCATIONAL SUMMARY")
print('='*70)
print("""
RSA ALGORITHM OVERVIEW:

1. KEY GENERATION:
    - Pick two primes p and q
    - Compute modulus  n = p * q          (PUBLIC)
    - Compute totient  phi = (p-1)(q-1)   (SECRET)
    - Pick public exponent e, coprime with phi
    - Compute private exponent d = e^-1 mod phi  (SECRET)

2. THE TWO KEYS (this is what makes it ASYMMETRIC):
    - Public key  (e, n): anyone may have it, used to ENCRYPT
    - Private key (d, n): owner only, used to DECRYPT

3. ENCRYPTION / DECRYPTION:
    - Encrypt: c = m^e mod n
    - Decrypt: m = c^d mod n
    - They undo each other because of how d relates to e mod phi

WHY IT IS HARD TO BREAK:
- An attacker sees (e, n) and c, but NOT d
- To get d they must compute phi, which needs p and q
- That means FACTORING n - and factoring large n is infeasible

KEY PROPERTIES:
- No shared secret needed beforehand (unlike every symmetric cipher here)
- Security rests entirely on the difficulty of factoring
- Bit-length of n is everything: bigger n = harder to factor

SECURITY WARNING (TEXTBOOK RSA):
- Deterministic: same input -> same output (leaks patterns)
- No padding (real RSA uses OAEP)
- Tiny primes here are factorable in milliseconds
- 'The math is right' is NOT 'the system is secure'

HISTORICAL IMPORTANCE:
- Rivest, Shamir, Adleman, 1977
- First widely usable public-key encryption scheme
- Still underpins much of TLS, signing, and key exchange today

MODERN CONTEXT:
- Real RSA: n >= 2048 bits, padded (OAEP/PSS)
- Increasingly paired with or replaced by elliptic-curve methods
- Quantum computing (Shor's algorithm) threatens it long-term
""")
