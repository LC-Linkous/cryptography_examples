#! /usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/hashing/sha256/hash_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Claude also added some additional commentary, which is neat.
#
#   Unlike the cipher tests, a hash has no decryption to check. Instead we
#   verify the digests against KNOWN ANSWERS (NIST test vectors), since a
#   from-scratch hash is only trustworthy if it matches the standard
#   bit-for-bit.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd

from hash import hash


print("=== SHA-256 Hash Function Educational Example ===")

# Configurations: mostly about how to display the digest.
configurations = [
    {'name': 'SHA-256 Hex Output',     'OUTPUT_FORMAT': ['HEX'],   'SHOW_STEPS': [False]},
    {'name': 'SHA-256 Step-by-Step',   'OUTPUT_FORMAT': ['HEX'],   'SHOW_STEPS': [True]},
    {'name': 'SHA-256 Binary Output',  'OUTPUT_FORMAT': ['BIN'],   'SHOW_STEPS': [False]},
]

test_messages = [
    "HELLO",
    "abc",
    "The quick brown fox jumps over the lazy dog",
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)

    options = pd.DataFrame(config)
    hasher = hash(None, options)

    hasher.show_hash_state()

    stats = hasher.get_cipher_stats()
    print(f"\nSHA-256 Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

    print(f"\n=== Hashing Messages ===")
    # Step mode is verbose; only hash one short message there.
    count = 1 if config['SHOW_STEPS'][0] else len(test_messages)
    for message in test_messages[:count]:
        digest = hasher.hash_message(message)
        if config['OUTPUT_FORMAT'][0] == 'BIN':
            # Binary is long; show just the first few bytes.
            shown = ' '.join(str(digest).split()[:4]) + ' ...'
            print(f"'{message}' ->\n    {shown}")
        else:
            print(f"'{message}' -> {digest}")

print(f"\n{'='*70}")
print("KNOWN-ANSWER VERIFICATION (NIST test vectors)")
print('='*70)
print("A from-scratch hash is only trustworthy if it matches the standard.")
print("These expected digests are the published SHA-256 test vectors.\n")

# (input, expected digest) - the canonical published vectors.
known_vectors = [
    ("",
     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    ("abc",
     "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
]

verifier = hash(None, pd.DataFrame({'OUTPUT_FORMAT': ['HEX'], 'SHOW_STEPS': [False]}))
all_pass = True
for text, expected in known_vectors:
    got = verifier.hash_message(text)
    ok = (got == expected)
    all_pass = all_pass and ok
    label = repr(text) if len(text) <= 24 else repr(text[:21] + "...")
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    print(f"        got:      {got}")
    print(f"        expected: {expected}")

print(f"\n  ALL KNOWN-ANSWER TESTS PASS: {all_pass}")

print(f"\n{'='*70}")
print("SHA-256 EDUCATIONAL SUMMARY")
print('='*70)
print("""
SHA-256 OVERVIEW:

1. WHAT IT IS:
    - A cryptographic HASH: maps any input to a fixed 256-bit digest
    - One-way: easy forward, infeasible to reverse
    - Not encryption - there is no key and no decryption

2. HOW IT WORKS (high level):
    - PAD the message to a multiple of 512 bits (includes the length)
    - Split into 512-bit blocks
    - For each block: expand into a 64-word MESSAGE SCHEDULE, then run
      64 ROUNDS of mixing into an 8-word state
    - Output the final state as the 256-bit digest

3. WHY THE STRUCTURE MATTERS:
    - The rounds + schedule create DIFFUSION: every input bit affects
      every output bit (see analysis.py's avalanche demo)
    - Including the length in the padding blocks length-extension tricks

WHAT MAKES A HASH USEFUL:
    - Deterministic: same input -> same digest, every time
    - Avalanche: a 1-bit input change flips ~half the output bits
    - Preimage resistance: cannot find an input for a given digest
    - Collision resistance: cannot find two inputs with the same digest

WHERE IT IS USED:
    - Password storage (store the hash, never the password)
    - File integrity / checksums
    - Digital signatures (sign the hash, not the whole document)
    - Blockchain, commit IDs, deduplication, and much more

SECURITY NOTE:
    - This from-scratch version is for LEARNING; it matches the standard
      but is not constant-time and is unoptimized
    - For real use, always use a vetted library (e.g. Python's hashlib)
    - For passwords specifically, use a SLOW salted hash (bcrypt, scrypt,
      Argon2) - a fast hash like raw SHA-256 is the wrong tool there
""")
