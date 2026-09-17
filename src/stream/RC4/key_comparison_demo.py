#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/stream/RC4/key_comparison_demo.py'
#   RC4 dictionary brute force demo: how partial / repeated keys perform
#
#   This is a stand-alone demo (NOT the standardized decrypt class). It
#   encrypts a fixed set of (message, key) pairs and then runs a small
#   dictionary brute force against each ciphertext to show two things:
#
#     1. If the key is IN the dictionary, the message is recovered by just
#        running down the list (the 'attempt N' counter shows where it hit).
#     2. RC4's KSA only ever sees key_bytes[i % len(key)], so a key that is
#        an exact REPEAT of a dictionary word (e.g. 'KEYKEYKEYKEYKEY' when
#        the period 15 is a multiple of len('KEY')=3) produces the IDENTICAL
#        keystream as the short word -- so it decrypts under 'KEY'. Keys that
#        are NOT in the dictionary, or are repeats of a word that is not in
#        the dictionary (e.g. 'FOXFOXFOXFOX'), are not recovered.
#
#   Claude AI was used to tidy the printouts and commentary (as elsewhere in
#   this repo). The (message, key) pairs and the dictionary are chosen on
#   purpose to make the contrast above visible. Discussion is in the README.
#
#   Author(s): Lauren Linkous
#   Last update: June 25, 2025
##--------------------------------------------------------------------\

import pandas as pd

# Reuse the real RC4 implementations so the demo cannot drift from the cipher.
from encrypt import encrypt
from decrypt import decrypt


# The dictionary the brute force runs down, in order. Keys actually used to
# encrypt some of the messages below are placed at known spots so the
# 'attempt N' counter is meaningful. 18 entries total -- short on purpose so
# 'NO KEY: Key not found in 18 attempts' stays readable.
BRUTE_FORCE_DICTIONARY = [
    'SECRET',    # 1
    'PASSWORD',  # 2
    'ADMIN',     # 3
    'X',         # 4
    'TEST',      # 5
    'DEMO',      # 6
    'KEY',       # 7
    'ABC',       # 8
    '123',       # 9
    'PASS',      # 10
    'USER',      # 11
    'RC4',       # 12
    'CIPHER',    # 13
    'HELLO',     # 14
    'WORLD',     # 15
    'QWERTY',    # 16
    'LETMEIN',   # 17
    'HIDDEN',    # 18
]


# (message, key) pairs. The first five use keys that ARE in the dictionary.
# The rest use keys that are not -- including 'KEYKEYKEYKEYKEY' (a repeat of
# the dictionary word 'KEY', which DOES recover) versus 'FOXFOXFOXFOX' (a
# repeat of 'FOX', which is NOT in the dictionary and so does NOT recover).
TEST_CASES = [
    ('HELLO', 'KEY'),
    ('SECRET', 'ABC'),
    ('TEST', '123'),
    ('RC4', 'X'),
    ('BRUTE', 'PASS'),
    ('TESTTESTTESTTESTTESTTEST', 'PEANUTBUTTER'),
    ('THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG', 'QUICKBROWNFOX'),
    ('THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG', 'FOXFOXFOXFOX'),
    ('THE QUICK BROWN FOX JUMPED OVER THE LAZY DOG', 'F'),
    ('THIS is a LONGER PHRASE with mixed letters', 'KEYKEYKEYKEYKEY'),
    ('THIS is a LONGER PHRASE with mixed letters', 'AMOREDIFFICULTKEY'),
]


def looks_like_text(candidate):
    # A lightweight "did we recover plaintext?" check for the brute force.
    # A wrong RC4 key produces effectively random bytes, which almost always
    # fail to decode as printable text. The decrypt class returns an UPPER
    # case hex string when UTF-8 decoding fails, so we reject all-hex results
    # as the "could not decode" signal rather than a real hit.
    if not isinstance(candidate, str) or len(candidate) == 0:
        return False
    # All-hex (and even length) means it is the decrypt class's hex fallback.
    if all(c in '0123456789ABCDEF' for c in candidate):
        return False
    # Require printable ASCII and at least one alphabetic character.
    if not all(32 <= ord(c) <= 126 for c in candidate):
        return False
    if not any(c.isalpha() for c in candidate):
        return False
    return True


def encrypt_all(encryptor):
    # STEP 1: encrypt every (message, key) pair and report the ciphertext.
    print("STEP 1: ENCRYPTING MESSAGES")
    print("=" * 50)

    ciphertexts = []
    for index, (message, key) in enumerate(TEST_CASES, start=1):
        encryptor.initialized = False  # reset RC4 state between messages
        ciphertext = encryptor.encrypt_message(message, key)
        ciphertexts.append(ciphertext)
        print(f"{index}. '{message}' + key '{key}' \u2192 {ciphertext}")

    return ciphertexts


def brute_force_all(decryptor, ciphertexts):
    # STEP 2: run the dictionary down each ciphertext, stop at the first key
    # that recovers readable text, and report which attempt that was.
    print("\nSTEP 2: BRUTE FORCE DECRYPTION ATTEMPTS")
    print("=" * 50)

    for index, ((message, key), ciphertext) in enumerate(zip(TEST_CASES, ciphertexts), start=1):
        print(f"\n{index}. Brute forcing: {ciphertext}")
        print(f"   (Original: '{message}' with key '{key}')")

        recovered = None
        for attempt, candidate in enumerate(BRUTE_FORCE_DICTIONARY, start=1):
            decryptor.initialized = False  # reset RC4 state for each attempt
            try:
                plaintext = decryptor.decrypt_message(ciphertext, candidate)
            except Exception:
                continue
            if looks_like_text(plaintext):
                recovered = (candidate, plaintext, attempt)
                break

        if recovered is not None:
            cand, plaintext, attempt = recovered
            print(f"SUCCESS! Key '{cand}' \u2192 '{plaintext}' (attempt {attempt})")
        else:
            print(f"NO KEY: Key not found in {len(BRUTE_FORCE_DICTIONARY)} attempts")


def main():
    # opt_df structures match the standardized encrypt/decrypt class interface.
    encrypt_options = pd.DataFrame({
        'KEY': ['SECRET'],            # overridden per message in encrypt_all
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False],
    })
    decrypt_options = pd.DataFrame({
        'KEY': ['SECRET'],            # overridden per attempt in brute_force_all
        'INPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False],
    })

    encryptor = encrypt(opt_df=encrypt_options)
    decryptor = decrypt(opt_df=decrypt_options)

    ciphertexts = encrypt_all(encryptor)
    brute_force_all(decryptor, ciphertexts)


if __name__ == '__main__':
    main()
