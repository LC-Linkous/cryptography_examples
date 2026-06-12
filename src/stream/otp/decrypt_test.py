#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/otp/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt

print("=== One-Time Pad Decrypt Class Example ===")

print(f"\n{'='*60}\nPART 1: LEGITIMATE DECRYPTION (correct pad)\n{'='*60}")
e = encrypt(None, pd.DataFrame({'MODE': ['xor'], 'SHOW_STEPS': [False]}))
msg = "MEET AT MIDNIGHT"
ct = e.encrypt_message(msg)
key = e.get_last_key()
d = decrypt(None, pd.DataFrame({'MODE': ['xor'], 'SHOW_STEPS': [False]}))
rec = d.decrypt_message(ct, key.hex())
print(f"  plaintext : {msg!r}")
print(f"  ciphertext: {ct}")
print(f"  decrypted : {rec!r}   match: {rec == msg}")

print(f"\n{'='*60}\nPART 2: WHY BRUTE FORCE FAILS (perfect secrecy)\n{'='*60}")
# The same ciphertext can be 'decrypted' to any message of equal length.
d.demonstrate_perfect_secrecy(ct, "SELL ALL SHARES!")  # 16 chars, matches "MEET AT MIDNIGHT"

print(f"\n{'='*60}\nPART 3: THE KEY-REUSE CATASTROPHE (two-time pad)\n{'='*60}")
# Encrypt two different messages with the SAME pad - the cardinal sin.
reused_key = '4a6f7365706820526f636b7321212121'  # 16 bytes, reused (BAD)
ea = encrypt(None, pd.DataFrame({'MODE': ['xor'], 'KEY': [reused_key], 'SHOW_STEPS': [False]}))
c1 = ea.encrypt_message("ATTACK AT DAWN!!")
eb = encrypt(None, pd.DataFrame({'MODE': ['xor'], 'KEY': [reused_key], 'SHOW_STEPS': [False]}))
c2 = eb.encrypt_message("RETREAT AT DUSK!")
leak = d.demonstrate_key_reuse(c1, c2)
# confirm the leak equals p1 ^ p2
p1, p2 = b"ATTACK AT DAWN!!", b"RETREAT AT DUSK!"
expected = bytes(a ^ b for a, b in zip(p1, p2))
print(f"  verification: leak == p1 XOR p2 : {leak == expected}")

print(f"\n{'='*60}\nPART 4: THE ATTACK SUMMARY\n{'='*60}")
d.brute_force_decrypt(ct)

print(f"\n{'='*60}\nONE-TIME PAD DECRYPT SUMMARY\n{'='*60}")
print("""
KEY INSIGHTS:
1. CORRECT pad -> exact decryption, and NO attack exists: brute force
   produces every possible plaintext (Part 2), so the ciphertext leaks
   nothing. This is Shannon's perfect secrecy, made tangible.
2. REUSED pad -> total collapse: c1 XOR c2 = p1 XOR p2 (Part 3). The key
   vanishes and both messages become recoverable by crib-dragging. The
   word 'one-time' is the entire security guarantee.
3. NON-RANDOM 'pad' (e.g. a repeating keyword) is just the Vigenere cipher
   -- breakable by the methods in src/substitution/vigenere.
The OTP is simultaneously the strongest cipher (in theory) and a museum of
how key MANAGEMENT, not algorithm choice, is where real systems fail.
""")
