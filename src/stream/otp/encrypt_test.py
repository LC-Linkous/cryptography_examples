#! /usr/bin/python3
##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/otp/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt

print("=== One-Time Pad (Vernam) Educational Example ===")

configs = [
    {'name': 'OTP XOR (random key)', 'MODE': ['xor'], 'SHOW_STEPS': [True]},
    {'name': 'OTP mod-26 (key XMCKL)', 'MODE': ['mod26'], 'KEY': ['XMCKL'], 'SHOW_STEPS': [True]},
]
for cfg in configs:
    print(f"\n{'='*70}\nCONFIGURATION: {cfg['name']}\n{'='*70}")
    cipher = encrypt(None, pd.DataFrame(cfg))
    cipher.show_otp_state()
    print(f"\nOTP Statistics:")
    for k, v in cipher.get_cipher_stats().items():
        print(f"  {k}: {v}")
    print(f"\n=== Testing ===")
    msg = "HELLO" if cfg['MODE'][0] == 'mod26' else "ATTACK AT DAWN"
    ct = cipher.encrypt_message(msg)
    print(f"  '{msg}' -> {ct}")
    print(f"  (key used: {cipher.get_last_key() if cfg['MODE'][0]=='mod26' else cipher.get_last_key().hex()})")

print(f"\n{'='*70}\nKNOWN-ANSWER CHECK (classic mod-26 OTP example)\n{'='*70}")
v = encrypt(None, pd.DataFrame({'MODE': ['mod26'], 'KEY': ['XMCKL'], 'SHOW_STEPS': [False]}))
ct = v.encrypt_message("HELLO")
print(f"  HELLO + XMCKL = {ct}  (expected EQNVZ)   MATCH: {ct == 'EQNVZ'}")

print(f"\n{'='*70}\nLENGTH-RULE CHECK (key must be >= message)\n{'='*70}")
try:
    short = encrypt(None, pd.DataFrame({'MODE': ['xor'], 'KEY': ['0011'], 'SHOW_STEPS': [False]}))
    short.encrypt_message("this message is far too long for that key")
    print("  ERROR: should have rejected the short key")
except ValueError as ex:
    print(f"  Correctly rejected short key: {ex}")

print(f"\n{'='*70}\nONE-TIME PAD EDUCATIONAL SUMMARY\n{'='*70}")
print("""
ONE-TIME PAD OVERVIEW:
1. THE ONLY cipher with PROVEN perfect secrecy (Shannon, 1949). Vernam
   patented the XOR form in 1919; Mauborgne added 'random, used once'.
2. c_i = p_i XOR k_i  (or (p_i + k_i) mod 26 for letters). Decryption
   reverses with the same pad.
3. PERFECT SECRECY requires ALL THREE: the key is truly random, at least as
   long as the message, and NEVER reused. Then the ciphertext is independent
   of the plaintext -- every message is equally likely.
4. THE CATCH: those conditions are usually harder to satisfy than just
   delivering the message securely in the first place. And any violation is
   catastrophic (see decrypt.py: key reuse leaks p1 XOR p2 immediately).
SECURITY STATUS: unbreakable IF used correctly; trivially broken if misused.
The pad is the theoretical gold standard and the practical cautionary tale
at the same time.
""")
