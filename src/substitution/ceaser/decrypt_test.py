#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/ceasar/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd
from decrypt import decrypt

print("=== Caesar Cipher Brute Force Decryptor ===\n")

# Create brute force decryptor
decryptor = decrypt()

# Test with some encrypted messages
test_cases = [
    "KHOOR ZRUOG",  # "HELLO WORLD" with offset 3
    "WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ",  # "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG" with offset 3
    "JBHF GUVF VF N GRKF ZRFFNTR",  # "THIS IS A TEST MESSAGE" with offset 13 (ROT13)
]

for i, encrypted_msg in enumerate(test_cases, 1):
    print(f"\n{'='*60}")
    print(f"TEST CASE {i}: '{encrypted_msg}'")
    print('='*60)
    
    # Try brute force decryption
    best_decryption = decryptor.auto_decrypt(encrypted_msg, top_n=3)
    
    print(f"\nMost likely decryption: '{best_decryption}'")


print("\n=== How the Brute Force Attack Works ===")
print("""
1. Try every possible offset (0 to dictionary_length - 1)
2. For each offset, decrypt the message
3. Score each decryption based on English letter frequency
4. Return results sorted by how "English-like" they appear

The scoring system:
- Compares letter frequencies in decrypted text to expected English frequencies
- Higher scores indicate more plausible English text
- Works best with longer messages (more statistical data)

Limitations:
- Assumes the original message was in English
- May struggle with very short messages
- Won't work if the original dictionary is unknown
""")