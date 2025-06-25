#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/block/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== Simple Block Cipher Class Example ===")

# Test different block cipher configurations
configurations = [
    # Small block, few rounds - educational
    {'BLOCK_SIZE': [8], 'NUM_ROUNDS': [3], 'KEY_HEX': ['0123456789ABCDEF'], 'PADDING_MODE': ['PKCS7'], 'OUTPUT_FORMAT': ['hex']},
    
    # Larger block, more rounds - more secure
    {'BLOCK_SIZE': [16], 'NUM_ROUNDS': [6], 'KEY_HEX': [None], 'PADDING_MODE': ['PKCS7'], 'OUTPUT_FORMAT': ['hex']},
    
    # Different output format
    {'BLOCK_SIZE': [8], 'NUM_ROUNDS': [4], 'KEY_HEX': ['DEADBEEFCAFEBABE'], 'PADDING_MODE': ['PKCS7'], 'OUTPUT_FORMAT': ['base64']},
]

test_messages = [
    "HELLO",
    "HELLO WORLD",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    "BLOCK CIPHER TEST MESSAGE",
    "A",  # Single character (tests padding)
    "EXACTLY8"  # Exactly one block for 8-byte cipher
]

for config_num, config in enumerate(configurations, 1):
    print(f"\n{'='*80}")
    print(f"CONFIGURATION {config_num}")
    print('='*80)
    
    # Create cipher instance
    options = pd.DataFrame(config)
    cipher = encrypt(None, options)  # No dictionary needed for block ciphers
    
    # Show cipher details
    cipher.show_cipher_details()
    
    # Test encryption/decryption
    print(f"\n=== Testing Messages ===")
    
    for message in test_messages[:3]:  # Test first 3 messages
        try:
            encrypted = cipher.encrypt_message(message)
            decrypted = cipher.decrypt_message(encrypted)
            
            match = message == decrypted
            print(f"'{message}' -> '{encrypted}' -> '{decrypted}' (Match: {match})")
            
            if not match:
                print(f"  ERROR: Decryption mismatch!")
                
        except Exception as e:
            print(f"'{message}' -> ERROR: {e}")

print(f"\n{'='*80}")
print("DETAILED ENCRYPTION PROCESS")
print('='*80)

# Show detailed process for educational purposes
demo_config = {'BLOCK_SIZE': [8], 'NUM_ROUNDS': [2], 'KEY_HEX': ['0123456789ABCDEF'], 'PADDING_MODE': ['PKCS7'], 'OUTPUT_FORMAT': ['hex']}
demo_options = pd.DataFrame(demo_config)
demo_cipher = encrypt(None, demo_options)

demo_cipher.show_encryption_process("HELLO", show_intermediate=True)

print(f"\n=== How Block Ciphers Work ===")
print("""
Block ciphers operate on fixed-size blocks of data using these components:

1. BLOCK SIZE:
    - Data is divided into fixed-size blocks (4, 8, 16 bytes common)
    - Each block is encrypted independently in basic modes
    - Padding is added to make data fit exact block boundaries

2. SUBSTITUTION-PERMUTATION NETWORK (SPN):
    - Substitution: S-boxes replace bytes with different values
    - Permutation: P-boxes rearrange bits within blocks
    - Round keys: Different key used in each round
    - Multiple rounds increase security

3. KEY SCHEDULE:
    - Main key is expanded into multiple round keys
    - Each round uses a different derived key
    - Prevents simple attacks on individual rounds

4. PADDING:
    - PKCS#7: Adds bytes indicating padding length
    - Zero padding: Fills with zero bytes
    - Necessary when message doesn't fit exact blocks

5. ENCRYPTION PROCESS:
    - Initial key addition (XOR with main key)
    - For each round:
        a) Substitute using S-box
        b) Permute bits using P-box
        c) Add round key (XOR)
    - Final round may skip permutation

6. DECRYPTION PROCESS:
    - Exact reverse of encryption
    - Uses inverse S-boxes and P-boxes
    - Applies round keys in reverse order

ADVANTAGES:
- Strong security with proper design
- Fast encryption/decryption
- Well-studied mathematical properties
- Basis for standards like AES, DES

VULNERABILITIES:
- Requires secure key management
- Simple modes reveal patterns in data
- Vulnerable if too few rounds
- S-box and P-box design is critical

EDUCATIONAL NOTE:
This is a simplified educational cipher. Real block ciphers like AES
use much more sophisticated S-boxes, key schedules, and operations.
""")