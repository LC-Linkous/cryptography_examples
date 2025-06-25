#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/rc4/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== RC4 Stream Cipher Educational Example ===")

# Test different RC4 configurations
configurations = [
    # Basic RC4 with short key
    {
        'name': 'RC4 Basic',
        'KEY': ['SECRET'],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    },
    
    # RC4 with longer key
    {
        'name': 'RC4 Long Key',
        'KEY': ['ThisIsALongerSecretKey123'],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    },
    
    # RC4 with step-by-step output
    {
        'name': 'RC4 Detailed Steps',
        'KEY': ['KEY'],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [True]
    },
    
    # Different output formats
    {
        'name': 'RC4 Decimal Output',
        'KEY': ['TEST'],
        'OUTPUT_FORMAT': ['DECIMAL'],
        'SHOW_STEPS': [False]
    }
]

test_messages = [
    "HELLO",
    "RC4",
    "HELLO WORLD",
    "Stream cipher test",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)
    
    # Create cipher instance
    options = pd.DataFrame(config)
    cipher = encrypt(None, options)
    
    # Show cipher state
    cipher.show_rc4_state()
    
    # Show statistics
    stats = cipher.get_cipher_stats()
    print(f"\nRC4 Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test encryption
    print(f"\n=== Testing Messages ===")
    
    # For detailed steps, only test short messages
    test_count = 2 if config['SHOW_STEPS'][0] else 3
    
    for message in test_messages[:test_count]:
        try:
            encrypted = cipher.encrypt_message(message)
            print(f"'{message}' → {encrypted}")
                
        except Exception as e:
            print(f"'{message}' → ERROR: {e}")

print(f"\n{'='*70}")
print("RC4 EDUCATIONAL DEMONSTRATIONS")
print('='*70)

# Create a demo cipher
demo_options = pd.DataFrame({
    'KEY': ['DEMO'],
    'OUTPUT_FORMAT': ['HEX'],
    'SHOW_STEPS': [False]
})
demo_cipher = encrypt(None, demo_options)

# Demonstrate RC4 internals
print("\n1. RC4 Internal Operations:")
demo_cipher.demonstrate_rc4_internals("HI")

print("\n" + "="*50)
print("2. Key Sensitivity Test:")
demo_cipher.test_key_sensitivity()

print("\n" + "="*50)
print("3. RC4 vs Simple XOR:")
demo_cipher.compare_with_manual_xor("TEST")

print(f"\n{'='*70}")
print("RC4 EDUCATIONAL SUMMARY")
print('='*70)
print("""
RC4 ALGORITHM OVERVIEW:

1. KEY SCHEDULING ALGORITHM (KSA):
    - Initialize S-box with values 0-255
    - Use key to scramble S-box via swapping
    - Creates initial permutation based on key

2. PSEUDO-RANDOM GENERATION ALGORITHM (PRGA):
    - Maintain two pointers: i and j
    - For each byte: increment i, update j, swap S[i]↔S[j]
    - Output: S[(S[i] + S[j]) % 256]

3. ENCRYPTION PROCESS:
    - Generate keystream using PRGA
    - XOR plaintext with keystream
    - Result is ciphertext

KEY PROPERTIES:
✅ Very fast and simple
✅ Variable key length (1-256 bytes)  
✅ Stream cipher - can encrypt any length
✅ Self-synchronizing

SECURITY ISSUES:
❌ Biased output in first bytes
❌ Key schedule vulnerabilities
❌ Statistical biases in keystream
❌ Related key attacks possible
❌ WEP protocol failures

HISTORICAL IMPORTANCE:
- Designed by Ron Rivest in 1987
- Widely used in 1990s/2000s
- Part of SSL/TLS, WEP, WPA (TKIP)
- Now deprecated due to vulnerabilities

LEARNING VALUE:
- Excellent introduction to stream ciphers
- Shows XOR encryption principles
- Demonstrates importance of algorithm analysis
- Good stepping stone to modern ciphers

MODERN ALTERNATIVES:
- ChaCha20 (Google's choice)
- AES-GCM (authenticated encryption)
- Salsa20 (ChaCha20's predecessor)
""")

print(f"\n=== WHY RC4 FAILED ===")
print("""
RC4's vulnerabilities led to its deprecation:

1. FIRST BYTE BIAS: First few keystream bytes are biased
2. INVARIANCE WEAKNESS: Some key-keystream correlations
3. WEP DISASTERS: Key reuse in WEP made WiFi insecure
4. STATISTICAL BIASES: Pattern detection in long streams

LESSONS LEARNED:
- Thorough cryptanalysis takes time
- Simple doesn't always mean secure
- Real-world usage can expose flaws
- Need for authenticated encryption

This is why we now use:
- Authenticated encryption (AES-GCM, ChaCha20-Poly1305)
- Rigorous security proofs
- Conservative security margins
- Regular algorithm updates
""")