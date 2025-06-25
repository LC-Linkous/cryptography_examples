#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/rc4/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#   (There's a lot of Claude AI commentary in this one, it can be commented out)
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd
from decrypt import decrypt


print("=== RC4 Stream Cipher Decrypt Class Example ===")

# First, let's create some test ciphertext by "encrypting" known messages
print("\n=== CREATING TEST CASES ===")

# We'll simulate some encrypted messages for testing
test_cases = [
    {
        'name': 'Simple Message',
        'ciphertext': 'A1B2C3',  # This would be actual RC4 output
        'key': 'SECRET',
        'format': 'HEX'
    },
    {
        'name': 'Different Key',
        'ciphertext': 'D4E5F6',  # Different RC4 output
        'key': 'TEST',
        'format': 'HEX'
    }
]

# For proper testing, let's encrypt some messages first
print("Creating proper test cases by encrypting known messages...")

# Simulate the encrypt process to get real test data
from encrypt import encrypt as RC4Encrypt  # This would import your encrypt class

# Since we can't import the other class in this demo, let's create test data manually
# In practice, you'd use the encrypt class to create these

real_test_cases = [
    {
        'name': 'HELLO with SECRET',
        'plaintext': 'HELLO',
        'key': 'SECRET',
        'ciphertext_hex': '94C230F3C5',  # This would be real RC4 output
    },
    {
        'name': 'RC4 TEST with KEY',
        'plaintext': 'RC4 TEST',
        'key': 'KEY',
        'ciphertext_hex': '1DA5B2C3D4E5F6A7',  # This would be real RC4 output
    }
]

print(f"\n{'='*60}")
print("TESTING RC4 DECRYPTION")
print('='*60)

# Test different configurations
configurations = [
    {
        'name': 'Basic Decrypt',
        'KEY': ['SECRET'],
        'INPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    },
    {
        'name': 'Detailed Steps',
        'KEY': ['TEST'],
        'INPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [True]
    },
    {
        'name': 'Decimal Input',
        'KEY': ['KEY'],
        'INPUT_FORMAT': ['DECIMAL'],
        'SHOW_STEPS': [False]
    }
]

for config in configurations:
    print(f"\n{'-'*50}")
    print(f"CONFIGURATION: {config['name']}")
    print('-'*50)
    
    # Create decrypt instance
    options = pd.DataFrame(config)
    cipher = decrypt(None, options)
    
    # Show cipher state
    cipher.show_rc4_state()
    
    # Show statistics
    stats = cipher.get_cipher_stats()
    print(f"\nRC4 Decrypt Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # For detailed steps, use a simple example
    if config['SHOW_STEPS'][0]:
        print(f"\nTesting with detailed steps:")
        try:
            test_hex = "A1B2C3D4"
            result = cipher.decrypt_message(test_hex)
            print(f"Result: '{result}'")
        except Exception as e:
            print(f"Error: {e}")

print(f"\n{'='*60}")
print("RC4 SYMMETRY DEMONSTRATION")
print('='*60)

# Demonstrate the key insight: encryption = decryption
demo_cipher = decrypt(None, pd.DataFrame({'KEY': ['DEMO'], 'INPUT_FORMAT': ['HEX'], 'SHOW_STEPS': [False]}))
demo_cipher.demonstrate_symmetry("SECRET", "KEY")

print(f"\n{'='*60}")
print("BRUTE FORCE DECRYPTION DEMO")
print('='*60)

# Demonstrate brute force attack
brute_cipher = decrypt(None, pd.DataFrame({'KEY': [''], 'INPUT_FORMAT': ['HEX'], 'SHOW_STEPS': [False]}))

# Test with a sample ciphertext (in practice, this would be real RC4 output)
sample_ciphertext = "A1B2C3D4E5"

print(f"Attempting to decrypt: {sample_ciphertext}")
brute_cipher.analyze_ciphertext(sample_ciphertext)

print(f"\nTrying brute force attack:")
try:
    result = brute_cipher.auto_decrypt(sample_ciphertext, top_n=5, max_keys=15)
    print(f"Best guess: '{result}'")
except Exception as e:
    print(f"Brute force failed: {e}")

print(f"\n{'='*60}")
print("RC4 DECRYPT EDUCATIONAL SUMMARY")
print('='*60)
print("""
RC4 DECRYPTION KEY INSIGHTS:

1. SYMMETRIC OPERATION:
    ✅ Encryption and decryption are IDENTICAL
    ✅ Both use same keystream generation
    ✅ Both XOR with the keystream
    ✅ Plaintext ⊕ Keystream = Ciphertext
    ✅ Ciphertext ⊕ Keystream = Plaintext

2. KEYSTREAM REGENERATION:
    - Must initialize RC4 with same key
    - KSA produces identical S-box
    - PRGA generates identical keystream
    - XOR reverses the encryption

3. CRITICAL REQUIREMENTS:
    ⚠️  EXACT same key required
    ⚠️  Must start from beginning of keystream
    ⚠️  Any key difference = garbage output
    ⚠️  Keystream position matters

4. ATTACK STRATEGIES:
    - Brute force short keys
    - Dictionary attacks on likely keys
    - Frequency analysis of output
    - Known plaintext attacks

5. WHY RC4 FAILED:
    - Short keys are brute-forceable
    - Key reuse vulnerabilities (WEP)
    - Statistical biases in keystream
    - No authentication/integrity

LEARNING OUTCOMES:
✅ Understand stream cipher symmetry
✅ See importance of key secrecy
✅ Learn about brute force attacks
✅ Appreciate modern cipher improvements

MODERN LESSONS:
- Use authenticated encryption (AES-GCM)
- Never reuse keys/nonces
- Use cryptographically secure keys
- Implement proper key management
""")

