#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/rc4/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   In order to use the actual encryption class it needed some prompting.

#   WARNING: "data" generated in test cases could be just random strings. 
#   If it is NOT GENERATED, there is no guarantee that it is accurate.
#
#
#   Claude also added some additional commentary, which is neat. 
#   (There's a lot of Claude AI commentary in this one, it can be commented out)
#
#   Last update: June 25, 2025
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt


print("=== RC4 Stream Cipher Decrypt Class Example ===")

# First, let's create some test ciphertext by "encrypting" known messages
print("\n=== CREATING TEST CASES ===")

# For proper testing, let's encrypt some messages first
print("Creating proper test cases by encrypting known messages...")

real_test_cases = [
    {
        'name': 'HELLO with SECRET',
        'plaintext': 'HELLO',
        'key': 'SECRET',
    },
    {
        'name': 'RC4 TEST with KEY',
        'plaintext': 'RC4 TEST',
        'key': 'KEY',
    },
    {
        'name': 'Different Key',
        'plaintext': 'TEST',
        'key': 'DIFFERENT',
    }
]

# Generate real ciphertext using encrypt class
for case in real_test_cases:
    encrypt_options = pd.DataFrame({
        'KEY': [case['key']],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    })
    
    encryptor = encrypt(None, encrypt_options)
    case['ciphertext_hex'] = encryptor.encrypt_message(case['plaintext'])

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
        'KEY': ['KEY'],
        'INPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [True]
    },
    {
        'name': 'Decimal Input',
        'KEY': ['DIFFERENT'],
        'INPUT_FORMAT': ['HEX'],
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
    
    # Test with real encrypted data
    test_key = config['KEY'][0]
    matching_case = next((case for case in real_test_cases if case['key'] == test_key), None)
    
    if matching_case:
        print(f"\nTesting with real encrypted data:")
        try:
            result = cipher.decrypt_message(matching_case['ciphertext_hex'])
            print(f"Ciphertext: {matching_case['ciphertext_hex']}")
            print(f"Result: '{result}'")
            print(f"Expected: '{matching_case['plaintext']}'")
            print(f"Match: {'✓' if result == matching_case['plaintext'] else '✗'}")
        except Exception as e:
            print(f"Error: {e}")
    
    # For detailed steps, use the matching case
    elif config['SHOW_STEPS'][0]:
        print(f"\nTesting with detailed steps:")
        try:
            # Use the KEY case for detailed demo
            key_case = next(case for case in real_test_cases if case['key'] == 'KEY')
            result = cipher.decrypt_message(key_case['ciphertext_hex'])
            print(f"Result: '{result}'")
        except Exception as e:
            print(f"Error: {e}")

print(f"\n{'='*60}")
print("RC4 SYMMETRY DEMONSTRATION")
print('='*60)

# Demonstrate the key insight: encryption = decryption
demo_cipher = decrypt(None, pd.DataFrame({'KEY': ['DEMO'], 'INPUT_FORMAT': ['HEX'], 'SHOW_STEPS': [False]}))
if hasattr(demo_cipher, 'demonstrate_symmetry'):
    demo_cipher.demonstrate_symmetry("SECRET", "KEY")
else:
    print("Demonstrating RC4 symmetry with real data:")
    
    # Show that encrypt and decrypt are identical operations
    demo_text = "SYMMETRY"
    demo_key = "DEMO"
    
    # Encrypt
    encrypt_options = pd.DataFrame({
        'KEY': [demo_key],
        'OUTPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    })
    encryptor = encrypt(None, encrypt_options)
    encrypted = encryptor.encrypt_message(demo_text)
    
    # Decrypt
    decrypt_options = pd.DataFrame({
        'KEY': [demo_key],
        'INPUT_FORMAT': ['HEX'],
        'SHOW_STEPS': [False]
    })
    decryptor = decrypt(None, decrypt_options)
    decrypted = decryptor.decrypt_message(encrypted)
    
    print(f"Original: '{demo_text}'")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: '{decrypted}'")
    print(f"RC4 Symmetry: {'✓ CONFIRMED' if decrypted == demo_text else '✗ FAILED'}")

print(f"\n{'='*60}")
print("DECRYPTION DEMO")
print('='*60)

# Demonstrate attack with real encrypted data
brute_cipher = decrypt(None, pd.DataFrame({'KEY': [''], 'INPUT_FORMAT': ['HEX'], 'SHOW_STEPS': [False]}))

# Use one of our real test cases
sample_case = real_test_cases[0]  # HELLO with SECRET
sample_ciphertext = sample_case['ciphertext_hex']

print(f"Attempting to decrypt: {sample_ciphertext}")
print(f"(This was '{sample_case['plaintext']}' encrypted with key '{sample_case['key']}')")

if hasattr(brute_cipher, 'analyze_ciphertext'):
    brute_cipher.analyze_ciphertext(sample_ciphertext)

print(f"\nTrying brute force attack:")
if hasattr(brute_cipher, 'auto_decrypt'):
    try:
        result = brute_cipher.auto_decrypt(sample_ciphertext, top_n=5, max_keys=15)
        print(f"Best guess: '{result}'")
    except Exception as e:
        print(f"Brute force failed: {e}")
else:
    # Simple brute force attempt with common keys
    common_keys = ['SECRET', 'KEY', 'PASSWORD', 'TEST', 'HELLO', 'ABC', '123']
    print("Trying common keys:")
    
    for test_key in common_keys:
        try:
            test_options = pd.DataFrame({
                'KEY': [test_key],
                'INPUT_FORMAT': ['HEX'],
                'SHOW_STEPS': [False]
            })
            test_cipher = decrypt(None, test_options)
            result = test_cipher.decrypt_message(sample_ciphertext)
            
            print(f"  Key '{test_key}': '{result}'", end="")
            if result == sample_case['plaintext']:
                print(" ✓ MATCH!")
                break
            else:
                print()
        except:
            print(f"  Key '{test_key}': ERROR")

print(f"\n{'='*60}")
print("RC4 DECRYPT SUMMARY")
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