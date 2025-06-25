#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/rail_fence/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt


print("=== Rail Fence Transposition Cipher Class Example ===")

# For rail fence, dictionary is less important, but we can provide one for consistency
alphabet = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)]
print("Character set:", ''.join(alphabet[:10]) + "...")

print("\n=== Basic Rail Fence Examples ===")

# Test different rail configurations
rail_configs = [
    (3, 'down', True),   # 3 rails, down direction, remove spaces
    (4, 'down', True),   # 4 rails
    (2, 'down', True),   # 2 rails (simplest case)
    (5, 'down', False),  # 5 rails, keep spaces
]

test_messages = [
    "HELLO WORLD",
    "ATTACK AT DAWN", 
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    "RAIL FENCE CIPHER",
    "MEETMEATMIDNIGHT"
]

for num_rails, direction, remove_spaces in rail_configs:
    print(f"\n=== {num_rails} Rails, Direction: {direction}, Remove Spaces: {remove_spaces} ===")
    
    # Create options dataframe
    options = pd.DataFrame({
        'NUM_RAILS': [num_rails],
        'DIRECTION': [direction],
        'REMOVE_SPACES': [remove_spaces]
    })
    
    # Create cipher instance
    cipher = encrypt(alphabet, options)
    
    # Test with first message
    test_message = test_messages[0]
    
    # Show the rail pattern
    cipher.show_cipher_mapping(test_message)
    
    # Encrypt and decrypt
    encrypted = cipher.encrypt_message(test_message)
    decrypted = cipher.decrypt_message(encrypted)
    
    print(f"\nOriginal:  '{test_message}'")
    print(f"Encrypted: '{encrypted}'")
    print(f"Decrypted: '{decrypted}'")
    print(f"Match: {test_message.replace(' ', '') == decrypted if remove_spaces else test_message == decrypted}")

print("\n=== Multiple Message Examples ===")

# Test with 3-rail configuration on multiple messages
options_3rail = pd.DataFrame({
    'NUM_RAILS': [3],
    'DIRECTION': ['down'],
    'REMOVE_SPACES': [True]
})

cipher_3rail = encrypt(alphabet, options_3rail)

for message in test_messages:
    encrypted = cipher_3rail.encrypt_message(message)
    decrypted = cipher_3rail.decrypt_message(encrypted)
    
    original_clean = ''.join(char for char in message if char.isalnum())
    match = original_clean == decrypted
    
    print(f"'{message}' -> '{encrypted}' -> '{decrypted}' (Match: {match})")

print("\n=== Visual Pattern Analysis ===")

# Show detailed pattern for educational purposes
demo_text = "RAILFENCECIPHER"
print(f"Demonstrating rail fence pattern with: '{demo_text}'")

for rails in [2, 3, 4, 5]:
    print(f"\n--- {rails} Rails ---")
    
    options_demo = pd.DataFrame({
        'NUM_RAILS': [rails],
        'DIRECTION': ['down'],
        'REMOVE_SPACES': [True]
    })
    
    cipher_demo = encrypt(alphabet, options_demo)
    encrypted_demo = cipher_demo.encrypt_message(demo_text)
    
    print(f"Encrypted: {encrypted_demo}")
    cipher_demo.show_cipher_mapping(demo_text, show_grid=True)

print("\n=== How Rail Fence Cipher Works ===")
print("""
The Rail Fence cipher is a transposition cipher that arranges plaintext in a zigzag pattern:

For 3 rails with "HELLO WORLD" (spaces removed = "HELLOWORLD"):

Rail 0: H . . . O . . . L .
Rail 1: . E . L . W . R . D
Rail 2: . . L . . . O . . .

Pattern: 0,1,2,1,0,1,2,1,0,1

Reading rails in order: "HOOL" + "ELWRD" + "LO" = "HOOLELWRDLO"

Key characteristics:
1. Text is written in a zigzag pattern across multiple rails
2. Direction alternates: down to bottom rail, then up to top rail
3. Encryption reads each rail left-to-right, concatenating results
4. Security depends on number of rails (more rails = more complex pattern)
5. Unlike substitution ciphers, letters aren't changed - only reordered

Advantages:
- Simple to implement
- No key distribution needed (just number of rails)
- Fast encryption/decryption

Disadvantages:
- Vulnerable to frequency analysis (letters unchanged)
- Pattern can be detected with sufficient ciphertext
- Limited key space (only as many keys as possible rail numbers)
""")

print("\n=== Security Analysis ===")
print("""
Rail Fence cipher security:

Key space: Limited to reasonable number of rails (2-20 typically)
- 2 rails: Very weak, simple alternating pattern
- 3-5 rails: Moderate security for short messages
- 6+ rails: Better but still vulnerable to cryptanalysis

Vulnerabilities:
- Frequency analysis still works (letters not substituted)
- Pattern recognition can reveal rail count
- Brute force feasible (try all reasonable rail counts)
- Known plaintext attacks very effective

Best use cases:
- Educational purposes
- Combination with other ciphers
- Short messages where pattern is less obvious
- Historical interest
""")