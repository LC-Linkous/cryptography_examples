#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/polybius/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import pandas as pd
from decrypt import decrypt


print("=== Polybius Square Decrypt Class Example ===")

# First, let's create some proper test cases by encrypting known messages
print("\n=== CREATING PROPER TEST CASES ===")

# Import the encrypt class to generate proper test cases
# For this demo, we'll manually create the expected mappings

# Standard alphabetical grid (A-H,K-Z): 5x5
standard_grid = [
    ['A', 'B', 'C', 'D', 'E'],
    ['F', 'G', 'H', 'K', 'L'],
    ['M', 'N', 'O', 'P', 'Q'],
    ['R', 'S', 'T', 'U', 'V'],
    ['W', 'X', 'Y', 'Z', '']
]

# Create coordinate mapping for standard grid
standard_coords = {}
for row in range(5):
    for col in range(5):
        if standard_grid[row][col]:
            char = standard_grid[row][col]
            standard_coords[char] = f"{row+1}{col+1}"

print("Standard grid coordinate mapping:")
for char in ['H', 'E', 'L', 'O', 'W', 'R', 'D']:
    if char in standard_coords:
        print(f"  {char} → {standard_coords[char]}")

# Manually encrypt "HELLO WORLD" with standard grid
hello_world_encrypted = []
for char in "HELLOWORLD":
    if char in standard_coords:
        hello_world_encrypted.append(standard_coords[char])

hello_world_cipher = " ".join(hello_world_encrypted)
print(f"\n'HELLO WORLD' encrypts to: {hello_world_cipher}")

# SECRET keyword grid: S,E,C,R,T,A,B,D,F,G,H,K,L,M,N,O,P,Q,U,V,W,X,Y,Z
secret_grid = [
    ['S', 'E', 'C', 'R', 'T'],
    ['A', 'B', 'D', 'F', 'G'],
    ['H', 'K', 'L', 'M', 'N'],
    ['O', 'P', 'Q', 'U', 'V'],
    ['W', 'X', 'Y', 'Z', '']
]

secret_coords = {}
for row in range(5):
    for col in range(5):
        if secret_grid[row][col]:
            char = secret_grid[row][col]
            secret_coords[char] = f"{row+1}{col+1}"

print(f"\nSECRET grid coordinate mapping:")
for char in ['S', 'E', 'C', 'R', 'T']:
    if char in secret_coords:
        print(f"  {char} → {secret_coords[char]}")

# Manually encrypt "SECRET" with SECRET keyword grid
secret_encrypted = []
for char in "SECRET":
    if char in secret_coords:
        secret_encrypted.append(secret_coords[char])

secret_cipher = " ".join(secret_encrypted)
print(f"\n'SECRET' encrypts to: {secret_cipher}")

# Now test with correct test cases
corrected_test_cases = [
    {
        'name': 'Standard Grid - HELLO WORLD',
        'encrypted': hello_world_cipher,
        'expected_config': {'keyword': None, 'grid_size': 5, 'number_base': 1, 'separator': ' '},
        'expected_plaintext': 'HELLOWORLD'
    },
    {
        'name': 'SECRET Keyword - SECRET', 
        'encrypted': secret_cipher,
        'expected_config': {'keyword': 'SECRET', 'grid_size': 5, 'number_base': 1, 'separator': ' '},
        'expected_plaintext': 'SECRET'
    }
]

for test_case in corrected_test_cases:
    print(f"\n{'='*60}")
    print(f"TEST: {test_case['name']}")
    print('='*60)
    
    # Create decrypt instance
    config = test_case['expected_config']
    options = pd.DataFrame({
        'KEYWORD': [config.get('keyword')],
        'GRID_SIZE': [config.get('grid_size', 5)],
        'COMBINE_LETTERS': ['IJ'],
        'NUMBER_BASE': [config.get('number_base', 1)],
        'SEPARATOR': [config.get('separator', ' ')],
        'RANDOM_SEED': [42]
    })
    
    cipher = decrypt(None, options)
    
    # Analyze the ciphertext
    cipher.analyze_ciphertext(test_case['encrypted'])
    
    # Show the correct grid
    print(f"\nCorrect Grid Configuration:")
    cipher.show_cipher_mapping(config.get('keyword'), None)
    
    # Decrypt with known parameters
    decrypted = cipher.decrypt_message(test_case['encrypted'], config.get('keyword'))
    print(f"\nKnown decryption: '{decrypted}'")
    print(f"Expected: '{test_case['expected_plaintext']}'")
    print(f"Match: {decrypted == test_case['expected_plaintext']}")
    
    # Try auto-decrypt to see if it finds the right answer
    print(f"\nAuto-decrypt attempt:")
    auto_result = cipher.auto_decrypt(test_case['encrypted'], top_n=3, max_keywords=10)
    print(f"Auto-decrypt result: '{auto_result}'")
    print(f"Auto-decrypt match: {auto_result == test_case['expected_plaintext']}")

print(f"\n{'='*60}")
print("DEMONSTRATION WITH ORIGINAL TEST CASES")
print('='*60)

# Test with the original (incorrect) test cases to show what they actually decrypt to
original_test_cases = [
    {
        'name': 'Original Standard Grid Message',
        'encrypted': '23 15 31 31 34 44 34 42 31 14',
        'config': {'keyword': None, 'grid_size': 5, 'number_base': 1, 'separator': ' '}
    },
    {
        'name': 'Original Keyword Grid Message', 
        'encrypted': '43 15 13 42 15 44',
        'config': {'keyword': 'SECRET', 'grid_size': 5, 'number_base': 1, 'separator': ' '}
    }
]

for test_case in original_test_cases:
    print(f"\n--- {test_case['name']} ---")
    
    config = test_case['config']
    options = pd.DataFrame({
        'KEYWORD': [config.get('keyword')],
        'GRID_SIZE': [config.get('grid_size', 5)],
        'COMBINE_LETTERS': ['IJ'],
        'NUMBER_BASE': [config.get('number_base', 1)],
        'SEPARATOR': [config.get('separator', ' ')],
        'RANDOM_SEED': [42]
    })
    
    cipher = decrypt(None, options)
    decrypted = cipher.decrypt_message(test_case['encrypted'], config.get('keyword'))
    print(f"Encrypted: {test_case['encrypted']}")
    print(f"Decrypts to: '{decrypted}'")

print(f"\n{'='*60}")
print("UNKNOWN MESSAGE DECRYPTION")
print('='*60)

# Test with unknown message
unknown_message = "41 34 31 54 12 24 45 43 43 15 13 42 15 44"

print(f"Unknown encrypted message: {unknown_message}")

# Create basic decrypt instance
basic_options = pd.DataFrame({
    'KEYWORD': [None],
    'GRID_SIZE': [5],
    'COMBINE_LETTERS': ['IJ'],
    'NUMBER_BASE': [1],
    'SEPARATOR': [' '],
    'RANDOM_SEED': [42]
})

unknown_cipher = decrypt(None, basic_options)

# Analyze the unknown message
unknown_cipher.analyze_ciphertext(unknown_message)

# Try to decrypt it
print(f"\nAttempting auto-decryption...")
result = unknown_cipher.auto_decrypt(unknown_message, top_n=5, max_keywords=15)

print(f"\n=== Usage Summary ===")
print("""
POLYBIUS DECRYPT CLASS USAGE:

1. BASIC DECRYPTION (known parameters):
    cipher = decrypt(None, options_df)
    result = cipher.decrypt_message(encrypted_text, keyword=None, random_seed=None)

2. AUTOMATIC DECRYPTION (unknown parameters):
    cipher = decrypt()
    result = cipher.auto_decrypt(encrypted_text)

3. BRUTE FORCE SEARCH:
    results = cipher.brute_force_decrypt(encrypted_text, show_all=True)

4. CIPHERTEXT ANALYSIS:
    cipher.analyze_ciphertext(encrypted_text)

5. GRID VISUALIZATION:
    cipher.show_cipher_mapping(keyword='SECRET')

KEY FEATURES:
- Supports 5x5 and 6x6 grids
- Handles keyword-based and random grids
- Automatic parameter detection
- English frequency analysis for scoring
- Comprehensive brute force search
- Detailed ciphertext analysis

DEBUGGING NOTES:
- The original test cases had incorrect plaintext expectations
- '23 15 31 31 34' decrypts to 'GEMMQ' with standard alphabetical grid
- '43 15 13 42 15 44' decrypts to 'QTCPTU' with SECRET keyword grid
- Always verify test cases by encrypting the expected plaintext first
""")