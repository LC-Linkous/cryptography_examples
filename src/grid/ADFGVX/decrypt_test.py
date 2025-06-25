#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/adfgvx/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd
from decrypt import decrypt

    
print("=== ADFGVX Cipher Decrypt Class Example ===")

# Create proper test cases by demonstrating encryption then decryption
print("\n=== CREATING PROPER TEST CASES ===")

# Let's manually create a simple ADFGVX encryption to test with
# Using the same grid and keyword as our decrypt example

# Create decrypt instance with known parameters
test_options = pd.DataFrame({
    'GRID_KEYWORD': [None],
    'TRANS_KEYWORD': ['KEY'],  # Shorter keyword for simpler test
    'RANDOM_SEED': [42],
    'SEPARATOR': [' ']
})

test_cipher = decrypt(None, test_options)

print("Test cipher configuration:")
test_cipher.show_cipher_mapping()

# Manual example: Let's say we want to encrypt "HELLO"
# Using the grid above, we can manually trace the encryption
print(f"\n=== MANUAL ENCRYPTION TRACE (for testing) ===")
print("Let's trace how 'HELLO' would be encrypted with this configuration:")
print("Grid lookup (manual):")

# Look up each character in our test grid
test_message = "HELLO"
manual_coords = []

# We need to create the grid first to see the mappings
test_cipher.create_substitution_grid(None, 42)

print("Character → Coordinate mapping:")
for char in test_message:
    if char in test_cipher.coordinate_map:
        coord = test_cipher.coordinate_map[char]
        manual_coords.append(coord)
        print(f"  {char} → {coord}")

substituted_manual = ''.join(manual_coords)
print(f"After substitution: '{substituted_manual}'")

# Now simulate the transposition with keyword "KEY"
# KEY has order: E(1), K(2), Y(3) → positions 2, 0, 1 in "KEY"
key = "KEY"
key_order = [2, 0, 1]  # E=1st, K=2nd, Y=3rd alphabetically

print(f"Transposition keyword: '{key}'")
print(f"Alphabetical order: {key_order}")

# Arrange in grid (3 columns for KEY)
padded = substituted_manual
while len(padded) % 3 != 0:
    padded += 'X'

print(f"Padded substituted text: '{padded}'")

# Create grid
rows = len(padded) // 3
grid = []
for i in range(rows):
    row = padded[i*3:(i+1)*3]
    grid.append(list(row))
    print(f"Row {i+1}: {' '.join(row)}")

# Read columns in alphabetical order of keyword
columns = []
for col_idx in [1, 0, 2]:  # E, K, Y positions
    col = ''.join(grid[row][col_idx] for row in range(rows))
    columns.append(col)
    print(f"Column {key[col_idx]}: '{col}'")

simulated_encrypted = ' '.join(columns)
print(f"Simulated encrypted result: '{simulated_encrypted}'")

# Now test our decryption
print(f"\n=== TESTING DECRYPTION ===")

try:
    decrypted = test_cipher.decrypt_message(simulated_encrypted, None, 'KEY', 42)
    print(f"Decrypted result: '{decrypted}'")
    print(f"Original message: '{test_message}'")
    print(f"Match: {decrypted.replace('X', '') == test_message}")
except Exception as e:
    print(f"Decryption failed: {e}")

# Test the step-by-step demonstration
print(f"\n=== STEP-BY-STEP DEMONSTRATION ===")
try:
    demo_result = test_cipher.demonstrate_decryption(simulated_encrypted, None, 'KEY', 42)
    print(f"Demo result: '{demo_result}'")
except Exception as e:
    print(f"Demonstration failed: {e}")

print(f"\n{'='*60}")
print("TESTING WITH ORIGINAL SAMPLE")
print('='*60)

# Test with the original problematic sample
original_sample = "DGFX AVAD GFVX DDFA"

print(f"Original sample: '{original_sample}'")

# Try with a 4-letter keyword to match the 4 columns
four_letter_options = pd.DataFrame({
    'GRID_KEYWORD': [None],
    'TRANS_KEYWORD': ['CODE'],  # 4-letter keyword
    'RANDOM_SEED': [42],
    'SEPARATOR': [' ']
})

four_cipher = decrypt(None, four_letter_options)

print("Trying with 4-letter transposition keyword 'CODE':")
try:
    result = four_cipher.decrypt_message(original_sample, None, 'CODE', 42)
    print(f"Decryption result: '{result}'")
except Exception as e:
    print(f"Decryption failed: {e}")

# Auto-decrypt with more appropriate settings
print(f"\n=== AUTO-DECRYPT WITH 4-COLUMN SAMPLE ===")
try:
    auto_result = four_cipher.auto_decrypt(original_sample, top_n=5, max_keywords=8)
    print(f"Best auto-decrypt result: '{auto_result}'")
except Exception as e:
    print(f"Auto-decrypt failed: {e}")

print(f"\n=== USAGE SUMMARY ===")
print("""
ADFGVX DECRYPT CLASS USAGE:

1. BASIC DECRYPTION (known parameters):
    cipher = decrypt(None, options_df)
    result = cipher.decrypt_message(encrypted_text, grid_keyword=None, trans_keyword='SECRET')

2. AUTOMATIC DECRYPTION (unknown parameters):
    cipher = decrypt()
    result = cipher.auto_decrypt(encrypted_text)

3. STEP-BY-STEP DEMONSTRATION:
    cipher.demonstrate_decryption(encrypted_text, grid_keyword, trans_keyword)

KEY INSIGHTS FROM TESTING:
- Column count must match transposition keyword length
- ADFGVX requires both substitution grid AND transposition keyword to be correct
- Padding with 'X' is removed during decryption
- Auto-decrypt tries multiple keyword combinations systematically

DEBUGGING TIPS:
- Check that number of columns matches keyword length
- Verify that all characters are valid ADFGVX letters
- Consider that some historical ADFGVX used different separators
- Grid keyword and transposition keyword are independent

COMMON ISSUES:
- Mismatched column count vs keyword length → Wrong transposition keyword
- Invalid coordinate pairs → Wrong grid arrangement or corrupted text
- Poor English score → Need to try more keyword combinations
""")