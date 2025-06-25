#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/polybius/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt

print("=== Polybius Square Cipher Class Example ===")

# Test different Polybius configurations
configurations = [
    # Standard 5x5 grid with I/J combined
    {'KEYWORD': [None], 'GRID_SIZE': [5], 'COMBINE_LETTERS': ['IJ'], 'NUMBER_BASE': [1], 'SEPARATOR': [' '], 'RANDOM_SEED': [7]},
    
    # Keyword-based 5x5 grid
    {'KEYWORD': ['SECRET'], 'GRID_SIZE': [5], 'COMBINE_LETTERS': ['IJ'], 'NUMBER_BASE': [1], 'SEPARATOR': [' '], 'RANDOM_SEED': [12]},
    
    # Zero-based numbering
    {'KEYWORD': [None], 'GRID_SIZE': [5], 'COMBINE_LETTERS': ['IJ'], 'NUMBER_BASE': [0], 'SEPARATOR': ['-'], 'RANDOM_SEED': [85]},
    
    # 6x6 grid with numbers
    {'KEYWORD': [None], 'GRID_SIZE': [6], 'COMBINE_LETTERS': [''], 'NUMBER_BASE': [1], 'SEPARATOR': [' '], 'RANDOM_SEED': [21]},
    
    # Random arrangement
    {'KEYWORD': [None], 'GRID_SIZE': [5], 'COMBINE_LETTERS': ['IJ'], 'NUMBER_BASE': [1], 'SEPARATOR': [' '], 'RANDOM_SEED': [42]},
]

test_messages = [
    "HELLO",
    "HELLO WORLD",
    "ATTACK AT DAWN", 
    "POLYBIUS SQUARE",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG",
    "SECRET MESSAGE"
]

for config_num, config in enumerate(configurations, 1):
    print(f"\n{'='*80}")
    print(f"CONFIGURATION {config_num}")
    print('='*80)
    
    # Create cipher instance
    options = pd.DataFrame(config)
    cipher = encrypt(None, options)  # No dictionary needed - we create our own
    cipher.create_cipher_grid()
    
    # Show cipher details
    cipher.show_cipher_mapping()
    
    # Show statistics
    stats = cipher.get_grid_stats()
    print(f"\nGrid Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test encryption/decryption
    print(f"\n=== Testing Messages ===")
    
    for message in test_messages[:3]:  # Test first 3 messages
        try:
            encrypted = cipher.encrypt_message(message)
            decrypted = cipher.decrypt_message(encrypted)
            
            match = message.replace('J', 'I') == decrypted if config['COMBINE_LETTERS'][0] == 'IJ' else message == decrypted
            print(f"'{message}' -> '{encrypted}' -> '{decrypted}' (Match: {match})")
            
            if not match:
                print(f"  Note: J→I substitution expected with IJ combination")
                
        except Exception as e:
            print(f"'{message}' -> ERROR: {e}")

print(f"\n{'='*80}")
print("DETAILED GRID EXAMPLES")
print('='*80)

# Show detailed examples with different keywords
keywords = ['CIPHER', 'POLYBIUS', 'GRID', 'EXAMPLE']

for keyword in keywords:
    print(f"\n--- Keyword: '{keyword}' ---")
    
    demo_config = {'KEYWORD': [keyword], 'GRID_SIZE': [5], 'COMBINE_LETTERS': ['IJ'], 'NUMBER_BASE': [1], 'SEPARATOR': [' '], 'RANDOM_SEED': [31]}
    demo_options = pd.DataFrame(demo_config)
    demo_cipher = encrypt(None, demo_options)
    demo_cipher.create_cipher_grid()
    
    demo_cipher.show_cipher_mapping(show_coordinates=False)
    
    # Test with the keyword as message
    test_msg = keyword
    encrypted = demo_cipher.encrypt_message(test_msg)
    decrypted = demo_cipher.decrypt_message(encrypted)
    print(f"Test: '{test_msg}' -> '{encrypted}' -> '{decrypted}'")

print(f"\n=== How Polybius Square Works ===")
print("""
The Polybius Square is a substitution cipher that uses a grid to encode letters:

1. GRID STRUCTURE:
    - 5×5 grid holds 25 letters (I/J combined or U/V combined)
    - 6×6 grid can hold 36 characters (A-Z + 0-9)
    - Each position has row,column coordinates

2. ENCRYPTION PROCESS:
    - Find letter in grid
    - Replace with its coordinates (row, column)
    - A in position (1,1) becomes "11"
    - B in position (1,2) becomes "12"

3. KEY VARIATIONS:
    - Standard: Alphabetical arrangement
    - Keyword: Keyword first, then remaining letters
    - Random: Shuffled arrangement (with seed for reproducibility)

4. COORDINATE SYSTEMS:
    - 1-based: Coordinates start from 1 (traditional)
    - 0-based: Coordinates start from 0 (modern/programming)

5. OUTPUT FORMATS:
    - Separated: "11 15 31 31 34" (with spaces)
    - Concatenated: "1115313134" (no separators)
    - Custom separator: "11-15-31-31-34"

ADVANTAGES:
- Simple to understand and implement
- Visual grid makes encryption process clear
- Can be done by hand with paper and pencil
- Good introduction to coordinate-based ciphers

DISADVANTAGES:
- Vulnerable to frequency analysis (coordinates reveal patterns)
- Grid arrangement might be guessable
- Limited key space (especially with keywords)
- Doubled text length (each letter becomes 2 digits)

SECURITY ANALYSIS:
- Key space: 25! for random 5×5 grid (very large)
- Keyword grids: Much smaller effective key space
- Frequency analysis: Works on coordinate pairs
- Pattern recognition: Repeated letters show as repeated coordinates
""")

print(f"\n=== Polybius vs Other Ciphers ===")
print("""
Comparison with other cipher types:

POLYBIUS vs CAESAR:
- Polybius: Substitution with coordinates (A→11, B→12...)
- Caesar: Simple shift (A→D, B→E...)
- Complexity: Polybius higher (grid arrangement vs single shift)

POLYBIUS vs MONOALPHABETIC:
- Polybius: Structured substitution (coordinates)
- Monoalphabetic: Random substitution (A→M, B→X...)
- Pattern: Polybius coordinates show structure, mono appears random

POLYBIUS vs PLAYFAIR:
- Polybius: Single letter → 2 digits
- Playfair: Letter pair → letter pair (complex rules)
- Implementation: Polybius much simpler

GRID CIPHER FOUNDATION:
Polybius Square demonstrates core concepts used in:
- Four-square cipher
- Two-square cipher  
- Bifid cipher
- Trifid cipher
- Modern coordinate-based systems
""")