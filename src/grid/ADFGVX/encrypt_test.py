#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/adfgvx/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt

print("=== ADFGVX Cipher Encrypt Class Example ===")

# Test different ADFGVX configurations
configurations = [
    # Basic configuration with standard keyword
    {'GRID_KEYWORD': [None], 'TRANS_KEYWORD': ['SECRET'], 'RANDOM_SEED': [42], 'SEPARATOR': [''], 'SHOW_STEPS': [False]},
    
    # With grid keyword
    {'GRID_KEYWORD': ['CIPHER'], 'TRANS_KEYWORD': ['KEYWORD'], 'RANDOM_SEED': [42], 'SEPARATOR': [' '], 'SHOW_STEPS': [False]},
    
    # Different random seed
    {'GRID_KEYWORD': [None], 'TRANS_KEYWORD': ['ADFGVX'], 'RANDOM_SEED': [123], 'SEPARATOR': ['-'], 'SHOW_STEPS': [False]},
    
    # Longer transposition keyword
    {'GRID_KEYWORD': ['POLYBIUS'], 'TRANS_KEYWORD': ['CRYPTOGRAPHY'], 'RANDOM_SEED': [789], 'SEPARATOR': [''], 'SHOW_STEPS': [False]},
]

test_messages = [
    "HELLO",
    "HELLO WORLD",
    "ATTACK AT DAWN", 
    "ADFGVX CIPHER",
    "SECRET MESSAGE",
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
]

for config_num, config in enumerate(configurations, 1):
    print(f"\n{'='*80}")
    print(f"CONFIGURATION {config_num}")
    print('='*80)
    
    # Create cipher instance
    options = pd.DataFrame(config)
    cipher = encrypt(None, options)  # Use default A-Z + 0-9 dictionary
    
    # Show cipher details
    cipher.show_cipher_mapping()
    
    # Show statistics
    stats = cipher.get_cipher_stats()
    print(f"\nCipher Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")
    
    # Test encryption
    print(f"\n=== Testing Messages ===")
    
    for message in test_messages[:3]:  # Test first 3 messages
        try:
            encrypted = cipher.encrypt_message(message)
            print(f"'{message}' -> '{encrypted}'")
                
        except Exception as e:
            print(f"'{message}' -> ERROR: {e}")

print(f"\n{'='*80}")
print("DETAILED DEMONSTRATION")
print('='*80)

# Detailed demonstration with a simple example
demo_config = {'GRID_KEYWORD': ['EXAMPLE'], 'TRANS_KEYWORD': ['SECRET'], 'RANDOM_SEED': [42], 'SEPARATOR': [' '], 'SHOW_STEPS': [True]}
demo_options = pd.DataFrame(demo_config)
demo_cipher = encrypt(None, demo_options)

demo_message = "HELLO WORLD"
print(f"Demonstrating ADFGVX encryption of '{demo_message}':")
demo_cipher.demonstrate_process(demo_message)

print(f"\n{'='*80}")
print("HOW ADFGVX CIPHER WORKS")
print('='*80)
print("""
The ADFGVX cipher is a fractionating transposition cipher that combines:

1. SUBSTITUTION PHASE:
    - Uses a 6×6 grid containing A-Z and 0-9 (36 characters)
    - Grid coordinates use letters A,D,F,G,V,X (not 1-6)
    - Each character becomes a 2-letter coordinate pair
    - Example: M in position (3,2) becomes "FD"

2. TRANSPOSITION PHASE:
    - Takes the substituted text and arranges it in rows
    - Number of columns = length of transposition keyword
    - Columns are read in alphabetical order of keyword letters
    - Example: Keyword "SECRET" → read columns S,C,E,R,T order

3. KEY COMPONENTS:
    - Grid Keyword: Determines arrangement of 36 characters in grid
    - Transposition Keyword: Determines column reading order
    - Both keywords provide significant cryptographic strength

4. HISTORICAL SIGNIFICANCE:
    - Used by German Army in WWI
    - Considered very secure for its time
    - Required both frequency analysis AND pattern recognition to break
    - Defeated by French cryptographers (Georges Painvin)

5. SECURITY FEATURES:
    - Double encipherment (substitution + transposition)
    - Large key space (36! × keyword permutations)
    - Resistant to simple frequency analysis
    - Breaks up character patterns through transposition

6. WEAKNESSES:
    - Vulnerable to statistical analysis of coordinate pairs
    - Transposition patterns can be detected with enough text
    - Grid arrangement might be partially recoverable
    - Requires relatively long messages to be truly secure

COMPARED TO SIMPLER CIPHERS:
- Much stronger than Caesar or Polybius alone
- Combines benefits of both substitution and transposition
- More complex to implement but significantly more secure
- Represents evolution toward modern cryptographic principles
""")

print(f"\n=== STEP-BY-STEP EXAMPLE ===")

# Simple step-by-step example
simple_config = {'GRID_KEYWORD': [None], 'TRANS_KEYWORD': ['KEY'], 'RANDOM_SEED': [1], 'SEPARATOR': [' '], 'SHOW_STEPS': [False]}
simple_options = pd.DataFrame(simple_config)
simple_cipher = encrypt(None, simple_options)

simple_message = "HELLO"
print(f"Simple example with message '{simple_message}' and keyword 'KEY':")
result = simple_cipher.demonstrate_process(simple_message)

print(f"\n=== ADFGVX vs Other Ciphers ===")
print("""
STRENGTH COMPARISON:

ADFGVX vs POLYBIUS:
- Polybius: Single substitution (A→11, B→12...)
- ADFGVX: Substitution + Transposition (A→AD→[rearranged])
- Security: ADFGVX much stronger due to double encipherment

ADFGVX vs PLAYFAIR:
- Playfair: Digraph substitution with single 5×5 grid
- ADFGVX: Monograph→digraph substitution + transposition
- Flexibility: ADFGVX handles numbers, more characters

ADFGVX vs FOUR-SQUARE:
- Four-square: Complex substitution with 4 grids
- ADFGVX: Single grid + transposition
- Implementation: ADFGVX simpler but still very secure

WHY ADFGVX WAS EFFECTIVE:
- Two-phase encryption hides both character and positional patterns
- Large keyspace makes brute force impractical
- Requires breaking both substitution AND transposition
- Grid keyword and transposition keyword are independent secrets
""")