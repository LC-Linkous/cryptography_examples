#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/rail_fence/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd
from decrypt import decrypt

print("=== Rail Fence Cipher Brute Force Decryptor ===\n")

# Create brute force decryptor
decryptor = decrypt()

# Test with some encrypted Rail Fence messages
# These were created using the encrypt.py with known rail counts
test_cases = [
    # "HELLOWORLD" with 3 rails = "HOLELWRDLO"  
    ("HOLELWRDLO", "Expected: HELLOWORLD (3 rails)"),
    
    # "ATTACKATDAWN" with 4 rails = "AATKTNTCDWAA"
    ("AATKTNTCDWAA", "Expected: ATTACKATDAWN (4 rails)"),
    
    # "MEETMEATMIDNIGHT" with 3 rails = "MMMIETETINGTEADH"
    ("MMMIETETINGTEADH", "Expected: MEETMEATMIDNIGHT (3 rails)"),
    
    # "RAILFENCECIPHER" with 2 rails = "RIFNEIHRALECCPE"
    ("RIFNEIHRALECCPE", "Expected: RAILFENCECIPHER (2 rails)"),
    
    # "THEQUICKBROWNFOX" with 5 rails = "TBHKRXECOOQIWFUN"
    ("TBHKRXECOOQIWFUN", "Expected: THEQUICKBROWNFOX (5 rails)"),
]

for i, (encrypted_msg, expected) in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"TEST CASE {i}: '{encrypted_msg}'")
    print(f"({expected})")
    print('='*80)
    
    # Try brute force decryption
    best_decryption = decryptor.auto_decrypt(encrypted_msg, max_rails=15, top_n=3)
    
    print(f"Most likely decryption: '{best_decryption}'")

print("\n" + "="*80)
print("DETAILED ANALYSIS EXAMPLE")
print("="*80)

# Show detailed analysis for one example
example_cipher = "HOLELWRDLO"
print(f"Detailed analysis of: '{example_cipher}'")
print("(Correct encryption of 'HELLOWORLD' with 3 rails)")

# Test specific rail counts
for rails in [2, 3, 4, 5]:
    decryptor.show_decryption_analysis(example_cipher, rails)
    print()

print("=== How Rail Fence Brute Force Works ===")
print("""
Rail Fence cipher brute force is different from substitution ciphers:

1. SMALL KEY SPACE:
    - Only need to try different numbers of rails (typically 2-20)
    - For text of length N, maximum useful rails is N
    - Much smaller than substitution cipher key spaces

2. EXHAUSTIVE SEARCH:
    - Can try EVERY possible key (number of rails)
    - No need for heuristic optimization like SA or GA
    - Guaranteed to find the correct solution if it exists

3. PATTERN ANALYSIS:
    - Each rail count creates a specific zigzag pattern
    - Pattern period = 2*(rails-1) for rails > 2
    - Rail distribution shows how characters are spread

4. SCORING SYSTEM:
    - Uses same English frequency analysis as other ciphers
    - Bigrams and trigrams help identify correct decryption
    - Vowel distribution analysis
    - Consonant cluster penalties

5. SPEED ADVANTAGE:
    - Each decryption attempt is just character rearrangement
    - No complex optimization needed
    - Can test all possibilities very quickly

LIMITATIONS:
- Still requires English text for scoring to work
- Very short texts may not have enough statistical information
- Multiple rail counts might produce plausible-looking results

EDUCATIONAL VALUE:
- Shows difference between small and large key spaces
- Demonstrates why transposition ciphers are vulnerable
- Illustrates the power of exhaustive search when feasible
""")