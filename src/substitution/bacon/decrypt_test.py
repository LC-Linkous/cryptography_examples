

#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/bacon/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

from decrypt import decrypt


print("=== Baconian Cipher Brute Force Decryptor ===\n")

# Create brute force decryptor

decryptor = decrypt(dictionary=None, lang_freq=None) # dont have a custom dictionary, and no custom language frequency

# Test with some encrypted Baconian messages
test_cases = [
    # "HELLO" with A/B symbols, 26-letter variant
    ("AABBBAABAAABABBABABBABBBA", "Expected: HELLO"),
    
    # "SECRET" with 0/1 symbols, 26-letter variant
    ("100100010000010100010010010011", "Expected: SECRET"),
    
    # "BACON" with ./- symbols (. = 0, - = 1)
    ("....-........-..---..--.-", "Expected: BACON"),
    
    # "TEST" with A/B symbols
    ("BAABBAABAABAABABAABB", "Expected: TEST"),
]

for i, (encrypted_msg, expected) in enumerate(test_cases, 1):
    print(f"\n{'='*80}")
    print(f"TEST CASE {i}: '{encrypted_msg}'")
    print(f"({expected})")
    print('='*80)
    
    # Try brute force decryption
    best_decryption = decryptor.auto_decrypt(encrypted_msg, top_n=3)
    
    print(f"Most likely decryption: '{best_decryption}'")

print("\n=== How the Brute Force Attack Works ===")
print("""
The Baconian cipher brute force attack works by:

1. SYMBOL IDENTIFICATION:
    - Analyzes character frequency to identify the two symbols used
    - Tests common symbol pairs (A/B, 0/1, ./-, etc.)
    - Validates that symbols appear in proper ratios

2. STRUCTURE VALIDATION:
    - Checks if cipher text length is divisible by 5
    - Verifies reasonable distribution of both symbols
    - Confirms patterns consistent with Baconian encoding

3. VARIANT TESTING:
    - Tests both 24-letter variant (I=J, U=V combined)
    - Tests 26-letter variant (all letters separate)

4. DECRYPTION SCORING:
    - Uses English letter frequency analysis
    - Looks for common English words
    - Ranks results by linguistic plausibility

LIMITATIONS:
- Requires the original message to be in English
- Works best with longer messages (more statistical data)
- May struggle if symbols are not clearly identifiable
- Assumes standard Baconian encoding (5-bit codes)

TIPS FOR BETTER RESULTS:
- Clean the input (remove spaces/punctuation if not part of cipher)
- Ensure exactly 2 symbols are used in the cipher portion
- Longer messages generally give better results
""")