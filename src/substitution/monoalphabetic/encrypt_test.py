#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/monoalphabetic/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 23, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt

print("=== Monoalphabetic Cipher Class Example ===")

# Create a simple alphabet dictionary
alphabet = [chr(i) for i in range(65, 91)]  # A-Z
print("Original alphabet:", ''.join(alphabet))

print("\n=== Random Key Generation ===")

# Create options dataframe for random key
opt_df = pd.DataFrame({
    'CUSTOM_KEY': [None],
    'SEED': [42],  # For reproducible results
    'WRAP_SEPARATELY': [False]
}) 

print("Seed:", opt_df['SEED'][0])

# Create encryptor instance
cipher_random = encrypt(alphabet, opt_df)
cipher_random.create_encryption_dictionary()

# Show the encryption mapping
print("\n=== Random Encryption Dictionary ===")
print("Original: ", ''.join(cipher_random.original_dictionary))
print("Encrypted:", ''.join(cipher_random.cipher_dict))
print("Full key: ", cipher_random.get_full_key())

# Show individual mappings (first 10)
cipher_random.show_cipher_mapping(10)

print("\n=== Custom Key Example ===")

# Example custom key (alphabet backwards)
custom_key = ''.join([chr(90-i) for i in range(26)])  # ZYXWVUTSRQPONMLKJIHGFEDCBA
print("Custom key:", custom_key)

options_custom = pd.DataFrame({
    'CUSTOM_KEY': [custom_key],
    'SEED': [15],
    'WRAP_SEPARATELY': [False]
})

cipher_custom = encrypt(alphabet, options_custom)
cipher_custom.create_encryption_dictionary()

print("\nCustom key mapping:")
cipher_custom.show_cipher_mapping(26)  # Show all mappings

# Test encryption
print("\n=== Encryption Examples ===")

test_messages = [
    "ABC",
    "HELLO",
    "WORLD", 
    "HELLO WORLD",  # Contains space (not in dictionary)
    "ABC123",       # Contains numbers (not in dictionary)
    "ATTACKATDAWN"  # Classic cryptography example
]




print("Using random key (seed=42):")
for message in test_messages:
    encrypted = cipher_random.encrypt_message(message)
    print(f"'{message}' -> '{encrypted}'")

print("\nUsing custom key (alphabet backwards):")
for message in test_messages:
    encrypted = cipher_custom.encrypt_message(message)
    print(f"'{message}' -> '{encrypted}'")

print("\n=== Different Seeds ===")

# Test with different seeds
seeds = [1, 100, 999, 12345]

for seed in seeds:
    opt_df = pd.DataFrame({
        'CUSTOM_KEY': [None],
        'SEED': [seed],
        'WRAP_SEPARATELY': [False]
    }) 
    test_cipher = encrypt(alphabet, opt_df)
    test_cipher.create_encryption_dictionary()

    encrypted = test_cipher.encrypt_message("HELLO")
    key = test_cipher.get_full_key()
    print(f"Seed {seed:5d}: 'HELLO' -> '{encrypted}' (Key: {key[:10]}...)")

print("\n=== Extended Alphabet Example ===")

# Test with lowercase included
extended_alphabet = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)]  # A-Z + a-z
print("Extended alphabet length:", len(extended_alphabet))

ext_options = pd.DataFrame({
    'CUSTOM_KEY': [None],
    'SEED': [42],
    'WRAP_SEPARATELY': [False]
}) 
ext_cipher = encrypt(extended_alphabet, ext_options)
ext_cipher.create_encryption_dictionary()

test_text = "Hello World"
encrypted_text = ext_cipher.encrypt_message(test_text)
print(f"Extended: '{test_text}' -> '{encrypted_text}'")

print("\n=== Separate Case Handling ===")

# Test wrap_separately option
sep_options = pd.DataFrame({
    'CUSTOM_KEY': [None],
    'SEED': [42],
    'WRAP_SEPARATELY': [True]
})
sep_cipher = encrypt(extended_alphabet, sep_options)
sep_cipher.create_encryption_dictionary()

test_text = "Hello World"
encrypted_sep = sep_cipher.encrypt_message(test_text)
print(f"Separate case: '{test_text}' -> '{encrypted_sep}'")

print("\n=== How Monoalphabetic Cipher Works ===")
print("""
1. Original dictionary: ['A', 'B', 'C', 'D', 'E', 'F', ...]
2. Create substitution by either:
    - Shuffling the alphabet randomly (with optional seed for reproducibility)
    - Using a custom key provided by the user
3. Each letter maps to exactly one other letter (1:1 relationship)
4. Unlike Caesar cipher, there's no mathematical relationship between letters
5. Example mapping: A->M, B->X, C->K, D->P, etc.
6. Characters not in dictionary (spaces, numbers, punctuation) remain unchanged

Security notes:
- Much stronger than Caesar cipher (26! possible keys vs 26)
- Vulnerable to frequency analysis for longer texts
- Can be broken with sufficient ciphertext and statistical analysis
""")

print("\n=== Key Management ===")
print("""
Key formats:
- Random generation: Use SEED for reproducible keys, None for truly random
- Custom key: Provide exact substitution as string (must contain all original chars)
- Mixed case: WRAP_SEPARATELY=True handles upper/lowercase independently

Example custom keys:
- Alphabet backwards: 'ZYXWVUTSRQPONMLKJIHGFEDCBA'
- Keyword-based: Start with keyword, then remaining letters
- Random with seed: Reproducible "random" substitutions
""")