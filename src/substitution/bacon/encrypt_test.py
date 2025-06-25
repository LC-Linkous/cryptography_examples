#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/bacon/encrypt_test.py'
#   Some AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt

print("=== Baconian Cipher Class Example ===")
# Note that this format is largely shared between ciphers

# Create alphabet dictionary (A-Z)
alphabet = [chr(i) for i in range(65, 91)]  # A-Z
print("Original alphabet:", ''.join(alphabet))

print("\n=== 26-Letter Variant (Default) ===")

# Create options dataframe - 26-letter variant
options_26 = pd.DataFrame({
    'SYMBOL_A': ['A'],
    'SYMBOL_B': ['B'], 
    'VARIANT_24': [False]
})

# Create encryptor instance
cipher_26 = encrypt(alphabet, options_26)

# Show the encryption mapping
print("\n=== Encryption Dictionary ===")
cipher_26.show_cipher_mapping(10)

# Test encryption
print("\n=== Encryption Examples ===")

test_messages = [
    "ABC",
    "HELLO",
    "WORLD", 
    "HELLO WORLD",  # Contains space
    "ABC123",       # Contains numbers
    "ZEBRA"
]

for message in test_messages:
    encrypted = cipher_26.encrypt_message(message)
    print(f"'{message}' -> '{encrypted}'")

print("\n=== 24-Letter Variant (I=J, U=V) ===")

# Create options dataframe - 24-letter variant
options_24 = pd.DataFrame({
    'SYMBOL_A': ['A'],
    'SYMBOL_B': ['B'], 
    'VARIANT_24': [True]
})

cipher_24 = encrypt(alphabet, options_24)

print("24-letter variant mapping (first 10):")
cipher_24.show_cipher_mapping(10)

test_text = "HELLO WORLD"
encrypted_24 = cipher_24.encrypt_message(test_text)
print(f"\n24-letter: '{test_text}' -> '{encrypted_24}'")

print("\n=== Different Symbol Sets ===")

symbol_sets = [
    ('0', '1'),
    ('.', '-'),
    ('*', '#'),
    ('X', 'O')
]

for sym_a, sym_b in symbol_sets:
    opt_df = pd.DataFrame({
        'SYMBOL_A': [sym_a],
        'SYMBOL_B': [sym_b], 
        'VARIANT_24': [False]
    })
    
    test_cipher = encrypt(alphabet, opt_df)
    encrypted = test_cipher.encrypt_message("HELLO")
    print(f"Symbols '{sym_a}'/'{sym_b}': 'HELLO' -> '{encrypted}'")

print("\n=== Comparison: 24 vs 26 Letter Variants ===")

test_cases = ["I", "J", "U", "V", "JUST", "QUIZ"]

print(f"{'Text':<6} {'26-letter':<30} {'24-letter':<30}")
print("-" * 70)

for text in test_cases:
    result_26 = cipher_26.encrypt_message(text)
    result_24 = cipher_24.encrypt_message(text)
    print(f"{text:<6} {result_26:<30} {result_24:<30}")

print("\n=== How Baconian Cipher Works ===")
print("""
The Baconian cipher encodes each letter as a 5-bit binary code using two symbols.

26-letter variant:
- Each of the 26 letters gets a unique 5-bit code
- A=00000, B=00001, C=00010, ..., Z=11001

24-letter variant (traditional):
- I and J share the same code
- U and V share the same code
- Uses only 24 unique codes

The binary codes are then converted to your chosen symbols:
- 0 becomes SYMBOL_A (default 'A')
- 1 becomes SYMBOL_B (default 'B')

Example: 'H' = 00111 = AABBB (with A/B symbols)
""")

print("\n=== Advanced Example: Hidden Message ===")

# Create cipher with binary symbols for steganography
binary_options = pd.DataFrame({
    'SYMBOL_A': ['0'],
    'SYMBOL_B': ['1'], 
    'VARIANT_24': [False]
})

binary_cipher = encrypt(alphabet, binary_options)

secret_message = "SECRET"
binary_encoded = binary_cipher.encrypt_message(secret_message)
print(f"Secret message '{secret_message}' in binary: {binary_encoded}")
print("This could be hidden in other text by using different formatting, fonts, etc.")