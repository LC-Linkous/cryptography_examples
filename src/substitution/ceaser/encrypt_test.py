#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/ceasar/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import pandas as pd

from encrypt import encrypt

print("=== Simple Caesar Cipher Class Example ===")

# Create a simple alphabet dictionary
alphabet = [chr(i) for i in range(65, 91)]  # A-Z
print("Original alphabet:", alphabet)

# Create options dataframe
options = pd.DataFrame({'OFFSET': [3],
                    'WRAP_SEPARATELY': [False]}) 

print("Offset:", options['OFFSET'][0])

# Create encryptor instance
cipher = encrypt(alphabet, options)

# use the basic dictionary because 'WRAP_SEPARATELY' is False
cipher.create_encryption_dictionary()

# Show the encryption mapping
print("\n=== Encryption Dictionary ===")
print("Original: ", ''.join(cipher.original_dictionary))
print("Encrypted:", ''.join(cipher.cipher_dict))

# Show individual mappings (first 10)
cipher.show_cipher_mapping(10)

# Test encryption
print("\n=== Encryption Examples ===")

test_messages = [
    "ABC",
    "HELLO",
    "WORLD", 
    "HELLO WORLD!",  # Contains space (not in dictionary)
    "ABC123",       # Contains numbers (not in dictionary)
    "ZEBRA"         # Tests wraparound
]

for message in test_messages:
    encrypted = cipher.encrypt_message(message)
    print(f"'{message}' -> '{encrypted}'")

print("\n=== Different Offsets ===")

# Test with different offsets
offsets = [1, 5, 13, 25, -1]

for offset in offsets:
    opt_df =  pd.DataFrame({'OFFSET': [offset],
                    'WRAP_SEPARATELY': [False]}) 
    test_cipher = encrypt(alphabet, opt_df)
    test_cipher.create_encryption_dictionary()

    encrypted = test_cipher.encrypt_message("HELLO")
    print(f"Offset {offset:2d}: 'HELLO' -> '{encrypted}'")

print("\n=== Extended Alphabet Example ===")

# Test with lowercase included
extended_alphabet = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)]  # A-Z + a-z
print("Extended alphabet length:", len(extended_alphabet))

ext_options = pd.DataFrame({'OFFSET': [3],
                    'WRAP_SEPARATELY': [False]}) 
ext_cipher = encrypt(extended_alphabet, ext_options)
ext_cipher.create_encryption_dictionary()

test_text = "Hello World"
encrypted_text = ext_cipher.encrypt_message(test_text)
print(f"Extended: '{test_text}' -> '{encrypted_text}'")

print("\n=== How It Works ===")
print("""
1. Original dictionary: ['A', 'B', 'C', 'D', 'E', 'F', ...]
2. With offset 3, cipher dictionary becomes: ['D', 'E', 'F', 'G', 'H', 'I', ...]
3. When encrypting:
    - Find 'A' at position 0 in original dictionary
    - Replace with character at position 0 in cipher dictionary ('D')
    - Find 'B' at position 1 in original dictionary  
    - Replace with character at position 1 in cipher dictionary ('E')
    - And so on...
4. Characters not in dictionary (like spaces, numbers) remain unchanged
""")