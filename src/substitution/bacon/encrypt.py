#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/bacon/encrypt.py'
#   Baconian cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

        # Optional parent class
        self.parent = parent 

        # set dictionary - for Baconian, this should be A-Z (26 letters)
        self.original_dictionary = np.array(dictionary)
        self.cipher_dict = None

        # unpack the dataframe of options configurable to this encryption method
        # these can be ANY 2 letters
        # unlike most of the opt_df configs, if there is no indicator or it's in the wrong format
        # were going to use a default. This could be a bit prettier, but it does the job
        self.symbol_a = opt_df['SYMBOL_A'][0] if 'SYMBOL_A' in opt_df.columns else 'A'
        self.symbol_b = opt_df['SYMBOL_B'][0] if 'SYMBOL_B' in opt_df.columns else 'B'
        
        # Baconian cipher variant (True = I/J and U/V combined, False = separate)  
        self.variant_24 = opt_df['VARIANT_24'][0] if 'VARIANT_24' in opt_df.columns else False
        
        # Create the cipher dictionary
        self.create_encryption_dictionary()


    def set_cipher_dict(self, cipher_dict):
        # if there's a unique case of the dictionary
        self.cipher_dict = cipher_dict


    def create_encryption_dictionary(self):
        # Create Baconian cipher dictionary mapping letters to 5-bit codes
        # The 24 bit variant has I&J, and U&V as pairs. Sometimes, if there is 
        # a 5x5 grid, just 1 set will be paired. Other times, both are paired
        # 
                
        if self.variant_24:
            # 24-letter variant: I/J combined, U/V combined
            baconian_codes = {
                'A': '00000', 'B': '00001', 'C': '00010', 'D': '00011', 'E': '00100',
                'F': '00101', 'G': '00110', 'H': '00111', 'I': '01000', 'J': '01000',  # I=J
                'K': '01001', 'L': '01010', 'M': '01011', 'N': '01100', 'O': '01101',
                'P': '01110', 'Q': '01111', 'R': '10000', 'S': '10001', 'T': '10010',
                'U': '10011', 'V': '10011',  # U=V
                'W': '10100', 'X': '10101', 'Y': '10110', 'Z': '10111'
            }
        else:
            # 26-letter variant: all letters separate
            baconian_codes = {
                'A': '00000', 'B': '00001', 'C': '00010', 'D': '00011', 'E': '00100',
                'F': '00101', 'G': '00110', 'H': '00111', 'I': '01000', 'J': '01001',
                'K': '01010', 'L': '01011', 'M': '01100', 'N': '01101', 'O': '01110',
                'P': '01111', 'Q': '10000', 'R': '10001', 'S': '10010', 'T': '10011',
                'U': '10100', 'V': '10101', 'W': '10110', 'X': '10111', 'Y': '11000', 'Z': '11001'
            }
        
        # Convert binary codes to symbol codes
        cipher_dict = {}
        for letter, binary_code in baconian_codes.items():
            symbol_code = binary_code.replace('0', self.symbol_a).replace('1', self.symbol_b)
            cipher_dict[letter] = symbol_code
        
        self.cipher_dict = cipher_dict
        
        # Also create reverse dictionary for decryption
        self.reverse_cipher_dict = {v: k for k, v in cipher_dict.items()}


    def show_cipher_mapping(self, show_first_n=10):
        # This shows the  current cipher mapping
        # this is mostly used for display/preview purposes

        print(f"Baconian cipher mapping (using '{self.symbol_a}' and '{self.symbol_b}'):")
        print(f"Variant: {'24-letter (I=J, U=V)' if self.variant_24 else '26-letter (all separate)'}")
        
        count = 0
        for letter in sorted(self.cipher_dict.keys()):
            if count >= show_first_n:
                print("...")
                break
            print(f"  {letter} -> {self.cipher_dict[letter]}")
            count += 1


    def encrypt_message(self, text):
        result = []
        
        for char in text.upper():  # Convert to uppercase
            if char in self.cipher_dict:
                # Character found in dictionary - replace with Baconian code
                result.append(self.cipher_dict[char])
            else:
                # Character not in dictionary - keep it unchanged or skip
                if char.isalpha():
                    # Unknown letter - this shouldn't happen with proper setup
                    result.append(f"[{char}]")  # Mark unknown letters
                else:
                    # Non-letter (space, punctuation, etc.) - keep as is
                    result.append(char)
        
        return ''.join(result)
    
