#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/ceasar/encrypt.py'
#   Ceasar cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import sys
np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

        # Optional parent class
        self.parent = parent 

        # set dictionary
        self.original_dictionary = np.array(dictionary) # [A,B,C,D,E,F...]
        self.cipher_dict = None

        # unpack the dataframe of options configurable to this encryption method
        self.offset = int(opt_df['OFFSET'][0])

        self.wrap_separately = opt_df['WRAP_SEPARATELY'][0] # bool


    def set_cipher_dict(self, cipher_dict):
        # if there's a unique case of the dictionary
        self.cipher_dict = np.array(cipher_dict)


    def create_encryption_dictionary(self):
        if self.wrap_separately == True:
            self.create_advanced_cipher_dict()
            return


        # Use self.original_dictionary instead of undefined 'values'
        values = self.original_dictionary
        
        # Ensure input is a numpy array
        if not isinstance(values, np.ndarray):
            values = np.array(values)
       
        # Create shifted array using modular arithmetic
        shifted_values = np.roll(values, self.offset)
       
        # Set Dictionary
        self.cipher_dict = shifted_values
       

    def create_advanced_cipher_dict(self):
        # this handles the mixed case options

        values = self.original_dictionary
        
        if not isinstance(values, np.ndarray):
            values = np.array(values)
        
        if self.wrap_separately and len(values) > 0 and isinstance(values[0], str):
            # Separate uppercase and lowercase
            uppercase_mask = np.array([c.isupper() for c in values])
            lowercase_mask = np.array([c.islower() for c in values])
            
            shifted_values = values.copy()
            
            # Shift uppercase separately
            if np.any(uppercase_mask):
                uppercase_chars = values[uppercase_mask]
                uppercase_indices = np.where(uppercase_mask)[0]
                shifted_uppercase = np.roll(uppercase_chars, self.offset)
                shifted_values[uppercase_indices] = shifted_uppercase
            
            # Shift lowercase separately  
            if np.any(lowercase_mask):
                lowercase_chars = values[lowercase_mask]
                lowercase_indices = np.where(lowercase_mask)[0]
                shifted_lowercase = np.roll(lowercase_chars, self.offset)
                shifted_values[lowercase_indices] = shifted_lowercase
            
            # Handle other characters (non-alphabetic)
            other_mask = ~(uppercase_mask | lowercase_mask)
            if np.any(other_mask):
                other_chars = values[other_mask]
                other_indices = np.where(other_mask)[0]
                shifted_other = np.roll(other_chars, self.offset)
                shifted_values[other_indices] = shifted_other
        else:
            # Simple shift of entire array (fallback to basic method)
            shifted_values = np.roll(values, self.offset)
        
        # Set Dictionary
        self.cipher_dict = shifted_values

       
    def show_cipher_mapping(self, show_first_n=10):
        """Display the current cipher mapping"""
        print("Current cipher mapping:")
        print("Original: ", ''.join(self.original_dictionary[:show_first_n]))
        print("Cipher:   ", ''.join(self.cipher_dict[:show_first_n]))
        if len(self.original_dictionary) > show_first_n:
            print(f"... (showing first {show_first_n} of {len(self.original_dictionary)} characters)")



    def encrypt_message(self, text):
        # use self.original_dictionary and self.cipher_dict to encrypt the text
        # uses the CURRENT self.cipher_dict

        result = []
        for char in text:
            # Find the position of the character in original dictionary
            char_positions = np.where(self.original_dictionary == char)[0]
            
            if len(char_positions) > 0:
                # Character found in dictionary - replace with encrypted version
                position = char_positions[0]  # Get first match
                encrypted_char = self.cipher_dict[position]
                result.append(encrypted_char)
            else:
                # Character not in dictionary - keep it unchanged
                result.append(char)
        
        return ''.join(result)
    

