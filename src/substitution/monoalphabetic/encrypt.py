#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/monoalphabetic/encrypt.py'
#   Monoalphabetic cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 23, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import sys
import random
np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

        # Optional parent class
        self.parent = parent 

        # set dictionary
        self.original_dictionary = np.array(dictionary) # [A,B,C,D,E,F...]
        self.cipher_dict = None

        # unpack the dataframe of options configurable to this encryption method
        # these do not have defaults
        self.custom_key = opt_df['CUSTOM_KEY'][0] 
        self.seed = int(opt_df['SEED'][0])
        self.wrap_separately = opt_df['WRAP_SEPARATELY'][0] 


    def set_cipher_dict(self, cipher_dict):
        # if there's a unique case of the dictionary
        self.cipher_dict = np.array(cipher_dict)


    def create_encryption_dictionary(self):
        # which dictionary func is determined by if the wrapping is accounted for
        if self.wrap_separately == True:
            self.create_advanced_cipher_dict()
            return

        # Use self.original_dictionary
        values = self.original_dictionary
        
        # Ensure input is a numpy array
        if not isinstance(values, np.ndarray):
            values = np.array(values)

        if self.custom_key is not None:
            # Use provided custom key
            if len(self.custom_key) != len(values):
                raise ValueError(f"Custom key length ({len(self.custom_key)}) must match dictionary length ({len(values)})")
            
            # Validate that custom key contains all original characters (no duplicates/missing)
            if set(self.custom_key) != set(values):
                raise ValueError("Custom key must contain exactly the same characters as the original dictionary")
            
            self.cipher_dict = np.array(list(self.custom_key))
        else:
            # Generate random substitution
            if self.seed is not None:
                random.seed(self.seed)
                np.random.seed(self.seed)
            
            # Create a shuffled copy of the original dictionary
            shuffled_values = values.copy()
            np.random.shuffle(shuffled_values)
            
            self.cipher_dict = shuffled_values


    def create_advanced_cipher_dict(self):
        # this handles the mixed case options

        values = self.original_dictionary
        
        if not isinstance(values, np.ndarray):
            values = np.array(values)
        
        if self.wrap_separately and len(values) > 0 and isinstance(values[0], str):
            # Separate uppercase and lowercase
            uppercase_mask = np.array([c.isupper() for c in values])
            lowercase_mask = np.array([c.islower() for c in values])
            
            substituted_values = values.copy()
            
            # Set seeds for reproducible randomness if specified
            if self.seed is not None:
                random.seed(self.seed)
                np.random.seed(self.seed)
            
            # Handle custom key for mixed case
            if self.custom_key is not None:
                if len(self.custom_key) != len(values):
                    raise ValueError(f"Custom key length ({len(self.custom_key)}) must match dictionary length ({len(values)})")
                
                if set(self.custom_key) != set(values):
                    raise ValueError("Custom key must contain exactly the same characters as the original dictionary")
                
                substituted_values = np.array(list(self.custom_key))
            else:
                # Substitute uppercase separately
                if np.any(uppercase_mask):
                    uppercase_chars = values[uppercase_mask]
                    uppercase_indices = np.where(uppercase_mask)[0]
                    shuffled_uppercase = uppercase_chars.copy()
                    np.random.shuffle(shuffled_uppercase)
                    substituted_values[uppercase_indices] = shuffled_uppercase
                
                # Substitute lowercase separately  
                if np.any(lowercase_mask):
                    lowercase_chars = values[lowercase_mask]
                    lowercase_indices = np.where(lowercase_mask)[0]
                    shuffled_lowercase = lowercase_chars.copy()
                    np.random.shuffle(shuffled_lowercase)
                    substituted_values[lowercase_indices] = shuffled_lowercase
                
                # Handle other characters (non-alphabetic)
                other_mask = ~(uppercase_mask | lowercase_mask)
                if np.any(other_mask):
                    other_chars = values[other_mask]
                    other_indices = np.where(other_mask)[0]
                    shuffled_other = other_chars.copy()
                    np.random.shuffle(shuffled_other)
                    substituted_values[other_indices] = shuffled_other
        else:
            # Simple substitution of entire array (fallback to basic method)
            if self.custom_key is not None:
                if len(self.custom_key) != len(values):
                    raise ValueError(f"Custom key length ({len(self.custom_key)}) must match dictionary length ({len(values)})")
                
                if set(self.custom_key) != set(values):
                    raise ValueError("Custom key must contain exactly the same characters as the original dictionary")
                
                substituted_values = np.array(list(self.custom_key))
            else:
                if self.seed is not None:
                    np.random.seed(self.seed)
                
                substituted_values = values.copy()
                np.random.shuffle(substituted_values)
        
        # Set Dictionary
        self.cipher_dict = substituted_values


    def show_cipher_mapping(self, show_first_n=10):
        print("Current monoalphabetic cipher mapping:")
        print("Original: ", ''.join(self.original_dictionary[:show_first_n]))
        print("Cipher:   ", ''.join(self.cipher_dict[:show_first_n]))
        if len(self.original_dictionary) > show_first_n:
            print(f"... (showing first {show_first_n} of {len(self.original_dictionary)} characters)")


    def get_full_key(self):
        return ''.join(self.cipher_dict) # as a string


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
