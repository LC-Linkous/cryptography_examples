#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/substitution/caesar/decrypt.py'
#   caesar cipher decryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import os
import sys
import numpy as np

# Allow 'from common...' whether this file is run from its own folder (the
# repo convention) or imported from the tests/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from common.english_score import ENGLISH_FREQ, chi_squared_score


#
# Dictionary: list of characters to use. If NONE, then the default caps and lower A-z are used
# wrap_separately: handle upper/lowercase separately
#
#


class decrypt:
    
    def __init__(self, dictionary=None, wrap_separately=False, lang_freq=None):

        if dictionary is None:
            # Default to A-Z, a-z
            self.dictionary = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)]
        else:
            self.dictionary = list(dictionary)
            
        self.original_dictionary = np.array(self.dictionary)
        self.wrap_separately = wrap_separately
        
        # Letter frequencies used for scoring; English by default. The
        # table lives in src/common/english_score.py so every decrypt
        # class shares one copy.
        self.lang_freq = ENGLISH_FREQ if lang_freq is None else lang_freq



    def decrypt_with_offset(self, encrypted_text, offset):
        #Decrypt text using a specific offset

        # Create decryption dictionary (reverse the encryption process)
        if self.wrap_separately:
            cipher_dict = self._create_advanced_cipher_dict(offset)
        else:
            cipher_dict = np.roll(self.original_dictionary, offset)
        
        result = []
        for char in encrypted_text:
            # Find the position of the character in original dictionary
            char_positions = np.where(self.original_dictionary == char)[0]
            
            if len(char_positions) > 0:
                # Character found in dictionary - replace with decrypted version
                position = char_positions[0]
                decrypted_char = cipher_dict[position]
                result.append(decrypted_char)
            else:
                # Character not in dictionary - keep it unchanged
                result.append(char)
        
        return ''.join(result)

    def _create_advanced_cipher_dict(self, offset):
        #Create cipher dictionary with separate wrapping for case
        values = self.original_dictionary
        
        if self.wrap_separately and len(values) > 0 and isinstance(values[0], str):
            uppercase_mask = np.array([c.isupper() for c in values])
            lowercase_mask = np.array([c.islower() for c in values])
            
            shifted_values = values.copy()
            
            # Shift uppercase separately
            if np.any(uppercase_mask):
                uppercase_chars = values[uppercase_mask]
                uppercase_indices = np.where(uppercase_mask)[0]
                shifted_uppercase = np.roll(uppercase_chars, offset)
                shifted_values[uppercase_indices] = shifted_uppercase
            
            # Shift lowercase separately  
            if np.any(lowercase_mask):
                lowercase_chars = values[lowercase_mask]
                lowercase_indices = np.where(lowercase_mask)[0]
                shifted_lowercase = np.roll(lowercase_chars, offset)
                shifted_values[lowercase_indices] = shifted_lowercase
            
            # Handle other characters
            other_mask = ~(uppercase_mask | lowercase_mask)
            if np.any(other_mask):
                other_chars = values[other_mask]
                other_indices = np.where(other_mask)[0]
                shifted_other = np.roll(other_chars, offset)
                shifted_values[other_indices] = shifted_other
        else:
            shifted_values = np.roll(values, offset)
        
        return shifted_values

    def calculate_english_score(self, text):
        # How "English-like" is this text? Higher = more English-like.
        #
        # Uses the chi-squared statistic over ALL 26 letters. The previous
        # version only summed over letters present in the candidate, which
        # rewarded candidates with few distinct letters; the README example
        # ('KHOOR ZRUOG' -> 'aXeeh phkeW' ranked above 'HELLO WORLD') was a
        # direct symptom of that.
        return chi_squared_score(text, self.lang_freq)

    def brute_force_decrypt(self, encrypted_text, max_offset=None, show_all=False):
       # Try all possible offsets to decrypt the message
        
        if max_offset is None:
            max_offset = len(self.dictionary)
        
        results = []
        
        print(f"Trying offsets 0 to {max_offset-1}...")
        print("=" * 60)
        
        for offset in range(max_offset):
            decrypted = self.decrypt_with_offset(encrypted_text, offset)
            score = self.calculate_english_score(decrypted)
            results.append((offset, decrypted, score))
            
            if show_all:
                print(f"Offset {offset:2d}: {decrypted[:50]:<50} (Score: {score:.1f})")
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results

    def auto_decrypt(self, encrypted_text, top_n=5):
        # find the most likely decryption

        results = self.brute_force_decrypt(encrypted_text, show_all=False)
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 60)
        
        for i, (offset, decrypted, score) in enumerate(results[:top_n]):
            print(f"{i+1}. Offset {offset:2d} (Score: {score:6.1f}): {decrypted}")
        
        return results[0][1] if results else encrypted_text

