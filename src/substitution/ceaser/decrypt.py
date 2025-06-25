#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/ceasar/decrypt.py'
#   Ceasar cipher decryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import string
from collections import Counter
import re


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
        
        # Common letter frequencies (for scoring)
        if lang_freq == None:
            # English default
            self.lang_freq = {
                'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
                'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
                'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
                'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
                'Q': 0.10, 'Z': 0.07
            }
        else:
            self.lang_freq = lang_freq



    def decrypt_with_offset(self, encrypted_text, offset):
        #Decrypt text using a specific offset

        # Create decryption dictionary (reverse the encryption process)
        if self.wrap_separately:
            cipher_dict = self._create_advanced_cipher_dict(-offset)
        else:
            cipher_dict = np.roll(self.original_dictionary, -offset)
        
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
       # Calculate how "English-like" a text is based on letter frequency
       # Score (higher = more English-like)
        
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return 0
        
        # Count letter frequencies
        letter_counts = Counter(clean_text)
        total_letters = len(clean_text)
        
        # Calculate score based on how close frequencies are to English
        score = 0
        for letter, count in letter_counts.items():
            observed_freq = (count / total_letters) * 100
            expected_freq = self.lang_freq.get(letter, 0)
            
            # Use negative squared difference (closer to expected = higher score)
            score -= (observed_freq - expected_freq) ** 2
        
        return score

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

