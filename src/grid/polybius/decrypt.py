#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/grid/polybius/decrypt.py'
#   Polybius Square cipher decryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 23, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import random
import re
import os
import sys

# Allow 'from common...' whether this file is run from its own folder (the
# repo convention) or imported from the tests/ directory.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
from common.english_score import ENGLISH_FREQ, english_score
np.seterr(all='raise')

class decrypt:
  
    def __init__(self, dictionary=None, opt_df=None, parent=None): 

        # Optional parent class
        self.parent = parent 

        # set dictionary (for Polybius, we typically use A-Z minus one letter)
        if dictionary is None:
            # Default: A-Z with I/J combined (traditional)
            self.original_dictionary = [chr(i) for i in range(65, 74)] + [chr(i) for i in range(75, 91)]  # A-H, K-Z
        else:
            self.original_dictionary = np.array(dictionary)
        
        self.cipher_grid = None
        self.coordinate_map = None
        self.reverse_coordinate_map = None

        # unpack the dataframe of options configurable to this decryption method
        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else None
        self.grid_size = int(opt_df['GRID_SIZE'][0]) if 'GRID_SIZE' in opt_df.columns else 5
        self.combine_letters = opt_df['COMBINE_LETTERS'][0] if 'COMBINE_LETTERS' in opt_df.columns else 'IJ'
        self.number_base = int(opt_df['NUMBER_BASE'][0]) if 'NUMBER_BASE' in opt_df.columns else 1
        self.separator = opt_df['SEPARATOR'][0] if 'SEPARATOR' in opt_df.columns else ' '
        self.random_seed = int(opt_df['RANDOM_SEED'][0]) if 'RANDOM_SEED' in opt_df.columns else 42

        # Validate parameters
        if self.grid_size not in [5, 6]:
            raise ValueError("Grid size must be 5 or 6")
        
        # Common English letter frequencies for scoring
        self.lang_freq = dict(ENGLISH_FREQ)
        
        # Prepare the character set
        self.prepare_character_set()


    def prepare_character_set(self):
        # 36 character set to put in the 6x6 grid
        # 25 set for 5x5
        # Polybius (like ADFGVX) traditionally uses A-Z + 0-9
        
        if self.grid_size == 5:
            # 5x5 grid needs exactly 25 characters
            if self.combine_letters == 'IJ':
                # Traditional: combine I and J
                chars = [chr(i) for i in range(65, 74)] + [chr(i) for i in range(75, 91)]  # A-I, K-Z (J -> I)
            elif self.combine_letters == 'UV':
                # Alternative: combine U and V
                chars = [chr(i) for i in range(65, 86)] + [chr(i) for i in range(87, 91)]  # A-U, W-Z (V -> U)
            else:
                # Use first 25 letters
                chars = [chr(i) for i in range(65, 90)]  # A-Y
        else:
            # 6x6 grid can hold 36 characters (A-Z + 0-9)
            chars = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(48, 58)]  # A-Z, 0-9
        
        self.working_chars = chars

    def create_cipher_grid(self, keyword=None, random_seed=None):
        # Create the grid for the polybius cipher
        # used to create the coordinate map

        # Override instance variables if parameters provided
        current_keyword = keyword if keyword is not None else self.keyword
        
        # Handle random seed carefully - only use instance random_seed if no explicit seed provided
        # and no keyword is being used
        if random_seed is not None:
            current_seed = random_seed
        elif keyword is not None or current_keyword is not None:
            # When using keywords, don't apply random seed unless explicitly requested
            current_seed = None
        else:
            # Only use instance random_seed for truly "standard" grids
            current_seed = self.random_seed if self.random_seed != 42 else None  # Don't use default seed for "standard"
        
        if current_keyword:
            # Use keyword to create grid
            grid_chars = self.create_keyword_grid(current_keyword)
        else:
            # Use standard alphabetical or random grid
            grid_chars = self.create_standard_grid(current_seed)
        
        # Create the grid
        self.cipher_grid = []
        chars_per_row = self.grid_size
        
        for i in range(self.grid_size):
            row = []
            for j in range(chars_per_row):
                idx = i * chars_per_row + j
                if idx < len(grid_chars):
                    row.append(grid_chars[idx])
                else:
                    row.append('')  # Empty cell if not enough characters
            self.cipher_grid.append(row)
        
        # Create coordinate mapping
        self.create_coordinate_map()


    def create_keyword_grid(self, keyword):
        # This creates the grid (substitution square) using a keyword, where the keyword starts
        # in the top left. Technically the keywor can be any length,
        # but they cannot have duplicate letters. 
        #
        # Keywords can only have 1 of each letter.
        # SECRET -> SECRT
        # VIOLET -> VIOLET

        if not keyword:
            return self.working_chars.copy()
        
        # Remove duplicates from keyword and convert to uppercase
        keyword_chars = []
        seen = set()
        
        for char in keyword.upper():
            if char.isalpha() and char not in seen:
                # Handle combined letters
                if self.combine_letters == 'IJ' and char == 'J':
                    char = 'I'
                elif self.combine_letters == 'UV' and char == 'V':
                    char = 'U'
                
                if char in self.working_chars and char not in seen:
                    keyword_chars.append(char)
                    seen.add(char)
        
        # Add remaining characters
        remaining_chars = [char for char in self.working_chars if char not in seen]
        
        return keyword_chars + remaining_chars


    def create_standard_grid(self, random_seed=None):
         # creates a reusable/reproducable grid
        chars = self.working_chars.copy()
        
        # Only shuffle if random_seed is explicitly provided AND not None
        # If random_seed is None, create alphabetical grid
        if random_seed is not None:
            # Create reproducible random grid
            random.seed(random_seed)
            random.shuffle(chars)
        # else: keep alphabetical order (chars already in order from prepare_character_set)
        
        return chars
    


    def create_coordinate_map(self):
        # create class variable for mapping between characters to coordinates
        # This is FROM characters TO ADFGVX coordinates in the grid
        # NOTE: if something looks backwards, check this function first
        self.coordinate_map = {}
        self.reverse_coordinate_map = {}
        
        for row in range(self.grid_size):
            for col in range(self.grid_size):
                char = self.cipher_grid[row][col]
                if char:  # Not empty
                    # Coordinates (1-based or 0-based depending on number_base)
                    coord_row = row + self.number_base
                    coord_col = col + self.number_base
                    
                    self.coordinate_map[char] = (coord_row, coord_col)
                    self.reverse_coordinate_map[(coord_row, coord_col)] = char



    def decrypt_message(self, encrypted_text, keyword=None, random_seed=None):
        # attempt to decrypt the emssage using the polybius squrare
        # Create grid with specified parameters
        self.create_cipher_grid(keyword, random_seed)
        # encrypt_message() joins every token with the separator, so a space
        # between words shows up as separator + ' ' + separator. Split on
        # that first so word breaks survive the round trip.
        word_break = f"{self.separator} {self.separator}" if self.separator else None
        if word_break and word_break in encrypted_text:
            return ' '.join(self._decode_tokens(word) for word in encrypted_text.split(word_break))
        return self._decode_tokens(encrypted_text)


    def _decode_tokens(self, encrypted_text):
        
        # Split by separator or parse coordinate pairs
        coordinate_pairs = []
        
        if self.separator and self.separator in encrypted_text:
            # Split by separator
            coordinate_pairs = encrypted_text.split(self.separator)
        else:
            # If no separator, assume each coordinate is 2 digits
            i = 0
            while i < len(encrypted_text):
                if i + 1 < len(encrypted_text) and encrypted_text[i:i+2].isdigit():
                    coordinate_pairs.append(encrypted_text[i:i+2])
                    i += 2
                else:
                    # Non-coordinate character
                    coordinate_pairs.append(encrypted_text[i])
                    i += 1
        
        result = []
        
        for item in coordinate_pairs:
            if len(item) == 2 and item.isdigit():
                # Convert to coordinate
                row = int(item[0])
                col = int(item[1])
                
                if (row, col) in self.reverse_coordinate_map:
                    char = self.reverse_coordinate_map[(row, col)]
                    result.append(char)
                else:
                    result.append(f"[{item}]")  # Mark invalid coordinates
            else:
                # Non-coordinate (space, punctuation, etc.)
                result.append(item)
        
        return ''.join(result)



    def calculate_english_score(self, text):
        # Calculate how English-like a text is
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return float('-inf')

        # Shared chi-squared over ALL letters, per letter (common/english_score.py):
        # letters English expects but the candidate lacks now count against it.
        score = english_score(text, self.lang_freq)
        
        return score


    def brute_force_decrypt(self, encrypted_text, max_keywords=None, show_all=False):
        # This attempts several strategies for decrypting this cipher
        # First it attempts a brute force (see notes on that function), 
        # and then it tries more analytical methods
        # The brute force is for DEMO purposes only. It is an attack based on some trypical keywords used
        # for learning grid ciphers. 
        # This can cause issues with the test cases doing better than actual encrypted messages.

        results = []
        
        # Test cases to try
        test_configs = []
        
        # 1. Standard alphabetical grid (no random seed)
        test_configs.append({
            'name': 'Standard Alphabetical',
            'keyword': None,
            'random_seed': None
        })
        
        # 2. Common random seeds
        common_seeds = [7, 12, 21, 31, 42, 85, 100, 123, 456, 789]
        for seed in common_seeds:
            test_configs.append({
                'name': f'Random (seed={seed})',
                'keyword': None,
                'random_seed': seed
            })
        
        # 3. Common keywords
        common_keywords = [
            'SECRET', 'CIPHER', 'KEY', 'CODE', 'POLYBIUS', 'GRID', 'SQUARE',
            'ENCRYPT', 'DECODE', 'MATRIX', 'TABLE', 'ALPHA', 'BETA', 'GAMMA',
            'PASSWORD', 'HIDDEN', 'MESSAGE', 'PRIVATE', 'SECURE', 'VAULT'
        ]
        
        if max_keywords:
            common_keywords = common_keywords[:max_keywords]
        
        for keyword in common_keywords:
            test_configs.append({
                'name': f'Keyword: {keyword}',
                'keyword': keyword,
                'random_seed': None
            })
        
        print(f"Trying {len(test_configs)} different grid configurations...")
        print("=" * 80)
        
        for i, config in enumerate(test_configs):
            try:
                decrypted = self.decrypt_message(
                    encrypted_text, 
                    config['keyword'], 
                    config['random_seed']
                )
                score = self.calculate_english_score(decrypted)
                results.append((config['name'], decrypted, score))
                
                if show_all:
                    print(f"{i+1:2d}. {config['name']:<25}: {decrypted[:40]:<40} (Score: {score:.1f})")
                    
            except Exception as e:
                if show_all:
                    print(f"{i+1:2d}. {config['name']:<25}: ERROR - {str(e)}")
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results



    def auto_decrypt(self, encrypted_text, top_n=5, max_keywords=20):

        results = self.brute_force_decrypt(encrypted_text, max_keywords, show_all=False)
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 80)
        
        for i, (config_name, decrypted, score) in enumerate(results[:top_n]):
            print(f"{i+1}. {config_name:<25} (Score: {score:6.1f}): {decrypted}")
        
        return results[0][1] if results else encrypted_text



    def show_cipher_mapping(self, keyword=None, random_seed=None, show_coordinates=True):
       # Display a preview of the current substitution grid and the transposition key

        # Create grid if not exists or parameters changed
        self.create_cipher_grid(keyword, random_seed)
        
        print(f"Polybius Square ({self.grid_size}x{self.grid_size}):")
        
        if keyword:
            print(f"Keyword: '{keyword}'")
        elif random_seed is not None:
            print(f"Random seed: {random_seed}")
        else:
            print("Standard alphabetical arrangement")
        
        print(f"Combined letters: {self.combine_letters}")
        print(f"Number base: {self.number_base} ({'1-based' if self.number_base == 1 else '0-based'})")
        
        # Show column headers
        header = "   "
        for col in range(self.grid_size):
            header += f"{col + self.number_base:2d} "
        print(header)
        
        # Show grid with row numbers
        for row in range(self.grid_size):
            row_str = f"{row + self.number_base:2d} "
            for col in range(self.grid_size):
                char = self.cipher_grid[row][col] if self.cipher_grid[row][col] else ' '
                row_str += f" {char} "
            print(row_str)
        
        if show_coordinates:
            print(f"\nCoordinate examples:")
            example_chars = ['A', 'E', 'M', 'Z'] if self.grid_size == 5 else ['A', 'E', 'M', 'Z', '5', '9']
            for char in example_chars:
                if char in self.coordinate_map:
                    coord = self.coordinate_map[char]
                    print(f"  {coord[0]}{coord[1]} → {char}")



    def analyze_ciphertext(self, encrypted_text):
        # Bulked out by Claude AI, covering more than the basic analysis in V1
        # This analyzes the stucture of the encrypted text to help with the decryption process
        print("=== Ciphertext Analysis ===")
        print(f"Text: {encrypted_text}")
        print(f"Length: {len(encrypted_text)}")
        
        # Check for separators
        separators_found = []
        common_seps = [' ', '-', ',', '|', ':', ';', '_']
        for sep in common_seps:
            if sep in encrypted_text:
                separators_found.append(sep)
        
        if separators_found:
            print(f"Possible separators found: {separators_found}")
        else:
            print("No common separators found - likely concatenated coordinates")
        
        # Extract coordinate pairs
        if self.separator and self.separator in encrypted_text:
            pairs = encrypted_text.split(self.separator)
        else:
            # Extract 2-digit sequences
            pairs = re.findall(r'\d{2}', encrypted_text)
        
        print(f"Coordinate pairs found: {len(pairs)}")
        if pairs:
            print(f"Sample pairs: {pairs[:10]}")
            
            # Analyze coordinate ranges
            rows = []
            cols = []
            for pair in pairs:
                if len(pair) == 2 and pair.isdigit():
                    rows.append(int(pair[0]))
                    cols.append(int(pair[1]))
            
            if rows and cols:
                print(f"Row coordinates: {min(rows)} to {max(rows)}")
                print(f"Col coordinates: {min(cols)} to {max(cols)}")
                
                # Guess grid size and number base
                max_coord = max(max(rows), max(cols))
                min_coord = min(min(rows), min(cols))
                
                if min_coord == 0:
                    print("Likely 0-based numbering")
                    suggested_base = 0
                    suggested_size = max_coord + 1
                elif min_coord == 1:
                    print("Likely 1-based numbering")
                    suggested_base = 1
                    suggested_size = max_coord
                else:
                    print(f"Unusual coordinate range: {min_coord} to {max_coord}")
                    suggested_base = min_coord
                    suggested_size = max_coord - min_coord + 1
                
                print(f"Suggested grid size: {suggested_size}x{suggested_size}")
                print(f"Suggested number base: {suggested_base}")

