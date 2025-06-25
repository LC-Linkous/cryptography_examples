#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/adfgvx/encrypt.py'
#   ADFGVX cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import sys
import random
import string
np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

        # Optional parent class
        self.parent = parent 

        # ADFGVX uses 36 characters (A-Z + 0-9) in a 6x6 grid
        if dictionary is None:
            # Default: A-Z + 0-9 (36 characters for 6x6 grid)
            self.original_dictionary = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(48, 58)]  # A-Z, 0-9
        else:
            self.original_dictionary = np.array(dictionary)
        
        self.substitution_grid = None
        self.coordinate_map = None
        self.transposition_key = None
        self.transposition_order = None

        # unpack the dataframe of options configurable to this encryption method
        self.grid_keyword = opt_df['GRID_KEYWORD'][0] if 'GRID_KEYWORD' in opt_df.columns else None
        self.trans_keyword = opt_df['TRANS_KEYWORD'][0] if 'TRANS_KEYWORD' in opt_df.columns else 'SECRET'
        self.random_seed = int(opt_df['RANDOM_SEED'][0]) if 'RANDOM_SEED' in opt_df.columns else 42
        self.separator = opt_df['SEPARATOR'][0] if 'SEPARATOR' in opt_df.columns else ''
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # ADFGVX coordinate system uses these 6 letters
        self.coordinates = ['A', 'D', 'F', 'G', 'V', 'X']
        
        # Validate that we have 36 characters for the 6x6 grid
        if len(self.original_dictionary) != 36:
            raise ValueError("ADFGVX cipher requires exactly 36 characters (A-Z + 0-9)")

        # Prepare the character set and create the grid
        self.prepare_character_set()


    def prepare_character_set(self):
        # 36 character set to put in the 6x grid
        # ADFGVX traditionally uses A-Z + 0-9
        self.working_chars = list(self.original_dictionary)


    def create_substitution_grid(self):
        # creating the substitution for the 6x6 grid
        if self.grid_keyword:
            # Use keyword to create grid
            grid_chars = self.create_keyword_grid()
        else:
            # Use random arrangement
            grid_chars = self.create_random_grid()
        
        # Create the 6x6 grid
        self.substitution_grid = []
        
        for i in range(6):
            row = []
            for j in range(6):
                idx = i * 6 + j
                row.append(grid_chars[idx])
            self.substitution_grid.append(row)
        
        # Create coordinate mapping
        self.create_coordinate_map()



    def create_keyword_grid(self):
        # This creates the grid (substitution square) using a keyword, where the keyword starts
        # in the top left. Technically the keywor can be any length,
        # but they cannot have duplicate letters. 
        #
        # Keywords can only have 1 of each letter.
        # SECRET -> SECRT
        # VIOLET -> VIOLET

        if not self.grid_keyword:
            return self.working_chars.copy()
        
        # Remove duplicates from keyword and convert to uppercase
        keyword_chars = []
        seen = set()
        
        for char in self.grid_keyword.upper():
            if char.isalnum() and char not in seen:  # Allow letters and numbers
                if char in self.working_chars and char not in seen:
                    keyword_chars.append(char)
                    seen.add(char)
        
        # Add remaining characters
        remaining_chars = [char for char in self.working_chars if char not in seen]
        
        return keyword_chars + remaining_chars
    



    def create_random_grid(self):
        # With the keyword filled in (or NOT filled in if there's no keyword)
        # fill in the rest of the characters (called our 'working characters')
        chars = self.working_chars.copy()
        
        if self.random_seed is not None:
            # Create reproducible random grid
            random.seed(self.random_seed)
            random.shuffle(chars)
        
        return chars
    

    def create_coordinate_map(self):
        # create class variable for mapping between characters to coordinates
        # This is FROM characters TO ADFGVX coordinates in the grid
        # NOTE: if something looks backwards, check this function first

        self.coordinate_map = {}
        self.reverse_coordinate_map = {}
        
        for row in range(6):
            for col in range(6):
                char = self.substitution_grid[row][col]
                # Use ADFGVX letters as coordinates
                coord_row = self.coordinates[row]
                coord_col = self.coordinates[col]
                coord_pair = coord_row + coord_col
                
                self.coordinate_map[char] = coord_pair
                self.reverse_coordinate_map[coord_pair] = char



    def create_transposition_key(self):
        # Function for creating the transposition key from the keyword
        # This class SHOULD use a keyword, but we can modifty it later for
        # using a random 'keyword' generated if no keyword is provided

        if not self.trans_keyword:
            raise ValueError("Transposition keyword is required for ADFGVX cipher")
        
        # Convert keyword to uppercase and remove duplicates while preserving order
        clean_keyword = []
        seen = set()
        for char in self.trans_keyword.upper():
            if char.isalpha() and char not in seen:
                clean_keyword.append(char)
                seen.add(char)
        
        self.transposition_key = ''.join(clean_keyword)
        
        # Create numerical order for transposition
        # Sort the letters and assign numbers based on alphabetical order
        sorted_chars = sorted(list(set(self.transposition_key)))
        char_to_num = {char: i + 1 for i, char in enumerate(sorted_chars)}
        
        self.transposition_order = [char_to_num[char] for char in self.transposition_key]



    def show_cipher_mapping(self, show_examples=True):
        # Display the cipher grid and the transposition key
        # this is a good way to preview how th keyword was set and how the rest
        # of the letters were laid out.
        
        # Ensure grids are created so not calling nulls
        if not self.substitution_grid:
            self.create_substitution_grid()
        if not self.transposition_key:
            self.create_transposition_key()
            
        print(f"ADFGVX Cipher Configuration:")
        
        if self.grid_keyword:
            print(f"Grid Keyword: '{self.grid_keyword}'")
        else:
            print(f"Random Grid (seed: {self.random_seed})")
        
        print(f"Transposition Keyword: '{self.trans_keyword}'")
        print(f"Transposition Order: {self.transposition_order}")
        
        print(f"\nSubstitution Grid (6x6):")
        
        # Show column headers (ADFGVX)
        header = "   " + "  ".join(self.coordinates)
        print(header)
        
        # Show grid with row labels (ADFGVX)
        for row in range(6):
            row_str = f"{self.coordinates[row]}  "
            for col in range(6):
                char = self.substitution_grid[row][col]
                row_str += f" {char} "
            print(row_str)
        
        if show_examples:
            print(f"\nSubstitution Examples:")
            example_chars = ['A', 'E', 'M', 'Z', '5', '9']
            for char in example_chars:
                if char in self.coordinate_map:
                    coord = self.coordinate_map[char]
                    print(f"  {char} → {coord}")

    def substitute_characters(self, text):
        # STEP 1
        # Substitution. Characters need to be substituted using the grid

        if not self.substitution_grid:
            self.create_substitution_grid()
        
        substituted = []
        
        for char in text.upper():
            if char in self.coordinate_map:
                # Character found in grid - replace with ADFGVX coordinates
                coord_pair = self.coordinate_map[char]
                substituted.append(coord_pair)
            else:
                # Character not in grid - skip or mark
                if char.isalnum():
                    substituted.append(f"[{char}]")  # Mark unknown characters
                # Ignore spaces and punctuation
        
        return ''.join(substituted) # as string
    


    def transpose_text(self, substituted_text):
        # STEP 2
        # Transposition. Transpose the substituted text using the keyword

        if not self.transposition_key:
            self.create_transposition_key()
        
        key_length = len(self.transposition_key)
        
        # Pad the text if necessary to fill complete rows
        while len(substituted_text) % key_length != 0:
            substituted_text += 'X'  # Pad with X's
        
        # Create the transposition grid
        rows = len(substituted_text) // key_length
        grid = []
        
        for i in range(rows):
            row = []
            for j in range(key_length):
                idx = i * key_length + j
                row.append(substituted_text[idx])
            grid.append(row)
        
        # Read columns in order specified by the transposition key
        result = []
        
        # Sort columns by the transposition order
        column_order = sorted(range(key_length), key=lambda x: self.transposition_order[x])
        
        for col_idx in column_order:
            column_text = ''.join(grid[row][col_idx] for row in range(rows))
            result.append(column_text)
        
        return self.separator.join(result)
    


    def encrypt_message(self, text, show_steps=None):
        # enrypting the message. This has the 2 steps split up
        # Substitution & Transposition

        show_steps = show_steps if show_steps is not None else self.show_steps
        
        if show_steps:
            print(f"=== ADFGVX Encryption Steps ===")
            print(f"Original text: '{text}'")
        
        # Step 1: Substitution using the grid
        substituted = self.substitute_characters(text)
        
        if show_steps:
            print(f"After substitution: '{substituted}'")
        
        # Step 2: Transposition using the keyword
        final_result = self.transpose_text(substituted)
        
        if show_steps:
            print(f"After transposition: '{final_result}'")
            print(f"=== End Encryption Steps ===")
        
        return final_result
       

    def demonstrate_process(self, text):
        # Bulked out with Claude AI.
        # This function walks through the encryption process
        # and provides printed out information about the different steps

        """Detailed demonstration of the ADFGVX encryption process"""
        print(f"=== ADFGVX CIPHER DEMONSTRATION ===")
        print(f"Input text: '{text}'")
        
        # Ensure grids are created before showing
        if not self.substitution_grid:
            self.create_substitution_grid()
        if not self.transposition_key:
            self.create_transposition_key()
        
        # Show the grid and keys
        self.show_cipher_mapping()
        
        # Step-by-step encryption
        print(f"\n=== STEP 1: SUBSTITUTION ===")
        substituted = self.substitute_characters(text)
        
        # Show character-by-character substitution
        print(f"Character-by-character substitution:")
        for char in text.upper():
            if char in self.coordinate_map:
                coord = self.coordinate_map[char]
                print(f"  {char} → {coord}")
        
        print(f"Substituted text: '{substituted}'")
        
        # Step 2: Transposition
        print(f"\n=== STEP 2: TRANSPOSITION ===")
        
        key_length = len(self.transposition_key)
        print(f"Transposition keyword: '{self.trans_keyword}'")
        print(f"Key order: {list(self.transposition_key)}")
        print(f"Numerical order: {self.transposition_order}")
        
        # Show the grid formation
        padded_text = substituted
        while len(padded_text) % key_length != 0:
            padded_text += 'X'
        
        print(f"Padded text: '{padded_text}'")
        
        rows = len(padded_text) // key_length
        print(f"Transposition grid ({rows} rows × {key_length} cols):")
        
        # Show headers
        header = "   " + "  ".join(f"{char}({self.transposition_order[i]})" for i, char in enumerate(self.transposition_key))
        print(header)
        
        # Show grid
        for i in range(rows):
            row_str = f"{i+1:2d} "
            for j in range(key_length):
                idx = i * key_length + j
                row_str += f"  {padded_text[idx]}   "
            print(row_str)
        
        # Show column reading order
        column_order = sorted(range(key_length), key=lambda x: self.transposition_order[x])
        print(f"\nColumn reading order: {[self.transposition_key[i] for i in column_order]}")
        
        # Read columns
        columns = []
        for col_idx in column_order:
            column_text = ''.join(padded_text[row * key_length + col_idx] for row in range(rows))
            columns.append(column_text)
            print(f"Column {self.transposition_key[col_idx]}: '{column_text}'")
        
        final_result = self.separator.join(columns)
        print(f"Final encrypted text: '{final_result}'")
        
        return final_result


    def get_cipher_stats(self):
        # Pulled form the Claude AI 'Improved' version
        # This is kind of cool to get the metrics for the cipher

        if not self.substitution_grid:
            self.create_substitution_grid()
        if not self.transposition_key:
            self.create_transposition_key()
        
        stats = {
            'cipher_type': 'ADFGVX',
            'grid_size': '6x6',
            'total_characters': 36,
            'grid_keyword_used': bool(self.grid_keyword),
            'grid_keyword': self.grid_keyword,
            'transposition_keyword': self.trans_keyword,
            'transposition_length': len(self.transposition_key),
            'transposition_order': self.transposition_order,
            'random_seed': self.random_seed,
            'separator': repr(self.separator)
        }
        
        return stats