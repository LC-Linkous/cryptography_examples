#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/adfgvx/decrypt.py'
#   ADFGVX cipher decryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import random
import re
from collections import Counter
np.seterr(all='raise')

class decrypt:
  
    def __init__(self, dictionary=None, opt_df=None, parent=None): 

        # Optional parent class
        self.parent = parent 

        # ADFGVX uses 36 characters (A-Z + 0-9) in a 6x6 grid
        # NOTE: this is a SET 6x6 grid. The Polybius cipher uses a 5x5
        if dictionary is None:
            # Default: A-Z + 0-9 (36 characters for 6x6 grid)
            self.original_dictionary = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(48, 58)]  # A-Z, 0-9
        else:
            self.original_dictionary = np.array(dictionary)
        
        self.substitution_grid = None
        self.coordinate_map = None
        self.reverse_coordinate_map = None
        self.transposition_key = None
        self.transposition_order = None


        # unpack the dataframe of options configurable to this decryption method - NO 'NONE' AS DEFAULT ALLOWED
        self.grid_keyword = opt_df['GRID_KEYWORD'][0] if 'GRID_KEYWORD' in opt_df.columns else None
        self.trans_keyword = opt_df['TRANS_KEYWORD'][0] if 'TRANS_KEYWORD' in opt_df.columns else 'SECRET'
        self.random_seed = int(opt_df['RANDOM_SEED'][0]) if 'RANDOM_SEED' in opt_df.columns else 42
        self.separator = opt_df['SEPARATOR'][0] if 'SEPARATOR' in opt_df.columns else ''

        # ADFGVX coordinate system uses these 6 letters
        self.coordinates = ['A', 'D', 'F', 'G', 'V', 'X']
        
        # Common English letter frequencies for scoring
        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        
        # Validate that we have 36 characters for the 6x6 grid
        if len(self.original_dictionary) != 36:
            raise ValueError("ADFGVX cipher requires exactly 36 characters (A-Z + 0-9)")

        # Prepare the character set
        self.prepare_character_set()


    def prepare_character_set(self):
        # 36 character set to put in the 6x grid
        # ADFGVX traditionally uses A-Z + 0-9
        self.working_chars = list(self.original_dictionary)



    def create_substitution_grid(self, grid_keyword=None, random_seed=None):
         # creating the substitution for the 6x6 grid

        # The 2 lines of code below differ from the encryption because we might have
        # demo information to use rather than starting from scratch.
        # Override instance variables if parameters provided
        current_grid_keyword = grid_keyword if grid_keyword is not None else self.grid_keyword
        current_seed = random_seed if random_seed is not None else self.random_seed
        
        if current_grid_keyword:
            # Use keyword to create grid
            grid_chars = self.create_keyword_grid(current_grid_keyword)
        else:
            # Use random arrangement
            grid_chars = self.create_random_grid(current_seed)
        
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


    def create_keyword_grid(self, grid_keyword):
        # This creates the grid (substitution square) using a keyword, where the keyword starts
        # in the top left. Technically the keywor can be any length,
        # but they cannot have duplicate letters. 
        #
        # Keywords can only have 1 of each letter.
        # SECRET -> SECRT
        # VIOLET -> VIOLET
        if not grid_keyword:
            return self.working_chars.copy()
        
        # Remove duplicates from keyword and convert to uppercase
        keyword_chars = []
        seen = set()
        
        for char in grid_keyword.upper():
            if char.isalnum() and char not in seen:  # Allow letters and numbers
                if char in self.working_chars and char not in seen:
                    keyword_chars.append(char)
                    seen.add(char)
        
        # Add remaining characters
        remaining_chars = [char for char in self.working_chars if char not in seen]
        
        return keyword_chars + remaining_chars



    def create_random_grid(self, random_seed=None):
        # With the keyword filled in (or NOT filled in if there's no keyword)
        # fill in the rest of the characters (called our 'working characters')
        chars = self.working_chars.copy()
        
        if random_seed is not None:
            # Create reproducible random grid
            random.seed(random_seed)
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



    def create_transposition_key(self, trans_keyword=None):
        # Function for creating the transposition key from the keyword
        # This class SHOULD use a keyword, but we can modifty it later for
        # using a random 'keyword' generated if no keyword is provided

        # We NEED something to start with here, but if the arg is None we might have an
        # already assigned value to fall back on
        current_keyword = trans_keyword if trans_keyword is not None else self.trans_keyword
        
        if not current_keyword:
            raise ValueError("Transposition keyword is required for ADFGVX cipher")
        
        # Convert keyword to uppercase and remove duplicates while preserving order
        clean_keyword = []
        seen = set()
        for char in current_keyword.upper():
            if char.isalpha() and char not in seen:
                clean_keyword.append(char)
                seen.add(char)
        
        self.transposition_key = ''.join(clean_keyword)
        
        # Create numerical order for transposition
        # Sort the letters and assign numbers based on alphabetical order
        sorted_chars = sorted(list(set(self.transposition_key)))
        char_to_num = {char: i + 1 for i, char in enumerate(sorted_chars)}
        
        self.transposition_order = [char_to_num[char] for char in self.transposition_key]



    def reverse_transposition(self, encrypted_text, trans_keyword=None):
        # STEP 1 of REVERSAL PROCESS

        # Display the cipher grid and the transposition key
        # this is a good way to preview how th keyword was set and how the rest
        # of the letters were laid out.

        # Create transposition key
        self.create_transposition_key(trans_keyword)
        
        key_length = len(self.transposition_key)
        
        # Split the encrypted text based on separator
        if self.separator and self.separator in encrypted_text:
            columns = encrypted_text.split(self.separator)
        else:
            # If no separator, we need to guess the column lengths
            columns = self.guess_column_arrangement(encrypted_text, key_length)
        
        # Handle case where column count doesn't match keyword length
        if len(columns) != key_length:
            # Try to adjust - maybe the keyword is wrong or text is incomplete
            if len(columns) < key_length:
                # Pad with empty columns
                while len(columns) < key_length:
                    columns.append('')
            else:
                # Too many columns - this might not be the right keyword
                raise ValueError(f"Expected {key_length} columns for keyword '{self.transposition_key}' but got {len(columns)}")
        
        # Check if all columns have consistent lengths (they should for proper ADFGVX)
        col_lengths = [len(col) for col in columns]
        if len(set(col_lengths)) > 2:  # Allow for at most 1 character difference
            # This might indicate the wrong transposition keyword
            pass  # Continue anyway, but this is suspicious
        
        # Determine the number of rows
        max_col_length = max(len(col) for col in columns) if columns else 0
        rows = max_col_length
        
        # Create column order mapping (reverse of encryption order)
        column_order = sorted(range(key_length), key=lambda x: self.transposition_order[x])
        
        # Rearrange columns back to original order
        original_columns = [''] * key_length
        for i, col_idx in enumerate(column_order):
            if i < len(columns):
                original_columns[col_idx] = columns[i]
        
        # Rebuild the text row by row
        result = []
        for row in range(rows):
            for col in range(key_length):
                if col < len(original_columns) and row < len(original_columns[col]):
                    result.append(original_columns[col][row])
        
        # Remove padding X's from the end
        result_text = ''.join(result).rstrip('X')
        
        return result_text



    def guess_column_arrangement(self, encrypted_text, key_length):
        # we can look at the length of the text to guess at some initial
        # column values. It has to be square, so there's a relation between
        # the encrypted text and key. (But it's not just this easy)

        # Simple approach: divide as evenly as possible
        total_length = len(encrypted_text)
        base_length = total_length // key_length
        extra_chars = total_length % key_length
        
        columns = []
        start = 0
        
        for i in range(key_length):
            # Some columns might be one character longer
            col_length = base_length + (1 if i < extra_chars else 0)
            columns.append(encrypted_text[start:start + col_length])
            start += col_length
        
        return columns


    def reverse_substitution(self, substituted_text, grid_keyword=None, random_seed=None):
        # STEP 2 of REVERSAL PROCESS
        # Revers the substitution to get a CANDIDATE message (might be the original, maybe :) 

        # Create substitution grid
        self.create_substitution_grid(grid_keyword, random_seed)
        
        # Process pairs of ADFGVX characters
        result = []
        
        # Clean the text - only keep ADFGVX characters
        clean_text = ''.join(char for char in substituted_text.upper() if char in self.coordinates)
        
        # Process in pairs
        for i in range(0, len(clean_text), 2):
            if i + 1 < len(clean_text):
                coord_pair = clean_text[i:i+2]
                if coord_pair in self.reverse_coordinate_map:
                    char = self.reverse_coordinate_map[coord_pair]
                    result.append(char)
                else:
                    result.append(f"[{coord_pair}]")  # Mark invalid coordinates
        
        return ''.join(result)
    


    def decrypt_message(self, encrypted_text, grid_keyword=None, trans_keyword=None, random_seed=None):
        # main function for decryption. This has BOTH the reversal of the transposition and substituion

        try:
            # Step 1: Reverse transposition
            substituted_text = self.reverse_transposition(encrypted_text, trans_keyword)
            
            # Step 2: Reverse substitution
            plaintext = self.reverse_substitution(substituted_text, grid_keyword, random_seed)
            
            return plaintext
            
        except Exception as e:
            return f"ERROR: {str(e)}"


    def calculate_english_score(self, text):
        # Calculate how English-like a text is
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
        
        # Common transposition keywords
        common_trans_keywords = [
            'SECRET', 'KEY', 'CIPHER', 'CODE', 'ADFGVX', 'CRYPT', 'ENCRYPT',
            'DECODE', 'MATRIX', 'GRID', 'KEYWORD', 'PASSWORD', 'HIDDEN'
        ]
        
        # Common grid keywords
        common_grid_keywords = [
            None,  # Random grid
            'CIPHER', 'POLYBIUS', 'EXAMPLE', 'GRID', 'SQUARE', 'ALPHABET',
            'SECRET', 'HIDDEN', 'CODE', 'ENCRYPT', 'MATRIX'
        ]
        
        if max_keywords:
            common_trans_keywords = common_trans_keywords[:max_keywords]
            common_grid_keywords = common_grid_keywords[:max_keywords]
        
        # Try combinations of transposition and grid keywords
        for trans_kw in common_trans_keywords:
            for grid_kw in common_grid_keywords:
                # Also try a few different random seeds if no grid keyword
                seeds_to_try = [42, 123, 7, 789] if grid_kw is None else [42]
                
                for seed in seeds_to_try:
                    config_name = f"Trans:{trans_kw}, Grid:{grid_kw or f'Random({seed})'}"
                    
                    try:
                        decrypted = self.decrypt_message(
                            encrypted_text, 
                            grid_keyword=grid_kw,
                            trans_keyword=trans_kw,
                            random_seed=seed
                        )
                        
                        if not decrypted.startswith("ERROR"):
                            score = self.calculate_english_score(decrypted)
                            results.append((config_name, decrypted, score))
                            
                            if show_all:
                                print(f"{config_name:<40}: {decrypted[:30]:<30} (Score: {score:.1f})")
                                
                    except Exception as e:
                        if show_all:
                            print(f"{config_name:<40}: ERROR - {str(e)}")
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results


    def auto_decrypt(self, encrypted_text, top_n=5, max_keywords=10):

        print(f"Trying ADFGVX brute force decryption...")
        print("=" * 80)
        
        results = self.brute_force_decrypt(encrypted_text, max_keywords, show_all=False)
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 80)
        
        for i, (config_name, decrypted, score) in enumerate(results[:top_n]):
            print(f"{i+1}. {config_name:<40} (Score: {score:6.1f}): {decrypted}")
        
        return results[0][1] if results else encrypted_text


    def show_cipher_mapping(self, grid_keyword=None, trans_keyword=None, random_seed=None):
       # Display a preview of the current substitution grid and the transposition key

        # Create grids with specified parameters
        self.create_substitution_grid(grid_keyword, random_seed)
        self.create_transposition_key(trans_keyword)
        
        print(f"ADFGVX Cipher Configuration:")
        
        current_grid_kw = grid_keyword if grid_keyword is not None else self.grid_keyword
        current_seed = random_seed if random_seed is not None else self.random_seed
        current_trans_kw = trans_keyword if trans_keyword is not None else self.trans_keyword
        
        if current_grid_kw:
            print(f"Grid Keyword: '{current_grid_kw}'")
        else:
            print(f"Random Grid (seed: {current_seed})")
        
        print(f"Transposition Keyword: '{current_trans_kw}'")
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
        
        print(f"\nCoordinate examples:")
        example_chars = ['A', 'E', 'M', 'Z', '5', '9']
        for char in example_chars:
            if char in self.coordinate_map:
                coord = self.coordinate_map[char]
                print(f"  {coord} → {char}")


    def analyze_ciphertext(self, encrypted_text):
        # Bulked out by Claude AI, covering more than the basic analysis in V1
        # This analyzes the stucture of the encrypted text to help with the decryption process
        print("=== ADFGVX Ciphertext Analysis ===")
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
            if self.separator in separators_found:
                columns = encrypted_text.split(self.separator)
                print(f"Number of columns (if '{self.separator}' is separator): {len(columns)}")
                print(f"Column lengths: {[len(col) for col in columns]}")
        else:
            print("No common separators found - likely concatenated columns")
        
        # Analyze character composition
        char_counts = Counter(encrypted_text.upper())
        adfgvx_chars = set(self.coordinates)
        
        valid_chars = sum(count for char, count in char_counts.items() if char in adfgvx_chars)
        total_chars = len(encrypted_text.replace(' ', '').replace('-', ''))  # Remove common separators
        
        print(f"Valid ADFGVX characters: {valid_chars}/{total_chars}")
        
        if valid_chars > 0:
            print("Character frequency in ciphertext:")
            for char in self.coordinates:
                count = char_counts.get(char, 0)
                pct = (count / valid_chars) * 100 if valid_chars > 0 else 0
                print(f"  {char}: {count:3d} ({pct:5.1f}%)")
        
        # Try to estimate transposition keyword length
        if not separators_found:
            print(f"\nEstimating transposition keyword length:")
            # Try common keyword lengths
            for kw_len in range(3, 12):
                if len(encrypted_text) % kw_len == 0:
                    print(f"  Length {kw_len}: Would create {len(encrypted_text) // kw_len} rows")


    def demonstrate_decryption(self, encrypted_text, grid_keyword=None, trans_keyword=None, random_seed=None):
        # this function is a detailed breakdown of the steps of the attempted decryption process

        print(f"=== ADFGVX CIPHER DECRYPTION DEMONSTRATION ===")
        print(f"Encrypted text: '{encrypted_text}'")
        
        # Show the configuration being used
        self.show_cipher_mapping(grid_keyword, trans_keyword, random_seed)
        
        print(f"\n=== STEP 1: REVERSE TRANSPOSITION ===")
        try:
            substituted = self.reverse_transposition(encrypted_text, trans_keyword)
            print(f"After reversing transposition: '{substituted}'")
            
            print(f"\n=== STEP 2: REVERSE SUBSTITUTION ===")
            # Show coordinate pair decoding
            clean_text = ''.join(char for char in substituted.upper() if char in self.coordinates)
            print(f"Coordinate pairs to decode:")
            
            for i in range(0, min(20, len(clean_text)), 2):  # Show first 10 pairs
                if i + 1 < len(clean_text):
                    coord_pair = clean_text[i:i+2]
                    if coord_pair in self.reverse_coordinate_map:
                        char = self.reverse_coordinate_map[coord_pair]
                        print(f"  {coord_pair} → {char}")
                    else:
                        print(f"  {coord_pair} → [INVALID]")
            
            if len(clean_text) > 20:
                print(f"  ... and {(len(clean_text) - 20) // 2} more pairs")
            
            plaintext = self.reverse_substitution(substituted, grid_keyword, random_seed)
            print(f"Final decrypted text: '{plaintext}'")
            
            return plaintext
            
        except Exception as e:
            print(f"Decryption failed: {e}")
            return None
