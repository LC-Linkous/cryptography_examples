#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/grid/polybius/encrypt.py'
#   Polybius Square cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\


import numpy as np
import random
np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

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

        # unpack the dataframe of options configurable to this encryption method
        self.keyword = opt_df['KEYWORD'][0] if 'KEYWORD' in opt_df.columns else None
        self.grid_size = int(opt_df['GRID_SIZE'][0]) if 'GRID_SIZE' in opt_df.columns else 5
        self.combine_letters = opt_df['COMBINE_LETTERS'][0] if 'COMBINE_LETTERS' in opt_df.columns else 'IJ'
        self.number_base = int(opt_df['NUMBER_BASE'][0]) if 'NUMBER_BASE' in opt_df.columns else 1
        self.separator = opt_df['SEPARATOR'][0] if 'SEPARATOR' in opt_df.columns else ' '
        self.random_seed = int(opt_df['RANDOM_SEED'][0]) if 'RANDOM_SEED' in opt_df.columns else 42

        # Validate parameters
        if self.grid_size not in [5, 6]:
            raise ValueError("Grid size must be 5 or 6")
        
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
                chars = [chr(i) for i in range(65, 73)] + [chr(i) for i in range(75, 91)]  # A-H, K-Z
            elif self.combine_letters == 'UV':
                # Alternative: combine U and V
                chars = [chr(i) for i in range(65, 85)] + [chr(i) for i in range(86, 91)]  # A-T, W-Z
            else:
                # Use first 25 letters
                chars = [chr(i) for i in range(65, 90)]  # A-Y
        else:
            # 6x6 grid can hold 36 characters (A-Z + 0-9)
            chars = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(48, 58)]  # A-Z, 0-9
        
        self.working_chars = chars


    def create_cipher_grid(self):
        # Create the grid for the polybius cipher
        # used to create the coordinate map

        if self.keyword:
            # Use keyword to create grid
            grid_chars = self.create_keyword_grid()
        else:
            # Use standard alphabetical or random grid
            grid_chars = self.create_standard_grid()
        
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


    def create_keyword_grid(self):
        # This creates the grid (substitution square) using a keyword, where the keyword starts
        # in the top left. Technically the keywor can be any length,
        # but they cannot have duplicate letters. 
        #
        # Keywords can only have 1 of each letter.
        # SECRET -> SECRT
        # VIOLET -> VIOLET

        if not self.keyword:
            return self.working_chars.copy()
        
        # Remove duplicates from keyword and convert to uppercase
        keyword_chars = []
        seen = set()
        
        for char in self.keyword.upper():
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


    def create_standard_grid(self):
        # creates a reusable/reproducable grid
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
        
        for row in range(self.grid_size):
            for col in range(self.grid_size):
                char = self.cipher_grid[row][col]
                if char:  # Not empty
                    # Coordinates (1-based or 0-based depending on number_base)
                    coord_row = row + self.number_base
                    coord_col = col + self.number_base
                    
                    self.coordinate_map[char] = (coord_row, coord_col)
                    self.reverse_coordinate_map[(coord_row, coord_col)] = char


    def show_cipher_mapping(self, show_coordinates=True):
        # Claude AI tuned up (heavily) to show the square whenever this
        # function is called.

        print(f"Polybius Square ({self.grid_size}x{self.grid_size}):")
        
        if self.keyword:
            print(f"Keyword: '{self.keyword}'")
        
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
                    print(f"  {char} → {coord[0]}{coord[1]}")



    def encrypt_message(self, text):
        if not self.cipher_grid:
            self.create_cipher_grid()
        
        result = []
        
        for char in text.upper():
            if char in self.coordinate_map:
                # Character found in grid - replace with coordinates
                coord = self.coordinate_map[char]
                coord_str = f"{coord[0]}{coord[1]}"
                result.append(coord_str)
            elif char == 'J' and self.combine_letters == 'IJ' and 'I' in self.coordinate_map:
                # Handle J → I substitution
                coord = self.coordinate_map['I']
                coord_str = f"{coord[0]}{coord[1]}"
                result.append(coord_str)
            elif char == 'V' and self.combine_letters == 'UV' and 'U' in self.coordinate_map:
                # Handle V → U substitution
                coord = self.coordinate_map['U']
                coord_str = f"{coord[0]}{coord[1]}"
                result.append(coord_str)
            else:
                # Character not in grid - keep unchanged
                if char.isalpha():
                    result.append(f"[{char}]")  # Mark unknown letters
                else:
                    result.append(char)  # Keep spaces, punctuation
        
        return self.separator.join(result)



    def decrypt_message(self, encrypted_text):
        # included in this class for DEMO purposes only. 
        # Actual decryption attempts happen in decrypt.py
        # This function has all of the encryption infromation already

        if not self.cipher_grid:
            self.create_cipher_grid()
        
        # Split by separator
        if self.separator in encrypted_text:
            coordinate_pairs = encrypted_text.split(self.separator)
        else:
            # If no separator, assume each coordinate is 2 digits
            coordinate_pairs = []
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

    def get_grid_stats(self):
        # Pulled form the Claude AI 'Improved' version
        # This is kind of cool to get the metrics for the cipher
        if not self.cipher_grid:
            return {}
        
        stats = {
            'grid_size': f"{self.grid_size}x{self.grid_size}",
            'total_positions': self.grid_size * self.grid_size,
            'filled_positions': sum(1 for row in self.cipher_grid for cell in row if cell),
            'keyword_used': bool(self.keyword),
            'combine_letters': self.combine_letters,
            'number_base': self.number_base,
            'separator': repr(self.separator)
        }
        
        return stats

