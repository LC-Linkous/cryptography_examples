#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/rail_fence/encrypt.py'
#  Rail Fence transposition cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 23, 2025
##--------------------------------------------------------------------\


import numpy as np
import pandas as pd
import sys
np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

        # Optional parent class
        self.parent = parent 

        # set dictionary (though rail fence doesn't really use it the same way)
        self.original_dictionary = np.array(dictionary) if dictionary else None
        self.cipher_pattern = None

        # unpack the dataframe of options configurable to this encryption method
        self.num_rails = int(opt_df['NUM_RAILS'][0])
        self.direction = opt_df['DIRECTION'][0] if 'DIRECTION' in opt_df.columns else 'down'
        self.fill_char = opt_df['FILL_CHAR'][0] if 'FILL_CHAR' in opt_df.columns else None
        self.remove_spaces = opt_df['REMOVE_SPACES'][0] if 'REMOVE_SPACES' in opt_df.columns else True

        # Validate parameters
        if self.num_rails < 2:
            raise ValueError("Number of rails must be at least 2")


    def set_cipher_pattern(self, pattern):
        # if there's a unique case of the pattern
        self.cipher_pattern = pattern


    def create_rail_pattern(self, text_length):
        # This creates the distinctive 'zig zag' pattern
        # of the rail fence algorithm
        # (NOTE: there's some edge cases that have caused
        # problems)


        if text_length == 0:
            return []
        
        # Create the rail pattern (zigzag)
        pattern = []
        current_rail = 0
        direction = 1 if self.direction == 'down' else -1
        
        for i in range(text_length):
            pattern.append(current_rail)
            
            # Change direction at the boundaries
            if current_rail == 0:
                direction = 1
            elif current_rail == self.num_rails - 1:
                direction = -1
            
            # Move to next rail (except for single rail case)
            if self.num_rails > 1:
                current_rail += direction
        
        self.cipher_pattern = pattern
        return pattern


    def show_cipher_mapping(self, text, show_grid=True):
       # This displays the 'zig zag' pattern of the rail fence algorithm
       # This is primarily for preview purposes, not decoding the message
       

        if not text:
            print("No text provided for rail fence visualization")
            return
            
        clean_text = self.prepare_text(text)
        pattern = self.create_rail_pattern(len(clean_text))
        
        print(f"Rail Fence cipher with {self.num_rails} rails:")
        print(f"Direction: {self.direction}")
        print(f"Text length: {len(clean_text)}")
        
        if show_grid and len(clean_text) <= 50:  # Only show grid for reasonable lengths
            print("\nRail visualization:")
            
            # Create and display the rail grid
            grid = self.create_rail_grid(clean_text)
            
            for rail_num, rail_content in enumerate(grid):
                rail_display = ''.join(rail_content)
                print(f"Rail {rail_num}: {rail_display}")
        
        print(f"\nRail pattern: {pattern[:20]}{'...' if len(pattern) > 20 else ''}")



    def create_rail_grid(self, text):
       # creates the ASCII pattern for visualization

        pattern = self.create_rail_pattern(len(text))
        
        # Initialize grid
        grid = []
        for rail in range(self.num_rails):
            grid.append([' '] * len(text))
        
        # Fill grid with characters
        for i, char in enumerate(text):
            rail = pattern[i]
            grid[rail][i] = char
        
        return grid



    def prepare_text(self, text):
        # Clean the text
        # This removes spaces and punctuation so that
        # only alphanumeric values are left. 
        # 
        # group work question: implement a diferent method to keep punctuation.
        # What does this do to the algorithm, and do you need a different dictionary?

        if self.remove_spaces:
            # Remove spaces and keep only letters/numbers
            clean_text = ''.join(char for char in text if char.isalnum())
        else:
            clean_text = text
        
        return clean_text
    



    def encrypt_message(self, text):
        
        if not text:
            return ""
        
        # Prepare text
        clean_text = self.prepare_text(text)
        
        if len(clean_text) == 0:
            return ""
        
        # Create rail pattern
        pattern = self.create_rail_pattern(len(clean_text))
        
        # Create rails
        rails = [[] for _ in range(self.num_rails)]
        
        # Distribute characters to rails according to pattern
        for i, char in enumerate(clean_text):
            rail_num = pattern[i]
            rails[rail_num].append(char)
        
        # Read rails in order to create ciphertext
        encrypted_text = ""
        for rail in rails:
            encrypted_text += ''.join(rail)
        
        return encrypted_text


    def decrypt_message(self, encrypted_text):
        # DEMO decrypt when you already know the features of the encryption method
        # This is NOT the brute force decryption
        if not encrypted_text:
            return ""
        
        text_length = len(encrypted_text)
        
        # Create the pattern to know which positions belong to which rail
        pattern = self.create_rail_pattern(text_length)
        
        # Count characters per rail
        rail_lengths = [0] * self.num_rails
        for rail_num in pattern:
            rail_lengths[rail_num] += 1
        
        # Extract characters for each rail from the encrypted text
        rails = []
        start_pos = 0
        
        for rail_num in range(self.num_rails):
            rail_length = rail_lengths[rail_num]
            rail_chars = encrypted_text[start_pos:start_pos + rail_length]
            rails.append(list(rail_chars))
            start_pos += rail_length
        
        # Reconstruct original text using the pattern
        decrypted_text = ""
        rail_indices = [0] * self.num_rails  # Track position in each rail
        
        for rail_num in pattern:
            if rail_indices[rail_num] < len(rails[rail_num]):
                decrypted_text += rails[rail_num][rail_indices[rail_num]]
                rail_indices[rail_num] += 1
        
        return decrypted_text

