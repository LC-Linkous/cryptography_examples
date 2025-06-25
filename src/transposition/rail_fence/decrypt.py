#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/rail_fence/decrypt.py'
#   Rail Fence cipher brute force decryption class
#
#   Rail Fence ciphers have a small key space (number of rails), making them
#   vulnerable to true brute force attacks. We can try every possible number
#   of rails and use frequency analysis to identify the correct decryption.      
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##--------------------------------------------------------------------\


import numpy as np
import pandas as pd
import string
from collections import Counter
import re

class decrypt:
    
    def __init__(self, dictionary=None, lang_freq=None):
        
        # can pass in a dictionary if a custom one exists
        if dictionary is None:
            # Default to A-Z + a-z
            self.dictionary = [chr(i) for i in range(65, 91)] + [chr(i) for i in range(97, 123)]
        else:
            self.dictionary = list(dictionary)
        
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
        
        # Common English bigrams and trigrams for pattern analysis
        # N
        # self.common_bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ED', 'ND', 
        #                       'ON', 'EN', 'AT', 'OU', 'EA', 'HA', 'NG', 'AS', 
        #                       'OR', 'TI', 'IS', 'ET', 'IT', 'AR', 'TE', 'SE', 'HI']
        
        # self.common_trigrams = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 
        #                        'ERE', 'FOR', 'ENT', 'ION', 'TER', 'WAS', 'YOU', 
        #                        'ITH', 'VER', 'ALL', 'WIT', 'THI', 'TIO']
        
        # Common English bigrams and trigrams for pattern analysis
        self.common_bigrams = ['TH', 'HE', 'IN', 'ER', 'AN', 'RE', 'ED', 'ND', 
                              'ON', 'EN', 'AT', 'OU', 'EA', 'HA', 'NG', 'AS', 
                              'OR', 'TI', 'IS', 'ET', 'IT', 'AR', 'TE', 'SE', 
                              'AL', 'HI', 'NT', 'RE', 'ES', 'CO','DE','TO',
                               'RA','SA','RM', 'RO' ]
        
        
        self.common_trigrams = ['THE', 'AND', 'ING', 'HER', 'HAT', 'HIS', 'THA', 
                               'ERE', 'FOR', 'ENT', 'ION', 'TER', 'WAS', 'YOU', 
                               'ITH', 'VER', 'ALL', 'WIT', 'THI', 'TIO', 'NDE',
                               'HAS', 'NCE','TIS', 'OFT', 'STH', 'MEN' ]
        
       

        # Common English words for pattern matching
        # The original dictionary
        # self.common_words = ['THE', 'AND', 'FOR', 'ARE', 'BUT', 'NOT', 'YOU', 
        #                     'ALL', 'CAN', 'HER', 'WAS', 'ONE', 'OUR', 'HAD', 
        #                     'BY', 'WORD', 'BUT', 'WHAT', 'SOME', 'WE', 'CAN', 
        #                     'OUT', 'OTHER', 'WERE', 'WHICH', 'THEIR', 'SAID', 
        #                     'EACH', 'SHE', 'DO', 'HOW', 'IF', 'WILL', 'UP', 
        #                     'ABOUT', 'GET', 'MADE', 'THEY', 'KNOW', 'TAKE', 'THAN']
                # More words can be added.
        # In fact, if there is known context for a message, adding context specific words
        # MIGHT make the decryption more accurate. However, the longer this list the longer
        # the decryption will take.
        # https://en.wikipedia.org/wiki/Most_common_words_in_English <- core word set
        self.common_words = ['ABOUT', 'AFTER', 'ALL', 'ALSO', 'AND', 'ANY', 'A', 'AN', 
                            'ARE', 'BACK', 'BAD', 'BE', 'BECAUSE', 'BUT', 'BY', 'CAN', 'COME',
                            'COULD', 'DAY', 'DO', 'EACH', 'EARLY', 'EVEN', 'FEW', 'FIRST', 'FOR', 
                            'FROM', 'GET', 'GIVE', 'GOOD', 'GROUP', 'HAD', 'HE', 'HER', 'HIM', 
                            'HOW', 'I', 'IF', 'IN', 'INTO', 'IT', 'ITS', 'JUST', 
                            'KNOW', 'LATE', 'LIKE', 'LONG', 'LOOK', 'MAKE', 'MANY', 
                            'ME', 'MOST', 'MY', 'NEW', 'NO', 'NOT', 'NOW', 'NUMBER', 'OF', 
                            'ON', 'ONLY', 'ONE', 'OR', 'OTHER', 'OUR', 'OUT', 'PEOPLE', 'PART', 
                            'SAID', 'SAY', 'SEE', 'SHE', 'SINCE', 'TAKE', 'THE', 
                            'THEIR', 'THEM', 'THEN', 'THERE', 'THEY', 'THIS', 'THINK', 'TIME', 
                            'TO', 'TWO', 'UP', 'USE', 'WANT', 'WAY', 'WELL', 'WHAT', 'WHEN', 
                            'WHERE', 'WHICH', 'WHO', 'WILL', 'WITH', 'WORK', 'WOULD', 'YEAR', 'YOU', 'YOUR']
                            # # and some additional long (longer than 4 letters), distinct words that occur in English
                            # # some of these were chosen based on 'secret message' topics, so there is som bias
                            # # words with multiple meanings were also chosen to get more mileage out of them
                            # 'RECENT', 'IMPORTANT', 'LETTERS', 'TOMORROW', 'TODAY', 'BEGINNING', 
                            # 'NECESSARY']  
                            # # ADD YOUR OWN WORDS HERE!! This is the place to start adding words for a known
                            # # context. It's a bit of a 'cheat', but that's part of decryption.


    def create_rail_pattern(self, text_length, num_rails, direction='down'):
        """Create the zigzag pattern for rail fence cipher"""
        if text_length == 0 or num_rails < 2:
            return []
        
        pattern = []
        current_rail = 0
        rail_direction = 1 if direction == 'down' else -1
        
        for i in range(text_length):
            pattern.append(current_rail)
            
            # Change direction at the boundaries
            if current_rail == 0:
                rail_direction = 1
            elif current_rail == num_rails - 1:
                rail_direction = -1
            
            # Move to next rail (except for single rail case)
            if num_rails > 1:
                current_rail += rail_direction
        
        return pattern

    def decrypt_rail_fence(self, encrypted_text, num_rails, direction='down'):
        """Decrypt rail fence cipher with specified number of rails"""
        if not encrypted_text or num_rails < 2:
            return encrypted_text
        
        text_length = len(encrypted_text)
        
        # Create the pattern to know which positions belong to which rail
        pattern = self.create_rail_pattern(text_length, num_rails, direction)
        
        # Count characters per rail
        rail_lengths = [0] * num_rails
        for rail_num in pattern:
            rail_lengths[rail_num] += 1
        
        # Extract characters for each rail from the encrypted text
        rails = []
        start_pos = 0
        
        for rail_num in range(num_rails):
            rail_length = rail_lengths[rail_num]
            if start_pos + rail_length <= len(encrypted_text):
                rail_chars = encrypted_text[start_pos:start_pos + rail_length]
                rails.append(list(rail_chars))
                start_pos += rail_length
            else:
                # Handle case where encrypted text is shorter than expected
                rails.append([])
        
        # Reconstruct original text using the pattern
        decrypted_text = ""
        rail_indices = [0] * num_rails  # Track position in each rail
        
        for rail_num in pattern:
            if rail_indices[rail_num] < len(rails[rail_num]):
                decrypted_text += rails[rail_num][rail_indices[rail_num]]
                rail_indices[rail_num] += 1
        
        return decrypted_text

    def calculate_english_score(self, text):
        """Calculate how English-like a text is"""
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return -1000
        
        score = 0
        text_length = len(clean_text)
        
        # 1. Letter frequency analysis
        letter_counts = Counter(clean_text)
        total_letters = len(clean_text)
        
        for letter, count in letter_counts.items():
            observed_freq = (count / total_letters) * 100
            expected_freq = self.lang_freq.get(letter, 0)
            # Penalize deviation from expected frequency
            score -= (observed_freq - expected_freq) ** 2
        
        # 2. Common words bonus
        word_bonus = 0
        for word in self.common_words:
            if word in clean_text:
                word_bonus += len(word) * 15  # Higher bonus for longer words
        
        # 3. Bigram analysis
        bigram_bonus = 0
        for i in range(len(clean_text) - 1):
            bigram = clean_text[i:i+2]
            if bigram in self.common_bigrams:
                bigram_bonus += 8
        
        # 4. Trigram analysis
        trigram_bonus = 0
        for i in range(len(clean_text) - 2):
            trigram = clean_text[i:i+3]
            if trigram in self.common_trigrams:
                trigram_bonus += 12
        
        # 5. Pattern bonus for natural English patterns
        pattern_bonus = 0
        
        # Vowel distribution check
        vowels = 'AEIOU'
        vowel_count = sum(1 for c in clean_text if c in vowels)
        vowel_ratio = vowel_count / text_length if text_length > 0 else 0
        
        # English typically has 35-45% vowels
        if 0.30 <= vowel_ratio <= 0.50:
            pattern_bonus += 15
        elif 0.25 <= vowel_ratio <= 0.55:
            pattern_bonus += 8
        else:
            pattern_bonus -= 10
        
        # Penalize sequences that look like random letters
        # Look for excessive consonant clusters
        consonant_clusters = 0
        consonants_in_row = 0
        
        for char in clean_text:
            if char not in vowels:
                consonants_in_row += 1
            else:
                if consonants_in_row > 3:  # More than 3 consonants in a row is unusual
                    consonant_clusters += consonants_in_row - 3
                consonants_in_row = 0
        
        pattern_bonus -= consonant_clusters * 5
        
        return score + word_bonus + bigram_bonus + trigram_bonus + pattern_bonus

    def analyze_rail_pattern(self, encrypted_text, num_rails):
        """Analyze the rail pattern for educational purposes"""
        pattern = self.create_rail_pattern(len(encrypted_text), num_rails)
        
        # Count characters per rail
        rail_counts = Counter(pattern)
        
        # Calculate pattern statistics
        stats = {
            'num_rails': num_rails,
            'text_length': len(encrypted_text),
            'rail_distribution': dict(rail_counts),
            'pattern_period': self.calculate_pattern_period(num_rails),
            'pattern_sample': pattern[:min(20, len(pattern))]
        }
        
        return stats

    def calculate_pattern_period(self, num_rails):
        """Calculate the period of the rail fence pattern"""
        if num_rails <= 1:
            return 1
        elif num_rails == 2:
            return 2
        else:
            # For n rails, the pattern period is 2*(n-1)
            return 2 * (num_rails - 1)

    def brute_force_decrypt(self, encrypted_text, max_rails=20, show_progress=True):
        """
        Try all possible numbers of rails to decrypt the message
        
        Unlike substitution ciphers, rail fence has a tiny key space:
        - Only need to try different numbers of rails (typically 2-20)
        - Each attempt is fast (just rearranging characters)
        - Can exhaustively search the entire key space
        """
        results = []
        
        if show_progress:
            print(f"Brute force attacking rail fence cipher (2-{max_rails} rails)...")
            print("=" * 70)
        
        text_length = len(encrypted_text)
        
        # Try each possible number of rails
        for num_rails in range(2, min(max_rails + 1, text_length + 1)):
            try:
                # Try both directions (though 'down' is standard)
                for direction in ['down']:  # Could add 'up' if needed
                    decrypted = self.decrypt_rail_fence(encrypted_text, num_rails, direction)
                    score = self.calculate_english_score(decrypted)
                    
                    # Analyze pattern for educational insight
                    pattern_stats = self.analyze_rail_pattern(encrypted_text, num_rails)
                    
                    results.append((num_rails, direction, decrypted, score, pattern_stats))
                    
                    if show_progress:
                        print(f"Rails: {num_rails:2d} | Score: {score:7.1f} | Result: {decrypted[:50]}")
                
            except Exception as e:
                if show_progress:
                    print(f"Error with {num_rails} rails: {e}")
                continue
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[3], reverse=True)
        
        return results

    def auto_decrypt(self, encrypted_text, max_rails=20, top_n=5):
        """
        Automatically find the most likely decryption
        """
        results = self.brute_force_decrypt(encrypted_text, max_rails, show_progress=False)
        
        if not results:
            print("Could not find any valid decryptions.")
            return encrypted_text
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 80)
        
        for i, (num_rails, direction, decrypted, score, stats) in enumerate(results[:top_n]):
            print(f"{i+1}. Rails: {num_rails}, Direction: {direction}, Score: {score:.1f}")
            print(f"   Result: {decrypted}")
            print(f"   Pattern period: {stats['pattern_period']}, Rail distribution: {stats['rail_distribution']}")
            print()
        
        return results[0][2] if results else encrypted_text

    def show_decryption_analysis(self, encrypted_text, num_rails):
        """Show detailed analysis of a specific rail configuration"""
        print(f"=== Detailed Analysis: {num_rails} Rails ===")
        
        decrypted = self.decrypt_rail_fence(encrypted_text, num_rails)
        score = self.calculate_english_score(decrypted)
        stats = self.analyze_rail_pattern(encrypted_text, num_rails)
        
        print(f"Encrypted:  '{encrypted_text}'")
        print(f"Decrypted:  '{decrypted}'")
        print(f"Score:      {score:.1f}")
        print(f"Text length: {stats['text_length']}")
        print(f"Pattern period: {stats['pattern_period']}")
        print(f"Rail distribution: {stats['rail_distribution']}")
        print(f"Pattern sample: {stats['pattern_sample']}")
        
        # Show rail visualization for shorter texts
        if len(encrypted_text) <= 30:
            print("\nRail visualization:")
            pattern = self.create_rail_pattern(len(encrypted_text), num_rails)
            
            # Create grid
            grid = []
            for rail in range(num_rails):
                grid.append([' '] * len(encrypted_text))
            
            # Fill grid with decrypted characters
            for i, char in enumerate(decrypted):
                rail = pattern[i]
                grid[rail][i] = char
            
            # Display grid
            for rail_num, rail_content in enumerate(grid):
                rail_display = ''.join(rail_content)
                print(f"Rail {rail_num}: {rail_display}")

