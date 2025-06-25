#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/monoalphabetic/decrypt.py'
#   Ceasar cipher decryption class
#       
#  monoalphabetic ciphers can't be broken by trying all possible keys (26! is impossibly large). 
#  Instead, this decryption process uses the statistical properties of English text (primarily frequency analysis and bi/tri grams) 
#  to gradually discover the correct substitution key through intelligent search and optimization.
#
#   This method is more effective on longer texts (50+ characters) where frequency analysis becomes more reliable,
#   but it can often crack shorter messages using pattern recognition.
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
import random

class decrypt:
    
    def __init__(self, dictionary=None, lang_freq=None):
        
        # can pass in a dictionary if a custom one exists
        if dictionary is None:
            # Default to A-Z
            self.dictionary = [chr(i) for i in range(65, 91)]
        else:
            self.dictionary = list(dictionary)
        
        # Common letter frequencies (for scoring)
        if lang_freq == None:
            # English default - ordered by frequency
            self.lang_freq = {
                'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
                'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
                'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
                'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
                'Q': 0.10, 'Z': 0.07
            }
        else:
            self.lang_freq = lang_freq
        
        # Most common English letters in order
        self.freq_order = ['E', 'T', 'A', 'O', 'I', 'N', 'S', 'H', 'R', 'D', 
                          'L', 'U', 'C', 'M', 'W', 'F', 'G', 'Y', 'P', 'B', 
                          'V', 'K', 'J', 'X', 'Q', 'Z']
        
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
                            #'CRYPTOGRAPHY', 'SUBSTITUTION', 'CIPHER', 'METHOD', 'ENCRYPT']
                            # # and some additional long (longer than 4 letters), distinct words that occur in English
                            # # some of these were chosen based on 'secret message' topics, so there is som bias
                            # # words with multiple meanings were also chosen to get more mileage out of them
                            # 'RECENT', 'IMPORTANT', 'LETTERS', 'TOMORROW', 'TODAY', 'BEGINNING', 
                            # 'NECESSARY']  
                            # # ADD YOUR OWN WORDS HERE!! This is the place to start adding words for a known
                            # # context. It's a bit of a 'cheat', but that's part of decryption.

    def analyze_frequency(self, text):
        # Analyze letter frequencies in the ciphertext
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return {}
        
        # Count letter frequencies
        letter_counts = Counter(clean_text)
        total_letters = len(clean_text)
        
        # Convert to percentages and sort by frequency
        frequencies = {}
        for letter, count in letter_counts.items():
            frequencies[letter] = (count / total_letters) * 100
        
        # Sort by frequency (most common first)
        sorted_freq = sorted(frequencies.items(), key=lambda x: x[1], reverse=True)
        
        return dict(sorted_freq)


    def create_frequency_key(self, ciphertext):
        #Create initial substitution key based on frequency analysis
        # monoalphabetic ciphers are harder to brute force because they can be 
        # a shift or they can be random. So its possible to need a create several frequency
        # keys or to test several times before anything begins to look like it might
        # be possible


        cipher_freq = self.analyze_frequency(ciphertext)
        
        # Get cipher letters ordered by frequency
        cipher_order = list(cipher_freq.keys())
        
        # Create initial mapping: most frequent cipher letter -> E, etc.
        initial_key = {}
        for i, cipher_letter in enumerate(cipher_order):
            if i < len(self.freq_order):
                initial_key[cipher_letter] = self.freq_order[i]
            else:
                # Handle case where we have more cipher letters than expected
                remaining_letters = [l for l in self.dictionary if l not in initial_key.values()]
                if remaining_letters:
                    initial_key[cipher_letter] = remaining_letters[0]
                    remaining_letters.pop(0)
        
        # Fill in any missing letters
        used_letters = set(initial_key.values())
        remaining_plain = [l for l in self.dictionary if l not in used_letters]
        remaining_cipher = [l for l in self.dictionary if l not in initial_key]
        
        for cipher_char, plain_char in zip(remaining_cipher, remaining_plain):
            initial_key[cipher_char] = plain_char
        
        return initial_key


    def word_pattern_analysis(self, ciphertext):
        # General pattern analysis without overfitting to specific test cases"""
        # This is a 'patch' to some general issues. Monoalphabetic texts are trickier
        # than Ceasar and Bacon ciphers, so we need to lean more into traits of a language
        # rather than general patterns
        
        patterns = {}
        words = re.findall(r'\b[A-Za-z]+\b', ciphertext.upper())
        
        if not words:
            return patterns
        
        # Analyze word patterns generically
        word_counts = Counter(words)
        word_lengths = Counter([len(w) for w in words])
        
        # Single-letter words (likely 'A' or 'I')
        single_letters = [w for w in words if len(w) == 1]
        if single_letters:
            most_common_single = Counter(single_letters).most_common(1)[0][0]
            # 'A' is more common than 'I' in typical English text
            patterns[most_common_single] = 'A'
        
        # Two-letter words (OF, TO, IN, IT, IS, etc.)
        two_letter_words = [w for w in words if len(w) == 2]
        if two_letter_words:
            most_common_two = Counter(two_letter_words).most_common(1)[0][0]
            # Most common 2-letter word is typically "OF"
            if len(set(most_common_two)) == 2:  # No repeated letters
                patterns[most_common_two[0]] = 'O'
                patterns[most_common_two[1]] = 'F'
        
        # Three-letter words - look for "THE" pattern
        three_letter_words = [w for w in words if len(w) == 3]
        if three_letter_words:
            # Find most common 3-letter word
            most_common_three = Counter(three_letter_words).most_common(1)[0][0]
            # "THE" is by far the most common 3-letter word in English
            if len(set(most_common_three)) == 3:  # All different letters
                patterns[most_common_three[0]] = 'T'
                patterns[most_common_three[1]] = 'H'
                patterns[most_common_three[2]] = 'E'
        
        return patterns


    def create_pattern_key(self, ciphertext):
        # key based on word patterns
        patterns = self.word_pattern_analysis(ciphertext)
        
        if not patterns:
            return self.create_frequency_key(ciphertext)
        
        # Start with pattern mappings
        key = patterns.copy()
        
        # Fill in remaining letters with frequency analysis
        used_cipher = set(key.keys())
        used_plain = set(key.values())
        
        cipher_freq = self.analyze_frequency(ciphertext)
        remaining_cipher = [c for c in cipher_freq.keys() if c not in used_cipher]
        remaining_plain = [p for p in self.freq_order if p not in used_plain]
        
        # Map remaining letters by frequency
        for i, cipher_char in enumerate(remaining_cipher):
            if i < len(remaining_plain):
                key[cipher_char] = remaining_plain[i]
        
        # Ensure all dictionary letters are mapped
        for letter in self.dictionary:
            if letter not in key:
                unused_plain = [p for p in self.dictionary if p not in key.values()]
                if unused_plain:
                    key[letter] = unused_plain[0]
        
        return key



    def apply_substitution_key(self, text, key):
        #Apply a substitution key to decrypt text
        # NOTE: this step doesn't mean it's going to work
        # it means we're going to TRY

        result = []
        for char in text:
            if char.upper() in key:
                decrypted_char = key[char.upper()]
                # Preserve original case
                if char.islower():
                    result.append(decrypted_char.lower())
                else:
                    result.append(decrypted_char)
            else:
                # Character not in key (spaces, punctuation, etc.)
                result.append(char)
        
        return ''.join(result) # as a string
    


    def calculate_english_score(self, text):
        #Calculate how English-like a text is
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return -1000 #penalty
        
        text_length = len(clean_text)
        score = 0
        
        # 1. Letter frequency analysis (always important)
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
                # Bonus proportional to word length, but not too dominant for short texts
                word_bonus += len(word) * 10  # Higher bonus for longer words.
                # we could apply more inteligent weighting schemes later,
                # but this works for right now. (DEMO question: what might 
                # the weighting look like, and what should it consider?)
        
        # 3. Bigram analysis (important for all text lengths)
        bigram_bonus = 0
        for i in range(len(clean_text) - 1):
            bigram = clean_text[i:i+2]
            if bigram in self.common_bigrams:
                bigram_bonus += 5
                
        # 4. Trigram analysis
        trigram_bonus = 0
        for i in range(len(clean_text) - 2):
            trigram = clean_text[i:i+3]
            if trigram in self.common_trigrams:
                trigram_bonus += 8


        # 5. Pattern bonus (repeated letters, common endings)
        pattern_bonus = 0
        # Double letters (common in English)
        for i in range(len(clean_text) - 1):
            if clean_text[i] == clean_text[i+1]:
                if clean_text[i] in 'EFILOSZ':  # Common double letters
                    pattern_bonus += 3
                elif clean_text[i] in 'BCDHMNPRT':  # Less common but possible
                    pattern_bonus += 1
                else:  # Rare double letters
                    pattern_bonus -= 2

        # Vowel distribution check
        vowels = 'AEIOU'
        vowel_count = sum(1 for c in clean_text if c in vowels)
        vowel_ratio = vowel_count / text_length if text_length > 0 else 0
        
        # English typically has 35-45% vowels
        if 0.30 <= vowel_ratio <= 0.50:
            pattern_bonus += 10
        elif 0.25 <= vowel_ratio <= 0.55:
            pattern_bonus += 5
        else:
            pattern_bonus -= 5
        
        return score + word_bonus + bigram_bonus + trigram_bonus + pattern_bonus


    def hill_climb_key(self, ciphertext, initial_key, max_iterations=1000):
        # Includes better termination conditions than V1
        # Improves a substitution key using hill climbing

        current_key = initial_key.copy()
        current_score = self.calculate_english_score(self.apply_substitution_key(ciphertext, current_key))
        
        improvements = 0
        no_improvement_count = 0
        
        for iteration in range(max_iterations):
            # Try swapping two random letters in the key
            key_letters = list(current_key.keys())
            
            if len(key_letters) < 2:
                break
                
            # Pick two random positions to swap
            pos1, pos2 = random.sample(range(len(key_letters)), 2)
            letter1, letter2 = key_letters[pos1], key_letters[pos2]
            
            # Create new key with swapped mappings
            new_key = current_key.copy()
            new_key[letter1], new_key[letter2] = new_key[letter2], new_key[letter1]
            
            # Test new key
            new_score = self.calculate_english_score(self.apply_substitution_key(ciphertext, new_key))
            
            # If improvement, keep the new key
            if new_score > current_score:
                current_key = new_key
                current_score = new_score
                improvements += 1
                no_improvement_count = 0
            else:
                no_improvement_count += 1
                
            # Early termination if no improvements for a while
            if no_improvement_count > 200:
                break
        
        return current_key, current_score, improvements
    


    def pattern_attack(self, ciphertext):
        # This is a direct approach to identify patterns and common words
        # This is one of the functions that makes this cipher decryption
        # language locked
        patterns = {}
        
        # Look for single-letter words (likely 'A' or 'I')
        words = re.findall(r'\b[A-Za-z]+\b', ciphertext.upper())
        
        single_letters = [w for w in words if len(w) == 1]
        if single_letters:
            most_common_single = Counter(single_letters).most_common(1)[0][0]
            patterns[most_common_single] = 'A'  # Assume most common single letter is 'A'
        
        # Look for common 3-letter words (THE, AND, etc.)
        three_letter_words = [w for w in words if len(w) == 3]
        if three_letter_words:
            most_common_three = Counter(three_letter_words).most_common(1)[0][0]
            # Assume it's "THE"
            if len(most_common_three) == 3:
                patterns[most_common_three[0]] = 'T'
                patterns[most_common_three[1]] = 'H'
                patterns[most_common_three[2]] = 'E'
        
        return patterns

    def brute_force_decrypt(self, encrypted_text, num_attempts=6, show_progress=True):
        # We're going to try multiple approaches to decrypt monoalphabetic cipher
        # this has 'Hill Climbing' as the main 'advanced' technique, but there are other 
        # options that are more dynamic, translate across languages, and frankly do much
        # better in brute force decrpytion

        results = []
        
        if show_progress:
            print(f"Analyzing monoalphabetic cipher with {num_attempts} different approaches...")
            print("=" * 70)
        
        # Remove non-alphabetic characters for analysis
        clean_cipher = re.sub(r'[^A-Za-z]', '', encrypted_text.upper())
        
        for attempt in range(num_attempts):
            try:
                # Method 1: Pattern-based analysis (best for short texts)
                if attempt == 0:
                    if show_progress:
                        print("Attempt 1: Pattern-based word analysis")
                    key = self.create_pattern_key(encrypted_text)
                
                # Method 2: Pure frequency analysis
                elif attempt == 1:
                    if show_progress:
                        print("Attempt 2: Frequency analysis mapping")
                    key = self.create_frequency_key(encrypted_text)
                
                # Method 3: Pattern + hill climbing
                elif attempt == 2:
                    if show_progress:
                        print("Attempt 3: Pattern analysis + hill climbing")
                    initial_key = self.create_pattern_key(encrypted_text)
                    key, score, improvements = self.hill_climb_key(encrypted_text, initial_key, 500)
                    if show_progress:
                        print(f"  Hill climbing made {improvements} improvements")
                
                # Method 4: Frequency + hill climbing
                elif attempt == 3:
                    if show_progress:
                        print("Attempt 4: Frequency analysis + hill climbing")
                    initial_key = self.create_frequency_key(encrypted_text)
                    key, score, improvements = self.hill_climb_key(encrypted_text, initial_key, 500)
                    if show_progress:
                        print(f"  Hill climbing made {improvements} improvements")
                
                # Method 5: Random start + hill climbing
                elif attempt == 4:
                    if show_progress:
                        print("Attempt 5: Random key + hill climbing")
                    cipher_letters = list(set(clean_cipher))
                    plain_letters = self.dictionary[:len(cipher_letters)]
                    random.shuffle(plain_letters)
                    key = dict(zip(cipher_letters, plain_letters))
                    key, score, improvements = self.hill_climb_key(encrypted_text, key, 1000)
                    if show_progress:
                        print(f"  Hill climbing made {improvements} improvements")
                
                # Method 6: Multiple random starts
                else:
                    if show_progress:
                        print("Attempt 6: Multiple random starts + aggressive hill climbing")
                    best_key = None
                    best_score = -float('inf')
                    
                    for _ in range(3):
                        cipher_letters = list(set(clean_cipher))
                        plain_letters = self.dictionary[:len(cipher_letters)]
                        random.shuffle(plain_letters)
                        random_key = dict(zip(cipher_letters, plain_letters))
                        
                        improved_key, score, improvements = self.hill_climb_key(encrypted_text, random_key, 1500)
                        if score > best_score:
                            best_key = improved_key
                            best_score = score
                    
                    key = best_key if best_key else self.create_frequency_key(encrypted_text)
                
                # Apply the key and score the result
                decrypted = self.apply_substitution_key(encrypted_text, key)
                score = self.calculate_english_score(decrypted)
                
                results.append((key, decrypted, score))
                
                if show_progress:
                    print(f"  Result: {decrypted[:50]:<50} (Score: {score:.1f})")
                
            except Exception as e:
                if show_progress:
                    print(f"  Error in attempt {attempt + 1}: {e}")
                continue
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results


    def auto_decrypt(self, encrypted_text, top_n=3):
       # automatically find the most likely decryption
       # (results may vary)

        results = self.brute_force_decrypt(encrypted_text, num_attempts=6, show_progress=False)
        
        if not results:
            print("Could not find any valid decryptions.")
            return encrypted_text
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 80)
        
        for i, (key, decrypted, score) in enumerate(results[:top_n]):
            print(f"{i+1}. Score: {score:.1f}")
            print(f"   Result: {decrypted}")
            # Show partial key mapping for verification
            key_sample = dict(list(key.items())[:10])
            key_str = ', '.join([f"{k}->{v}" for k, v in key_sample.items()])
            print(f"   Key sample: {key_str}...")
            print()
        
        return results[0][1] if results else encrypted_text


    def show_key_mapping(self, key):
       # Show the substitution key in a readable format. 
       # This is more important here than with simplier substitution ciphers


        print("Substitution Key Mapping:")
        print("Cipher -> Plain")
        print("-" * 15)
        
        # Sort by cipher letter for easier reading
        sorted_key = sorted(key.items())
        
        for cipher_char, plain_char in sorted_key:
            print(f"  {cipher_char}    ->   {plain_char}")

