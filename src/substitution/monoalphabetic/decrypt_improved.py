#!/usr/bin/python3

##---------------------------------------------------------------------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/monoalphabetic/decrypt_improved.py'
#   improved monoalphabetic cipher decryption class
#       
#  monoalphabetic ciphers can't be broken by trying all possible keys (26! is impossibly large). 
#  Instead, this decryption process uses the statistical properties of English text (primarily frequency analysis and bi/tri grams) 
#  to gradually discover the correct substitution key through intelligent search and optimization.
#
#   The original 'decrypt.pt' class for this cipher uses a 'hill climbing' approach, which only accepts new solutions that are
#   BETTER than the previous answer. This can cause the algorithm to get stuck in a local optima since it cannot 'backtrack'
#   This class changes the approach to one called 'simulated annealing' (and some genetic algorithm backup), which will allow for some
#   'backtracking' by accepting solutions that are slightly worse (within a % margin or probability) in order to find a global solution.
#   The genetic algorithm is what lets the method 'evolve' by balancing the space exploration and what's currently working
#
#   - https://www.geeksforgeeks.org/machine-learning/difference-between-hill-climbing-and-simulated-annealing-algorithm/
#
#   Author(s): Lauren Linkous
#   Last update: June 22, 2025
##---------------------------------------------------------------------------------------------------------------------------------\


import numpy as np
import pandas as pd
import string
from collections import Counter
import re
import random
import math

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
                            'WHERE', 'WHICH', 'WHO', 'WILL', 'WITH', 'WORK', 'WOULD', 'YEAR', 'YOU', 'YOUR',
                            # # and some additional long (longer than 4 letters), distinct words that occur in English
                            # # some of these were chosen based on 'secret message' topics, so there is som bias
                            # # words with multiple meanings were also chosen to get more mileage out of them
                            'RECENT', 'IMPORTANT', 'LETTERS', 'TOMORROW', 'TODAY', 'BEGINNING', 
                            'NECESSARY'] #
                            # # ADD YOUR OWN WORDS HERE!! This is the place to start adding words for a known
                            # # context. It's a bit of a 'cheat', but that's part of decryption.
                            #'CRYPTOGRAPHY', 'SUBSTITUTION', 'CIPHER', 'METHOD', 'ENCRYPT']

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
        # Create initial substitution key based on frequency analysis
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
        
        # Fill in any missing letters
        used_letters = set(initial_key.values())
        remaining_plain = [l for l in self.dictionary if l not in used_letters]
        remaining_cipher = [l for l in self.dictionary if l not in initial_key]
        
        for cipher_char, plain_char in zip(remaining_cipher, remaining_plain):
            initial_key[cipher_char] = plain_char
        
        return initial_key

    def apply_substitution_key(self, text, key):
        # Apply a substitution key to decrypt text
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
        # Calculate how English-like a text is
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return -1000 # penalty
        
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

    def simulated_annealing(self, ciphertext, initial_key, max_iterations=5000, initial_temp=100.0):
        # Simulated Annealing optimization - better than hill climbing at escaping local optima.
        # 
        # Key differences from hill climbing:
        # 1. Accepts worse solutions with probability based on temperature
        # 2. Temperature decreases over time (cooling schedule)
        # 3. Can escape local optima early in the search
        # 4. Converges to hill climbing behavior as temperature approaches 0
        # It's still not perfect, but this method produces much better results on longer text

        current_key = initial_key.copy()
        current_score = self.calculate_english_score(self.apply_substitution_key(ciphertext, current_key))
        
        best_key = current_key.copy()
        best_score = current_score
        
        improvements = 0
        accepted_moves = 0
        temperature = initial_temp
        
        for iteration in range(max_iterations):
            # Calculate current temperature (cooling schedule)
            temperature = initial_temp * (1 - iteration / max_iterations)
            
            # Try swapping two random letters
            key_letters = list(current_key.keys())
            if len(key_letters) < 2:
                break
                
            pos1, pos2 = random.sample(range(len(key_letters)), 2)
            letter1, letter2 = key_letters[pos1], key_letters[pos2]
            
            # Create new key with swapped mappings
            new_key = current_key.copy()
            new_key[letter1], new_key[letter2] = new_key[letter2], new_key[letter1]
            
            # Test new key
            new_score = self.calculate_english_score(self.apply_substitution_key(ciphertext, new_key))
            
            # Accept or reject the new solution
            accept = False
            
            if new_score > current_score:
                # Always accept improvements
                accept = True
                improvements += 1
            elif temperature > 0:
                # Accept worse solutions with probability based on temperature
                score_diff = new_score - current_score
                probability = math.exp(score_diff / temperature)
                if random.random() < probability:
                    accept = True
            
            if accept:
                current_key = new_key
                current_score = new_score
                accepted_moves += 1
                
                # Track best solution found
                if new_score > best_score:
                    best_key = new_key.copy()
                    best_score = new_score
        
        return best_key, best_score, improvements, accepted_moves

    def genetic_algorithm(self, ciphertext, population_size=20, generations=100):
        # Genetic Algorithm - maintains population of solutions and evolves them
        # this is 
        # Better than both hill climbing and simulated annealing for complex search spaces
        
        # Create initial population
        population = []
        for _ in range(population_size):
            # Create random key
            cipher_letters = list(set(re.sub(r'[^A-Za-z]', '', ciphertext.upper())))
            plain_letters = self.dictionary[:len(cipher_letters)]
            random.shuffle(plain_letters)
            key = dict(zip(cipher_letters, plain_letters))
            
            score = self.calculate_english_score(self.apply_substitution_key(ciphertext, key))
            population.append((key, score))
        
        best_key = None
        best_score = -float('inf')
        
        for generation in range(generations):
            # Sort population by fitness
            population.sort(key=lambda x: x[1], reverse=True)
            
            # Track best solution
            if population[0][1] > best_score:
                best_key = population[0][0].copy()
                best_score = population[0][1]
            
            # Create new generation
            new_population = []
            
            # Keep top 25% (elitism)
            elite_count = population_size // 4
            for i in range(elite_count):
                new_population.append(population[i])
            
            # Create offspring through crossover and mutation
            while len(new_population) < population_size:
                # Select parents (tournament selection)
                parent1 = self.tournament_selection(population, 3)
                parent2 = self.tournament_selection(population, 3)
                
                # Crossover
                child_key = self.crossover(parent1[0], parent2[0])
                
                # Mutation
                if random.random() < 0.1:  # 10% mutation rate
                    child_key = self.mutate(child_key)
                
                child_score = self.calculate_english_score(self.apply_substitution_key(ciphertext, child_key))
                new_population.append((child_key, child_score))
            
            population = new_population
        
        return best_key, best_score

    def tournament_selection(self, population, tournament_size):
        """Select parent using tournament selection"""
        tournament = random.sample(population, min(tournament_size, len(population)))
        return max(tournament, key=lambda x: x[1])

    def crossover(self, parent1, parent2):
        """Create child by combining two parent solutions"""
        child = {}
        
        # For each cipher letter, randomly choose mapping from parent1 or parent2
        all_plain_used = set()
        
        for cipher_letter in parent1.keys():
            if random.random() < 0.5:
                plain_letter = parent1[cipher_letter]
            else:
                plain_letter = parent2[cipher_letter]
            
            # Avoid duplicates
            if plain_letter not in all_plain_used:
                child[cipher_letter] = plain_letter
                all_plain_used.add(plain_letter)
        
        # Fill in missing mappings
        remaining_cipher = [c for c in parent1.keys() if c not in child]
        remaining_plain = [p for p in self.dictionary if p not in all_plain_used]
        
        for cipher, plain in zip(remaining_cipher, remaining_plain):
            child[cipher] = plain
        
        return child

    def mutate(self, key):
        """Randomly swap two mappings"""
        key_copy = key.copy()
        letters = list(key_copy.keys())
        if len(letters) >= 2:
            pos1, pos2 = random.sample(range(len(letters)), 2)
            letter1, letter2 = letters[pos1], letters[pos2]
            key_copy[letter1], key_copy[letter2] = key_copy[letter2], key_copy[letter1]
        return key_copy

    def brute_force_decrypt(self, encrypted_text, num_attempts=8, show_progress=True):
        # We're going to try multiple approaches to decrypt monoalphabetic cipher
        # this has 'Simulated Annealing' and 'Genetic Algorithm' as the main 'advanced' techniques
        # These are much better than Hill Climbing at escaping local optima
        # There are other options that are more dynamic, translate across languages, 
        # and frankly do much better in brute force decryption

        results = []
        
        if show_progress:
            print(f"Analyzing monoalphabetic cipher with {num_attempts} different approaches...")
            print("=" * 70)
        
        # Remove non-alphabetic characters for analysis
        clean_cipher = re.sub(r'[^A-Za-z]', '', encrypted_text.upper())
        
        for attempt in range(num_attempts):
            try:
                # Method 1: Pure frequency analysis
                if attempt == 0:
                    if show_progress:
                        print("Attempt 1: Frequency analysis mapping")
                    key = self.create_frequency_key(encrypted_text)
                
                # Method 2: Simulated Annealing with frequency start
                elif attempt == 1:
                    if show_progress:
                        print("Attempt 2: Frequency + Simulated Annealing")
                    initial_key = self.create_frequency_key(encrypted_text)
                    key, score, improvements, accepted = self.simulated_annealing(
                        encrypted_text, initial_key, max_iterations=3000, initial_temp=50.0)
                    if show_progress:
                        print(f"  SA made {improvements} improvements, accepted {accepted} moves")
                
                # Method 3: Simulated Annealing with random start
                elif attempt == 2:
                    if show_progress:
                        print("Attempt 3: Random + Simulated Annealing")
                    cipher_letters = list(set(clean_cipher))
                    plain_letters = self.dictionary[:len(cipher_letters)]
                    random.shuffle(plain_letters)
                    initial_key = dict(zip(cipher_letters, plain_letters))
                    key, score, improvements, accepted = self.simulated_annealing(
                        encrypted_text, initial_key, max_iterations=5000, initial_temp=100.0)
                    if show_progress:
                        print(f"  SA made {improvements} improvements, accepted {accepted} moves")
                
                # Method 4: High temperature Simulated Annealing
                elif attempt == 3:
                    if show_progress:
                        print("Attempt 4: High-temp Simulated Annealing")
                    initial_key = self.create_frequency_key(encrypted_text)
                    key, score, improvements, accepted = self.simulated_annealing(
                        encrypted_text, initial_key, max_iterations=4000, initial_temp=200.0)
                    if show_progress:
                        print(f"  High-temp SA: {improvements} improvements, {accepted} accepted")
                
                # Method 5: Genetic Algorithm
                elif attempt == 4:
                    if show_progress:
                        print("Attempt 5: Genetic Algorithm")
                    key, score = self.genetic_algorithm(encrypted_text, population_size=30, generations=50)
                    if show_progress:
                        print(f"  GA final score: {score:.1f}")
                
                # Method 6: Multiple SA runs with different parameters
                elif attempt == 5:
                    if show_progress:
                        print("Attempt 6: Multi-run Simulated Annealing")
                    best_key = None
                    best_score = -float('inf')
                    
                    for run in range(3):
                        if run == 0:
                            temp, iterations = 150.0, 3000
                        elif run == 1:
                            temp, iterations = 75.0, 4000
                        else:
                            temp, iterations = 300.0, 2000
                        
                        initial_key = self.create_frequency_key(encrypted_text)
                        run_key, run_score, _, _ = self.simulated_annealing(
                            encrypted_text, initial_key, max_iterations=iterations, initial_temp=temp)
                        
                        if run_score > best_score:
                            best_key = run_key
                            best_score = run_score
                    
                    key = best_key
                    if show_progress:
                        print(f"  Multi-SA best score: {best_score:.1f}")
                
                # Method 7: Hybrid GA + SA
                elif attempt == 6:
                    if show_progress:
                        print("Attempt 7: Hybrid Genetic Algorithm + Simulated Annealing")
                    # Start with GA
                    ga_key, ga_score = self.genetic_algorithm(encrypted_text, population_size=20, generations=30)
                    # Refine with SA
                    key, score, improvements, accepted = self.simulated_annealing(
                        encrypted_text, ga_key, max_iterations=2000, initial_temp=50.0)
                    if show_progress:
                        print(f"  Hybrid: GA score {ga_score:.1f} → SA score {score:.1f}")
                
                # Method 8: Long-run Genetic Algorithm
                else:
                    if show_progress:
                        print("Attempt 8: Extended Genetic Algorithm")
                    key, score = self.genetic_algorithm(encrypted_text, population_size=40, generations=100)
                    if show_progress:
                        print(f"  Extended GA final score: {score:.1f}")
                
                # Apply the key and score the result
                decrypted = self.apply_substitution_key(encrypted_text, key)
                final_score = self.calculate_english_score(decrypted)
                
                results.append((key, decrypted, final_score))
                
                if show_progress:
                    print(f"  Result: {decrypted[:50]:<50} (Score: {final_score:.1f})")
                
            except Exception as e:
                if show_progress:
                    print(f"  Error in attempt {attempt + 1}: {e}")
                continue
        
        results.sort(key=lambda x: x[2], reverse=True)
        return results

    def auto_decrypt(self, encrypted_text, top_n=3):
        # Automatically find the most likely decryption using advanced algorithms
        # (results may vary)

        results = self.brute_force_decrypt(encrypted_text, num_attempts=8, show_progress=False)
        
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

