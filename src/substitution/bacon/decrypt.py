#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/substitution/bacon/decrypt.py'
#   Baconian cipher brute force decryption class
#   
#   Author: Lauren Linkous
#   Date: June 23, 2025
##--------------------------------------------------------------------\


from collections import Counter
import re
import itertools

class decrypt:
    
    def __init__(self, dictionary=None, lang_freq=None):
        # can pass in a dictionary if a custom one exists
        if dictionary is None:
            # Default to A-Z, a-z
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
            
        # Common symbol pairs to try
        self.common_symbol_pairs = [
            ('A', 'B'), ('0', '1'), ('a', 'b'), ('.', '-'), ('*', '#'),
            ('X', 'O'), ('I', 'V'), ('L', 'S'), ('!', '?'), ('+', '-'),
            ('>', '<'), ('(', ')'), ('[', ']'), ('{', '}'), ('|', '/'),
            ('~', '^'), ('@', '$'), ('%', '&'), ('=', '_'), (':', ';')
        ]



    def create_baconian_decoder(self, symbol_a, symbol_b, variant_24=False):
        if variant_24:
            # 24-letter variant: I/J combined, U/V combined
            baconian_codes = {
                'A': '00000', 'B': '00001', 'C': '00010', 'D': '00011', 'E': '00100',
                'F': '00101', 'G': '00110', 'H': '00111', 'I': '01000', 'J': '01000',
                'K': '01001', 'L': '01010', 'M': '01011', 'N': '01100', 'O': '01101',
                'P': '01110', 'Q': '01111', 'R': '10000', 'S': '10001', 'T': '10010',
                'U': '10011', 'V': '10011',
                'W': '10100', 'X': '10101', 'Y': '10110', 'Z': '10111'
            }
        else:
            # 26-letter variant: all letters separate
            baconian_codes = {
                'A': '00000', 'B': '00001', 'C': '00010', 'D': '00011', 'E': '00100',
                'F': '00101', 'G': '00110', 'H': '00111', 'I': '01000', 'J': '01001',
                'K': '01010', 'L': '01011', 'M': '01100', 'N': '01101', 'O': '01110',
                'P': '01111', 'Q': '10000', 'R': '10001', 'S': '10010', 'T': '10011',
                'U': '10100', 'V': '10101', 'W': '10110', 'X': '10111', 'Y': '11000', 'Z': '11001'
            }
        
        # Create reverse lookup: symbol_code -> letter
        decoder = {}
        for letter, binary_code in baconian_codes.items():
            symbol_code = binary_code.replace('0', symbol_a).replace('1', symbol_b)
            if symbol_code in decoder:
                # Handle duplicates in 24-letter variant (I=J, U=V)
                if isinstance(decoder[symbol_code], str):
                    decoder[symbol_code] = [decoder[symbol_code], letter]
                else:
                    decoder[symbol_code].append(letter)
            else:
                decoder[symbol_code] = letter
        
        return decoder


    def extract_symbol_pairs(self, text):
        # Count character frequencies
        char_counts = Counter(text)
        
        # Get characters that appear frequently (likely to be cipher symbols)
        frequent_chars = [char for char, count in char_counts.most_common() 
                         if count >= 5 and char != ' ']
        
        symbol_pairs = []
        
        # Try combinations of the most frequent characters
        for i in range(min(10, len(frequent_chars))):
            for j in range(i + 1, min(10, len(frequent_chars))):
                symbol_pairs.append((frequent_chars[i], frequent_chars[j]))
                symbol_pairs.append((frequent_chars[j], frequent_chars[i]))
        
        # Also try common symbol pairs if they appear in text
        for sym_a, sym_b in self.common_symbol_pairs:
            if sym_a in text and sym_b in text:
                symbol_pairs.append((sym_a, sym_b))
        
        return list(set(symbol_pairs))  # Remove duplicates
    


    def decrypt_with_symbols(self, text, symbol_a, symbol_b, variant_24=False):

        decoder = self.create_baconian_decoder(symbol_a, symbol_b, variant_24)
        
        result = []
        i = 0
        
        while i < len(text):
            # Try to extract a 5-character code
            if i + 4 < len(text):
                code = text[i:i+5]
                
                # Check if this is a valid Baconian code (only contains our symbols)
                if all(c in [symbol_a, symbol_b] for c in code):
                    if code in decoder:
                        decoded_char = decoder[code]
                        # Handle multiple possibilities (I/J, U/V in 24-letter variant)
                        if isinstance(decoded_char, list):
                            result.append(decoded_char[0])  # Choose first option
                        else:
                            result.append(decoded_char)
                        i += 5
                        continue
            
            # If current character is not part of our symbol set, skip it
            if text[i] not in [symbol_a, symbol_b]:
                result.append(text[i])  # Keep non-cipher chars (spaces, etc.)
                i += 1
                continue
            
            # If we have cipher symbols but can't form a valid code, 
            # this might be padding or the end of the message
            result.append(text[i])
            i += 1
        
        return ''.join(result)

    def calculate_english_score(self, text):
        # Calculate how "English-like" a text is based on letter frequency

        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return -1000  # Very low score for empty text
        
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
        
        # Bonus for having common English words
        # modified from https://en.wikipedia.org/wiki/Most_common_words_in_English
        common_words = ['ALL', 'AND', 'ARE', 'BE', 'BEEN', 
                        'BUT', 'BY', 'CALL', 'CAN', 'COME',
                          'DID', 'DOWN', 'FIND', 'FOR', 'FROM', 'GET', 
                          'HAD', 'HAVE', 'HER', 'HOW', 'ITS', 'LONG', 'MADE', 
                          'MAY', 'NOT', 'NOW', 'OF', 'ONE', 'OUR',
                            'PART', 'THE', 'THAT', 'THERE', 'TO', 'WAS', 'WAY',
                              'WILL', 'WITH', 'WHO', 'WORD', 'YOU']
        
        word_bonus = 0
        for word in common_words:
            if word in clean_text:
                word_bonus += len(word) * 10
        
        return score + word_bonus


    def is_valid_baconian_structure(self, text, symbol_a, symbol_b):
        # Count occurrences of both symbols
        count_a = text.count(symbol_a)
        count_b = text.count(symbol_b)
        total_symbols = count_a + count_b
        
        if total_symbols == 0:
            return False, 0
        
        # Must have at least 5 characters to form one Baconian code
        if total_symbols < 5:
            return False, 0
        
        # Calculate ratio of symbol usage (should be roughly balanced for good cipher)
        ratio_a = count_a / total_symbols
        ratio_b = count_b / total_symbols
        
        # Good Baconian cipher should have reasonable distribution
        # (not too skewed toward one symbol, but some imbalance is normal)
        balance_score = 1.0 - abs(ratio_a - 0.5) * 2  # Penalty for being far from 50/50
        balance_score = max(0, balance_score)  # Don't go negative
        
        # Check how much of the text consists of our symbols
        coverage = total_symbols / len(text)
        
        # Higher coverage suggests this is likely the right symbol pair
        coverage_score = min(coverage * 2, 1.0)  # Cap at 1.0
        
        confidence = (balance_score + coverage_score) / 2
        
        return True, confidence



    def brute_force_decrypt(self, encrypted_text, show_progress=True):
        results = []
        
        # Extract potential symbol pairs from the text
        symbol_pairs = self.extract_symbol_pairs(encrypted_text)
        
        if show_progress:
            print(f"Analyzing text with {len(symbol_pairs)} potential symbol pairs...")
            print("=" * 70)
        
        for symbol_a, symbol_b in symbol_pairs:
            # Check if this symbol pair makes structural sense
            is_valid, confidence = self.is_valid_baconian_structure(encrypted_text, symbol_a, symbol_b)
            
            if not is_valid:
                continue
            
            # Try both 24-letter and 26-letter variants
            for variant_24 in [False, True]:
                try:
                    decrypted = self.decrypt_with_symbols(encrypted_text, symbol_a, symbol_b, variant_24)
                    score = self.calculate_english_score(decrypted)
                    
                    # Adjust score based on structural confidence
                    adjusted_score = score + (confidence * 100)
                    
                    results.append((symbol_a, symbol_b, variant_24, decrypted, adjusted_score))
                    
                    if show_progress:
                        variant_str = "24-letter" if variant_24 else "26-letter"
                        print(f"'{symbol_a}'/'{symbol_b}' ({variant_str}): {decrypted[:50]:<50} (Score: {adjusted_score:.1f})")
                
                except Exception as e:
                    # Skip if decryption fails
                    continue
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[4], reverse=True)        
        return results


    def auto_decrypt(self, encrypted_text, top_n=5):
        results = self.brute_force_decrypt(encrypted_text, show_progress=False)
        
        if not results:
            print("No valid Baconian cipher patterns found.")
            return encrypted_text
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 80)
        
        for i, (sym_a, sym_b, variant_24, decrypted, score) in enumerate(results[:top_n]):
            variant_str = "24-letter" if variant_24 else "26-letter"
            print(f"{i+1}. Symbols: '{sym_a}'/'{sym_b}' ({variant_str}) - Score: {score:.1f}")
            print(f"   Result: {decrypted}")
            print()
        
        return results[0][3] if results else encrypted_text
