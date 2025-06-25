#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/block/decrypt.py'
#   Rail Fence cipher brute force decryption class
#
#   Block ciphers have enormous key spaces (2^64 to 2^256) making
#   exhaustive brute force computationally infeasible, in both time and resources.
#    Instead, we use cryptanalytic attacks like differential analysis, linear analysis,
#   and statistical methods to break weak block ciphers. (emphasis on WEAK block ciphers)
#
#   This demonstrates educational attacks on simplified block ciphers.
#   Real ciphers like AES are designed to resist these attacks.
#
#   Claude AI was used to clean this class up and comment on what was happening.
#       The comments are more readable than in V1, but the print out statements
#       may convey too much information to be useful for an introduction to this cipher.
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\


from collections import Counter
import secrets
from statistics import mean, stdev

class decrypt:
    
    def __init__(self, block_size=8, num_rounds=4, dictionary=None):
        
        # Block cipher parameters (must match the cipher being attacked)
        self.block_size = block_size
        self.num_rounds = num_rounds
        
        # Dictionary for plaintext analysis
        if dictionary is None:
            self.dictionary = [chr(i) for i in range(32, 127)]  # Printable ASCII
        else:
            self.dictionary = list(dictionary)
        
        # Expected frequency distributions for plaintext detection
        self.english_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }
        
        # Common English words for plaintext validation
        # this dictionary is different than some of the others. 
        # There's nothing better/worse about changing default dictionaries with these examples,
        # but Claude AI demonstrates interesting preferences.
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
                            'WHERE', 'WHICH', 'WHO', 'WILL', 'WITH', 'WORK', 'WOULD', 'YEAR', 
                            'YOU', 'YOUR']


    def exhaustive_key_search(self, ciphertext_blocks, key_bits=32, max_keys=10000, num_best=10):
        # This attempts and exhaustive key search. 
        # An exhaustive key search is only a realistic option for very small keys, which is 
        # going to be unlikely the more security-focused the person implementing the algorithm
        # is. For instance, in demos we might be create something that could be brute force decrypted
        # in this manner, but it's extremly unlikely by the time you start getting to something with the
        # complexity of DES and AES.
        # From Claude:
            # This demonstrates why block cipher brute force is impossible:
            # - 64-bit key: 2^64 = 18.4 quintillion possibilities
            # - 128-bit key: 2^128 = 340 undecillion possibilities  
            # - 256-bit key: 2^256 = more than atoms in universe
        
        print(f"=== Exhaustive Key Search (max {max_keys} keys) ===")
        print(f"Key space: 2^{key_bits} = {2**key_bits:,} total keys")
        print(f"Testing only {max_keys:,} keys for demonstration...")
        
        if key_bits > 20:
            print("WARNING: Key space too large for exhaustive search!")
            print("This demonstrates why block ciphers are secure against brute force!")
            return []
        
        candidates = []
        
        # Try random keys from the key space
        for attempt in range(min(max_keys, 2**key_bits)):
            if key_bits <= 16:
                # For small spaces, try keys sequentially
                test_key = attempt.to_bytes((key_bits + 7) // 8, 'big')
            else:
                # For larger spaces, try random keys
                test_key = secrets.token_bytes((key_bits + 7) // 8)
            
            # Truncate or pad key to match block size
            if len(test_key) < self.block_size:
                test_key = test_key + b'\x00' * (self.block_size - len(test_key))
            elif len(test_key) > self.block_size:
                test_key = test_key[:self.block_size]
            
            try:
                # Attempt decryption with this key
                plaintext = self.test_decrypt_with_key(ciphertext_blocks, test_key)
                score = self.calculate_plaintext_score(plaintext)
                
                if score > -500:  # Only keep reasonable candidates
                    candidates.append((test_key, plaintext, score))
                
                if attempt % 1000 == 0 and attempt > 0:
                    print(f"  Tested {attempt:,} keys...")
                    
            except Exception:
                continue
        
        # Sort by score
        candidates.sort(key=lambda x: x[2], reverse=True)
        
        print(f"Found {len(candidates)} candidate keys")
        return candidates[:num_best]  # Return top 10 by default


    def differential_cryptanalysis(self, plaintext_pairs, ciphertext_pairs):
        # Differential cryptanalysis attack function
        # this function is mean to analyze differences in plaintext vs the cipher text
        # this kind of attack can look for hints on the cipher structure, such as repeating patterns.
        # Typically, this type of attack wants to find a non-uniform distribution of differences in the 
        # cipher text. This is effective when looked at in context of many input/output pairs
        # https://library.fiveable.me/cryptography/unit-8/differential-linear-cryptanalysis/study-guide/HeWJCX1GLYMUAuRX

        print("=== Differential Cryptanalysis ===")
        
        if len(plaintext_pairs) != len(ciphertext_pairs):
            raise ValueError("Must have equal number of plaintext and ciphertext pairs")
        
        # Collect differential data
        differentials = []
        
        for i in range(len(plaintext_pairs)):
            for j in range(i + 1, len(plaintext_pairs)):
                # Calculate input and output differences
                input_diff = self.xor_bytes(plaintext_pairs[i], plaintext_pairs[j])
                output_diff = self.xor_bytes(ciphertext_pairs[i], ciphertext_pairs[j])
                
                differentials.append((input_diff, output_diff))
        
        # Analyze differential patterns
        diff_counts = Counter(differentials)
        
        print(f"Analyzed {len(differentials)} differential pairs")
        print("Most common differentials:")
        
        for (input_diff, output_diff), count in diff_counts.most_common(10):
            input_hex = input_diff.hex().upper()
            output_hex = output_diff.hex().upper()
            print(f"  {input_hex} -> {output_hex}: {count} times")
        
        # Look for non-random patterns
        expected_random = len(differentials) / (256 ** self.block_size)
        suspicious_patterns = []
        
        for (input_diff, output_diff), count in diff_counts.most_common(20):
            if count > expected_random * 2:  # Significantly more common than random
                suspicious_patterns.append(((input_diff, output_diff), count))
        
        print(f"\nSuspicious non-random patterns: {len(suspicious_patterns)}")
        return suspicious_patterns


    def linear_cryptanalysis(self, known_pairs):
        # Linear cryptanalysis attack function
        # This kind of attack looks at the relation between the plaintext, ciphertext, and key bits to see if there
        # is a linear relation. Finding an 'affine' relation means that this can be reduced to an algebraic problem
        # which reduces the complexity and increases the chances of finding something in the encryption algorithm
        # https://library.fiveable.me/cryptography/unit-8/differential-linear-cryptanalysis/study-guide/HeWJCX1GLYMUAuRX
        # https://en.wikipedia.org/wiki/Linear_cryptanalysis
        
        print("=== Linear Cryptanalysis ===")
        
        # For educational purposes, we'll look for simple linear relationships
        linear_equations = []
        
        for plaintext, ciphertext in known_pairs:
            # Convert to bit arrays
            p_bits = self.bytes_to_bits(plaintext)
            c_bits = self.bytes_to_bits(ciphertext)
            
            # Look for correlations between specific bit positions
            for p_pos in range(min(8, len(p_bits))):  # Check first 8 bits
                for c_pos in range(min(8, len(c_bits))):
                    correlation = p_bits[p_pos] ^ c_bits[c_pos]
                    linear_equations.append((p_pos, c_pos, correlation))
        
        # Analyze correlations
        correlation_counts = Counter(linear_equations)
        
        print(f"Analyzed {len(known_pairs)} plaintext-ciphertext pairs")
        print("Bit correlations (P[i] ⊕ C[j] = bias):")
        
        total_pairs = len(known_pairs)
        
        for (p_pos, c_pos, bias), count in correlation_counts.most_common(20):
            bias_strength = abs(count - total_pairs/2) / (total_pairs/2)
            if bias_strength > 0.1:  # Significant bias
                print(f"  P[{p_pos}] ⊕ C[{c_pos}] = {bias}: {count}/{total_pairs} (bias: {bias_strength:.3f})")
        
        return correlation_counts


    def frequency_analysis_attack(self, ciphertext_blocks):
        # Frequency Analysis attack function
        # This is similar to the approach taken with the substitution ciphers, 
        # as a frequency attack works with any 'language' to provide insights into the algorithm.
        # Performed properly, block encryption should not be easy to attack with this approach,
        # but weak ciphers or improperly used algorithms may show some kind of pattern or hint.

        print("=== Frequency Analysis Attack ===")
        
        # Analyze block frequencies
        block_counts = Counter([block.hex() for block in ciphertext_blocks])
        
        print(f"Analyzed {len(ciphertext_blocks)} ciphertext blocks")
        print("Block frequency analysis:")
        
        total_blocks = len(ciphertext_blocks)
        
        for block_hex, count in block_counts.most_common(10):
            frequency = count / total_blocks
            print(f"  {block_hex}: {count} times ({frequency:.3%})")
        
        # Look for repeated blocks (ECB mode vulnerability)
        repeated_blocks = [(block, count) for block, count in block_counts.items() if count > 1]
        
        print(f"\nRepeated blocks (ECB vulnerability): {len(repeated_blocks)}")
        
        # Analyze byte position frequencies within blocks
        position_freq = [Counter() for _ in range(self.block_size)]
        
        for block in ciphertext_blocks:
            for pos, byte in enumerate(block):
                position_freq[pos][byte] += 1
        
        print("\nByte frequency by position:")
        for pos in range(self.block_size):
            most_common = position_freq[pos].most_common(1)
            if most_common:
                byte_val, count = most_common[0]
                freq = count / len(ciphertext_blocks)
                print(f"  Position {pos}: 0x{byte_val:02X} appears {count} times ({freq:.3%})")
        
        return block_counts, position_freq


    def statistical_tests(self, ciphertext_data):
        # This function is less of a direct attack and more of an analysis. 
        # A 'good' block cipher should produce statistically random output.
        # That is, there should be no mathematical certainty that there is a pattern.
        # A weak cipher will have some statistical indication that it's not completely random.


        print("=== Statistical Randomness Tests ===")
        
        # Convert to byte array
        bytes_data = []
        for block in ciphertext_data:
            bytes_data.extend(block)
        
        if len(bytes_data) == 0:
            print("No data to analyze")
            return {}
        
        # Test 1: Byte frequency distribution
        byte_counts = Counter(bytes_data)
        expected_freq = len(bytes_data) / 256
        
        chi_square = sum((count - expected_freq) ** 2 / expected_freq 
                        for count in byte_counts.values())
        
        print(f"Chi-square test (byte frequency):")
        print(f"  Chi-square statistic: {chi_square:.2f}")
        print(f"  Expected for random: ~255")
        print(f"  Assessment: {'PASS' if chi_square < 400 else 'FAIL'}")
        
        # Test 2: Runs test (consecutive identical bytes)
        runs = 0
        if len(bytes_data) > 1:
            for i in range(len(bytes_data) - 1):
                if bytes_data[i] != bytes_data[i + 1]:
                    runs += 1
        
        expected_runs = (len(bytes_data) - 1) / 2
        runs_deviation = abs(runs - expected_runs) / expected_runs if expected_runs > 0 else 0
        
        print(f"\nRuns test (consecutive bytes):")
        print(f"  Observed runs: {runs}")
        print(f"  Expected runs: {expected_runs:.1f}")
        print(f"  Deviation: {runs_deviation:.3f}")
        print(f"  Assessment: {'PASS' if runs_deviation < 0.1 else 'FAIL'}")
        
        # Test 3: Autocorrelation test
        if len(bytes_data) > 10:
            lag1_correlation = self.calculate_autocorrelation(bytes_data, lag=1)
            print(f"\nAutocorrelation test (lag=1):")
            print(f"  Correlation coefficient: {lag1_correlation:.4f}")
            print(f"  Assessment: {'PASS' if abs(lag1_correlation) < 0.1 else 'FAIL'}")
        
        return {
            'chi_square': chi_square,
            'runs': runs,
            'autocorrelation': lag1_correlation if len(bytes_data) > 10 else None
        }



    def known_plaintext_attack(self, known_pairs):
        """
        Known plaintext attack
        
        Uses known plaintext-ciphertext pairs to deduce key information.
        Most effective attack when available.
        """
        print("=== Known Plaintext Attack ===")
        
        if len(known_pairs) == 0:
            print("No known pairs available")
            return []
        
        print(f"Using {len(known_pairs)} known plaintext-ciphertext pairs")
        
        # Try to deduce round keys or cipher structure
        key_candidates = []
        
        # For simplified analysis, try to find keys that work for first block
        if known_pairs:
            plaintext, ciphertext = known_pairs[0]
            
            print(f"Analyzing first pair:")
            print(f"  Plaintext:  {plaintext.hex().upper()}")
            print(f"  Ciphertext: {ciphertext.hex().upper()}")
            
            # Try simple key recovery (XOR of plaintext and ciphertext)
            # This only works for very weak ciphers
            simple_key = self.xor_bytes(plaintext, ciphertext)
            
            print(f"  Simple XOR key: {simple_key.hex().upper()}")
            
            # Test if this "key" works for other pairs
            success_count = 0
            for p, c in known_pairs[1:]:
                test_result = self.xor_bytes(p, simple_key)
                if test_result == c:
                    success_count += 1
            
            print(f"  Simple key success rate: {success_count}/{len(known_pairs)-1}")
            
            key_candidates.append((simple_key, success_count))
        
        return key_candidates


    def xor_bytes(self, a, b):
        # Helper function for XORing 2 bytes
        """XOR two byte sequences"""
        return bytes([x ^ y for x, y in zip(a, b)])


    def bytes_to_bits(self, data):
        # Helper func for converying bytes to bit array
        bits = []
        for byte in data:
            for i in range(8):
                bits.append((byte >> i) & 1)
        return bits


    def calculate_autocorrelation(self, data, lag):
        # Helper function for calculating autocorrelation coefficient
        if len(data) <= lag:
            return 0
        
        x = data[:-lag] if lag > 0 else data
        y = data[lag:] if lag > 0 else data
        
        if len(x) == 0 or len(y) == 0:
            return 0
        
        mean_x = mean(x)
        mean_y = mean(y)
        
        numerator = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(len(x)))
        
        var_x = sum((x[i] - mean_x) ** 2 for i in range(len(x)))
        var_y = sum((y[i] - mean_y) ** 2 for i in range(len(y)))
        
        if var_x == 0 or var_y == 0:
            return 0
        
        return numerator / (var_x * var_y) ** 0.5


    def test_decrypt_with_key(self, ciphertext_blocks, key):
        #Test decryption with a specific key. SIMPLIFIED!!
        # This is a placeholder - would need actual cipher implementation
        # For demo, we'll just XOR with key
        decrypted_blocks = []
        for block in ciphertext_blocks:
            # Simple XOR decryption (not realistic for real block ciphers)
            decrypted = self.xor_bytes(block, key[:len(block)])
            decrypted_blocks.append(decrypted)
        
        return b''.join(decrypted_blocks)


    def calculate_plaintext_score(self, data):
        # Function to score how likely data is to be a valid planetext message
        # Using English frequency score by default

        try:
            # Try to decode as text
            text = data.decode('utf-8', errors='ignore')
            
            # Count printable characters
            printable_ratio = sum(1 for c in text if c.isprintable()) / max(len(text), 1)
            
            # Letter frequency analysis
            letters = [c.upper() for c in text if c.isalpha()]
            if len(letters) > 0:
                letter_counts = Counter(letters)
                total_letters = len(letters)
                
                # Calculate deviation from expected English frequencies
                freq_score = 0
                for letter, count in letter_counts.items():
                    observed_freq = count / total_letters * 100
                    expected_freq = self.english_freq.get(letter, 0.1)
                    freq_score -= (observed_freq - expected_freq) ** 2
                
                # Bonus for common words
                word_bonus = sum(50 for word in self.common_words if word in text.upper())
                
                return printable_ratio * 100 + freq_score + word_bonus
            else:
                return printable_ratio * 50
                
        except UnicodeDecodeError:
            return -1000


    def comprehensive_cryptanalysis(self, ciphertext_hex, known_pairs=None):
        # Function to use multiple of the attacks from the above functions
        # This is trying them all rather than selecting based on some criteria


        print("=== Comprehensive Block Cipher Cryptanalysis ===")
        
        # Parse ciphertext
        try:
            ciphertext_data = bytes.fromhex(ciphertext_hex)
        except ValueError:
            print("Invalid hex ciphertext")
            return None
        
        # Split into blocks
        if len(ciphertext_data) % self.block_size != 0:
            print(f"Ciphertext length not multiple of block size ({self.block_size})")
            return None
        
        ciphertext_blocks = []
        for i in range(0, len(ciphertext_data), self.block_size):
            ciphertext_blocks.append(ciphertext_data[i:i + self.block_size])
        
        print(f"Analyzing {len(ciphertext_blocks)} blocks of {self.block_size} bytes each")
        
        results = {}
        
        # 1. Statistical Analysis
        print("\n" + "="*60)
        results['statistical'] = self.statistical_tests(ciphertext_blocks)
        
        # 2. Frequency Analysis
        print("\n" + "="*60)
        results['frequency'] = self.frequency_analysis_attack(ciphertext_blocks)
        
        # 3. Known Plaintext Attack (if pairs available)
        if known_pairs:
            print("\n" + "="*60)
            results['known_plaintext'] = self.known_plaintext_attack(known_pairs)
            
            # Extract plaintext and ciphertext lists
            plaintexts = [pair[0] for pair in known_pairs]
            ciphertexts = [pair[1] for pair in known_pairs]
            
            # 4. Differential Cryptanalysis
            print("\n" + "="*60)
            results['differential'] = self.differential_cryptanalysis(plaintexts, ciphertexts)
            
            # 5. Linear Cryptanalysis
            print("\n" + "="*60)
            results['linear'] = self.linear_cryptanalysis(known_pairs)
        
        # 6. Limited Exhaustive Search (educational)
        print("\n" + "="*60)
        results['exhaustive'] = self.exhaustive_key_search(ciphertext_blocks, key_bits=16, max_keys=1000)
        
        return results
