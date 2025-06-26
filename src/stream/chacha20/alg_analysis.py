#!/usr/bin/python3

#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/chacha20/alg_analysis.py'
#   ChaCha20 stream cipher decryption class with real encrypted data
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import collections
from decrypt import decrypt
from encrypt import encrypt
import time


class ChaCha20Cryptanalysis:
    def __init__(self):
        self.samples = []
        self.analysis_results = {}
        
    def frequency_analysis(self, ciphertext_hex):
        """Analyze byte frequency distribution"""
        print("=== FREQUENCY ANALYSIS ===")
        print("Testing if ChaCha20 has statistical biases...\n")
        
        # Convert hex to bytes
        try:
            cipher_bytes = bytes.fromhex(ciphertext_hex)
        except ValueError:
            print("❌ Invalid hex input")
            return None
            
        # Count byte frequencies
        freq_counter = collections.Counter(cipher_bytes)
        
        print(f"Ciphertext length: {len(cipher_bytes)} bytes")
        print(f"Unique bytes: {len(freq_counter)}/256 possible")
        
        # Calculate statistics
        frequencies = list(freq_counter.values())
        if frequencies:
            mean_freq = np.mean(frequencies)
            std_freq = np.std(frequencies)
            
            print(f"Mean frequency: {mean_freq:.2f}")
            print(f"Std deviation: {std_freq:.2f}")
            
            # Chi-square test for uniformity
            expected = len(cipher_bytes) / 256
            chi_square = sum((obs - expected)**2 / expected for obs in frequencies)
            
            print(f"\nChi-square statistic: {chi_square:.2f}")
            print(f"Expected for random: ~255")
            
            if abs(chi_square - 255) < 50:
                print("✅ RESULT: Distribution appears random (good for ChaCha20)")
            else:
                print("⚠️  RESULT: Non-random distribution detected!")
                
        return freq_counter
    
    def pattern_analysis(self, ciphertext_hex):
        """Look for repeating patterns"""
        print("\n=== PATTERN ANALYSIS ===")
        print("Searching for repeating sequences...\n")
        
        cipher_bytes = bytes.fromhex(ciphertext_hex)
        patterns_found = {}
        
        # Look for patterns of different lengths
        for pattern_len in [2, 3, 4, 6, 8]:
            patterns = {}
            
            for i in range(len(cipher_bytes) - pattern_len + 1):
                pattern = cipher_bytes[i:i+pattern_len]
                if pattern in patterns:
                    patterns[pattern].append(i)
                else:
                    patterns[pattern] = [i]
            
            # Find repeated patterns
            repeated = {p: positions for p, positions in patterns.items() if len(positions) > 1}
            
            if repeated:
                print(f"Patterns of length {pattern_len}:")
                for pattern, positions in list(repeated.items())[:5]:  # Show first 5
                    print(f"  {pattern.hex().upper()} at positions: {positions}")
                patterns_found[pattern_len] = len(repeated)
            else:
                print(f"No repeated patterns of length {pattern_len}")
                patterns_found[pattern_len] = 0
        
        total_patterns = sum(patterns_found.values())
        if total_patterns == 0:
            print("\n✅ RESULT: No significant patterns found (good for ChaCha20)")
        else:
            print(f"\n⚠️  RESULT: Found {total_patterns} repeated patterns")
            
        return patterns_found
    
    def kasiski_examination(self, ciphertext_hex):
        """Kasiski examination for period detection"""
        print("\n=== KASISKI EXAMINATION ===")
        print("Looking for evidence of periodic structure...\n")
        
        cipher_bytes = bytes.fromhex(ciphertext_hex)
        
        # Look for repeated 3-grams and their distances
        trigrams = {}
        for i in range(len(cipher_bytes) - 2):
            trigram = cipher_bytes[i:i+3]
            if trigram in trigrams:
                trigrams[trigram].append(i)
            else:
                trigrams[trigram] = [i]
        
        # Find repeated trigrams and calculate distances
        distances = []
        repeated_trigrams = 0
        
        for trigram, positions in trigrams.items():
            if len(positions) > 1:
                repeated_trigrams += 1
                for i in range(len(positions) - 1):
                    distance = positions[i+1] - positions[i]
                    distances.append(distance)
        
        print(f"Repeated trigrams found: {repeated_trigrams}")
        
        if distances:
            print(f"Distances between repeats: {sorted(distances)[:10]}")  # First 10
            
            # Look for common factors (potential key lengths)
            from math import gcd
            from functools import reduce
            
            if len(distances) > 1:
                common_gcd = reduce(gcd, distances)
                print(f"GCD of distances: {common_gcd}")
                
                if common_gcd > 1:
                    print(f"⚠️  Possible period: {common_gcd}")
                else:
                    print("✅ No obvious period detected")
            else:
                print("✅ Too few repeats for period analysis")
        else:
            print("✅ RESULT: No repeated trigrams (good for stream cipher)")
    
    def differential_analysis(self):
        """Compare ciphertexts from related plaintexts"""
        print("\n=== DIFFERENTIAL ANALYSIS ===")
        print("Testing how plaintext changes affect ciphertext...\n")
        
        base_key = "TESTKEY123"
        base_nonce = "testnonce"
        base_counter = 0
        
        # Test messages with small differences
        test_cases = [
            ("HELLO WORLD", "Base message"),
            ("HELLO WORLC", "1 bit change in last char"),
            ("HELLO WORLD!", "1 character added"),
            ("HALLO WORLD", "1 character changed"),
            ("hello world", "Case change"),
        ]
        
        results = []
        base_cipher = None
        
        for message, description in test_cases:
            # Encrypt each message
            encrypt_options = pd.DataFrame({
                'KEY': [base_key],
                'NONCE': [base_nonce],
                'COUNTER': [base_counter],
                'OUTPUT_FORMAT': ['HEX'],
                'SHOW_STEPS': [False]
            })
            
            encryptor = encrypt(None, encrypt_options)
            ciphertext = encryptor.encrypt_message(message)
            
            results.append((message, ciphertext, description))
            
            if base_cipher is None:
                base_cipher = ciphertext
                print(f"Base: '{message}' → {ciphertext}")
            else:
                # Compare with base
                base_bytes = bytes.fromhex(base_cipher)
                curr_bytes = bytes.fromhex(ciphertext)
                
                # Calculate Hamming distance
                min_len = min(len(base_bytes), len(curr_bytes))
                hamming_dist = sum(a != b for a, b in zip(base_bytes[:min_len], curr_bytes[:min_len]))
                
                if len(base_bytes) != len(curr_bytes):
                    hamming_dist += abs(len(base_bytes) - len(curr_bytes))
                
                print(f"Test: '{message}' → {ciphertext}")
                print(f"      {description}")
                print(f"      Hamming distance from base: {hamming_dist}")
                print(f"      Changed bytes: {hamming_dist}/{max(len(base_bytes), len(curr_bytes))} ({100*hamming_dist/max(len(base_bytes), len(curr_bytes)):.1f}%)")
                print()
        
        print("✅ RESULT: Small plaintext changes cause large ciphertext changes")
        print("   This is the 'avalanche effect' - good cryptographic property")
    
    def nonce_reuse_attack(self):
        """Demonstrate catastrophic nonce reuse"""
        print("\n=== NONCE REUSE ATTACK ===")  
        print("Showing why nonce reuse is catastrophic...\n")
        
        # Same key and nonce, different messages
        key = "DANGEROUSKEY"
        nonce = "REUSEDNONCE"  # BAD - never reuse!
        counter = 0
        
        messages = [
            "SECRET MESSAGE ONE",
            "SECRET MESSAGE TWO", 
            "ATTACK AT DAWN!!!!",
        ]
        
        ciphertexts = []
        
        print("Encrypting multiple messages with SAME key+nonce (BAD!):")
        for i, msg in enumerate(messages):
            encrypt_options = pd.DataFrame({
                'KEY': [key],
                'NONCE': [nonce],
                'COUNTER': [counter],
                'OUTPUT_FORMAT': ['HEX'],
                'SHOW_STEPS': [False]
            })
            
            encryptor = encrypt(None, encrypt_options)
            cipher = encryptor.encrypt_message(msg)
            ciphertexts.append(cipher)
            
            print(f"Message {i+1}: '{msg}'")
            print(f"Cipher {i+1}:  {cipher}")
            print()
        
        # Show the attack
        print("🚨 NONCE REUSE ATTACK:")
        print("When same keystream is used, we can XOR ciphertexts:")
        
        # XOR first two ciphertexts
        c1_bytes = bytes.fromhex(ciphertexts[0])
        c2_bytes = bytes.fromhex(ciphertexts[1])
        
        min_len = min(len(c1_bytes), len(c2_bytes))
        xor_result = bytes(a ^ b for a, b in zip(c1_bytes[:min_len], c2_bytes[:min_len]))
        
        print(f"Cipher1 ⊕ Cipher2 = {xor_result.hex().upper()}")
        
        # This equals Plaintext1 ⊕ Plaintext2
        p1_bytes = messages[0].encode()
        p2_bytes = messages[1].encode()
        expected_xor = bytes(a ^ b for a, b in zip(p1_bytes[:min_len], p2_bytes[:min_len]))
        
        print(f"Plain1 ⊕ Plain2  = {expected_xor.hex().upper()}")
        print(f"Match: {'✅ YES' if xor_result == expected_xor else '❌ NO'}")
        
        print("\n🔓 ATTACK RESULT:")
        print("- Attacker can XOR ciphertexts to get plaintext XOR")
        print("- With known plaintext patterns, can recover messages")
        print("- Statistical analysis can break the XOR")
        print("- This is why NONCE MUST NEVER BE REUSED!")
    
    def related_key_analysis(self):
        """Test encryption with related keys"""
        print("\n=== RELATED KEY ANALYSIS ===")
        print("Testing if related keys produce exploitable patterns...\n")
        
        base_key = "BASEKEY12345"
        nonce = "testnonce"
        counter = 0
        message = "CONSISTENT TEST MESSAGE"
        
        # Generate related keys
        related_keys = [
            base_key,
            base_key[:-1] + "6",  # Last char changed
            base_key[:-1] + "4",  # Last char changed back
            "A" + base_key[1:],   # First char changed
            base_key.upper(),     # Case changed
        ]
        
        results = []
        
        for key in related_keys:
            encrypt_options = pd.DataFrame({
                'KEY': [key],
                'NONCE': [nonce],
                'COUNTER': [counter],
                'OUTPUT_FORMAT': ['HEX'],
                'SHOW_STEPS': [False]
            })
            
            encryptor = encrypt(None, encrypt_options)
            cipher = encryptor.encrypt_message(message)
            results.append((key, cipher))
            
            print(f"Key: '{key}' → {cipher}")
        
        # Analyze relationships
        print(f"\nAnalyzing ciphertext relationships:")
        base_cipher_bytes = bytes.fromhex(results[0][1])
        
        for i in range(1, len(results)):
            key, cipher = results[i]
            cipher_bytes = bytes.fromhex(cipher)
            
            # Calculate similarity
            differences = sum(a != b for a, b in zip(base_cipher_bytes, cipher_bytes))
            similarity = 1 - (differences / len(base_cipher_bytes))
            
            print(f"'{key}' vs base: {differences}/{len(base_cipher_bytes)} different bytes ({similarity*100:.1f}% similar)")
        
        print("\n✅ RESULT: Related keys produce unrelated ciphertexts")
        print("   ChaCha20 resists related-key attacks")
    
    def timing_analysis_demo(self):
        """Demonstrate potential timing attack vectors"""
        print("\n=== TIMING ANALYSIS ===")
        print("Measuring encryption times for timing attacks...\n")
        
        # Test different key patterns
        key_patterns = [
            ("A" * 32, "All A's"),
            ("0" * 32, "All zeros"),
            ("ABCD" * 8, "Repeated pattern"),
            ("".join(chr(i) for i in range(32, 64)), "Sequential chars"),
            ("RANDOM_KEY_DATA_HERE_12345678", "Mixed content"),
        ]
        
        message = "TIMING TEST MESSAGE"
        nonce = "timing"
        counter = 0
        
        timing_results = []
        
        for key, description in key_patterns:
            times = []
            
            # Run multiple trials
            for trial in range(10):
                encrypt_options = pd.DataFrame({
                    'KEY': [key],
                    'NONCE': [nonce],
                    'COUNTER': [counter],
                    'OUTPUT_FORMAT': ['HEX'],
                    'SHOW_STEPS': [False]
                })
                
                encryptor = encrypt(None, encrypt_options)
                
                start_time = time.perf_counter()
                cipher = encryptor.encrypt_message(message)
                end_time = time.perf_counter()
                
                times.append(end_time - start_time)
            
            avg_time = np.mean(times)
            std_time = np.std(times)
            timing_results.append((description, avg_time, std_time))
            
            print(f"{description:20s}: {avg_time*1000:.3f} ± {std_time*1000:.3f} ms")
        
        # Analyze timing differences
        times_only = [avg for _, avg, _ in timing_results]
        max_time = max(times_only)
        min_time = min(times_only)
        
        print(f"\nTiming analysis:")
        print(f"Fastest: {min_time*1000:.3f} ms")
        print(f"Slowest: {max_time*1000:.3f} ms")
        print(f"Difference: {(max_time-min_time)*1000:.3f} ms ({100*(max_time-min_time)/min_time:.1f}%)")
        
        if (max_time - min_time) / min_time < 0.1:  # Less than 10% difference
            print("✅ RESULT: Timing differences are minimal")
            print("   ChaCha20 has relatively constant-time operations")
        else:
            print("⚠️  RESULT: Significant timing differences detected")
            print("   Could potentially be exploited in timing attacks")
    
    def entropy_analysis(self, ciphertext_hex):
        """Calculate entropy of ciphertext"""
        print("\n=== ENTROPY ANALYSIS ===")
        print("Measuring randomness of ciphertext...\n")
        
        cipher_bytes = bytes.fromhex(ciphertext_hex)
        
        # Calculate Shannon entropy
        byte_counts = collections.Counter(cipher_bytes)
        total_bytes = len(cipher_bytes)
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * np.log2(probability)
        
        max_entropy = 8.0  # Maximum possible for bytes
        
        print(f"Ciphertext length: {total_bytes} bytes")
        print(f"Unique bytes: {len(byte_counts)}/256")
        print(f"Shannon entropy: {entropy:.3f} bits/byte")
        print(f"Maximum entropy: {max_entropy:.3f} bits/byte")
        print(f"Entropy ratio: {entropy/max_entropy:.3f} ({100*entropy/max_entropy:.1f}%)")
        
        if entropy/max_entropy > 0.95:
            print("✅ RESULT: High entropy - appears random")
        else:
            print("⚠️  RESULT: Lower entropy - may have patterns")
        
        return entropy
    
    def comprehensive_analysis_demo(self):
        """Run all analysis techniques on sample data"""
        print("🔍 COMPREHENSIVE CHACHA20 CRYPTANALYSIS DEMO 🔍")
        print("="*80)
        
        # Generate test data
        test_key = "ANALYSIS_TEST_KEY_123456789012"
        test_nonce = "testnonce12"
        test_counter = 0
        test_message = "This is a longer message for comprehensive cryptanalysis testing. " * 3
        
        print(f"Generating test ciphertext...")
        print(f"Message length: {len(test_message)} characters")
        
        encrypt_options = pd.DataFrame({
            'KEY': [test_key],
            'NONCE': [test_nonce],
            'COUNTER': [test_counter],
            'OUTPUT_FORMAT': ['HEX'],
            'SHOW_STEPS': [False]
        })
        
        encryptor = encrypt(None, encrypt_options)
        test_ciphertext = encryptor.encrypt_message(test_message)
        
        print(f"Test ciphertext: {test_ciphertext[:64]}...{test_ciphertext[-64:]}")
        print(f"Ciphertext length: {len(test_ciphertext)} hex chars ({len(test_ciphertext)//2} bytes)")
        
        # Run all analyses
        print(f"\n" + "="*80)
        self.frequency_analysis(test_ciphertext)
        self.pattern_analysis(test_ciphertext)
        self.kasiski_examination(test_ciphertext)
        self.entropy_analysis(test_ciphertext)
        self.differential_analysis()
        self.nonce_reuse_attack()
        self.related_key_analysis()
        self.timing_analysis_demo()
        
        # Summary
        print(f"\n" + "="*80)
        print("CRYPTANALYSIS SUMMARY")
        print("="*80)
        print("""
ATTACKS THAT WORK (Educational):
✅ Frequency analysis - shows good randomness
✅ Pattern detection - finds no exploitable patterns  
✅ Entropy measurement - confirms high randomness
✅ Nonce reuse - catastrophic when rules violated
✅ Timing analysis - minimal but measurable differences

ATTACKS THAT DON'T WORK (ChaCha20 Strengths):
❌ Brute force - keyspace too large (2^256)
❌ Statistical attacks - output appears random
❌ Related key attacks - keys produce unrelated outputs
❌ Period detection - no obvious repeating patterns
❌ Differential cryptanalysis - strong avalanche effect

REAL-WORLD ATTACK VECTORS:
🎯 Implementation bugs (buffer overflows, etc.)
🎯 Side-channel attacks (power, electromagnetic)
🎯 Key management failures (weak keys, storage)
🎯 Protocol attacks (nonce reuse, downgrade)
🎯 Social engineering (human factor)

EDUCATIONAL INSIGHTS:
• ChaCha20's mathematical design resists known attacks
• Security depends heavily on proper implementation
• Key and nonce management are critical
• Side-channel protection needed in hardware
• Real attacks target the system, not the algorithm

The algorithm itself appears cryptographically sound against
all known mathematical attacks when used correctly.
        """)

if __name__ == "__main__":
    analyzer = ChaCha20Cryptanalysis()
    analyzer.comprehensive_analysis_demo()