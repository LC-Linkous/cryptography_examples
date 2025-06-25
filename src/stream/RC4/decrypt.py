#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/rc4/decrypt.py'
#   RC4 stream cipher decryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import numpy as np
import re
from collections import Counter
np.seterr(all='raise')

class decrypt:
  
    def __init__(self, dictionary=None, opt_df=None, parent=None): 

        # Optional parent class
        self.parent = parent 

        # RC4 works on bytes, not character dictionaries
        # But we'll keep this for compatibility with the framework
        self.original_dictionary = dictionary

        # Unpack the data frame. While these could be default values, we want them
        # explicitly set in the test cases
        self.key = opt_df['KEY'][0] if 'KEY' in opt_df.columns else 'SECRET'
        self.input_format = opt_df['INPUT_FORMAT'][0] if 'INPUT_FORMAT' in opt_df.columns else 'HEX'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # RC4 internal state (identical to encrypt class)
        self.S = None  # S-box (substitution box)
        self.i = 0     # First index pointer
        self.j = 0     # Second index pointer
        self.initialized = False # an extra check for resets
        
        # Common English letter frequencies for scoring
        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }

        # This method includes a brute force attempt with some common test keys.
        # This is for demo purposes only. Some of them could be 'default', but these are
        # also related to our specific test cases.
        self.brute_force_keys = ['SECRET', 'KEY', 'PASSWORD', 'ADMIN', 
            'USER', 'TEST', 'DEMO','RC4', 'CIPHER', 'ENCRYPT',
             'DECODE', 'HIDDEN', 'PRIVATE', 'MESSAGE', 'HELLOWORLD',
            '123', '1234', '12345', 'ABC', 'QWERTY', 'LETMEIN',
            'A', 'B', 'C', 'X', 'Y', 'Z',  # Single characters (less typical)
        ]


    def prepare_key(self, key_string):
        # Convert the string to BYTES
        if isinstance(key_string, str):
            return key_string.encode('utf-8')
        else:
            return key_string


    def parse_ciphertext(self, ciphertext_string):
    # When asked for ways to clean up some of the functions,
    # Claude AI suggested adding other formats. Seemed fun, left it in.
    # This is the companion to "format_output()" in the encrypt class. 
    # It does make this approach more robust

        if self.input_format == 'HEX':
            # Remove spaces and convert from hex
            clean_hex = re.sub(r'\s+', '', ciphertext_string)
            try:
                return bytes.fromhex(clean_hex)
            except ValueError:
                raise ValueError(f"Invalid hex format: {ciphertext_string}")
                
        elif self.input_format == 'BASE64':
            import base64
            try:
                return base64.b64decode(ciphertext_string)
            except Exception:
                raise ValueError(f"Invalid base64 format: {ciphertext_string}")
                
        elif self.input_format == 'DECIMAL':
            # Parse space-separated decimal numbers
            decimal_strs = ciphertext_string.split()
            try:
                return bytes(int(d) for d in decimal_strs)
            except ValueError:
                raise ValueError(f"Invalid decimal format: {ciphertext_string}")
                
        elif self.input_format == 'BINARY':
            # Parse space-separated binary strings
            binary_strs = ciphertext_string.split()
            try:
                return bytes(int(b, 2) for b in binary_strs)
            except ValueError:
                raise ValueError(f"Invalid binary format: {ciphertext_string}")
                
        elif self.input_format == 'BYTES':
            # Already bytes
            return ciphertext_string
            
        else:
            raise ValueError(f"Unsupported input format: {self.input_format}")


    def initialize_rc4(self, key=None):
        # This initializes the RC4 alg with KSA
        # KSA_ Key Scheduling Algorithm
        # "[...]an algorithm that calculates all the round keys from the key."
        # - https://en.wikipedia.org/wiki/Key_schedule

        actual_key = key if key is not None else self.key
        key_bytes = self.prepare_key(actual_key)
        
        if self.show_steps:
            print(f"=== RC4 Key Scheduling Algorithm (KSA) for Decryption ===")
            print(f"Key: '{actual_key}' = {key_bytes.hex().upper()}")
            print(f"Key length: {len(key_bytes)} bytes")
        
        # Step 1: Initialize S-box with identity permutation
        self.S = list(range(256))
        
        if self.show_steps:
            print(f"Initial S-box: [0, 1, 2, ..., 255]")
        
        # Step 2: Use key to scramble S-box
        j = 0
        for i in range(256):
            j = (j + self.S[i] + key_bytes[i % len(key_bytes)]) % 256
            
            # Swap S[i] and S[j]
            self.S[i], self.S[j] = self.S[j], self.S[i]
            
            if self.show_steps and i < 8:  # Show first few iterations
                key_byte = key_bytes[i % len(key_bytes)]
                print(f"i={i:3d}: j=({j-key_byte}+{self.S[j]}+{key_byte})%256={j:3d}, swap S[{i}]↔S[{j}]")
        
        if self.show_steps:
            print(f"Final S-box first 16 values: {self.S[:16]}")
            print(f"Final S-box last 16 values:  {self.S[-16:]}")
        
        # Reset stream generation pointers
        self.i = 0
        self.j = 0
        self.initialized = True
        
        return self.S.copy()



    def generate_keystream_byte(self):
        # This function generates a single BYTE of the keystream using PRGA
        # PRGA: Pseudo-random Generation Algorithm
        # Note that we're using the swap based on i and j locations (as POINTERS)
        # This doesn't use a random number generator library call
        # This is identical to the encrypt class function

        if not self.initialized:
            raise ValueError("RC4 not initialized - call initialize_rc4() first")
        
        # Increment i
        self.i = (self.i + 1) % 256
        
        # Update j
        self.j = (self.j + self.S[self.i]) % 256
        
        # Swap S[i] and S[j]
        self.S[self.i], self.S[self.j] = self.S[self.j], self.S[self.i]
        
        # Generate keystream byte
        keystream_byte = self.S[(self.S[self.i] + self.S[self.j]) % 256]
        
        return keystream_byte
    


    def generate_keystream(self, length):
        # The function that uses the above single BYTE generation function
        # this way we can manage streams of differen lengths (and keep track)
        # (Claude AI responsible for the pretty table print outs in these 2 functions)
        # This is identical to the encrypt version of this function

        if not self.initialized:
            self.initialize_rc4()
        
        keystream = []
        
        if self.show_steps:
            print(f"\n=== RC4 Pseudo-Random Generation Algorithm (PRGA) for Decryption ===")
            print(f"Generating {length} keystream bytes...")
            print("Step | i   | j   | S[i] | S[j] | S[i]+S[j] | S[sum] | Keystream")
            print("-" * 65)
        
        for step in range(length):
            old_i, old_j = self.i, self.j
            
            keystream_byte = self.generate_keystream_byte()
            keystream.append(keystream_byte)
            
            if self.show_steps and step < 10:  # Show first 10 steps
                sum_indices = (self.S[self.i] + self.S[self.j]) % 256
                print(f"{step:4d} | {self.i:3d} | {self.j:3d} | {self.S[self.i]:3d}  | {self.S[self.j]:3d}  | {sum_indices:8d} | {keystream_byte:3d}    | 0x{keystream_byte:02X}")
        
        if self.show_steps and length > 10:
            print(f"... (generated {length - 10} more bytes)")
        
        return bytes(keystream)



    def decrypt_message(self, ciphertext, key=None):
        # Group work question: How similar to the encrypt_message function is this? Why?


        # Use provided key or default
        actual_key = key if key is not None else self.key
        
        # Parse ciphertext from input format
        ciphertext_bytes = self.parse_ciphertext(ciphertext)
        
        if self.show_steps:
            print(f"\n=== RC4 Decryption Process ===")
            print(f"Ciphertext: '{ciphertext}'")
            print(f"Ciphertext bytes: {ciphertext_bytes.hex().upper()}")
            print(f"Length: {len(ciphertext_bytes)} bytes")
        
        # Initialize RC4 with the key (creates identical keystream as encryption)
        self.initialize_rc4(actual_key)
        
        # Generate keystream (identical to what was used for encryption)
        keystream = self.generate_keystream(len(ciphertext_bytes))
        
        if self.show_steps:
            print(f"\nKeystream: {keystream.hex().upper()}")
        
        # XOR ciphertext with keystream (identical operation)
        plaintext_bytes = bytes(c ^ k for c, k in zip(ciphertext_bytes, keystream))
        
        if self.show_steps:
            print(f"\n=== XOR Operation (Decryption) ===")
            print("Pos | Cipher | Key | Plain")
            print("-" * 26)
            for i in range(min(16, len(ciphertext_bytes))):  # Show first 16 bytes
                c, k, p = ciphertext_bytes[i], keystream[i], plaintext_bytes[i]
                print(f"{i:3d} | 0x{c:02X}   | 0x{k:02X} | 0x{p:02X}")
            
            if len(ciphertext_bytes) > 16:
                print(f"... ({len(ciphertext_bytes) - 16} more bytes)")
            
            print(f"\nPlaintext bytes: {plaintext_bytes.hex().upper()}")
        
        # Try to decode as UTF-8 text
        try:
            return plaintext_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # If not valid UTF-8, return as hex
            return plaintext_bytes.hex().upper()


    def calculate_english_score(self, text):
        # Calculate how English-like a text is
        # Remove non-alphabetic characters and convert to uppercase

        if not isinstance(text, str):
            return -1000  # Penalize non-text results
        
        # Remove non-alphabetic characters and convert to uppercase
        clean_text = re.sub(r'[^A-Za-z]', '', text.upper())
        
        if len(clean_text) == 0:
            return -1000
        
        # Count letter frequencies
        letter_counts = Counter(clean_text)
        total_letters = len(clean_text)
        
        # Calculate score based on closeness to English frequencies
        score = 0
        for letter, count in letter_counts.items():
            observed_freq = (count / total_letters) * 100
            expected_freq = self.lang_freq.get(letter, 0)
            
            # Use negative squared difference (closer to expected = higher score)
            score -= (observed_freq - expected_freq) ** 2
        
        # Bonus for common English words
        common_words = ['THE', 'AND', 'TO', 'OF', 'A', 'IN', 'IS', 'IT', 'YOU', 'THAT', 'HE', 'WAS', 'FOR', 'ON', 'ARE', 'AS', 'WITH', 'HIS', 'THEY', 'I']
        word_bonus = sum(10 for word in common_words if word in text.upper())
        score += word_bonus
        
        return score

    def brute_force_decrypt(self, ciphertext, max_keys=None, show_all=False):
        # NOTE: the 'keys' included in this function include 
        # a very specific dictionary tied to the use cases. 
        # The dictionary can be changed at the top of the class

        results = []
               
        # Add some systematic variations
        extended_keys = []
        for key in self.brute_force_keys[:10]:  # Don't make it too long
            extended_keys.extend([
                key.lower(),
                key + '1',
                key + '123',
                '1' + key,
            ])
        
        all_keys = self.brute_force_keys + extended_keys
        
        if max_keys:
            all_keys = all_keys[:max_keys]
        
        print(f"Trying {len(all_keys)} different keys...")
        print("=" * 60)
        
        for i, key in enumerate(all_keys):
            try:
                # Reset RC4 state for each attempt
                self.initialized = False
                decrypted = self.decrypt_message(ciphertext, key)
                score = self.calculate_english_score(decrypted)
                results.append((key, decrypted, score))
                
                if show_all:
                    print(f"{i+1:3d}. Key '{key:12s}' → {decrypted[:30]:<30} (Score: {score:.1f})")
                    
            except Exception as e:
                if show_all:
                    print(f"{i+1:3d}. Key '{key:12s}' → ERROR: {str(e)}")
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results



    def auto_decrypt(self, ciphertext, top_n=5, max_keys=30):
       # automatically find the most likely decryption
       # (results may vary)
        results = self.brute_force_decrypt(ciphertext, max_keys, show_all=False)
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 70)
        
        for i, (key, decrypted, score) in enumerate(results[:top_n]):
            print(f"{i+1}. Key '{key:12s}' (Score: {score:6.1f}): {decrypted}")
        
        return results[0][1] if results else "No valid decryption found"


    def demonstrate_symmetry(self, plaintext="HELLO RC4", key="TEST"):
        # Claude AI added as part of the decrypt_tesy.py demo. 
        # Since the setup for encryption and decryption are the same,
        # we can take advantage of that and test out the process.
        # That XOR does a lot of heavy lifting!
        # THIS IS DEMO ONLY

        print(f"=== RC4 SYMMETRY DEMONSTRATION ===")
        print(f"Plaintext: '{plaintext}'")
        print(f"Key: '{key}'")
        
        # Step 1: "Encrypt" (actually just generate keystream and XOR)
        print(f"\n--- Step 1: Encryption ---")
        old_show_steps = self.show_steps
        self.show_steps = True
        
        plaintext_bytes = plaintext.encode('utf-8')
        self.initialize_rc4(key)
        keystream1 = self.generate_keystream(len(plaintext_bytes))
        ciphertext_bytes = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream1))
        ciphertext_hex = ciphertext_bytes.hex().upper()
        
        print(f"Ciphertext: {ciphertext_hex}")
        
        # Step 2: "Decrypt" (generate same keystream and XOR again)
        print(f"\n--- Step 2: Decryption ---")
        self.initialize_rc4(key)  # Reset RC4 state
        keystream2 = self.generate_keystream(len(ciphertext_bytes))
        decrypted_bytes = bytes(c ^ k for c, k in zip(ciphertext_bytes, keystream2))
        decrypted_text = decrypted_bytes.decode('utf-8')
        
        self.show_steps = old_show_steps
        
        print(f"Decrypted: '{decrypted_text}'")
        
        # Verify
        print(f"\n--- Verification ---")
        print(f"Keystream 1: {keystream1.hex().upper()}")
        print(f"Keystream 2: {keystream2.hex().upper()}")
        print(f"Keystreams identical: {keystream1 == keystream2}")
        print(f"Decryption successful: {plaintext == decrypted_text}")
        
        return decrypted_text


    def analyze_ciphertext(self, ciphertext):
        # Since 1-shot decryption on this algorithm is EXTREMLY UNLIKELY,
        # this function analyzes some patterns in the cipher text to make
        # some observations

        print("=== RC4 Ciphertext Analysis ===")
        print(f"Ciphertext: {ciphertext}")
        print(f"Input format: {self.input_format}")
        
        try:
            ciphertext_bytes = self.parse_ciphertext(ciphertext)
            print(f"Length: {len(ciphertext_bytes)} bytes")
            
            # Byte frequency analysis
            byte_counts = Counter(ciphertext_bytes)
            print(f"Unique bytes: {len(byte_counts)}/256 possible")
            
            # Most common bytes
            most_common = byte_counts.most_common(5)
            print(f"Most frequent bytes: {[(f'0x{b:02X}', c) for b, c in most_common]}")
            
            # Entropy estimate (simplified)
            total_bytes = len(ciphertext_bytes)
            entropy = -sum((count/total_bytes) * np.log2(count/total_bytes) for count in byte_counts.values())
            print(f"Approximate entropy: {entropy:.2f} bits/byte (max 8.0 for random)")
            
            # Compare entropy
            if entropy < 6.0:
                print("Low entropy:: might not be RC4 or very short key.")
            elif entropy > 7.5:
                print("High entropy:: consistent with good a stream cipher implementation")
            
        except Exception as e:
            print(f"Error parsing ciphertext: {e}")


    def show_rc4_state(self):
        # preview of what's currently happening inside the cipher process
        # This is for DEMO purposes only.
        print(f"RC4 Decrypt State Information:")
        print(f"  Key: '{self.key}'")
        print(f"  Input format: {self.input_format}")
        print(f"  Initialized: {self.initialized}")
        
        if self.initialized:
            print(f"  Current i: {self.i}")
            print(f"  Current j: {self.j}")
            print(f"  S-box sample: S[0-15] = {self.S[:16]}")
        else:
            print("  S-box: Not initialized")


    def get_cipher_stats(self):
        # Claude AI suggested stats printout for the cipher configuration
        # I did remove ~ 10 extra lines of information about the creator and the process.
        # See the references section for more information on this algorithm

        key_bytes = self.prepare_key(self.key)
        
        stats = {
            'cipher_name': 'RC4 Decrypt',
            'key': self.key,
            'key_length_chars': len(self.key),
            'key_length_bytes': len(key_bytes),
            'input_format': self.input_format,
            'initialized': self.initialized  }
        
        if self.initialized:
            stats['current_i'] = self.i
            stats['current_j'] = self.j
        
        return stats


