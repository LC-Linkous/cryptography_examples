#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/chacha20/decrypt.py'
#   ChaCha20 stream cipher decryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import sys
import struct
import hashlib
import re
from collections import Counter
from secrets import token_bytes
np.seterr(all='raise')

class decrypt:
  
    def __init__(self, dictionary=None, opt_df=None, parent=None): 

        # Optional parent class
        self.parent = parent 

        # ChaCha20 works on bytes, not character dictionaries
        # But we'll keep this for compatibility with the framework
        self.original_dictionary = dictionary

        # Default options if no dataframe provided
        if opt_df is None:
            opt_df = pd.DataFrame({
                'KEY': ['MySecretKey256BitLongForChaCha'],
                'NONCE': ['MyNonce123'],
                'COUNTER': [0],
                'INPUT_FORMAT': ['HEX'],
                'SHOW_STEPS': [False]
            })

        # unpack the dataframe of options configurable to this decryption method
        self.key = opt_df['KEY'][0] if 'KEY' in opt_df.columns else 'MySecretKey256BitLongForChaCha'
        self.nonce = opt_df['NONCE'][0] if 'NONCE' in opt_df.columns else 'MyNonce123'
        self.counter = int(opt_df['COUNTER'][0]) if 'COUNTER' in opt_df.columns else 0
        self.input_format = opt_df['INPUT_FORMAT'][0] if 'INPUT_FORMAT' in opt_df.columns else 'HEX'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # ChaCha20 internal state (identical to encrypt class)
        self.initial_state = None
        self.current_counter = 0
        self.key_bytes = None
        self.nonce_bytes = None
        self.initialized = False

        # ChaCha20 constants
        self.constants = b"expand 32-byte k"
        
        # Common English letter frequencies for scoring
        self.lang_freq = {
            'E': 12.7, 'T': 9.1, 'A': 8.2, 'O': 7.5, 'I': 7.0, 'N': 6.7,
            'S': 6.3, 'H': 6.1, 'R': 6.0, 'D': 4.3, 'L': 4.0, 'C': 2.8,
            'U': 2.8, 'M': 2.4, 'W': 2.4, 'F': 2.2, 'G': 2.0, 'Y': 2.0,
            'P': 1.9, 'B': 1.3, 'V': 1.0, 'K': 0.8, 'J': 0.15, 'X': 0.15,
            'Q': 0.10, 'Z': 0.07
        }

    def parse_ciphertext(self, ciphertext_string):
        """Parse ciphertext from various input formats"""
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

    def prepare_key(self, key_string):
        """Convert key to exactly 32 bytes (256 bits) for ChaCha20 - identical to encrypt"""
        if isinstance(key_string, str):
            key_bytes = key_string.encode('utf-8')
        else:
            key_bytes = key_string
        
        if len(key_bytes) == 32:
            return key_bytes
        elif len(key_bytes) < 32:
            # Pad with zeros
            return key_bytes + b'\x00' * (32 - len(key_bytes))
        else:
            # Use SHA-256 to derive exactly 32 bytes
            return hashlib.sha256(key_bytes).digest()

    def prepare_nonce(self, nonce_string):
        """Convert nonce to exactly 12 bytes (96 bits) for ChaCha20 - identical to encrypt"""
        if not nonce_string:
            # For decryption, we can't generate random nonce - it must be provided
            raise ValueError("Nonce is required for ChaCha20 decryption")
        
        if isinstance(nonce_string, str):
            nonce_bytes = nonce_string.encode('utf-8')
        else:
            nonce_bytes = nonce_string
        
        if len(nonce_bytes) == 12:
            return nonce_bytes
        elif len(nonce_bytes) < 12:
            # Pad with zeros
            return nonce_bytes + b'\x00' * (12 - len(nonce_bytes))
        else:
            # Use SHA-256 and truncate to 12 bytes
            return hashlib.sha256(nonce_bytes).digest()[:12]

    def initialize_chacha20(self, key=None, nonce=None, counter=None):
        """Initialize ChaCha20 state matrix - identical to encrypt"""
        actual_key = key if key is not None else self.key
        actual_nonce = nonce if nonce is not None else self.nonce
        actual_counter = counter if counter is not None else self.counter
        
        self.key_bytes = self.prepare_key(actual_key)
        self.nonce_bytes = self.prepare_nonce(actual_nonce)
        self.current_counter = actual_counter
        
        if self.show_steps:
            print(f"=== ChaCha20 Initialization for Decryption ===")
            print(f"Key: '{actual_key}'")
            print(f"Key bytes ({len(self.key_bytes)}): {self.key_bytes.hex().upper()}")
            print(f"Nonce: '{actual_nonce}'")
            print(f"Nonce bytes ({len(self.nonce_bytes)}): {self.nonce_bytes.hex().upper()}")
            print(f"Counter: {actual_counter}")
        
        # Build initial state (16 32-bit words)
        state = []
        
        # Constants (4 words): "expand 32-byte k"
        state.extend(struct.unpack('<4I', self.constants))
        
        # Key (8 words)
        state.extend(struct.unpack('<8I', self.key_bytes))
        
        # Counter (1 word)
        state.append(actual_counter)
        
        # Nonce (3 words)
        state.extend(struct.unpack('<3I', self.nonce_bytes))
        
        self.initial_state = state.copy()
        self.initialized = True
        
        if self.show_steps:
            print(f"\nInitial ChaCha20 state matrix:")
            self.print_state_matrix(state)
        
        return state

    def print_state_matrix(self, state):
        """Print the 4x4 ChaCha20 state matrix in readable format"""
        print("     +0        +1        +2        +3")
        for row in range(4):
            row_str = f"  {row}: "
            for col in range(4):
                idx = row * 4 + col
                word = state[idx]
                row_str += f"0x{word:08x} "
            print(row_str)
        
        # Show what each section represents
        print(f"\n  Legend:")
        print(f"    Row 0: Constants ('expand 32-byte k')")
        print(f"    Row 1-2: Key (256 bits)")
        print(f"    Row 3: Counter + Nonce (32 + 96 bits)")

    def quarter_round(self, state, a, b, c, d):
        """ChaCha20 quarter round function - identical to encrypt"""
        if self.show_steps:
            old_state = [state[a], state[b], state[c], state[d]]
        
        # a += b; d ^= a; d <<<= 16;
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] ^= state[a]
        state[d] = ((state[d] << 16) | (state[d] >> 16)) & 0xffffffff
        
        # c += d; b ^= c; b <<<= 12;
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] ^= state[c]
        state[b] = ((state[b] << 12) | (state[b] >> 20)) & 0xffffffff
        
        # a += b; d ^= a; d <<<= 8;
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] ^= state[a]
        state[d] = ((state[d] << 8) | (state[d] >> 24)) & 0xffffffff
        
        # c += d; b ^= c; b <<<= 7;
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] ^= state[c]
        state[b] = ((state[b] << 7) | (state[b] >> 25)) & 0xffffffff
        
        if self.show_steps:
            new_state = [state[a], state[b], state[c], state[d]]
            print(f"    Quarter round ({a},{b},{c},{d}): {[f'0x{x:08x}' for x in old_state]} → {[f'0x{x:08x}' for x in new_state]}")

    def chacha20_block(self, counter=None):
        """Generate one ChaCha20 block (64 bytes) - identical to encrypt"""
        if not self.initialized:
            self.initialize_chacha20()
        
        # Set counter value
        if counter is not None:
            block_counter = counter
        else:
            block_counter = self.current_counter
            self.current_counter += 1
        
        # Start with initial state
        working_state = self.initial_state.copy()
        working_state[12] = block_counter  # Set counter in position 12
        
        if self.show_steps:
            print(f"\n=== ChaCha20 Block Generation for Decryption (Counter: {block_counter}) ===")
            print("Initial working state:")
            self.print_state_matrix(working_state)
        
        # Save original state for final addition
        original_state = working_state.copy()
        
        # 10 double rounds (20 rounds total)
        for round_num in range(10):
            if self.show_steps and round_num < 1:  # Show first round in detail for decrypt
                print(f"\n--- Double Round {round_num + 1} ---")
            
            # Column rounds
            self.quarter_round(working_state, 0, 4, 8, 12)
            self.quarter_round(working_state, 1, 5, 9, 13)
            self.quarter_round(working_state, 2, 6, 10, 14)
            self.quarter_round(working_state, 3, 7, 11, 15)
            
            # Diagonal rounds
            self.quarter_round(working_state, 0, 5, 10, 15)
            self.quarter_round(working_state, 1, 6, 11, 12)
            self.quarter_round(working_state, 2, 7, 8, 13)
            self.quarter_round(working_state, 3, 4, 9, 14)
            
            if self.show_steps and round_num < 1:
                print(f"After double round {round_num + 1}:")
                self.print_state_matrix(working_state)
        
        # Add original state to final state
        for i in range(16):
            working_state[i] = (working_state[i] + original_state[i]) & 0xffffffff
        
        if self.show_steps:
            print(f"\nFinal state after adding original:")
            self.print_state_matrix(working_state)
        
        # Convert to bytes (little-endian)
        block_bytes = struct.pack('<16I', *working_state)
        
        if self.show_steps:
            print(f"Generated block ({len(block_bytes)} bytes): {block_bytes[:32].hex().upper()}...")
        
        return block_bytes

    def generate_keystream(self, length):
        """Generate ChaCha20 keystream of specified length - identical to encrypt"""
        if not self.initialized:
            self.initialize_chacha20()
        
        keystream = b''
        blocks_needed = (length + 63) // 64  # Round up to nearest block
        
        if self.show_steps:
            print(f"\n=== ChaCha20 Keystream Generation for Decryption ===")
            print(f"Requested length: {length} bytes")
            print(f"Blocks needed: {blocks_needed}")
        
        for block_num in range(blocks_needed):
            block = self.chacha20_block(self.current_counter - blocks_needed + block_num)
            keystream += block
            
            if self.show_steps and block_num < 1:
                print(f"Block {block_num}: {block[:16].hex().upper()}... ({len(block)} bytes)")
        
        # Truncate to requested length
        keystream = keystream[:length]
        
        if self.show_steps:
            print(f"Final keystream ({len(keystream)} bytes): {keystream[:32].hex().upper()}...")
        
        return keystream



    def decrypt_message(self, ciphertext, key=None, nonce=None, counter=None):
        # Decryption function. This process is identical to the encryption process (symmetrical).
     
        # Use provided parameters or defaults
        actual_key = key if key is not None else self.key
        actual_nonce = nonce if nonce is not None else self.nonce
        actual_counter = counter if counter is not None else self.counter
        
        # Parse ciphertext from input format
        ciphertext_bytes = self.parse_ciphertext(ciphertext)
        
        if self.show_steps:
            print(f"\n=== ChaCha20 Decryption Process ===")
            print(f"Ciphertext: '{ciphertext}'")
            print(f"Ciphertext bytes: {ciphertext_bytes.hex().upper()}")
            print(f"Length: {len(ciphertext_bytes)} bytes")
        
        # Initialize ChaCha20 (creates identical keystream as encryption)
        self.initialize_chacha20(actual_key, actual_nonce, actual_counter)
        
        # Generate keystream (identical to what was used for encryption)
        keystream = self.generate_keystream(len(ciphertext_bytes))
        
        # XOR ciphertext with keystream (identical operation)
        plaintext_bytes = bytes(c ^ k for c, k in zip(ciphertext_bytes, keystream))
        
        if self.show_steps:
            print(f"\n=== XOR Operation (Decryption) ===")
            print("Pos | Cipher | Key | Plain")
            print("-" * 27)
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
        common_words = ['THE', 'AND', 'TO', 'OF', 'A', 'IN', 'IS', 'IT', 'YOU', 'THAT']
        word_bonus = sum(10 for word in common_words if word in text.upper())
        score += word_bonus
        
        return score

    def brute_force_decrypt(self, ciphertext, max_attempts=None, show_all=False):
        # The brute force decryption default. 
        # most decryption algorithms start with a brute force dictionary-based attack
        # because it takes the least amount of resources and on occasion it works.

        # Claude AI was used to select the default keys. They also match a few of the
        # demo test cases in order to trigger a 'find'

 
        
        results = []
        
        # Common keys to try
        common_keys = [
            'SECRET', 'PASSWORD', 'CHACHA20', 'KEY', 'TESTKEY', 'MYKEY',
            'ENCRYPT', 'CIPHER', 'SECURE', 'PRIVATE', 'HIDDEN', 'DEMO'
        ]
        
        # Common nonces to try
        common_nonces = [
            'nonce123', 'test', 'mynonce', 'nonce', '123456789012',
            'chacha20', 'iv123456', 'random12', 'nonce1', 'testnonce'
        ]
        
        # Common counters
        common_counters = [0, 1]
        
        attempts = 0
        max_attempts = max_attempts or 50
        
        print(f"Trying ChaCha20 brute force decryption (max {max_attempts} attempts)...")
        print("=" * 70)
        
        for key in common_keys:
            for nonce in common_nonces:
                for counter in common_counters:
                    if attempts >= max_attempts:
                        break
                    
                    try:
                        # Reset ChaCha20 state for each attempt
                        self.initialized = False
                        decrypted = self.decrypt_message(ciphertext, key, nonce, counter)
                        score = self.calculate_english_score(decrypted)
                        results.append((f"Key:{key}, Nonce:{nonce}, Counter:{counter}", decrypted, score))
                        
                        attempts += 1
                        
                        if show_all:
                            print(f"{attempts:3d}. K:'{key:8s}' N:'{nonce:8s}' C:{counter} → {decrypted[:20]:<20} (Score: {score:.1f})")
                            
                    except Exception as e:
                        if show_all:
                            print(f"{attempts:3d}. K:'{key:8s}' N:'{nonce:8s}' C:{counter} → ERROR: {str(e)}")
                        attempts += 1
                
                if attempts >= max_attempts:
                    break
            if attempts >= max_attempts:
                break
        
        # Sort by score (best first)
        results.sort(key=lambda x: x[2], reverse=True)
        
        return results

    def auto_decrypt(self, ciphertext, top_n=5, max_attempts=30):
        results = self.brute_force_decrypt(ciphertext, max_attempts, show_all=False)
        
        print(f"\nTop {top_n} most likely decryptions:")
        print("=" * 80)
        
        for i, (config, decrypted, score) in enumerate(results[:top_n]):
            print(f"{i+1}. {config:<35} (Score: {score:6.1f}): {decrypted}")
        
        return results[0][1] if results else "No valid decryption found"



    def demonstrate_symmetry(self, plaintext="HELLO CHACHA20", key="TESTKEY", nonce="testnonce"):
        # Claude AI added demo for the symmetry of this algorithm

        print(f"=== ChaCha20 SYMMETRY DEMONSTRATION ===")
        print(f"Plaintext: '{plaintext}'")
        print(f"Key: '{key}'")
        print(f"Nonce: '{nonce}'")
        
        # Step 1: "Encrypt" (generate keystream and XOR)
        print(f"\n--- Step 1: Encryption ---")
        old_show_steps = self.show_steps
        self.show_steps = True
        
        plaintext_bytes = plaintext.encode('utf-8')
        self.initialize_chacha20(key, nonce, 0)
        keystream1 = self.generate_keystream(len(plaintext_bytes))
        ciphertext_bytes = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream1))
        ciphertext_hex = ciphertext_bytes.hex().upper()
        
        print(f"Ciphertext: {ciphertext_hex}")
        
        # Step 2: "Decrypt" (generate same keystream and XOR again)
        print(f"\n--- Step 2: Decryption ---")
        self.initialize_chacha20(key, nonce, 0)  # Reset ChaCha20 state
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
        # The decryption methods used for this are not intelligent enough 
        # to do a full analysis of potential attack vectors for this algorithm
        # but theres some topical analysis that can be done for demo purposes


        print("=== ChaCha20 Ciphertext Analysis ===")
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
            
            if entropy < 6.0:
                print("⚠️  Low entropy - might not be ChaCha20 or very weak key")
            elif entropy > 7.5:
                print("✅ High entropy - consistent with good stream cipher")
            
            # Block analysis
            if len(ciphertext_bytes) >= 64:
                print(f"Large enough for {len(ciphertext_bytes) // 64} full ChaCha20 blocks")
            else:
                print(f"Smaller than one ChaCha20 block (64 bytes)")
            
        except Exception as e:
            print(f"Error parsing ciphertext: {e}")



    def show_chacha20_state(self):
        # Show the current internal state of the algorithm.
        # This is mostly used for showing the steps.
        # It is NOT part of the encryption algorithm

        print(f"ChaCha20 Decrypt State Information:")
        print(f"  Key: '{self.key}' ({len(self.key)} chars)")
        print(f"  Nonce: '{self.nonce}' ({len(self.nonce)} chars)")
        print(f"  Counter: {self.counter}")
        print(f"  Input format: {self.input_format}")
        print(f"  Initialized: {self.initialized}")
        
        if self.initialized:
            print(f"  Key bytes: {len(self.key_bytes)} bytes")
            print(f"  Nonce bytes: {len(self.nonce_bytes)} bytes")
            print(f"  Current counter: {self.current_counter}")

    def get_cipher_stats(self):
        # For comparison against other runs and to check that everything
        # has been set correctly. 
        stats = {
            'cipher_name': 'ChaCha20 Decrypt',
            'key': self.key,
            'key_length_chars': len(self.key),
            'nonce': self.nonce,
            'nonce_length_chars': len(self.nonce),
            'counter': self.counter,
            'input_format': self.input_format,
            'initialized': self.initialized,
            'security_level': 'EXCELLENT - ChaCha20 is cryptographically secure'
        }
        
        if self.initialized:
            stats['key_bytes'] = len(self.key_bytes)
            stats['nonce_bytes'] = len(self.nonce_bytes)
            stats['current_counter'] = self.current_counter
        
        return stats


