#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/chacha20/encrypt.py'
#   ChaCha20 stream cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 26, 2025
##--------------------------------------------------------------------\

import numpy as np
import struct
import hashlib
from secrets import token_bytes
np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary=None, opt_df=None, parent=None): 

        # Optional parent class
        self.parent = parent 

        # ChaCha20 works on bytes, not character dictionaries
        # We're keeping this for compatibility with the framework
        self.original_dictionary = dictionary

        # unpack the dataframe of options configurable to this encryption method
        self.key = opt_df['KEY'][0] # A KEY must be set. No defaults
        self.nonce = opt_df['NONCE'][0] # A NONCE must be set, no defaults
        self.counter = int(opt_df['COUNTER'][0]) 
        self.output_format = opt_df['OUTPUT_FORMAT'][0] if 'OUTPUT_FORMAT' in opt_df.columns else 'HEX'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # ChaCha20 internal state
        self.initial_state = None
        self.current_counter = 0
        self.key_bytes = None
        self.nonce_bytes = None
        self.initialized = False #for resets

        # ChaCha20 constants
        self.constants = b"expand 32-byte k"

    def prepare_key(self, key_string):
        # Convert the KEY string to BYTES
        # unlike RC4, the key must be converted to EXACTLY 
        # 32 BYTES (256 BITS).
        # If it's too short, we pad it. Too long & it must be shortened

        if isinstance(key_string, str):
            key_bytes = key_string.encode('utf-8')
        else:
            key_bytes = key_string
        
        if len(key_bytes) == 32: # equal
            return key_bytes
        elif len(key_bytes) < 32: # too short
            # Pad with zeros 
            return key_bytes + b'\x00' * (32 - len(key_bytes))
        else: # too long
            # Use SHA-256 to get the key down to 32 bytes
            # This uses an actual library to perform (real) cryptographic 
            # hashing to convert a key that's too long into exactly 32 bytes
            
            return hashlib.sha256(key_bytes).digest()



    def prepare_nonce(self, nonce_string):
        # Convert the NONCE string to BYTES
        # This must be converted to EXACTLY 
        # 12 BYTES (96 BITS).
        # If it's too short, we pad it. Too long & it must be shortened
        if not nonce_string:
            # Generate random nonce if none provided
            return token_bytes(12)
        
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
            # Use SHA-256 to get the key down to 12 bytes
            # This uses an actual library to perform (real) cryptographic 
            # hashing to convert a key that's too long into exactly 32 bytes
            return hashlib.sha256(nonce_bytes).digest()[:12]



    def initialize_chacha20(self, key=None, nonce=None, counter=None):
        # Initialize the state matrix. 
        # This started as a Claude AI printout modification,
        # but has done really well for debugging
        # A shortened version can be used for the actual algorithm

        actual_key = key if key is not None else self.key
        actual_nonce = nonce if nonce is not None else self.nonce
        actual_counter = counter if counter is not None else self.counter
        
        self.key_bytes = self.prepare_key(actual_key)
        self.nonce_bytes = self.prepare_nonce(actual_nonce)
        self.current_counter = actual_counter
        
        if self.show_steps:
            print(f"=== ChaCha20 Initialization ===")
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
    

    def show_chacha20_state(self):
        # Show the current internal state of the algorithm.
        # This is mostly used for showing the steps.
        # It is NOT part of the encryption algorithm

        print(f"ChaCha20 State Information:")
        print(f"  Key: '{self.key}' ({len(self.key)} chars)")
        print(f"  Nonce: '{self.nonce}' ({len(self.nonce)} chars)")
        print(f"  Counter: {self.counter}")
        print(f"  Output format: {self.output_format}")
        print(f"  Initialized: {self.initialized}")
        
        if self.initialized:
            print(f"  Key bytes: {len(self.key_bytes)} bytes")
            print(f"  Nonce bytes: {len(self.nonce_bytes)} bytes")
            print(f"  Current counter: {self.current_counter}")


    def print_state_matrix(self, state):
        # Claude AI addition. Gets the state matrix (great for debug)
        # and prints it out nicely in a 4x4 table.
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
        # The 'quarter round' is one of the core functions of ChaCha
        # From the 2008 paper introducing it:
        # "[ChaCha20] uses 4 additions and 4 xors and 4 rotations to invert-
        # ibly update 4 32-bit state words. However, ChaCha applies the operations in
        # a different order, and in particular updates each word twice rather than once."

        # This action makes it so that each INPUT word/phrase has an chance to affect 
        # each OUTPUT word/phrase


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
        # This function generates one block (64 BYTES)
        # Note the 8 quarter rounds 

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
            print(f"\n=== ChaCha20 Block Generation (Counter: {block_counter}) ===")
            print("Initial working state:")
            self.print_state_matrix(working_state)
        
        # Save original state for final addition
        original_state = working_state.copy()
        
        # 10 double rounds (20 rounds total)
        for round_num in range(10):
            if self.show_steps and round_num < 2:  # Show first 2 rounds in detail
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
            
            if self.show_steps and round_num < 2:
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
        # This generates a keystream os a specified length
        # Note how it rounds to the nearest block (this is an alg that 
        # pads values out so that all of the rotational work never has
        # null values)


        if not self.initialized:
            self.initialize_chacha20()
        
        keystream = b''
        blocks_needed = (length + 63) // 64  # Round up to nearest block
        
        if self.show_steps:
            print(f"\n=== ChaCha20 Keystream Generation ===")
            print(f"Requested length: {length} bytes")
            print(f"Blocks needed: {blocks_needed}")
        
        for block_num in range(blocks_needed):
            block = self.chacha20_block(self.current_counter - blocks_needed + block_num)
            keystream += block
            
            if self.show_steps and block_num < 2:
                print(f"Block {block_num}: {block[:16].hex().upper()}... ({len(block)} bytes)")
        
        # Truncate to requested length
        keystream = keystream[:length]
        
        if self.show_steps:
            print(f"Final keystream ({len(keystream)} bytes): {keystream[:32].hex().upper()}...")
        
        return keystream



    def encrypt_message(self, text, key=None, nonce=None, counter=None):
        # Use provided parameters or defaults
        actual_key = key if key is not None else self.key
        actual_nonce = nonce if nonce is not None else self.nonce
        actual_counter = counter if counter is not None else self.counter
        
        # Convert text to bytes
        if isinstance(text, str):
            plaintext_bytes = text.encode('utf-8')
        else:
            plaintext_bytes = text
        
        if self.show_steps:
            print(f"\n=== ChaCha20 Encryption Process ===")
            print(f"Plaintext: '{text}'")
            print(f"Plaintext bytes: {plaintext_bytes.hex().upper()}")
            print(f"Length: {len(plaintext_bytes)} bytes")
        
        # Initialize ChaCha20
        self.initialize_chacha20(actual_key, actual_nonce, actual_counter)
        
        # Generate keystream
        keystream = self.generate_keystream(len(plaintext_bytes))
        
        # XOR plaintext with keystream
        ciphertext = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream))
        
        if self.show_steps:
            print(f"\n=== XOR Operation ===")
            print("Pos | Plain | Key | Cipher")
            print("-" * 26)
            for i in range(min(16, len(plaintext_bytes))):  # Show first 16 bytes
                p, k, c = plaintext_bytes[i], keystream[i], ciphertext[i]
                print(f"{i:3d} | 0x{p:02X}  | 0x{k:02X} | 0x{c:02X}")
            
            if len(plaintext_bytes) > 16:
                print(f"... ({len(plaintext_bytes) - 16} more bytes)")
            
            print(f"\nCiphertext bytes: {ciphertext.hex().upper()}")
        
        # Format output
        return self.format_output(ciphertext)



    def format_output(self, ciphertext_bytes):
        # Claude AI addition for the stream ciphers so that they can 
        # be in a few different formats instead of 1 hardcoded format

        if self.output_format == 'HEX':
            return ciphertext_bytes.hex().upper()
        elif self.output_format == 'BASE64':
            import base64
            return base64.b64encode(ciphertext_bytes).decode('ascii')
        elif self.output_format == 'BYTES':
            return ciphertext_bytes
        elif self.output_format == 'DECIMAL':
            return ' '.join(str(b) for b in ciphertext_bytes)
        elif self.output_format == 'BINARY':
            return ' '.join(f'{b:08b}' for b in ciphertext_bytes)
        else:
            return ciphertext_bytes.hex().upper()


    def demonstrate_chacha20_internals(self, sample_text="HELLO"):
        # This is a Claude AI addition. It breaks down the process 
        # of how the algorithm works internally as steps are happening

        print(f"=== ChaCha20 DETAILED DEMONSTRATION ===")
        print(f"Sample text: '{sample_text}'")
        
        # Show step-by-step process
        old_show_steps = self.show_steps
        self.show_steps = True
        
        result = self.encrypt_message(sample_text)
        
        self.show_steps = old_show_steps
        
        print(f"\nFinal encrypted result: {result}")
        
        return result
    


    def test_nonce_sensitivity(self):
        # Claude AI addition. The Nonce has a strong impact on the algorithm
        # Unlike RC4, even when KEYS are reused, the NONCE is NOT. 
        # The algorithm is very sensitive to the nonce changes, which
        # makes this algorithm strong against key variations attacks
                        
        print(f"\nNotice how nonce changes produce completely different output!")
        print(f"This is crucial for security - never reuse key+nonce combinations!")

        test_message = "HELLO CHACHA20"
        test_nonces = [
            "nonce123",
            "nonce124",  # One digit different
            "nonce12",   # Shorter
            "different", # Completely different
            "",          # Empty (will generate random)
        ]
        
        print(f"=== ChaCha20 Nonce Sensitivity Test ===")
        print(f"Test message: '{test_message}'")
        print(f"Testing different nonces with same key:\n")
        
        for nonce in test_nonces:
            # Reset ChaCha20 state
            self.initialized = False
            encrypted = self.encrypt_message(test_message, nonce=nonce)
            nonce_display = nonce if nonce else "[random]"
            print(f"Nonce '{nonce_display:12s}' → {encrypted}")



    def show_block_structure(self):
        # Claude AI addition. It really likes showing off the blocks
        # inside this algorithm

        print(f"=== ChaCha20 Block Structure Demo ===")
        
        # Initialize with simple parameters
        self.initialize_chacha20("TESTKEY", "TESTNONCE", 0)
        
        print(f"ChaCha20 generates 64-byte blocks from a 4×4 matrix of 32-bit words:")
        
        # Generate a few blocks to show structure
        for i in range(3):
            print(f"\n--- Block {i} ---")
            block = self.chacha20_block(i)
            print(f"Block bytes: {block[:16].hex().upper()}...{block[-16:].hex().upper()}")
            print(f"Full length: {len(block)} bytes")
            # NOTE: blocks are generated INDEPENDENTLY



    def get_cipher_stats(self):
        # For comparison against other runs and to check that everything
        # has been set correctly. 
        """Get statistics about the current ChaCha20 configuration"""
        stats = {
            'cipher_name': 'ChaCha20',
            'key': self.key,
            'key_length_chars': len(self.key),
            'nonce': self.nonce,
            'nonce_length_chars': len(self.nonce),
            'counter': self.counter,
            'output_format': self.output_format,
            'initialized': self.initialized,
        }
        
        if self.initialized:
            stats['key_bytes'] = len(self.key_bytes)
            stats['nonce_bytes'] = len(self.nonce_bytes)
            stats['current_counter'] = self.current_counter
        
        return stats


