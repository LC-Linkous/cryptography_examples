#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/rc4/encrypt.py'
#   RC4 stream cipher encryption class
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 25, 2025
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary=None, opt_df=None, parent=None): 

        # Optional parent class
        self.parent = parent 

        # RC4 works on bytes, not character dictionaries
        # We're keeping this this for compatibility with the framework
        self.original_dictionary = dictionary

        # Unpack the data frame. While these could be default values, we want them
        # explicitly set in the test cases
        self.key = opt_df['KEY'][0] if 'KEY' in opt_df.columns else 'SECRET'
        self.output_format = opt_df['OUTPUT_FORMAT'][0] if 'OUTPUT_FORMAT' in opt_df.columns else 'HEX'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False #bool

        # RC4 internal state
        self.S = None  # S-box (substitution box)
        self.i = 0     # First index pointer
        self.j = 0     # Second index pointer
        self.initialized = False # an extra check for resets



    def prepare_key(self, key_string):
        # Convert the string to BYTES
        if isinstance(key_string, str):
            return key_string.encode('utf-8')
        else:
            return key_string



    def initialize_rc4(self, key=None):
        # This initializes the RC4 alg with KSA
        # KSA_ Key Scheduling Algorithm
        # "[...]an algorithm that calculates all the round keys from the key."
        # - https://en.wikipedia.org/wiki/Key_schedule

        actual_key = key if key is not None else self.key
        key_bytes = self.prepare_key(actual_key)
        
        if self.show_steps:
            print(f"=== RC4 Key Scheduling Algorithm (KSA) ===")
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

        if not self.initialized:
            raise ValueError("RC4 not initialized - call initialize_rc4() first")
        
        # Increment i (pointer)
        self.i = (self.i + 1) % 256
        
        # Update j (pointer)
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

        if not self.initialized:
            self.initialize_rc4()
        
        keystream = []
        
        if self.show_steps:
            print(f"\n=== RC4 Pseudo-Random Generation Algorithm (PRGA) ===")
            print(f"Generating {length} keystream bytes...")
            print("Step | i   | j   | S[i] | S[j] | S[i]+S[j] | S[sum] | Keystream")
            print("-" * 65)
        
        for step in range(length):
            old_i, old_j = self.i, self.j # check this if it looks like something
                                        # isn't re-writing. Might need a DEEPCOPY so 
                                        # these aren't shaing pointers to the mem 
                                        # address and getting rewritten at the wrong time
            old_si = self.S[(self.i + 1) % 256]
            
            keystream_byte = self.generate_keystream_byte()
            keystream.append(keystream_byte)
            
            if self.show_steps and step < 10:  # Show first 10 steps
                sum_indices = (self.S[self.i] + self.S[self.j]) % 256
                print(f"{step:4d} | {self.i:3d} | {self.j:3d} | {self.S[self.i]:3d}  | {self.S[self.j]:3d}  | {sum_indices:8d} | {keystream_byte:3d}    | 0x{keystream_byte:02X}")
        
        if self.show_steps and length > 10:
            print(f"... (generated {length - 10} more bytes)")
        
        return bytes(keystream)
    

    def encrypt_message(self, text, key=None):

        # Use provided key or default
        actual_key = key if key is not None else self.key
        
        # Convert text to bytes
        if isinstance(text, str):
            plaintext_bytes = text.encode('utf-8')
        else:
            plaintext_bytes = text
        
        if self.show_steps:
            print(f"\n=== RC4 Encryption Process ===")
            print(f"Plaintext: '{text}'")
            print(f"Plaintext bytes: {plaintext_bytes.hex().upper()}")
            print(f"Length: {len(plaintext_bytes)} bytes")
        
        # Initialize RC4 with the key
        self.initialize_rc4(actual_key)
        
        # Generate keystream
        keystream = self.generate_keystream(len(plaintext_bytes))
        
        if self.show_steps:
            print(f"\nKeystream: {keystream.hex().upper()}")
        
        # XOR plaintext with keystream
        ciphertext = bytes(p ^ k for p, k in zip(plaintext_bytes, keystream))
        
        if self.show_steps:
            print(f"\n=== XOR Operation ===")
            print("Pos | Plain | Key | Cipher")
            print("-" * 25)
            for i in range(min(16, len(plaintext_bytes))):  # Show first 16 bytes
                p, k, c = plaintext_bytes[i], keystream[i], ciphertext[i]
                print(f"{i:3d} | 0x{p:02X}  | 0x{k:02X} | 0x{c:02X}")
            
            if len(plaintext_bytes) > 16:
                print(f"... ({len(plaintext_bytes) - 16} more bytes)")
            
            print(f"\nCiphertext bytes: {ciphertext.hex().upper()}")
        
        # Format output
        return self.format_output(ciphertext)



    def format_output(self, ciphertext_bytes):
        # When asked for ways to clean up some of the functions,
        # Claude AI suggested adding other formats. Seemed fun, left it in.

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
            # Default to hex
            return ciphertext_bytes.hex().upper()


    def show_rc4_state(self):
        # preview of what's currently happening inside the cipher process
        # This is for DEMO purposes only.

        print(f"RC4 State Information:")
        print(f"  Key: '{self.key}'")
        print(f"  Initialized: {self.initialized}")
        
        if self.initialized:
            print(f"  Current i: {self.i}")
            print(f"  Current j: {self.j}")
            print(f"  S-box sample: S[0-15] = {self.S[:16]}")
            print(f"  Output format: {self.output_format}")
        else:
            print("  S-box: Not initialized")




    def demonstrate_rc4_internals(self, sample_text="HELLO"):
        # detailed printout. NOT NEEDED FOR ENCRYPTION
        print(f"=== RC4 DETAILED DEMONSTRATION ===")
        print(f"Sample text: '{sample_text}'")
        
        # Show step-by-step process
        old_show_steps = self.show_steps
        self.show_steps = True
        
        result = self.encrypt_message(sample_text)
        
        self.show_steps = old_show_steps
        
        print(f"\nFinal encrypted result: {result}")
        
        return result



    def test_key_sensitivity(self):
        # This is for DEMO purposes only. 
        # Meant to show how key changes (even single letter ones)
        # cause the output of the cipher to change. 
        # This is an extremly SENSITIVE algorithm

        test_message = "HELLO WORLD"
        test_keys = [
            "SECRET",
            "SECRE",   # One char shorter
            "SECRET1", # One char longer  
            "SECRET2", # Different last char
            "TECRET",  # Different first char
        ]
        
        print(f"=== RC4 Key Sensitivity Test ===")
        print(f"Test message: '{test_message}'")
        print(f"Testing different keys:\n")
        
        for key in test_keys:
            # Reset RC4 state
            self.initialized = False
            encrypted = self.encrypt_message(test_message, key)
            print(f"Key '{key:8s}' → {encrypted}")
        
        print(f"\nNotice how even tiny key changes produce completely different output!")



    def compare_with_manual_xor(self, text="HI"):
        # CLAUDE AI suggested edit for demo purposes.
        # Compares how RC4 stacks up to a XOR operation.

        print(f"=== RC4 vs Simple XOR Comparison ===")
        print(f"Text: '{text}'")
        
        # RC4 encryption
        rc4_result = self.encrypt_message(text)
        print(f"RC4 result:        {rc4_result}")
        
        # Simple repeating XOR (like Vigenère)
        key_bytes = self.prepare_key(self.key)
        text_bytes = text.encode('utf-8')
        simple_xor = bytes(t ^ key_bytes[i % len(key_bytes)] for i, t in enumerate(text_bytes))
        simple_xor_hex = simple_xor.hex().upper()
        print(f"Simple XOR result: {simple_xor_hex}")
        
        print(f"\nDifference:")
        print(f"- RC4 generates unique keystream for each position")
        print(f"- Simple XOR repeats the key pattern")
        print(f"- RC4 is much more secure (though still deprecated)")


    def get_cipher_stats(self):
        # Claude AI suggested stats printout for the cipher configuration
        # I did remove ~ 10 extra lines of information about the creator and the process.
        # See the references section for more information on this algorithm
        
        key_bytes = self.prepare_key(self.key)
        
        stats = {
            'cipher_name': 'RC4',
            'key': self.key,
            'key_length_chars': len(self.key),
            'key_length_bytes': len(key_bytes),
            'output_format': self.output_format,
            'initialized': self.initialized}
        
        if self.initialized:
            stats['current_i'] = self.i
            stats['current_j'] = self.j
            stats['s_box_state'] = f"S[0]={self.S[0]}, S[255]={self.S[255]}"
        
        return stats
