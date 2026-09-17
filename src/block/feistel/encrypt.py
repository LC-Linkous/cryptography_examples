#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/block/encrypt.py'
#   Simple block cipher encryption class. This is based on the Feistel cipher.
#       
#
#   Author(s): Lauren Linkous
#   Last update: June 23, 2025
##--------------------------------------------------------------------\

import numpy as np
import secrets


np.seterr(all='raise')

class encrypt:
  
    def __init__(self, dictionary, opt_df, parent=None): 

        # Optional parent class
        self.parent = parent 

        # set dictionary (for block ciphers, this is less relevant)
        self.original_dictionary = np.array(dictionary) if dictionary else None
        
        # unpack the dataframe of options configurable to this encryption method
        self.block_size = int(opt_df['BLOCK_SIZE'][0]) if 'BLOCK_SIZE' in opt_df.columns else 8
        self.num_rounds = int(opt_df['NUM_ROUNDS'][0]) if 'NUM_ROUNDS' in opt_df.columns else 4
        self.key_hex = opt_df['KEY_HEX'][0] if 'KEY_HEX' in opt_df.columns else None
        self.padding_mode = opt_df['PADDING_MODE'][0] if 'PADDING_MODE' in opt_df.columns else 'PKCS7'
        self.output_format = opt_df['OUTPUT_FORMAT'][0] if 'OUTPUT_FORMAT' in opt_df.columns else 'hex'
        
        # Validate parameters
        if self.block_size not in [4, 8, 16]:
            raise ValueError("Block size must be 4, 8, or 16 bytes")
        if self.num_rounds < 1 or self.num_rounds > 16:
            raise ValueError("Number of rounds must be between 1 and 16")
        
        # Generate or set the key
        self.key = self.setup_key()
        
        # Create S-boxes and P-boxes for the cipher
        self.sbox = self.create_sbox()
        self.inv_sbox = self.create_inverse_sbox()
        self.pbox = self.create_pbox()
        self.inv_pbox = self.create_inverse_pbox()
        
        # Generate round keys
        self.round_keys = self.generate_round_keys()


    def setup_key(self):
        # create the main cipher key
        # a key can be provided or generated

        if self.key_hex:
            # Use provided key
            try:
                key_bytes = bytes.fromhex(self.key_hex)
                if len(key_bytes) != self.block_size:
                    raise ValueError(f"Key must be {self.block_size} bytes ({self.block_size * 2} hex characters)")
                return key_bytes
            except ValueError as e:
                raise ValueError(f"Invalid hex key: {e}")
        else:
            # Generate random key
            # needs at least Python 3.6
            # this is better than random() in generating random tokens
            # it is ACTUALLY random, or as close as we can get to it
            return secrets.token_bytes(self.block_size)


    def create_sbox(self):
        # Create the S-box for the S-P-N process.
        # ENCRYPTION STEP. substitution

        # Simple S-box based on a permutation of 0-255
        # In practice, this would be carefully designed for cryptographic properties
        np.random.seed(42)  # Fixed seed for reproducibility in demo
        sbox = np.arange(256, dtype=np.uint8)
        np.random.shuffle(sbox)
        return sbox


    def create_inverse_sbox(self):
        # Create the INVERSE S-box for the DECRYPTION step
        # (This is included here for testing, not for the brute force decryption in decrypt.py)

        inv_sbox = np.zeros(256, dtype=np.uint8)
        for i in range(256):
            inv_sbox[self.sbox[i]] = i
        return inv_sbox
    


    def create_pbox(self):
        # Create the P-box for bit shuffling
        # ENCRYPTION STEP. permutation
        # Permutation within a byte (8 bits)
        # In practice, this would permute across the entire block
        bit_positions = list(range(8))
        np.random.seed(123)  # Fixed seed for reproducibility
        np.random.shuffle(bit_positions)
        return bit_positions


    def create_inverse_pbox(self):
        # Create the INVERSE P-box for the DECRYPTION step
        # (This is included here for testing, not for the brute force decryption in decrypt.py)

        inv_pbox = [0] * 8
        for i, pos in enumerate(self.pbox):
            inv_pbox[pos] = i
        return inv_pbox


    def generate_round_keys(self):
        # Generate the round keys from the main key
        # these do NOT need to be invertable for the final cipher to be invertable

        round_keys = []
        
        # Simple key schedule: rotate key and XOR with round counter
        current_key = list(self.key)
        
        for round_num in range(self.num_rounds):
            # Rotate key left by 1 position
            current_key = current_key[1:] + [current_key[0]]
            
            # XOR with round number
            round_key = []
            for i, byte in enumerate(current_key):
                round_key.append(byte ^ round_num ^ i)
            
            round_keys.append(bytes(round_key))
        
        return round_keys



    def substitute_bytes(self, data, use_inverse=False):
       # Applies the S-Box to substitute the data

        sbox = self.inv_sbox if use_inverse else self.sbox
        return bytes([sbox[byte] for byte in data])



    def permute_bits(self, data, use_inverse=False):
        # Applies the P-box to the data
        pbox = self.inv_pbox if use_inverse else self.pbox
        result = []
        
        for byte in data:
            # Extract bits
            bits = [(byte >> i) & 1 for i in range(8)]
            
            # Permute bits
            permuted_bits = [0] * 8
            for i, pos in enumerate(pbox):
                permuted_bits[pos] = bits[i]
            
            # Reconstruct byte
            new_byte = 0
            for i, bit in enumerate(permuted_bits):
                new_byte |= (bit << i)
            
            result.append(new_byte)
        
        return bytes(result)


    def add_round_key(self, data, round_key):
        # This is an XOR step!
        # This function XOR's the data with the round key
        return bytes([a ^ b for a, b in zip(data, round_key)])


    def encrypt_block(self, block):
        # This will encrypt a single block with the S-P-N structure.
        # There is a complement function in decrypt_block() for demo purposes

        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes")
        
        state = block
        
        # Initial key addition
        state = self.add_round_key(state, self.key)
        
        # Main rounds
        for round_num in range(self.num_rounds):
            # Substitution layer
            state = self.substitute_bytes(state)
            
            # Permutation layer (skip on last round)
            if round_num < self.num_rounds - 1:
                state = self.permute_bits(state)
            
            # Key addition
            state = self.add_round_key(state, self.round_keys[round_num])
        
        return state


    def pad_data(self, data):
        # This function adds pading. 
        # If a message is not long enough to fill a block, this will fill the space.
        # There's also an option to NOT use padding
        # group work question: do you notice anything different in the decryption analysis
        # when padding is used vs. when not? Are there other kinds of padding that might be
        # useful in this kind of encryption?

        if self.padding_mode == 'PKCS7':
            # PKCS#7 padding
            pad_length = self.block_size - (len(data) % self.block_size)
            if pad_length == 0:
                pad_length = self.block_size
            
            padding = bytes([pad_length] * pad_length)
            return data + padding
        
        elif self.padding_mode == 'zero':
            # Zero padding
            pad_length = self.block_size - (len(data) % self.block_size)
            if pad_length == 0:
                return data
            
            return data + bytes(pad_length)
        
        else:
            raise ValueError(f"Unknown padding mode: {self.padding_mode}")

    def unpad_data(self, data):
       # strip padding from the dataset

        if self.padding_mode == 'PKCS7':
            # PKCS#7 padding removal
            if len(data) == 0:
                return data
            
            pad_length = data[-1]
            if pad_length > self.block_size or pad_length == 0:
                raise ValueError("Invalid PKCS#7 padding")
            
            # Verify padding
            for i in range(pad_length):
                if data[-(i+1)] != pad_length:
                    raise ValueError("Invalid PKCS#7 padding")
            
            return data[:-pad_length]
        
        elif self.padding_mode == 'zero':
            # Zero padding removal (remove trailing zeros)
            return data.rstrip(b'\x00')
        
        else:
            raise ValueError(f"Unknown padding mode: {self.padding_mode}")

    def encrypt_message(self, text):
        # Convert to bytes if string
        if isinstance(text, str):
            data = text.encode('utf-8')
        else:
            data = text
        
        # Add padding
        padded_data = self.pad_data(data)
        
        # Encrypt block by block
        encrypted_blocks = []
        for i in range(0, len(padded_data), self.block_size):
            block = padded_data[i:i + self.block_size]
            encrypted_block = self.encrypt_block(block)
            encrypted_blocks.append(encrypted_block)
        
        # Combine blocks
        encrypted_data = b''.join(encrypted_blocks)
        
        # Format output
        if self.output_format == 'hex':
            return encrypted_data.hex().upper()
        elif self.output_format == 'base64':
            import base64
            return base64.b64encode(encrypted_data).decode('ascii')
        else:
            return encrypted_data



    def decrypt_block(self, block):
        # Decrypt a single block
        # This is the reverse function for encrypt_block. 
        # It has access to all of the encryption information, so it is NOT a brute force attempt
        # See decrypt.py for the brute force decryption class
        if len(block) != self.block_size:
            raise ValueError(f"Block must be {self.block_size} bytes")
        
        state = block
        
        # Reverse the encryption process
        for round_num in range(self.num_rounds - 1, -1, -1):
            # Reverse key addition
            state = self.add_round_key(state, self.round_keys[round_num])
            
            # Reverse permutation layer (skip on last round)
            if round_num < self.num_rounds - 1:
                state = self.permute_bits(state, use_inverse=True)
            
            # Reverse substitution layer
            state = self.substitute_bytes(state, use_inverse=True)
        
        # Reverse initial key addition
        state = self.add_round_key(state, self.key)
        
        return state



    def decrypt_message(self, encrypted_text):
        # DEMO purposes only
        # Convert from output format
        if self.output_format == 'hex':
            try:
                encrypted_data = bytes.fromhex(encrypted_text)
            except ValueError:
                raise ValueError("Invalid hex string")
        elif self.output_format == 'base64':
            import base64
            try:
                encrypted_data = base64.b64decode(encrypted_text)
            except Exception:
                raise ValueError("Invalid base64 string")
        else:
            encrypted_data = encrypted_text
        
        # Decrypt block by block
        decrypted_blocks = []
        for i in range(0, len(encrypted_data), self.block_size):
            block = encrypted_data[i:i + self.block_size]
            if len(block) != self.block_size:
                raise ValueError(f"Invalid block size: expected {self.block_size}, got {len(block)}")
            
            decrypted_block = self.decrypt_block(block)
            decrypted_blocks.append(decrypted_block)
        
        # Combine blocks
        decrypted_data = b''.join(decrypted_blocks)
        
        # Remove padding
        unpadded_data = self.unpad_data(decrypted_data)
        
        # Convert back to string if possible
        try:
            return unpadded_data.decode('utf-8')
        except UnicodeDecodeError:
            return unpadded_data



    def show_cipher_details(self):
        # This function displays the ciper configuration information and a 
        # breakdown of the internal structures of the cipher.
        # it's a bit long, so don't print it for EVERY test case.
        # (Claude AI used to make this more readable than V1)

        print(f"Block Cipher Configuration:")
        print(f"  Block size: {self.block_size} bytes")
        print(f"  Number of rounds: {self.num_rounds}")
        print(f"  Key: {self.key.hex().upper()}")
        print(f"  Padding mode: {self.padding_mode}")
        print(f"  Output format: {self.output_format}")
        
        print(f"\nS-box (first 16 values): {[hex(x) for x in self.sbox[:16]]}")
        print(f"P-box (bit positions): {self.pbox}")
        
        print(f"\nRound keys:")
        for i, rk in enumerate(self.round_keys):
            print(f"  Round {i+1}: {rk.hex().upper()}")

    def show_encryption_process(self, text, show_intermediate=True):
        # This shows the encryption as a step-by-step process
        # it's very long, so don't print it for EVERY test case.
        # (Claude AI used to make this more readable than V1)

        print(f"=== Encryption Process for '{text}' ===")
        
        # Convert to bytes
        if isinstance(text, str):
            data = text.encode('utf-8')
        else:
            data = text
        
        print(f"1. Input data: {data} ({data.hex().upper()})")
        
        # Add padding
        padded_data = self.pad_data(data)
        print(f"2. After padding: {padded_data.hex().upper()} ({len(padded_data)} bytes)")
        
        # Process each block
        encrypted_blocks = []
        for block_num, i in enumerate(range(0, len(padded_data), self.block_size)):
            block = padded_data[i:i + self.block_size]
            print(f"\n--- Block {block_num + 1} ---")
            print(f"Input: {block.hex().upper()}")
            
            if show_intermediate:
                # Show intermediate steps
                state = block
                
                # Initial key addition
                state = self.add_round_key(state, self.key)
                print(f"After initial key addition: {state.hex().upper()}")
                
                # Rounds
                for round_num in range(self.num_rounds):
                    print(f"\nRound {round_num + 1}:")
                    
                    # Substitution
                    state = self.substitute_bytes(state)
                    print(f"  After substitution: {state.hex().upper()}")
                    
                    # Permutation (skip on last round)
                    if round_num < self.num_rounds - 1:
                        state = self.permute_bits(state)
                        print(f"  After permutation: {state.hex().upper()}")
                    
                    # Key addition
                    state = self.add_round_key(state, self.round_keys[round_num])
                    print(f"  After key addition: {state.hex().upper()}")
                
                encrypted_block = state
            else:
                encrypted_block = self.encrypt_block(block)
            
            print(f"Block output: {encrypted_block.hex().upper()}")
            encrypted_blocks.append(encrypted_block)
        
        # Final result
        encrypted_data = b''.join(encrypted_blocks)
        if self.output_format == 'hex':
            result = encrypted_data.hex().upper()
        else:
            result = encrypted_data
        
        print(f"\n3. Final encrypted result: {result}")
        return result

