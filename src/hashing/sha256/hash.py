#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/sha256/hash.py'
#   SHA-256 cryptographic hash function (from scratch, educational)
#
#   This is the repo's first HASHING example. A hash is NOT encryption:
#   there is no key and no decryption. It is a ONE-WAY function - easy to
#   compute forward, infeasible to reverse. The README already describes
#   hashing as the 'one-directional' method used for verification (e.g.
#   storing password hashes instead of passwords); this is the worked
#   implementation of that idea.
#
#   Because there is no decryption, there is no 'decrypt' class. The
#   companion file is 'analysis.py', which demonstrates the PROPERTIES
#   that make a hash useful (avalanche effect) and WHY reversing it by
#   brute force is hopeless - the resist-don't-break framing also used by
#   the ChaCha20 example.
#
#   This implementation follows FIPS 180-4. It is written for clarity, not
#   speed, and is verified against known test vectors in hash_test.py.
#   For real hashing, use a vetted library (Python's hashlib); a from-
#   scratch hash should never guard real secrets.
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')


class hash:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        # Optional parent class
        self.parent = parent

        # Hashing works on bytes, not character dictionaries. Kept for
        # framework compatibility with the cipher classes.
        self.original_dictionary = dictionary

        # Unpack the data frame. opt_df is optional for a hash since there
        # is no key; the only knob is the step-by-step display.
        if opt_df is not None and 'SHOW_STEPS' in opt_df.columns:
            self.show_steps = opt_df['SHOW_STEPS'][0]
        else:
            self.show_steps = False

        if opt_df is not None and 'OUTPUT_FORMAT' in opt_df.columns:
            self.output_format = opt_df['OUTPUT_FORMAT'][0]
        else:
            self.output_format = 'HEX'

        # --- SHA-256 CONSTANTS (FIPS 180-4) ---

        # Initial hash values H0..H7: the first 32 bits of the fractional
        # parts of the square roots of the first 8 primes (2,3,5,7,11,13,17,19).
        self.H_init = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]

        # Round constants K[0..63]: the first 32 bits of the fractional parts
        # of the cube roots of the first 64 primes.
        self.K = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        # 32-bit mask, used everywhere to keep arithmetic in 32 bits.
        self.MASK32 = 0xFFFFFFFF


    # --- bit-level helpers (all operate on 32-bit words) ---

    def _rotr(self, x, n):
        # Rotate right (circular shift) within 32 bits.
        return ((x >> n) | (x << (32 - n))) & self.MASK32

    def _shr(self, x, n):
        # Logical shift right within 32 bits.
        return (x >> n) & self.MASK32


    def preprocess(self, message_bytes):
        # PADDING (FIPS 180-4 sec 5.1.1):
        #   append a single '1' bit, then '0' bits, then the original
        #   message length in bits as a 64-bit big-endian integer, so the
        #   total length becomes a multiple of 512 bits (64 bytes).
        original_bit_len = len(message_bytes) * 8

        # Append the 0x80 byte = the '1' bit followed by seven '0' bits.
        padded = bytearray(message_bytes)
        padded.append(0x80)

        # Append 0x00 until length is 56 mod 64, leaving room for the 8-byte
        # length field that completes the final 64-byte block.
        while len(padded) % 64 != 56:
            padded.append(0x00)

        # Append the original length as a 64-bit big-endian integer.
        padded += original_bit_len.to_bytes(8, byteorder='big')

        if self.show_steps:
            print(f"  Message length: {len(message_bytes)} bytes "
                  f"({original_bit_len} bits)")
            print(f"  Padded length:  {len(padded)} bytes "
                  f"({len(padded)//64} block(s) of 64 bytes)")

        return bytes(padded)


    def process_block(self, block, H):
        # The COMPRESSION FUNCTION: take a 64-byte block and the current
        # hash state H[0..7], and produce the updated state.

        # 1. MESSAGE SCHEDULE: expand the 16 words of the block into 64 words.
        w = [0] * 64
        for t in range(16):
            w[t] = int.from_bytes(block[t*4:t*4+4], byteorder='big')
        for t in range(16, 64):
            s0 = self._rotr(w[t-15], 7) ^ self._rotr(w[t-15], 18) ^ self._shr(w[t-15], 3)
            s1 = self._rotr(w[t-2], 17) ^ self._rotr(w[t-2], 19) ^ self._shr(w[t-2], 10)
            w[t] = (w[t-16] + s0 + w[t-7] + s1) & self.MASK32

        # 2. Initialize working variables from the current state.
        a, b, c, d, e, f, g, h = H

        # 3. THE 64 ROUNDS: mash the working variables together with the
        #    schedule words and round constants. Each round mixes in one
        #    more word so every input bit eventually influences every output.
        for t in range(64):
            S1 = self._rotr(e, 6) ^ self._rotr(e, 11) ^ self._rotr(e, 25)
            ch = (e & f) ^ ((~e & self.MASK32) & g)
            temp1 = (h + S1 + ch + self.K[t] + w[t]) & self.MASK32
            S0 = self._rotr(a, 2) ^ self._rotr(a, 13) ^ self._rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & self.MASK32

            h = g
            g = f
            f = e
            e = (d + temp1) & self.MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & self.MASK32

            if self.show_steps and t < 4:
                print(f"    round {t:2d}: a={a:08x} e={e:08x}")

        # 4. Add the compressed block back into the running state.
        H_new = [
            (H[0] + a) & self.MASK32, (H[1] + b) & self.MASK32,
            (H[2] + c) & self.MASK32, (H[3] + d) & self.MASK32,
            (H[4] + e) & self.MASK32, (H[5] + f) & self.MASK32,
            (H[6] + g) & self.MASK32, (H[7] + h) & self.MASK32,
        ]
        return H_new


    def hash_message(self, text):
        # The full SHA-256: preprocess, then run every 64-byte block through
        # the compression function, then serialize the final state.

        if isinstance(text, str):
            message_bytes = text.encode('utf-8')
        else:
            message_bytes = bytes(text)

        if self.show_steps:
            print(f"\n=== SHA-256 of {text!r} ===")

        padded = self.preprocess(message_bytes)

        # Start from the standard initial hash values.
        H = list(self.H_init)

        # Process each 512-bit (64-byte) block in turn.
        num_blocks = len(padded) // 64
        for i in range(num_blocks):
            block = padded[i*64:(i+1)*64]
            if self.show_steps:
                print(f"  -- processing block {i+1}/{num_blocks} --")
            H = self.process_block(block, H)

        # Serialize H0..H7 as big-endian into the 32-byte digest.
        digest = b''.join(h.to_bytes(4, byteorder='big') for h in H)

        if self.show_steps:
            print(f"  Digest: {digest.hex()}")

        return self.format_output(digest)


    def format_output(self, digest_bytes):
        # Companion to the cipher classes' format_output().
        if self.output_format == 'HEX':
            return digest_bytes.hex()
        elif self.output_format == 'BYTES':
            return digest_bytes
        elif self.output_format == 'BIN':
            return ' '.join(f'{byte:08b}' for byte in digest_bytes)
        elif self.output_format == 'INT':
            return int.from_bytes(digest_bytes, byteorder='big')
        else:
            return digest_bytes.hex()


    def show_hash_state(self):
        # Preview of the hash configuration. DEMO purposes only.
        print(f"SHA-256 State Information:")
        print(f"  Algorithm: SHA-256 (FIPS 180-4)")
        print(f"  Digest size: 256 bits / 32 bytes / 64 hex chars")
        print(f"  Block size: 512 bits / 64 bytes")
        print(f"  Rounds per block: 64")
        print(f"  Output format: {self.output_format}")


    def get_cipher_stats(self):
        # Stats printout matching the shape used elsewhere in the repo.
        return {
            'cipher_name': 'SHA-256',
            'type': 'cryptographic hash (one-way)',
            'digest_bits': 256,
            'block_bits': 512,
            'rounds': 64,
            'output_format': self.output_format,
            'reversible': False}
