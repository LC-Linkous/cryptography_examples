#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/merkle_damgard/hash.py'
#   A clean Merkle-Damgard teaching hash (from scratch, educational)
#
#   This is NOT a standard hash and must NEVER be used for anything real.
#   It is a deliberately TRANSPARENT Merkle-Damgard construction whose only
#   job is to show the SKELETON shared by MD5, SHA-1, and SHA-256 without the
#   distraction of a heavily-optimized compression function. Once you see the
#   skeleton here, those three real hashes read as "the same shape with a
#   better compression function and more rounds."
#
#   THE MERKLE-DAMGARD CONSTRUCTION:
#     1. Pad the message so its length is a block multiple, ENCODING THE
#        MESSAGE LENGTH in the padding (the "MD strengthening" -- essential
#        to the security proof and to preventing trivial extension tricks).
#     2. Split into fixed-size blocks m_1, ..., m_k.
#     3. Start from a fixed IV: h_0 = IV.
#     4. Chain a compression function f: h_i = f(h_{i-1}, m_i).
#     5. Output h_k.
#   THE THEOREM (Merkle, Damgard, 1989): if the compression function f is
#   collision-resistant, then so is the whole hash. This is why hash design
#   reduces to compression-function design.
#
#   THE INHERITED FLAW: the output IS the final chaining value, which enables
#   the LENGTH-EXTENSION attack (demonstrated in analysis.py). Modern designs
#   (SHA-3's sponge) avoid it; this teaching hash has it, on purpose, so the
#   lesson is concrete.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')


class hashfn:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.show_steps = opt_df['SHOW_STEPS'][0] if (opt_df is not None and 'SHOW_STEPS' in opt_df.columns) else False
        # 32-bit chaining value; 4-byte (32-bit) message blocks. Small and
        # readable. The IV is an arbitrary fixed constant.
        self.IV = 0x811C9DC5
        self.block_size = 4
        self.initialized = True

    def _compress(self, chaining, block):
        # A simple but nonlinear compression function f(h, m). This is NOT
        # cryptographically strong -- it is illustrative. It mixes the
        # chaining value and the block with multiply, XOR, rotate, and an
        # ARX-style avalanche so that single-bit changes propagate (you can
        # watch this in analysis.py).
        h = chaining & 0xFFFFFFFF
        m = int.from_bytes(block, 'big') & 0xFFFFFFFF
        for r in range(16):  # several rounds for diffusion
            h = (h + m) & 0xFFFFFFFF
            h = (h * 0x01000193) & 0xFFFFFFFF        # FNV-style prime multiply
            h ^= (h >> 15)
            h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF  # rotate left 13
            m = ((m << 7) | (m >> 25)) & 0xFFFFFFFF   # stir the block too
        return h & 0xFFFFFFFF

    def _pad(self, msg):
        # MD strengthening: 0x80, zeros, then 64-bit big-endian bit length,
        # padded to a block multiple.
        ml = len(msg) * 8
        msg = msg + b'\x80'
        while (len(msg) + 8) % self.block_size != 0:
            msg += b'\x00'
        msg += (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')
        return msg

    def hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        data = self._pad(message)
        h = self.IV
        if self.show_steps:
            print(f"\n=== Merkle-Damgard hash of {message!r} ===")
            print(f"  IV = {h:08x}")
        for i in range(0, len(data), self.block_size):
            block = data[i:i + self.block_size]
            h = self._compress(h, block)
            if self.show_steps:
                print(f"  block {block.hex():8} -> chaining {h:08x}")
        result = f'{h:08x}'
        if self.show_steps:
            print(f"  digest = {result}")
        return result

    def hash_from_state(self, state, extension_blocks_data, total_prior_len):
        # Resume hashing from a given chaining state -- the capability that
        # makes LENGTH EXTENSION possible. Used by analysis.py to demonstrate
        # the attack. (A real attacker sets state = a published digest.)
        h = int(state, 16) if isinstance(state, str) else state
        data = extension_blocks_data
        # re-pad accounting for the prior length (so the length field is right)
        ml = (total_prior_len + len(data)) * 8
        data = data + b'\x80'
        while (len(data) + 8) % self.block_size != 0:
            data += b'\x00'
        data += (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')
        for i in range(0, len(data), self.block_size):
            h = self._compress(h, data[i:i + self.block_size])
        return f'{h:08x}'

    def show_hash_state(self):
        print(f"Merkle-Damgard Teaching Hash State Information:")
        print(f"  Output size: 32 bits (8 hex chars) -- TOY size")
        print(f"  Construction: Merkle-Damgard, {self.block_size*8}-bit blocks")
        print(f"  IV: 0x{self.IV:08X}")
        print(f"  Security: NONE -- teaching skeleton only")
        print(f"  Has length-extension flaw: yes (by design, see analysis.py)")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'Merkle-Damgard teaching hash',
            'output_bits': 32,
            'construction': 'Merkle-Damgard',
            'block_bits': self.block_size * 8,
            'security_status': 'NONE - illustrative skeleton only',
            'length_extension_vulnerable': True,
            'initialized': self.initialized}
