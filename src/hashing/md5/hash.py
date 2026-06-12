#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/md5/hash.py'
#   MD5 cryptographic hash function (from scratch, educational)
#
#   MD5 (Rivest, 1992, RFC 1321) is a 128-bit hash built on the Merkle-
#   Damgard construction. It is INCLUDED HERE AS A BROKEN HASH: it is no
#   longer cryptographically secure and must never be used to protect
#   anything. Its value is entirely pedagogical -- it shows the Merkle-
#   Damgard skeleton clearly, and its DOWNFALL is one of the great teaching
#   stories in cryptography (see analysis.py).
#
#   WHY IT FELL (short version; the long one is in analysis.py):
#     - 2004: Wang et al. announced practical COLLISIONS (two different
#       inputs with the same MD5 hash), found by hand-guided differential
#       cryptanalysis. Collisions can now be made in seconds on a laptop.
#     - 2008: researchers used MD5 collisions to forge a rogue CA
#       certificate -- a real, weaponized break of the web's trust system.
#     - 2012: the Flame malware used an MD5 chosen-prefix collision to forge
#       a Microsoft code-signing certificate.
#   Collision resistance is COMPLETELY broken. (Preimage resistance is
#   weakened but not as catastrophically.)
#
#   Implementation follows RFC 1321, verified against hashlib in hash_test.py.
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

        # Per-round left-rotation amounts (RFC 1321).
        self.s = [7, 12, 17, 22] * 4 + [5, 9, 14, 20] * 4 + \
                 [4, 11, 16, 23] * 4 + [6, 10, 15, 21] * 4
        # Constants K[i] = floor(2^32 * abs(sin(i+1))), i = 0..63.
        self.K = [int(abs(np.sin(i + 1)) * (2 ** 32)) & 0xFFFFFFFF for i in range(64)]
        # Initialization vector (little-endian "magic" constants).
        self.A0, self.B0, self.C0, self.D0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        self.initialized = True

    @staticmethod
    def _lrot(x, c):
        x &= 0xFFFFFFFF
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def _pad(self, msg):
        # MD5 padding: append 0x80, then zeros, then the 64-bit LITTLE-endian
        # bit length, to a 512-bit (64-byte) multiple.
        ml = len(msg) * 8
        msg = msg + b'\x80'
        while len(msg) % 64 != 56:
            msg += b'\x00'
        msg += (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'little')
        return msg

    def hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        data = self._pad(message)
        a0, b0, c0, d0 = self.A0, self.B0, self.C0, self.D0

        for chunk_start in range(0, len(data), 64):
            chunk = data[chunk_start:chunk_start + 64]
            M = [int.from_bytes(chunk[4 * i:4 * i + 4], 'little') for i in range(16)]
            A, B, C, D = a0, b0, c0, d0
            for i in range(64):
                if i < 16:
                    F = (B & C) | (~B & D); g = i
                elif i < 32:
                    F = (D & B) | (~D & C); g = (5 * i + 1) % 16
                elif i < 48:
                    F = B ^ C ^ D; g = (3 * i + 5) % 16
                else:
                    F = C ^ (B | (~D & 0xFFFFFFFF)); g = (7 * i) % 16
                F = (F + A + self.K[i] + M[g]) & 0xFFFFFFFF
                A = D; D = C; C = B
                B = (B + self._lrot(F, self.s[i])) & 0xFFFFFFFF
            a0 = (a0 + A) & 0xFFFFFFFF
            b0 = (b0 + B) & 0xFFFFFFFF
            c0 = (c0 + C) & 0xFFFFFFFF
            d0 = (d0 + D) & 0xFFFFFFFF

        digest = b''.join(x.to_bytes(4, 'little') for x in (a0, b0, c0, d0))
        result = digest.hex()
        if self.show_steps:
            print(f"  MD5({message!r}) = {result}")
        return result

    def show_hash_state(self):
        print(f"MD5 State Information:")
        print(f"  Output size: 128 bits (32 hex chars)")
        print(f"  Construction: Merkle-Damgard, 512-bit blocks, 64 rounds")
        print(f"  Security: BROKEN (collisions trivial since 2004)")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'MD5',
            'output_bits': 128,
            'construction': 'Merkle-Damgard',
            'block_bits': 512,
            'rounds': 64,
            'security_status': 'BROKEN - do not use (collisions trivial)',
            'initialized': self.initialized}
