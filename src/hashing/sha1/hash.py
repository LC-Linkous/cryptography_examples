#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/sha1/hash.py'
#   SHA-1 cryptographic hash function (from scratch, educational)
#
#   SHA-1 (NSA/NIST, 1995, FIPS 180-1) is a 160-bit Merkle-Damgard hash that
#   succeeded MD5 and secured much of the internet for two decades. It is
#   INCLUDED HERE AS A BROKEN HASH -- a cautionary tale about the gap between
#   "no attack yet" and "secure," and about how long a wounded primitive can
#   limp on in deployed systems.
#
#   THE DOWNFALL (full version in analysis.py):
#     - 2005: Wang, Yin, Yu showed a theoretical collision attack far below
#       the 2^80 birthday bound (~2^69), signalling SHA-1 was mortally wounded.
#     - 2017: Google + CWI announced SHATTERED -- the first PRACTICAL SHA-1
#       collision, two distinct PDFs with the same SHA-1 digest, at a cost of
#       ~2^63 (about 6500 CPU-years, done with Google's resources).
#     - 2020: a CHOSEN-PREFIX collision (Leurent & Peyrin) made the attack
#       far more dangerous and cheap enough to threaten real protocols (e.g.
#       PGP web-of-trust). Browsers and CAs had already deprecated SHA-1.
#   Collision resistance is broken in practice; SHA-1 is retired. Migrate to
#   SHA-256 (already in this repo) or SHA-3.
#
#   Implementation follows FIPS 180-4, verified against hashlib in hash_test.py.
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
        # Five 32-bit IV words (FIPS 180-4).
        self.H0 = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
        self.initialized = True

    @staticmethod
    def _lrot(x, c):
        x &= 0xFFFFFFFF
        return ((x << c) | (x >> (32 - c))) & 0xFFFFFFFF

    def _pad(self, msg):
        # SHA-1 padding: 0x80, zeros, then 64-bit BIG-endian bit length.
        ml = len(msg) * 8
        msg = msg + b'\x80'
        while len(msg) % 64 != 56:
            msg += b'\x00'
        msg += (ml & 0xFFFFFFFFFFFFFFFF).to_bytes(8, 'big')
        return msg

    def hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        data = self._pad(message)
        h = list(self.H0)

        for cs in range(0, len(data), 64):
            chunk = data[cs:cs + 64]
            w = [int.from_bytes(chunk[4 * i:4 * i + 4], 'big') for i in range(16)]
            for i in range(16, 80):
                w.append(self._lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
            a, b, c, d, e = h
            for i in range(80):
                if i < 20:
                    f = (b & c) | (~b & d); k = 0x5A827999
                elif i < 40:
                    f = b ^ c ^ d; k = 0x6ED9EBA1
                elif i < 60:
                    f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
                else:
                    f = b ^ c ^ d; k = 0xCA62C1D6
                temp = (self._lrot(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
                e = d; d = c; c = self._lrot(b, 30); b = a; a = temp
            h = [(h[j] + v) & 0xFFFFFFFF for j, v in enumerate((a, b, c, d, e))]

        result = ''.join(f'{x:08x}' for x in h)
        if self.show_steps:
            print(f"  SHA1({message!r}) = {result}")
        return result

    def show_hash_state(self):
        print(f"SHA-1 State Information:")
        print(f"  Output size: 160 bits (40 hex chars)")
        print(f"  Construction: Merkle-Damgard, 512-bit blocks, 80 rounds")
        print(f"  Security: BROKEN (SHATTERED practical collision, 2017)")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'SHA-1',
            'output_bits': 160,
            'construction': 'Merkle-Damgard',
            'block_bits': 512,
            'rounds': 80,
            'security_status': 'BROKEN - retired (SHATTERED 2017)',
            'initialized': self.initialized}
