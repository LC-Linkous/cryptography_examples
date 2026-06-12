#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/hashing/crc32/hash.py'
#   CRC32 -- a CHECKSUM, deliberately included as a NON-cryptographic
#   counterexample
#
#   CRC32 (Cyclic Redundancy Check, 32-bit) is NOT a cryptographic hash and
#   this file exists to make that distinction unmistakable. CRC32 is a
#   CHECKSUM: it is designed to detect ACCIDENTAL errors (flipped bits from
#   noise on a wire or disk), and it is excellent at that. It is used in
#   Ethernet, ZIP, PNG, gzip, etc. But it provides ZERO security against a
#   deliberate adversary.
#
#   WHY IT IS NOT CRYPTOGRAPHIC (the whole lesson):
#     - It is LINEAR over GF(2): CRC(a XOR b) = CRC(a) XOR CRC(b) XOR CRC(0).
#       That linearity is exactly what makes it fast and good at catching
#       burst errors -- and exactly what makes it useless against tampering.
#     - Given a message and its CRC, an attacker can MODIFY the message and
#       trivially recompute or even surgically PATCH the CRC to match. There
#       is no preimage resistance, no collision resistance, no secret.
#     - It has no key, so it cannot even act as a MAC.
#
#   The mathematics: treat the message bits as a polynomial over GF(2),
#   divide by a fixed generator polynomial, and the REMAINDER is the CRC.
#   (Same GF(2) polynomial arithmetic as the AES field work and the CRC's
#   cousins in coding theory -- a nice cross-link.)
#
#   Verified against Python's zlib.crc32 in hash_test.py.
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
        # The standard CRC-32 (IEEE 802.3) reversed polynomial.
        self.poly = 0xEDB88320
        self.table = self._build_table()
        self.initialized = True

    def _build_table(self):
        # Precompute the 256-entry byte table (the standard fast CRC method).
        table = []
        for n in range(256):
            c = n
            for _ in range(8):
                c = (self.poly ^ (c >> 1)) if (c & 1) else (c >> 1)
            table.append(c & 0xFFFFFFFF)
        return table

    def hash_message(self, message):
        if isinstance(message, str):
            message = message.encode('utf-8')
        crc = 0xFFFFFFFF
        for byte in message:
            crc = self.table[(crc ^ byte) & 0xFF] ^ (crc >> 8)
            crc &= 0xFFFFFFFF
        crc ^= 0xFFFFFFFF
        result = f'{crc:08x}'
        if self.show_steps:
            print(f"  CRC32({message!r}) = {result}")
        return result

    def demonstrate_linearity(self, a, b):
        # Show CRC32 is LINEAR: this is the property a cryptographic hash must
        # NOT have. We verify CRC(a XOR b) == CRC(a) XOR CRC(b) XOR CRC(0)
        # over equal-length inputs.
        if isinstance(a, str): a = a.encode()
        if isinstance(b, str): b = b.encode()
        n = min(len(a), len(b))
        a, b = a[:n], b[:n]
        xored = bytes(x ^ y for x, y in zip(a, b))
        ca = int(self.hash_message(a), 16)
        cb = int(self.hash_message(b), 16)
        cx = int(self.hash_message(xored), 16)
        c0 = int(self.hash_message(b'\x00' * n), 16)
        linear = (cx == (ca ^ cb ^ c0))
        return linear, ca, cb, cx, c0

    def show_hash_state(self):
        print(f"CRC32 State Information:")
        print(f"  Output size: 32 bits (8 hex chars)")
        print(f"  Type: CHECKSUM (error detection), NOT a cryptographic hash")
        print(f"  Generator polynomial: 0x{self.poly:08X} (reversed, IEEE 802.3)")
        print(f"  Security: NONE (linear, no preimage/collision resistance)")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'CRC32 (checksum, NOT cryptographic)',
            'output_bits': 32,
            'type': 'cyclic redundancy check / error detection',
            'polynomial': f'0x{self.poly:08X}',
            'security_status': 'NONE - detects accidental errors only',
            'is_cryptographic': False,
            'initialized': self.initialized}
