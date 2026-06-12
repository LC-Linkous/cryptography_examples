#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/stream/otp/encrypt.py'
#   One-Time Pad (Vernam cipher) encryption class
#
#   The One-Time Pad is the ONLY cipher with PROVEN perfect secrecy
#   (Shannon, 1949). Each plaintext symbol is combined with a key symbol that
#   is (1) truly random, (2) at least as long as the message, and (3) NEVER
#   reused. Under those three conditions the ciphertext reveals literally
#   nothing about the plaintext: every plaintext of that length is an equally
#   likely explanation of the ciphertext.
#
#   Gilbert Vernam patented the XOR-teletype version in 1919; Joseph Mauborgne
#   added the crucial "random, used once" insight. We implement the classic
#   byte-wise XOR pad, plus a mod-26 letter variant for the historical form.
#
#   THE CATCH: the three conditions are brutal in practice. A truly random
#   key as long as all traffic, distributed secretly and never reused, is
#   usually harder to manage than the message itself. Violate ANY condition
#   (reuse a key, use a non-random key) and perfect secrecy collapses
#   completely -- see the decrypt class for the key-reuse demonstration.
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
import os

np.seterr(all='raise')


class encrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary

        # MODE: 'xor' (byte-wise, the modern form) or 'mod26' (letters only,
        #       the historical teletype/letter form).
        # KEY:  optional explicit key (hex for xor, letters for mod26). If
        #       omitted, a fresh random key is generated per message.
        self.mode = opt_df['MODE'][0] if (opt_df is not None and 'MODE' in opt_df.columns) else 'xor'
        self.key = opt_df['KEY'][0] if (opt_df is not None and 'KEY' in opt_df.columns) else None
        self.show_steps = opt_df['SHOW_STEPS'][0] if (opt_df is not None and 'SHOW_STEPS' in opt_df.columns) else False

        self.last_key = None   # remember the key actually used (for decrypt demos)
        self.initialized = True

    def _gen_key_bytes(self, n):
        # Cryptographically secure random bytes for the pad. os.urandom is
        # the right source; the security PROOF assumes true randomness.
        return os.urandom(n)

    def encrypt_message(self, text):
        if self.mode == 'xor':
            return self._encrypt_xor(text)
        elif self.mode == 'mod26':
            return self._encrypt_mod26(text)
        raise ValueError(f"Unknown MODE: {self.mode}")

    def _encrypt_xor(self, text):
        data = text.encode('utf-8') if isinstance(text, str) else bytes(text)
        if self.key is not None:
            key = bytes.fromhex(self.key) if isinstance(self.key, str) else bytes(self.key)
            if len(key) < len(data):
                raise ValueError(
                    f"KEY ({len(key)} bytes) shorter than message "
                    f"({len(data)} bytes) -- violates the OTP length rule.")
        else:
            key = self._gen_key_bytes(len(data))
        self.last_key = key
        ct = bytes(d ^ k for d, k in zip(data, key))
        if self.show_steps:
            print(f"\n=== One-Time Pad (XOR) ===")
            print(f"  plaintext  (hex): {data.hex()}")
            print(f"  key/pad    (hex): {key[:len(data)].hex()}")
            print(f"  ciphertext (hex): {ct.hex()}")
        return ct.hex()

    def _encrypt_mod26(self, text):
        # Letters only; c_i = (p_i + k_i) mod 26. The historical letter form.
        letters = [c for c in text.upper() if c.isalpha()]
        n = len(letters)
        if self.key is not None:
            key_letters = [c for c in self.key.upper() if c.isalpha()]
            if len(key_letters) < n:
                raise ValueError("Key shorter than message -- violates OTP rule.")
        else:
            # random letters
            rnd = self._gen_key_bytes(n)
            key_letters = [chr(b % 26 + ord('A')) for b in rnd]
        self.last_key = ''.join(key_letters[:n])
        ct = []
        for i, ch in enumerate(letters):
            p = ord(ch) - ord('A')
            k = ord(key_letters[i]) - ord('A')
            ct.append(chr((p + k) % 26 + ord('A')))
        ciphertext = ''.join(ct)
        if self.show_steps:
            print(f"\n=== One-Time Pad (mod 26) ===")
            print(f"  plaintext : {''.join(letters)}")
            print(f"  key/pad   : {self.last_key}")
            print(f"  ciphertext: {ciphertext}")
        return ciphertext

    def get_last_key(self):
        # The key must be shared secretly with the recipient (and never
        # reused). Exposed here so the test/decrypt demos can use it.
        return self.last_key

    def show_otp_state(self):
        print(f"One-Time Pad State Information:")
        print(f"  Mode: {self.mode}")
        print(f"  Key source: {'explicit' if self.key is not None else 'random per message'}")
        print(f"  Perfect secrecy requires: random key, length >= message, NEVER reused")
        print(f"  Initialized: {self.initialized}")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'One-Time Pad (Vernam)',
            'mode': self.mode,
            'security': 'perfect secrecy (Shannon 1949) IF used correctly',
            'conditions': 'random key, length >= message, never reused',
            'type': 'stream cipher / additive',
            'initialized': self.initialized}
