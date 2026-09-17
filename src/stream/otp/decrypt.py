#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/stream/otp/decrypt.py'
#   One-Time Pad (Vernam cipher) decryption class
#
#   Two roles:
#     1. LEGITIMATE decryption with the correct pad (XOR again, or subtract
#        mod 26). Trivial and exact.
#     2. The "ATTACK" -- which is really a demonstration of WHY there is no
#        attack when the pad is used correctly, and how catastrophically it
#        fails when it is NOT:
#        a) PERFECT SECRECY: brute-forcing the key produces EVERY possible
#           plaintext of the right length, each equally valid. The attacker
#           gains zero information. We show that the ciphertext can be
#           "decrypted" to any chosen message by some key.
#        b) KEY-REUSE CATASTROPHE: if one pad encrypts two messages, XORing
#           the two ciphertexts cancels the key (c1 ^ c2 = p1 ^ p2), leaking
#           the XOR of the plaintexts -- which is readable. This is the
#           classic "two-time pad" break that has sunk real systems (VENONA).
#
#   Author(s): Lauren Linkous  (with Claude AI for structure/commentary)
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.mode = opt_df['MODE'][0] if (opt_df is not None and 'MODE' in opt_df.columns) else 'xor'
        self.show_steps = opt_df['SHOW_STEPS'][0] if (opt_df is not None and 'SHOW_STEPS' in opt_df.columns) else False
        self.initialized = True

    # ---- legitimate decryption ----

    def decrypt_message(self, ciphertext, key):
        if self.mode == 'xor':
            ct = bytes.fromhex(ciphertext) if isinstance(ciphertext, str) else bytes(ciphertext)
            k = bytes.fromhex(key) if isinstance(key, str) else bytes(key)
            pt = bytes(c ^ kk for c, kk in zip(ct, k))
            try:
                return pt.decode('utf-8')
            except UnicodeDecodeError:
                return pt  # raw bytes if not valid utf-8
        elif self.mode == 'mod26':
            key_letters = [c for c in key.upper() if c.isalpha()]
            out = []
            for i, ch in enumerate(ciphertext.upper()):
                if ch.isalpha():
                    c = ord(ch) - ord('A')
                    kk = ord(key_letters[i]) - ord('A')
                    out.append(chr((c - kk) % 26 + ord('A')))
            return ''.join(out)

    # ---- demonstration a: perfect secrecy ----

    def demonstrate_perfect_secrecy(self, ciphertext, target_plaintext):
        # Show that for ANY target plaintext of the right length, there is a
        # key that "decrypts" the ciphertext to exactly that target. So a
        # brute-force attacker sees every message as possible -- no
        # information is leaked. This is the essence of Shannon's proof.
        print(f"=== One-Time Pad: why brute force is useless ===")
        print(f"  Claim: this ciphertext decrypts to ANY chosen plaintext")
        print(f"  under SOME key. So the attacker learns nothing.\n")
        ct = bytes.fromhex(ciphertext) if isinstance(ciphertext, str) else bytes(ciphertext)
        target = target_plaintext.encode('utf-8')
        if len(target) != len(ct):
            print(f"  (target must match ciphertext length {len(ct)}; "
                  f"got {len(target)})")
            return None
        # The key that maps this ciphertext to the chosen target:
        forged_key = bytes(c ^ t for c, t in zip(ct, target))
        check = self.decrypt_message(ciphertext, forged_key.hex())
        print(f"  chosen target : {target_plaintext!r}")
        print(f"  required key  : {forged_key.hex()}")
        print(f"  decrypt check : {check!r}")
        print(f"  It worked: {check == target_plaintext}")
        print(f"\n  Since SOME key yields every possible message, the")
        print(f"  ciphertext alone cannot favor the true plaintext over any")
        print(f"  other. That is PERFECT SECRECY -- brute force returns the")
        print(f"  entire message space, not the answer.")
        return forged_key

    # ---- demonstration b: the key-reuse catastrophe ----

    def demonstrate_key_reuse(self, ciphertext1, ciphertext2):
        # If the SAME pad encrypted two messages, then
        #   c1 ^ c2 = (p1 ^ k) ^ (p2 ^ k) = p1 ^ p2.
        # The key cancels. p1 ^ p2 is enough to start reading both via
        # crib-dragging. This shows WHY "one-time" is non-negotiable.
        print(f"=== One-Time Pad: the KEY-REUSE catastrophe (two-time pad) ===")
        c1 = bytes.fromhex(ciphertext1) if isinstance(ciphertext1, str) else bytes(ciphertext1)
        c2 = bytes.fromhex(ciphertext2) if isinstance(ciphertext2, str) else bytes(ciphertext2)
        xor = bytes(a ^ b for a, b in zip(c1, c2))
        print(f"  c1 ^ c2 = p1 ^ p2 (the key cancels!): {xor.hex()}")
        print(f"  The attacker now has the XOR of the two plaintexts, with NO")
        print(f"  key involved. With known structure (spaces, common words),")
        print(f"  'crib dragging' peels both messages apart. Reusing a pad")
        print(f"  even ONCE destroys all security -- this is how real systems")
        print(f"  fell (e.g. the VENONA decrypts of reused Soviet pads).")
        return xor

    def brute_force_decrypt(self, ciphertext, length_hint=None):
        # The honest 'attack' summary: there is nothing to brute force when
        # the pad is correct (perfect secrecy). The only breaks come from
        # MISUSE (reuse, non-random keys). Pointers to the two demos above.
        print(f"=== One-Time Pad 'Attack' ===")
        print(f"  Against a CORRECTLY used pad: impossible. Brute force yields")
        print(f"  every possible plaintext (see demonstrate_perfect_secrecy).")
        print(f"  The only real attacks target MISUSE:")
        print(f"    - key reuse  -> demonstrate_key_reuse (two-time pad break)")
        print(f"    - non-random key (e.g. a Vigenere-style repeating 'pad')")
        print(f"      -> then it is just Vigenere; use that decrypt class.")
        return None

    def show_otp_state(self):
        print(f"One-Time Pad Decrypt State Information:")
        print(f"  Mode: {self.mode}")
        print(f"  Correct pad: trivial exact decryption")
        print(f"  Incorrect/abuse: perfect secrecy (no info) or total collapse (reuse)")

    def get_cipher_stats(self):
        return {
            'cipher_name': 'One-Time Pad Decrypt',
            'mode': self.mode,
            'attack_on_correct_use': 'none possible (perfect secrecy)',
            'attack_on_misuse': 'key reuse -> total break',
            'type': 'stream cipher / additive'}
