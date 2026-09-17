#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/hashing/sha256/analysis.py'
#   SHA-256 property analysis (educational)
#
#   A hash has no key and no decryption, so there is no 'decrypt' attack
#   like the ciphers have. Instead this file - in the spirit of the
#   ChaCha20 'alg_analysis.py' - DEMONSTRATES the properties that make
#   SHA-256 useful and shows WHY reversing it is infeasible. It analyzes;
#   it does not break.
#
#   Three demonstrations:
#     1. AVALANCHE EFFECT: flipping one input bit changes ~half the output
#        bits. This is what makes the output look random and unrelated to
#        the input.
#     2. DETERMINISM + SENSITIVITY: same input -> same digest, always;
#        the tiniest change -> a completely different digest.
#     3. PREIMAGE / BRUTE-FORCE COST: why trying to find an input for a
#        given digest, or two inputs with the same digest, is hopeless.
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
import pandas as pd
import time

from hash import hash

np.seterr(all='raise')


class analysis:

    def __init__(self, dictionary=None, opt_df=None, parent=None):
        self.parent = parent
        self.original_dictionary = dictionary
        self.show_steps = False
        if opt_df is not None and 'SHOW_STEPS' in opt_df.columns:
            self.show_steps = opt_df['SHOW_STEPS'][0]

        # Use the real hash implementation for all analysis.
        self.hasher = hash(None, pd.DataFrame({
            'SHOW_STEPS': [False], 'OUTPUT_FORMAT': ['BYTES']
        }))


    def _digest_bits(self, text):
        # Return the digest of text as a flat list of 256 bits.
        digest = self.hasher.hash_message(text)
        bits = []
        for byte in digest:
            for i in range(7, -1, -1):
                bits.append((byte >> i) & 1)
        return bits


    def hamming_distance(self, bits1, bits2):
        # Count the positions where two equal-length bit lists differ.
        return sum(b1 != b2 for b1, b2 in zip(bits1, bits2))


    # --- DEMONSTRATION 1: AVALANCHE EFFECT ---

    def demonstrate_avalanche(self, base_text="The quick brown fox", trials=20):
        # Flip a single character in the input and measure how many of the
        # 256 output bits change. A good hash changes about HALF (~128).

        print(f"=== Avalanche Effect Demonstration ===")
        print(f"Base input: {base_text!r}")
        base_bits = self._digest_bits(base_text)
        print(f"Base digest: {self.hasher.hash_message(base_text).hex()}")
        print()
        print(f"Flipping one character at a time and counting changed bits")
        print(f"(out of 256). A strong hash changes ~128 (~50%).")
        print("-" * 60)

        distances = []
        text_list = list(base_text)
        n = min(trials, len(text_list))
        for i in range(n):
            modified = list(base_text)
            # Flip the lowest bit of one character's code point.
            modified[i] = chr(ord(modified[i]) ^ 0x01)
            modified_text = ''.join(modified)
            mod_bits = self._digest_bits(modified_text)
            dist = self.hamming_distance(base_bits, mod_bits)
            distances.append(dist)
            pct = 100.0 * dist / 256
            print(f"  change char {i:2d} ({base_text[i]!r}->{modified[i]!r}): "
                  f"{dist:3d}/256 bits differ ({pct:5.1f}%)")

        avg = sum(distances) / len(distances)
        print("-" * 60)
        print(f"  Average bits changed: {avg:.1f}/256 ({100.0*avg/256:.1f}%)")
        print(f"  Ideal is ~128 (50%). Close to that = strong diffusion.")
        return avg


    # --- DEMONSTRATION 2: DETERMINISM + SENSITIVITY ---

    def demonstrate_sensitivity(self):
        # Same input always hashes the same; near-identical inputs hash to
        # totally unrelated digests. This is what makes a hash a reliable
        # 'fingerprint' for verification.

        print(f"=== Determinism & Sensitivity Demonstration ===")

        # Determinism: repeat the same input.
        text = "verify me"
        d1 = self.hasher.hash_message(text).hex()
        d2 = self.hasher.hash_message(text).hex()
        print(f"  Same input twice:")
        print(f"    {text!r} -> {d1[:32]}...")
        print(f"    {text!r} -> {d2[:32]}...")
        print(f"    Identical: {d1 == d2}  (a hash is DETERMINISTIC)")
        print()

        # Sensitivity: tiny variations.
        print(f"  Tiny changes produce unrelated digests:")
        variants = ["password", "Password", "password ", "passw0rd"]
        for v in variants:
            print(f"    {v!r:14s} -> {self.hasher.hash_message(v).hex()[:32]}...")
        print(f"  No visible relationship between these - that is the point.")


    # --- DEMONSTRATION 3: PREIMAGE / BRUTE-FORCE COST ---

    def demonstrate_preimage_cost(self, prefix_bits=16, max_attempts=2_000_000):
        # We CANNOT reverse SHA-256. To show why, we attempt a tiny version
        # of a preimage search: find any input whose digest starts with a
        # given run of zero bits. Matching just a FEW bits already takes many
        # attempts; matching all 256 (a true preimage) is 2^256 - impossible.

        print(f"=== Preimage Brute-Force Cost Demonstration ===")
        print(f"There is no 'decrypt' for a hash. The only way to find an")
        print(f"input for a target digest is to GUESS inputs and hash them.")
        print()
        print(f"Mini-demo: find an input whose digest starts with "
              f"{prefix_bits} zero bits.")
        print(f"  Expected attempts ~ 2^{prefix_bits} = {2**prefix_bits:,}")
        print("-" * 60)

        target_zero_bytes = prefix_bits // 8
        start = time.time()
        found = None
        for attempt in range(max_attempts):
            candidate = f"nonce_{attempt}"
            digest = self.hasher.hash_message(candidate)
            # Check whether the first prefix_bits bits are zero.
            leading_ok = all(digest[b] == 0 for b in range(target_zero_bytes))
            if leading_ok:
                found = (candidate, digest, attempt + 1)
                break

        elapsed = time.time() - start
        if found:
            candidate, digest, attempts = found
            print(f"  FOUND after {attempts:,} attempts in {elapsed:.3f}s")
            print(f"    input:  {candidate!r}")
            print(f"    digest: {digest.hex()}")
        else:
            print(f"  No match in {max_attempts:,} attempts ({elapsed:.3f}s)")

        print("-" * 60)
        print(f"  Now scale up: a FULL preimage matches all 256 bits.")
        print(f"  That is 2^256 ~ 1.2e77 attempts - more than the number of")
        print(f"  atoms in the observable universe. THIS is why a hash is")
        print(f"  called one-way: forward is instant, backward is impossible.")
        return found


    def demonstrate_collision_cost(self):
        # DEMO ONLY (explanatory): the birthday bound. Finding ANY two inputs
        # with the same digest is easier than a targeted preimage, but for
        # SHA-256 it is still ~2^128 - far beyond reach.
        print(f"=== Collision Cost (the Birthday Bound) ===")
        print(f"  A 'collision' is any two different inputs with the SAME")
        print(f"  digest. By the birthday paradox, the effort is about")
        print(f"  sqrt(2^256) = 2^128 attempts - not 2^256, but still")
        print(f"  astronomically infeasible (~3.4e38).")
        print(f"  This sqrt gap is why digest SIZE must be generous: a")
        print(f"  128-bit hash would have only ~2^64 collision resistance,")
        print(f"  which modern hardware can threaten. 256 bits keeps the")
        print(f"  birthday bound comfortably out of reach.")


    def get_cipher_stats(self):
        return {
            'cipher_name': 'SHA-256 Analysis',
            'preimage_resistance_bits': 256,
            'collision_resistance_bits': 128,
            'avalanche_target_pct': 50}
