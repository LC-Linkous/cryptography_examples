#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/rsa/decrypt.py'
#   RSA decryption class (TEXTBOOK RSA - educational only)
#
#   This file does TWO things, which is the whole lesson of RSA:
#
#   1. LEGITIMATE decryption: if you hold the private key (d, n), you
#      recover the message instantly with m = c^d mod n.
#
#   2. The ATTACK: if you only have the PUBLIC key (e, n) and the
#      ciphertext - like a real eavesdropper - the only way in is to
#      FACTOR n back into its primes p and q. This file's brute force
#      does that the naive way: trial division. Watch it scale.
#
#   This mirrors the symmetric decrypt classes, where the "attack" tries
#   to recover the shared key. Here the attack recovers the PRIVATE key
#   by factoring. The 'decrypt_improved.py' file uses smarter factoring
#   (Fermat, Pollard's rho) for comparison.
#
#   ##  WARNING - TEXTBOOK RSA  ##  see encrypt.py and the README.
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
import time
from math import gcd, isqrt

np.seterr(all='raise')


class decrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        # Optional parent class
        self.parent = parent

        # RSA works on integers, not character dictionaries.
        self.original_dictionary = dictionary

        # Unpack the data frame.
        # The PUBLIC key is what an attacker always has. n is required;
        # e defaults to the common 65537-ish teaching value if not given.
        self.n = int(opt_df['N'][0]) if 'N' in opt_df.columns else None
        self.e = int(opt_df['E'][0]) if 'E' in opt_df.columns else 17
        # d is the PRIVATE exponent. Only the legitimate owner has it.
        # Left as None for the attacker case.
        self.d = int(opt_df['D'][0]) if 'D' in opt_df.columns else None
        self.input_format = opt_df['INPUT_FORMAT'][0] if 'INPUT_FORMAT' in opt_df.columns else 'INT'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False

        # Filled in if/when an attack succeeds in factoring n
        self.recovered_p = None
        self.recovered_q = None
        self.recovered_d = None


    def parse_ciphertext(self, ciphertext):
        # Companion to encrypt.format_output(). Turn the transmitted form
        # back into a list of integers (one per character).
        if isinstance(ciphertext, list):
            return [int(c) for c in ciphertext]

        if self.input_format == 'INT':
            return [int(tok) for tok in ciphertext.split()]
        elif self.input_format == 'HEX':
            return [int(tok, 16) for tok in ciphertext.split()]
        else:
            return [int(tok) for tok in ciphertext.split()]


    def mod_inverse(self, a, m):
        # Extended Euclidean Algorithm - identical to the encrypt class.
        # Needed to rebuild d once an attack has recovered phi.
        old_r, r = a, m
        old_s, s = 1, 0
        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s
        if old_r != 1:
            raise ValueError(f"No modular inverse for {a} mod {m}.")
        return old_s % m


    # -----------------------------------------------------------------\
    #   ROLE 1: LEGITIMATE DECRYPTION (you hold the private key)
    # -----------------------------------------------------------------/

    def decrypt_message(self, ciphertext, d=None, n=None):
        # Recover plaintext with the private key: m = c^d mod n.
        # Instant when you legitimately know d. This is the easy direction.

        actual_d = d if d is not None else self.d
        actual_n = n if n is not None else self.n

        if actual_d is None or actual_n is None:
            raise ValueError(
                "Legitimate decryption needs the private exponent d and "
                "modulus n. If you only have the public key, use an attack "
                "method (brute_force_decrypt) instead.")

        cipher_ints = self.parse_ciphertext(ciphertext)

        if self.show_steps:
            print(f"\n=== RSA Decryption (m = c^d mod n) ===")
            print(f"Using private key (d={actual_d}, n={actual_n})")
            print("c           | m = c^d mod n | char")
            print("-" * 40)

        chars = []
        for c in cipher_ints:
            m = pow(c, actual_d, actual_n)
            ch = chr(m)
            chars.append(ch)
            if self.show_steps:
                print(f"  {c:<10d} | {m:>11d}   | {ch!r}")

        return ''.join(chars)


    # -----------------------------------------------------------------\
    #   ROLE 2: THE ATTACK (you only have the public key + ciphertext)
    # -----------------------------------------------------------------/

    def brute_force_decrypt(self, ciphertext, n=None, e=None, max_seconds=None):
        # The naive attack: FACTOR n by trial division.
        #
        # An attacker has (e, n) and the ciphertext but NOT d. To get d they
        # need phi = (p-1)(q-1), which needs p and q, which means factoring n.
        # Trial division just tests candidate divisors one at a time.
        #
        # This is deliberately the "dumb" method so students can watch the
        # operation count explode as n grows. decrypt_improved.py is smarter.

        actual_n = n if n is not None else self.n
        actual_e = e if e is not None else self.e

        if actual_n is None:
            raise ValueError("Need the public modulus n to attempt factoring.")

        print(f"=== Brute-Force Attack: factoring n = {actual_n} ===")
        print(f"  Public key in hand: (e={actual_e}, n={actual_n})")
        print(f"  Modulus size: {actual_n.bit_length()} bits")
        print(f"  Method: trial division (the naive approach)")
        print(f"  We only need to test up to sqrt(n) = {isqrt(actual_n)}")
        print("-" * 60)

        start = time.time()
        operations = 0
        found_p = None

        # Handle the even case first (real RSA primes are odd, but be safe)
        candidate = 2
        if actual_n % 2 == 0:
            found_p = 2
        else:
            # Step through odd candidates up to sqrt(n)
            candidate = 3
            limit = isqrt(actual_n)
            while candidate <= limit:
                operations += 1
                if actual_n % candidate == 0:
                    found_p = candidate
                    break
                candidate += 2

                # Optional time budget so a huge n doesn't hang a class demo
                if max_seconds is not None and (operations % 100000 == 0):
                    if time.time() - start > max_seconds:
                        elapsed = time.time() - start
                        print(f"  GAVE UP after {operations:,} trial divisions "
                              f"({elapsed:.2f}s, exceeded {max_seconds}s budget).")
                        print(f"  This is the point: big enough n makes this hopeless.")
                        return "Attack abandoned - n too large to factor naively"

        elapsed = time.time() - start

        if found_p is None:
            print(f"  No factor found - n may be prime (not a valid RSA modulus).")
            return "Attack failed - no factor found"

        found_q = actual_n // found_p
        print(f"  FACTORED after {operations:,} trial divisions in {elapsed:.4f}s")
        print(f"  Recovered primes: p = {found_p}, q = {found_q}")

        # Now reconstruct the private key from the recovered primes.
        recovered_phi = (found_p - 1) * (found_q - 1)
        if gcd(actual_e, recovered_phi) != 1:
            print(f"  Recovered phi not coprime with e - unexpected; aborting.")
            return "Attack failed - key reconstruction error"

        recovered_d = self.mod_inverse(actual_e, recovered_phi)
        self.recovered_p = found_p
        self.recovered_q = found_q
        self.recovered_d = recovered_d

        print(f"  Rebuilt phi(n) = {recovered_phi}")
        print(f"  Rebuilt PRIVATE exponent d = {recovered_d}")
        print(f"  The private key is now fully recovered. Decrypting...")
        print("-" * 60)

        # Decrypt with the recovered private key.
        recovered_message = self.decrypt_message(ciphertext, d=recovered_d, n=actual_n)
        print(f"  RECOVERED MESSAGE: '{recovered_message}'")
        return recovered_message


    def estimate_attack_cost(self, n=None):
        # DEMO ONLY. Doesn't attack - just reports the scale of the problem,
        # so students see why bit-length is everything. Trial division needs
        # roughly sqrt(n) operations in the worst case.
        actual_n = n if n is not None else self.n
        if actual_n is None:
            raise ValueError("Need n to estimate attack cost.")

        worst_case_ops = isqrt(actual_n)
        print(f"=== Trial-Division Cost Estimate for n = {actual_n} ===")
        print(f"  Modulus size: {actual_n.bit_length()} bits")
        print(f"  Worst-case trial divisions ~ sqrt(n) = {worst_case_ops:,}")

        # Pretend a generous billion operations per second.
        ops_per_sec = 1_000_000_000
        seconds = worst_case_ops / ops_per_sec
        if seconds < 1:
            print(f"  At ~1e9 ops/sec: under a second. TRIVIALLY breakable.")
        elif seconds < 3600:
            print(f"  At ~1e9 ops/sec: about {seconds:.1f} seconds.")
        elif seconds < 86400 * 365:
            print(f"  At ~1e9 ops/sec: about {seconds/86400:.1f} days.")
        else:
            years = seconds / (86400 * 365)
            print(f"  At ~1e9 ops/sec: about {years:.2e} years. Effectively safe")
            print(f"  (and real 2048-bit moduli are FAR beyond even this).")
        return worst_case_ops


    def show_rsa_state(self):
        # Preview of what the attacker/decryptor currently knows. DEMO only.
        print(f"RSA Decrypt State Information:")
        print(f"  Public modulus n: {self.n}")
        print(f"  Public exponent e: {self.e}")
        print(f"  Private exponent d: "
              f"{'(known - legitimate)' if self.d is not None else '(unknown - attacker)'}")
        print(f"  Input format: {self.input_format}")
        if self.recovered_d is not None:
            print(f"  [ATTACK SUCCEEDED] recovered p={self.recovered_p}, "
                  f"q={self.recovered_q}, d={self.recovered_d}")


    def get_cipher_stats(self):
        # Matches the shape of the symmetric classes' get_cipher_stats().
        stats = {
            'cipher_name': 'RSA Decrypt (textbook)',
            'modulus_n': self.n,
            'modulus_bits': self.n.bit_length() if self.n else None,
            'public_exponent_e': self.e,
            'has_private_key': self.d is not None,
            'input_format': self.input_format}

        if self.recovered_d is not None:
            stats['attack_recovered_p'] = self.recovered_p
            stats['attack_recovered_q'] = self.recovered_q
            stats['attack_recovered_d'] = self.recovered_d

        return stats
