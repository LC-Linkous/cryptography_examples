#!/usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/asymmetric/rsa/encrypt.py'
#   RSA public-key encryption class (TEXTBOOK RSA - educational only)
#
#   This is the first ASYMMETRIC example in the repo. Unlike the
#   symmetric ciphers (Caesar, RC4, etc.), encryption and decryption
#   use DIFFERENT keys: a public key to encrypt, a private key to decrypt.
#
#   ##  WARNING - TEXTBOOK RSA  ##
#   This implements "textbook" (raw) RSA: m^e mod n, with no padding
#   (no OAEP), deterministic, and using small teaching-sized primes by
#   default. It is correct for showing HOW RSA works and WHY factoring
#   matters, but it is NOT secure for real use. Real RSA needs large
#   primes (>= 2048-bit n) and a padding scheme. See the README.
#   The point of this example is that "the math is right" is NOT the
#   same as "the system is secure."
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np
from math import gcd

# RSA uses arbitrarily large integers. numpy's fixed-width int types
# would overflow, so all the actual RSA math is done with Python's
# native big ints. numpy is imported to stay consistent with the rest
# of the repo (and is used for some display helpers).
np.seterr(all='raise')


class encrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        # Optional parent class
        self.parent = parent

        # RSA works on integers, not character dictionaries.
        # We keep this for compatibility with the framework.
        self.original_dictionary = dictionary

        # Unpack the data frame. While these could be default values, we want
        # them explicitly set in the test cases.
        # P and Q are the two primes. Small by default ON PURPOSE so the
        # attack files can actually break this in front of students.
        self.p = int(opt_df['P'][0]) if 'P' in opt_df.columns else 61
        self.q = int(opt_df['Q'][0]) if 'Q' in opt_df.columns else 53
        # Public exponent. 65537 is the real-world standard; smaller is fine
        # for tiny teaching moduli.
        self.e = int(opt_df['E'][0]) if 'E' in opt_df.columns else 17
        self.output_format = opt_df['OUTPUT_FORMAT'][0] if 'OUTPUT_FORMAT' in opt_df.columns else 'INT'
        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False  # bool

        # Key material, filled in by generate_keypair()
        self.n = None          # modulus (p * q) - this is PUBLIC
        self.phi = None         # Euler's totient - this is SECRET
        self.d = None          # private exponent - this is SECRET
        self.initialized = False  # an extra check for resets

        # Build the keypair on construction so the cipher is ready to use,
        # the same way the symmetric classes are ready after __init__.
        self.generate_keypair()


    def is_prime(self, num):
        # Simple primality check. Fine for the small teaching primes used here.
        # NOT a fast/industrial primality test - see README for how real RSA
        # generates primes (probabilistic tests like Miller-Rabin).
        if num < 2:
            return False
        if num == 2:
            return True
        if num % 2 == 0:
            return False
        # Only need to check odd divisors up to sqrt(num)
        i = 3
        while i * i <= num:
            if num % i == 0:
                return False
            i += 2
        return True


    def mod_inverse(self, a, m):
        # Find d such that (a * d) % m == 1, using the Extended Euclidean
        # Algorithm. This is how we get the private exponent d from e and phi.
        # (Claude AI tidied the variable names in this function; the math is
        #  the standard extended Euclidean algorithm.)

        # Track the coefficients as we go
        old_r, r = a, m
        old_s, s = 1, 0

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_s, s = s, old_s - quotient * s

        # old_r is gcd(a, m); for an inverse to exist it must be 1
        if old_r != 1:
            raise ValueError(
                f"No modular inverse for e={a} mod phi={m} "
                f"(gcd is {old_r}, not 1). Pick a different E.")

        # old_s may be negative; bring it into range [0, m)
        return old_s % m


    def generate_keypair(self):
        # Build the RSA keypair from p and q.
        # Public key  = (e, n)   -> shared with everyone
        # Private key = (d, n)   -> kept secret by the owner

        if not self.is_prime(self.p):
            raise ValueError(f"P={self.p} is not prime. RSA requires two primes.")
        if not self.is_prime(self.q):
            raise ValueError(f"Q={self.q} is not prime. RSA requires two primes.")
        if self.p == self.q:
            raise ValueError("P and Q must be DIFFERENT primes.")

        # n is the modulus. This is public, and breaking RSA comes down to
        # factoring it back into p and q.
        self.n = self.p * self.q

        # phi(n) = (p-1)(q-1). This is SECRET - knowing it is equivalent to
        # knowing the private key, because d is derived from it.
        self.phi = (self.p - 1) * (self.q - 1)

        # e must be coprime with phi for the inverse to exist.
        if gcd(self.e, self.phi) != 1:
            raise ValueError(
                f"E={self.e} is not coprime with phi={self.phi}. "
                f"Pick a different E (common choices: 3, 17, 65537).")

        # d is the private exponent: the modular inverse of e mod phi.
        self.d = self.mod_inverse(self.e, self.phi)

        self.initialized = True

        if self.show_steps:
            print(f"=== RSA Key Generation ===")
            print(f"  Chose primes p = {self.p}, q = {self.q}")
            print(f"  Modulus      n = p*q = {self.n}   (PUBLIC)")
            print(f"  Totient    phi = (p-1)(q-1) = {self.phi}   (SECRET)")
            print(f"  Public exponent  e = {self.e}   (PUBLIC)")
            print(f"  Private exponent d = {self.d}   (SECRET)")
            print(f"  Public key  = ({self.e}, {self.n})")
            print(f"  Private key = ({self.d}, {self.n})")
            # The size of n is what an attacker faces. Spell it out.
            print(f"  Modulus size: {self.n.bit_length()} bits "
                  f"(real RSA uses >= 2048 bits)")

        return {'public': (self.e, self.n), 'private': (self.d, self.n)}


    def encrypt_message(self, text):
        # Encrypt with the PUBLIC key: c = m^e mod n, one integer per character.
        #
        # Textbook RSA encrypts a NUMBER. We turn each character into its
        # code point and encrypt those one at a time. This is simple and
        # readable, but it is exactly why textbook RSA leaks information:
        # the same character always produces the same ciphertext integer
        # (it is deterministic). The decrypt_improved attack discussion
        # picks this apart.

        if not self.initialized:
            self.generate_keypair()

        if isinstance(text, str):
            code_points = [ord(ch) for ch in text]
        else:
            # Assume an iterable of ints already
            code_points = list(text)

        if self.show_steps:
            print(f"\n=== RSA Encryption (c = m^e mod n) ===")
            print(f"Plaintext: '{text}'")
            print(f"Using public key (e={self.e}, n={self.n})")
            print("Char | m (ord) | c = m^e mod n")
            print("-" * 38)

        cipher_ints = []
        for ch, m in zip(text, code_points):
            # Each character's code point MUST be smaller than n, otherwise
            # m^e mod n wraps around and the message can't be recovered.
            if m >= self.n:
                raise ValueError(
                    f"Character {ch!r} has code point {m} >= n ({self.n}). "
                    f"Modulus is too small for this character. Use larger primes.")
            # pow(m, e, n) is Python's fast modular exponentiation.
            c = pow(m, self.e, self.n)
            cipher_ints.append(c)

            if self.show_steps:
                print(f"  {ch!r:4s} | {m:7d} | {c}")

        return self.format_output(cipher_ints)


    def format_output(self, cipher_ints):
        # Companion to the symmetric classes' format_output(). Keeps the
        # multi-format idea so output can be displayed or piped to decrypt.
        if self.output_format == 'INT':
            # Space-separated integers (one per character)
            return ' '.join(str(c) for c in cipher_ints)
        elif self.output_format == 'LIST':
            # Raw Python list of ints (useful for passing to decrypt directly)
            return cipher_ints
        elif self.output_format == 'HEX':
            return ' '.join(format(c, 'x').upper() for c in cipher_ints)
        else:
            # Default to space-separated ints
            return ' '.join(str(c) for c in cipher_ints)


    def get_public_key(self):
        # What an attacker is allowed to know: (e, n) only.
        return (self.e, self.n)


    def show_rsa_state(self):
        # Preview of the cipher's configuration. DEMO purposes only.
        # NOTE: this prints the private values too, which a real system would
        # NEVER expose. We show them here so students can follow the math.
        print(f"RSA State Information:")
        print(f"  Public key  (e, n): ({self.e}, {self.n})")
        print(f"  Initialized: {self.initialized}")
        if self.initialized:
            print(f"  [SECRET] primes p, q: {self.p}, {self.q}")
            print(f"  [SECRET] phi(n): {self.phi}")
            print(f"  [SECRET] private exponent d: {self.d}")
            print(f"  Modulus size: {self.n.bit_length()} bits")
            print(f"  Output format: {self.output_format}")
        else:
            print("  Keypair: Not generated")


    def get_cipher_stats(self):
        # Stats printout for the cipher configuration, matching the symmetric
        # classes' get_cipher_stats() shape.
        stats = {
            'cipher_name': 'RSA (textbook)',
            'public_exponent_e': self.e,
            'modulus_n': self.n,
            'modulus_bits': self.n.bit_length() if self.n else None,
            'output_format': self.output_format,
            'initialized': self.initialized}

        if self.initialized:
            # Included for teaching only - these are the secret values.
            stats['secret_p'] = self.p
            stats['secret_q'] = self.q
            stats['secret_phi'] = self.phi
            stats['secret_d'] = self.d

        return stats


    def demonstrate_determinism(self, sample_text="HELLO"):
        # DEMO ONLY. Shows the textbook-RSA weakness directly: identical
        # plaintext characters encrypt to identical ciphertext integers.
        # This is the hook for the "math is right, system is not secure" lesson.
        print(f"=== RSA Determinism Demonstration ===")
        print(f"Sample text: '{sample_text}'")
        print(f"Watch for repeated characters producing repeated ciphertext:\n")

        # Quiet the per-step encryption printout so the demo stays readable.
        old_show_steps = self.show_steps
        self.show_steps = False
        encrypted = self.encrypt_message(sample_text)
        self.show_steps = old_show_steps

        pieces = encrypted.split() if isinstance(encrypted, str) else encrypted

        for ch, c in zip(sample_text, pieces):
            print(f"  {ch!r} -> {c}")

        print(f"\nNotice: every repeated letter maps to the SAME number.")
        print(f"That means an attacker can spot patterns WITHOUT factoring n.")
        print(f"Real RSA adds randomized padding (OAEP) to prevent exactly this.")
