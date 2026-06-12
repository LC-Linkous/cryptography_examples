#!/usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/ecdh/encrypt.py'
#   Elliptic-Curve Diffie-Hellman key exchange (TEACHING-SIZED curve)
#
#   This is the second ASYMMETRIC example, and a companion to RSA.
#   RSA's security rests on factoring being hard; ECDH's rests on the
#   ELLIPTIC-CURVE DISCRETE LOG problem being hard: given a base point G
#   and a public point P = k*G, recovering the secret scalar k is
#   infeasible once the curve is large enough.
#
#   ECDH is a KEY EXCHANGE, not a message cipher. Two parties each pick a
#   private scalar, derive a public point, swap public points, and each
#   computes the SAME shared secret WITHOUT ever transmitting it. This
#   "encrypt" class plays the role of the exchange: it builds the curve,
#   makes keypairs, and derives the shared secret.
#
#   ##  WARNING - TEACHING CURVE  ##
#   The curve here uses a tiny prime field so the decrypt attack files can
#   actually solve the discrete log in front of a class. Real ECDH uses
#   curves like Curve25519 with ~256-bit fields. The point of this example
#   is to make the group law and the exchange VISIBLE, not to be secure.
#
#   Author(s): Lauren Linkous
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import numpy as np

# All curve arithmetic is over a prime field, so it stays in Python ints.
# numpy is imported for consistency with the rest of the repo.
np.seterr(all='raise')


class encrypt:

    def __init__(self, dictionary=None, opt_df=None, parent=None):

        # Optional parent class
        self.parent = parent

        # ECDH works on curve points, not character dictionaries.
        # Kept for compatibility with the framework.
        self.original_dictionary = dictionary

        # Unpack the data frame. The curve is y^2 = x^3 + a*x + b (mod p).
        # Defaults are a small, well-behaved teaching curve.
        #   Curve:  y^2 = x^3 + 2x + 2  (mod 17)
        #   Base point G = (5, 1), which generates a group of order 19.
        # These are the classic textbook values used in many courses.
        self.a = int(opt_df['A'][0]) if 'A' in opt_df.columns else 2
        self.b = int(opt_df['B'][0]) if 'B' in opt_df.columns else 2
        self.p = int(opt_df['P'][0]) if 'P' in opt_df.columns else 17
        gx = int(opt_df['GX'][0]) if 'GX' in opt_df.columns else 5
        gy = int(opt_df['GY'][0]) if 'GY' in opt_df.columns else 1
        self.G = (gx, gy)

        # Private scalars for the two parties (Alice and Bob). In a real
        # exchange these are randomly chosen; we let the test cases set them
        # explicitly so results are reproducible.
        self.priv_a = int(opt_df['PRIV_A'][0]) if 'PRIV_A' in opt_df.columns else 3
        self.priv_b = int(opt_df['PRIV_B'][0]) if 'PRIV_B' in opt_df.columns else 7

        self.show_steps = opt_df['SHOW_STEPS'][0] if 'SHOW_STEPS' in opt_df.columns else False  # bool

        # Derived public material, filled in by run_exchange()
        self.pub_a = None     # Alice's public point = priv_a * G
        self.pub_b = None     # Bob's public point   = priv_b * G
        self.shared = None    # the agreed shared secret point
        self.initialized = False

        # Validate the curve and base point up front.
        self.validate_curve()


    def validate_curve(self):
        # A curve is non-singular (usable) when 4a^3 + 27b^2 != 0 (mod p).
        # Also confirm the base point G actually lies on the curve.
        discriminant = (4 * self.a**3 + 27 * self.b**2) % self.p
        if discriminant == 0:
            raise ValueError(
                f"Singular curve: 4a^3 + 27b^2 = 0 (mod {self.p}). "
                f"Pick different a, b.")
        if not self.is_on_curve(self.G):
            raise ValueError(
                f"Base point G={self.G} is not on the curve "
                f"y^2 = x^3 + {self.a}x + {self.b} (mod {self.p}).")
        self.initialized = True


    def is_on_curve(self, point):
        # The point at infinity (None) is always "on" the curve - it is the
        # group's identity element.
        if point is None:
            return True
        x, y = point
        return (y * y - (x**3 + self.a * x + self.b)) % self.p == 0


    def inverse_mod(self, k, p):
        # Modular inverse via Fermat's little theorem (p is prime here):
        #   k^(p-2) mod p  is the inverse of k mod p.
        # Used in the slope calculations of the group law.
        if k % p == 0:
            raise ZeroDivisionError("Division by zero in modular inverse.")
        return pow(k % p, p - 2, p)


    def point_add(self, point1, point2):
        # The ELLIPTIC-CURVE GROUP LAW. Adding two points geometrically:
        # draw a line through them, find the third intersection with the
        # curve, and reflect it over the x-axis. Over a prime field this
        # becomes the modular formulas below.
        # (Claude AI helped tidy the case handling; the formulas are the
        #  standard short-Weierstrass group law.)

        # Identity element: P + O = P
        if point1 is None:
            return point2
        if point2 is None:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        # P + (-P) = O  (the point at infinity). -P is (x, -y).
        if x1 == x2 and (y1 + y2) % self.p == 0:
            return None

        if x1 == x2 and y1 == y2:
            # POINT DOUBLING: slope is the tangent (3x^2 + a) / (2y)
            numerator = (3 * x1 * x1 + self.a) % self.p
            denominator = self.inverse_mod((2 * y1) % self.p, self.p)
            slope = (numerator * denominator) % self.p
        else:
            # POINT ADDITION: slope of the line through the two points
            numerator = (y2 - y1) % self.p
            denominator = self.inverse_mod((x2 - x1) % self.p, self.p)
            slope = (numerator * denominator) % self.p

        x3 = (slope * slope - x1 - x2) % self.p
        y3 = (slope * (x1 - x3) - y1) % self.p
        return (x3, y3)


    def scalar_mult(self, k, point):
        # Compute k*point by the DOUBLE-AND-ADD method (the additive analogue
        # of fast modular exponentiation). This is the cheap direction.
        # The whole security of ECDH is that going BACKWARD - recovering k
        # from k*point - has no comparably cheap method.

        result = None        # start at the identity (point at infinity)
        addend = point

        while k:
            if k & 1:
                result = self.point_add(result, addend)
            addend = self.point_add(addend, addend)  # double
            k >>= 1

        return result


    def derive_public(self, private_scalar):
        # A party's public key is private_scalar * G.
        return self.scalar_mult(private_scalar, self.G)


    def run_exchange(self):
        # The full ECDH handshake.
        #   Alice: priv_a (secret) -> pub_a = priv_a * G (public)
        #   Bob:   priv_b (secret) -> pub_b = priv_b * G (public)
        # They swap public points, then:
        #   Alice computes priv_a * pub_b
        #   Bob   computes priv_b * pub_a
        # Both equal (priv_a * priv_b) * G - the SHARED SECRET - even though
        # neither secret scalar ever crossed the wire.

        if self.show_steps:
            print(f"=== ECDH Key Exchange ===")
            print(f"  Curve: y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})")
            print(f"  Base point G = {self.G}")
            print(f"  Field size p = {self.p} "
                  f"(~{self.p.bit_length()} bits; real ECDH uses ~256)")
            print()

        # Each party derives their public point
        self.pub_a = self.derive_public(self.priv_a)
        self.pub_b = self.derive_public(self.priv_b)

        if self.show_steps:
            print(f"  Alice: private a = {self.priv_a} (SECRET)")
            print(f"         public  A = a*G = {self.pub_a}")
            print(f"  Bob:   private b = {self.priv_b} (SECRET)")
            print(f"         public  B = b*G = {self.pub_b}")
            print(f"  --- public points A and B are exchanged over the wire ---")

        # Each computes the shared secret from the OTHER's public point
        alice_secret = self.scalar_mult(self.priv_a, self.pub_b)
        bob_secret = self.scalar_mult(self.priv_b, self.pub_a)

        if self.show_steps:
            print(f"  Alice computes a*B = {alice_secret}")
            print(f"  Bob   computes b*A = {bob_secret}")
            print(f"  Shared secrets match: {alice_secret == bob_secret}")

        # They are equal by construction; store the agreed value.
        if alice_secret != bob_secret:
            raise RuntimeError(
                "Shared secrets did not match - check curve/base point order.")

        self.shared = alice_secret
        return self.shared


    def encrypt_message(self, text=None):
        # ECDH does not encrypt messages directly - it agrees on a shared
        # secret. We keep this method name for framework consistency: it runs
        # the exchange and returns the shared secret point. In practice the
        # shared secret would then key a symmetric cipher (e.g. one of the
        # stream ciphers elsewhere in this repo).
        secret = self.run_exchange()

        if self.show_steps and text is not None:
            print(f"\n  (In real use, the shared secret would now key a "
                  f"symmetric cipher to protect '{text}'.)")

        return secret


    def list_all_points(self):
        # Enumerate every point on the curve. Only feasible because the field
        # is tiny - that smallness is exactly what the attack files exploit.
        # Great for showing students the whole finite group at once.
        points = [None]  # the point at infinity
        for x in range(self.p):
            for y in range(self.p):
                if (y * y - (x**3 + self.a * x + self.b)) % self.p == 0:
                    points.append((x, y))
        return points


    def show_curve_state(self):
        # Preview of the curve configuration. DEMO purposes only.
        print(f"ECDH Curve State Information:")
        print(f"  Curve: y^2 = x^3 + {self.a}x + {self.b} (mod {self.p})")
        print(f"  Base point G: {self.G}")
        print(f"  Field size p: {self.p} ({self.p.bit_length()} bits)")
        print(f"  Initialized: {self.initialized}")
        if self.shared is not None:
            print(f"  [SECRET] Alice private: {self.priv_a}")
            print(f"  [SECRET] Bob private:   {self.priv_b}")
            print(f"  Alice public A: {self.pub_a}")
            print(f"  Bob public B:   {self.pub_b}")
            print(f"  Shared secret:  {self.shared}")


    def get_cipher_stats(self):
        # Stats printout matching the shape used elsewhere in the repo.
        total_points = len(self.list_all_points())
        stats = {
            'cipher_name': 'ECDH (teaching curve)',
            'curve': f'y^2 = x^3 + {self.a}x + {self.b} mod {self.p}',
            'base_point_G': self.G,
            'field_prime_p': self.p,
            'field_bits': self.p.bit_length(),
            'total_curve_points': total_points,
            'initialized': self.initialized}

        if self.shared is not None:
            # Teaching only - these are the secret values.
            stats['secret_priv_a'] = self.priv_a
            stats['secret_priv_b'] = self.priv_b
            stats['public_A'] = self.pub_a
            stats['public_B'] = self.pub_b
            stats['shared_secret'] = self.shared

        return stats
