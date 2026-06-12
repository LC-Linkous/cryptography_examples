#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/asymmetric/ecdh/encrypt_test.py'
#   Some (mostly) AI generated test cases, for fun.
#   Claude also added some additional commentary, which is neat.
#
#   ECDH is a KEY EXCHANGE, so this test shows two parties agreeing on a
#   shared secret over a public channel - not a message being encrypted.
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd

from asymmetric.ECDH.encrypt import encrypt


print("=== ECDH Key Exchange Educational Example ===")
print("(TEACHING CURVE - educational only, NOT secure for real use)")

# Different exchanges on the classic teaching curve y^2 = x^3 + 2x + 2 (mod 17).
# Private scalars are set explicitly so results are reproducible.
configurations = [
    {
        'name': 'ECDH Classic (a=3, b=7)',
        'A': [2], 'B': [2], 'P': [17], 'GX': [5], 'GY': [1],
        'PRIV_A': [3], 'PRIV_B': [7],
        'SHOW_STEPS': [False]
    },
    {
        'name': 'ECDH Step-by-Step',
        'A': [2], 'B': [2], 'P': [17], 'GX': [5], 'GY': [1],
        'PRIV_A': [3], 'PRIV_B': [7],
        'SHOW_STEPS': [True]
    },
    {
        'name': 'ECDH Different Secrets (a=9, b=14)',
        'A': [2], 'B': [2], 'P': [17], 'GX': [5], 'GY': [1],
        'PRIV_A': [9], 'PRIV_B': [14],
        'SHOW_STEPS': [False]
    },
]

for config in configurations:
    print(f"\n{'='*70}")
    print(f"CONFIGURATION: {config['name']}")
    print('='*70)

    options = pd.DataFrame(config)
    cipher = encrypt(None, options)

    # Run the exchange (this fills in the public points and shared secret)
    cipher.encrypt_message()

    cipher.show_curve_state()

    stats = cipher.get_cipher_stats()
    print(f"\nECDH Statistics:")
    for key, value in stats.items():
        print(f"  {key}: {value}")

print(f"\n{'='*70}")
print("ECDH EDUCATIONAL DEMONSTRATIONS")
print('='*70)

# Show the whole finite group of points on the curve.
demo = encrypt(None, pd.DataFrame({
    'A': [2], 'B': [2], 'P': [17], 'GX': [5], 'GY': [1],
    'PRIV_A': [3], 'PRIV_B': [7], 'SHOW_STEPS': [False]
}))

print("\n1. Every point on the curve (the finite group):")
points = demo.list_all_points()
print(f"   Total: {len(points)} points (including the point at infinity)")
for pt in points:
    label = "O (infinity)" if pt is None else pt
    print(f"     {label}")

print("\n2. The base point G generates the group (k*G cycles):")
for k in range(1, len(points) + 2):
    pt = demo.scalar_mult(k, demo.G)
    label = "O (back to infinity - full cycle!)" if pt is None else pt
    print(f"     {k:2d}*G = {label}")

print(f"\n{'='*70}")
print("ECDH EDUCATIONAL SUMMARY")
print('='*70)
print("""
ECDH OVERVIEW:

1. PUBLIC SETUP (everyone agrees on these):
    - A curve  y^2 = x^3 + a*x + b  (mod p)
    - A base point G on that curve

2. THE EXCHANGE (this is what makes it asymmetric):
    - Alice picks secret a, publishes A = a*G
    - Bob   picks secret b, publishes B = b*G
    - Alice computes a*B,  Bob computes b*A
    - Both equal (a*b)*G = the SHARED SECRET
    - The secret scalars a and b NEVER cross the wire

3. WHY IT IS HARD TO BREAK:
    - An eavesdropper sees G, A, and B
    - To get a from A = a*G they must solve the DISCRETE LOG problem
    - On a large curve there is no efficient way to do this

KEY PROPERTIES:
    - No shared secret needed in advance
    - Security rests on the elliptic-curve discrete log problem (ECDLP)
    - Much smaller keys than RSA for comparable strength

SECURITY WARNING (TEACHING CURVE):
    - Tiny field (p=17): the discrete log is brute-forceable - see decrypt.py
    - Real ECDH uses curves like Curve25519 over ~256-bit fields
    - 'The math is right' is NOT 'the system is secure'

HISTORICAL CONTEXT:
    - Diffie-Hellman key exchange: 1976 (over integers mod p)
    - Elliptic-curve variant: mid-1980s (Koblitz, Miller)
    - Now the backbone of modern TLS key agreement

COMPANION TO RSA:
    - RSA security  = factoring is hard
    - ECDH security = discrete log is hard
    - Together they are the two pillars of classical public-key crypto
""")
