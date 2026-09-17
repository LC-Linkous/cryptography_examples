#! /usr/bin/python3

##--------------------------------------------------------------------\
#   cryptography_examples
#   './cryptography_examples/src/asymmetric/rsa/decrypt_improved_test.py'
#   Some (mostly) AI generated test cases, for fun.
#
#   This compares the NAIVE attack (decrypt.py, trial division) against
#   the SMART attacks (decrypt_improved.py: Fermat and Pollard's rho).
#   The iteration counts tell the story.
#
#   There are several group questions that come out of this file - e.g.
#   "why does Fermat finish in 1 step for one modulus and crawl for
#    another?" (Answer: how close together p and q are.)
#
#   Last update: June 02, 2026
##--------------------------------------------------------------------\

import pandas as pd
from encrypt import encrypt
from decrypt import decrypt
from decrypt_improved import decrypt_improved


print("=== RSA Smart-Attack Comparison ===")
print("(TEXTBOOK RSA - educational only)")

# Two scenarios that produce very different attack behavior:
#   A) primes CLOSE together  -> Fermat wins instantly (a security lesson)
#   B) primes FAR apart       -> Fermat struggles, Pollard's rho wins
scenarios = [
    {'name': 'Primes CLOSE together', 'plaintext': 'RSA', 'P': 10007, 'Q': 10037, 'E': 17},
    {'name': 'Primes FAR apart',      'plaintext': 'RSA', 'P': 1009,  'Q': 99991, 'E': 17},
]

for sc in scenarios:
    enc = encrypt(None, pd.DataFrame({
        'P': [sc['P']], 'Q': [sc['Q']], 'E': [sc['E']],
        'OUTPUT_FORMAT': ['INT'], 'SHOW_STEPS': [False]
    }))
    stats = enc.get_cipher_stats()
    sc['ciphertext'] = enc.encrypt_message(sc['plaintext'])
    sc['n'] = stats['modulus_n']

print()
for sc in scenarios:
    print(f"\n{'#'*70}")
    print(f"# SCENARIO: {sc['name']}")
    print(f"#   n = {sc['n']} ({sc['n'].bit_length()} bits), "
          f"p={sc['P']}, q={sc['Q']}")
    print('#'*70)

    # --- Naive: trial division ---
    print(f"\n>>> NAIVE trial division (decrypt.py)")
    naive = decrypt(None, pd.DataFrame({
        'N': [sc['n']], 'E': [sc['E']], 'INPUT_FORMAT': ['INT'], 'SHOW_STEPS': [False]
    }))
    r_naive = naive.brute_force_decrypt(sc['ciphertext'])

    # --- Smart: Fermat ---
    print(f"\n>>> SMART Fermat (decrypt_improved.py)")
    fermat = decrypt_improved(None, pd.DataFrame({
        'N': [sc['n']], 'E': [sc['E']], 'METHOD': ['FERMAT'],
        'INPUT_FORMAT': ['INT'], 'SHOW_STEPS': [False]
    }))
    r_fermat = fermat.brute_force_decrypt(sc['ciphertext'])

    # --- Smart: Pollard's rho ---
    print(f"\n>>> SMART Pollard's rho (decrypt_improved.py)")
    pollard = decrypt_improved(None, pd.DataFrame({
        'N': [sc['n']], 'E': [sc['E']], 'METHOD': ['POLLARD'],
        'INPUT_FORMAT': ['INT'], 'SHOW_STEPS': [False]
    }))
    r_pollard = pollard.brute_force_decrypt(sc['ciphertext'])

    all_ok = (r_naive == r_fermat == r_pollard == sc['plaintext'])
    print(f"\n  All methods recovered '{sc['plaintext']}': {all_ok}")

print(f"\n{'='*60}")
print("SMART-ATTACK SUMMARY")
print('='*60)
print("""
WHAT THE COMPARISON SHOWS:

1. ALL methods break our tiny moduli - the question is HOW HARD they work.

2. FERMAT'S METHOD:
    - Near-instant when p and q are CLOSE together
    - This is a real security rule: never pick primes near each other,
      or sqrt(n)-style protection evaporates regardless of key size
    - Slow when p and q are far apart

3. POLLARD'S RHO:
    - General-purpose; beats trial division badly on bigger n
    - Doesn't care whether the primes are close or far

4. THE BIG PICTURE:
    - 'Smarter math' shrinks the attack effort dramatically
    - This is exactly why real RSA needs BOTH large n AND well-chosen primes
    - Modern key generation enforces these rules so these attacks fail

GROUP DISCUSSION PROMPTS:
    - Why does Fermat finish in 1 step for the 'close primes' case?
    - At what bit-length does trial division stop being practical?
    - Which method would you reach for if you knew nothing about the primes?
""")
