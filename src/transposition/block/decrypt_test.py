#! /usr/bin/python3

##--------------------------------------------------------------------\
#   encryption_examples
#   './encryption_examples/src/transposition/block/decrypt_test.py'
#   Some (mostly) AI generated test cases, for fun. 
#   Claude also added some additional commentary, which is neat. 
#
#   Last update: June 24, 2025
##--------------------------------------------------------------------\

import pandas as pd
from decrypt import decrypt

print("=== Block Cipher Cryptanalysis Demo ===\n")

# Create analyzer
analyzer = decrypt(block_size=8, num_rounds=4)

# Example ciphertext (hex format)
# This would be output from our block cipher
#   The repeated pattern that shows up because of this in the analysis
#   is a key indicator that suggests if test data wasn't properly encrypted
example_ciphertext = "A1B2C3D4E5F67890" * 8  # 64 bytes = 8 blocks

print("=== Analysis of Unknown Ciphertext ===")
print(f"Ciphertext: {example_ciphertext}")

# Perform analysis without known plaintexts
results = analyzer.comprehensive_cryptanalysis(example_ciphertext)

print("\n" + "="*80)
print("=== Analysis with Known Plaintext-Ciphertext Pairs ===")

# Simulate some known pairs (in practice, these might be obtained through
# various means like social engineering, protocol analysis, etc.)
known_pairs = [
    (b"HELLO123", bytes.fromhex("A1B2C3D4E5F67890")),
    (b"WORLD456", bytes.fromhex("B2C3D4E5F6789012")),
    (b"TEST789A", bytes.fromhex("C3D4E5F678901234")),
]

# Analyze with known pairs
results_with_known = analyzer.comprehensive_cryptanalysis(
    example_ciphertext, known_pairs=known_pairs)

print(f"\n=== Block Cipher Cryptanalysis Summary ===")
print("""
Block cipher cryptanalysis is fundamentally different from classical ciphers:

1. KEY SPACE SIZE:
    - Classical ciphers: 26! ≈ 4×10²⁶ (still huge but searchable with quantum)
    - Block ciphers: 2¹²⁸ ≈ 3×10³⁸ (AES-128) - completely infeasible
    - Brute force is impossible, even with all computers on Earth

2. CRYPTANALYTIC ATTACKS:
    - Differential cryptanalysis: Analyze input/output differences
    - Linear cryptanalysis: Find linear approximations
    - Statistical tests: Detect non-random patterns
    - Known/chosen plaintext: Use known pairs to deduce key info

3. ATTACK REQUIREMENTS:
    - Differential: Many plaintext-ciphertext pairs with controlled differences
    - Linear: Statistical analysis of many pairs
    - Known plaintext: Some known input-output pairs
    - Statistical: Only ciphertext needed, but limited effectiveness

4. REAL-WORLD SECURITY:
    - Modern ciphers (AES, ChaCha20) resist these attacks
    - Attacks often target implementation flaws, not math
    - Side-channel attacks (timing, power) more practical
    - Key management failures more common than cryptanalytic breaks

5. EDUCATIONAL VALUE:
    - Shows why proper cipher design is critical
    - Demonstrates importance of statistical randomness
    - Illustrates advanced cryptanalytic techniques
    - Explains why we can trust modern block ciphers

CONCLUSION:
Unlike classical ciphers which can be broken with enough computational power,
well-designed block ciphers provide security through mathematical complexity
that is believed to be computationally intractable even for quantum computers
(with appropriate key sizes).
""")