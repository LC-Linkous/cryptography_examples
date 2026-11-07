#!/usr/bin/python3
"""
demo_birthday_collisions.py -- Why finding a hash COLLISION is far cheaper than
you would guess, and why that is the story behind every broken hash.

The repo's hashing section repeats a theme: MD5 and SHA-1 are "broken by
collisions." But why are collisions findable at all for a function nobody can
invert? The answer is the birthday paradox, and this demo makes it concrete.

Intuition (the birthday paradox): in a room of just 23 people, two share a
birthday with >50% probability -- not because any ONE person is likely to
match you, but because the number of PAIRS grows as the square of the group.
The same math applies to hash outputs. To find SOME pair that collides in an
n-bit hash you expect about sqrt(2^n) ~= 2^(n/2) attempts -- the square root
of the naive 2^n, not 2^n itself.

This demo truncates real SHA-256 to n bits (so collisions are findable at
teaching scale), searches for a collision at several values of n, and lays the
MEASURED number of attempts beside the theoretical prediction. They track.

The punchline: collision resistance is only HALF the digest length. A 128-bit
hash (MD5) offers ~64-bit collision resistance -- and 2^64 was reachable, which
is precisely how MD5 and then SHA-1 fell.

Run:  python demo_birthday_collisions.py
Standard library only. Runs in a few seconds.
"""
import hashlib
import math
import os


def truncated_hash(data, n_bits):
    """Real SHA-256, keeping only the top n_bits as an integer."""
    full = hashlib.sha256(data).digest()
    full_int = int.from_bytes(full, "big")
    # Keep the most significant n_bits of the 256-bit digest.
    return full_int >> (256 - n_bits)


def find_collision(n_bits, max_tries):
    """Hash random messages until two share an n-bit truncated digest."""
    seen = {}
    for attempt in range(1, max_tries + 1):
        msg = os.urandom(16)
        h = truncated_hash(msg, n_bits)
        if h in seen and seen[h] != msg:
            return attempt, seen[h], msg, h
        seen[h] = msg
    return None, None, None, None


def expected_tries(n_bits):
    """Birthday expectation for the first collision: ~sqrt(pi/2) * 2^(n/2)."""
    return math.sqrt(math.pi / 2) * (2 ** (n_bits / 2))


def main():
    print("=" * 72)
    print("Finding collisions in SHA-256 truncated to n bits")
    print("=" * 72)
    print(f"{'n bits':>7} | {'naive 2^n':>14} | {'birthday ~2^(n/2)':>18} | "
          f"{'measured tries':>15}")
    print("-" * 72)

    for n_bits in (16, 24, 32, 40):
        # Generous cap at ~8x the expectation so a run essentially always finds one.
        cap = int(expected_tries(n_bits) * 8) + 100
        tries, m1, m2, h = find_collision(n_bits, cap)
        naive = f"2^{n_bits}"
        birthday = f"{expected_tries(n_bits):,.0f}"
        measured = f"{tries:,}" if tries else f">{cap:,} (none)"
        print(f"{n_bits:>7} | {naive:>14} | {birthday:>18} | {measured:>15}")
        if tries:
            # Show one concrete collision so it is not just a number.
            print(f"{'':>7}   collision: sha256({m1.hex()})>>{256-n_bits}")
            print(f"{'':>7}          and  sha256({m2.hex()})>>{256-n_bits}")
            print(f"{'':>7}   both truncate to the same {n_bits}-bit value {h:#x}")

    print("-" * 72)
    print("\nRead the gap between columns 2 and 3: that square-root is the whole")
    print("point. Each extra bit of digest only buys HALF a bit of collision")
    print("resistance.\n")
    print("Scaling it up to the real hashes:")
    for name, bits in (("MD5", 128), ("SHA-1", 160), ("SHA-256", 256)):
        print(f"  {name:8} {bits:>3}-bit digest -> ~2^{bits // 2} work to collide")
    print("\n  2^64 (MD5) was reached in practice; 2^80 (SHA-1) was pushed over")
    print("  the line by the 2017 SHATTERED attack using ~2^63 computation with")
    print("  clever shortcuts. 2^128 (SHA-256) remains comfortably out of reach.")
    print("\nThis is also WHY digests are sized the way they are: if you want")
    print("128-bit collision security, you must publish a 256-bit hash.")
    print("=" * 72)


if __name__ == "__main__":
    main()
