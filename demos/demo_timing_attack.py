#!/usr/bin/python3
"""
demo_timing_attack.py -- A comparison that quits early leaks a secret through
the clock. Verifying a token or a MAC with a plain byte-by-byte `==` tells an
attacker, by how LONG the rejection takes, how many leading bytes they got
right -- so the secret can be recovered one byte at a time without ever
guessing the whole thing.

This is the practical face of the repo's recurring lesson: a scheme can be
mathematically sound and still leak through its IMPLEMENTATION. The MAC itself
is fine; comparing it carelessly is the hole. (The 2009 attacks on Google
Keyczar and on the Xbox 360's HMAC check were exactly this.)

How the leak works:
  insecure_compare() returns False at the FIRST mismatching byte. So a guess
  with k correct leading bytes runs the loop k+1 times; one more correct byte
  means one more trip through the loop. Timing the rejection reveals k.

  The attack: at each position, try all 256 byte values, keep the one whose
  comparison is reliably SLOWEST (it matched one byte further), lock it in,
  move on. That recovers every byte but the last in 256 * (L-1) guesses.
  The last byte is free: there is no byte after it to create a timing gap, so
  instead we just try all 256 and keep the one the server ACCEPTS. Total work
  ~256 * L, versus 256**L to brute-force the whole secret blind.

Two robustness notes, both honest parts of how this is really done:
  * Interleaving. We sample every candidate once per round over many rounds and
    keep each candidate's MINIMUM time. A scheduler hiccup then lands on
    different candidates each round instead of consistently framing one, and
    the minimum is the cleanest estimate of true compute time (interrupts only
    ever ADD time). Timing each candidate's samples back-to-back instead lets a
    single slow patch inflate one candidate and derail the attack.
  * Amplification. insecure_compare() does a small fixed chunk of busywork per
    matched byte (clearly marked) so the per-byte gap clears the noise floor on
    an ordinary shared machine. The point is the SHAPE of the leak.

Runs in ~15-20 seconds. Standard library only.
"""
import hmac
import os
import time

SECRET = os.urandom(5)          # the token/MAC the attacker is trying to recover
ROUNDS = 20                     # interleaved timing rounds per byte position
WORK = 2500                     # per-matched-byte busywork, to amplify the signal


def _burn(n):
    # Stand-in for the real per-byte work a comparison does. Amplified so the
    # timing difference clears the noise floor on an ordinary machine.
    x = 0
    for _ in range(n):
        x += 1
    return x


def insecure_compare(a, b):
    """Byte-by-byte, SHORT-CIRCUITS on first mismatch -- the vulnerable pattern."""
    if len(a) != len(b):
        return False
    for xa, xb in zip(a, b):
        _burn(WORK)             # time spent grows with each byte that matches
        if xa != xb:
            return False
    return True


def secure_compare(a, b):
    """Constant-time: time does not depend on where/whether bytes differ."""
    return hmac.compare_digest(a, b)


def time_once(compare, guess):
    t0 = time.perf_counter()
    compare(guess, SECRET)
    return time.perf_counter() - t0


def recover(compare, label):
    print(f"\n--- attacking {label} ---")
    recovered = bytearray()

    # Positions 0 .. L-2: recover by timing. All candidates share the known
    # prefix, so the correct next byte is the one that matches one byte further
    # and therefore runs reliably slower.
    for pos in range(len(SECRET) - 1):
        mins = [float("inf")] * 256
        filler = b"\x00" * (len(SECRET) - pos - 1)
        for _ in range(ROUNDS):
            for cand in range(256):
                guess = bytes(recovered) + bytes([cand]) + filler
                dt = time_once(compare, guess)
                if dt < mins[cand]:
                    mins[cand] = dt
        best = max(range(256), key=lambda c: mins[c])
        recovered.append(best)
        print(f"  position {pos}: recovered 0x{best:02x} (reliably slowest rejection)")

    # Last byte: no following byte to leak a gap, so just submit all 256 and
    # keep the one the server ACCEPTS. This is where a wrong earlier byte would
    # doom the attack -- nothing completes the match.
    last = None
    for cand in range(256):
        if compare(bytes(recovered) + bytes([cand]), SECRET):
            last = cand
            break
    if last is None:
        recovered.append(0)
        print("  last byte: no guess accepted -> an earlier byte was wrong")
    else:
        recovered.append(last)
        print(f"  position {len(SECRET)-1}: recovered 0x{last:02x} (the one accepted)")

    ok = bytes(recovered) == SECRET
    print(f"  recovered: {bytes(recovered).hex()}   actual: {SECRET.hex()}   "
          f"{'SECRET STOLEN' if ok else 'attack failed'}")
    return ok


if __name__ == "__main__":
    print("=" * 72)
    print(f"Secret to recover: {len(SECRET)} bytes, never revealed to the attacker")
    print("=" * 72)

    # Show the raw leak first: time rejections for guesses with 0,1,2,... correct
    # leading bytes and watch the clock climb, one step per matched byte.
    print("\nStep 1 -- the leak itself. Rejection time vs. #correct leading bytes")
    print("(minimum of many samples, to show the clean signal):")
    for k in range(len(SECRET)):
        probe = SECRET[:k] + bytes([SECRET[k] ^ 0xFF]) + b"\x00" * (len(SECRET) - k - 1)
        best = min(time_once(insecure_compare, probe) for _ in range(200))
        print(f"  {k} correct leading bytes -> {best * 1e6:7.1f} us to reject")

    print("\nStep 2 -- weaponize it: recover the secret.")
    stolen = recover(insecure_compare, "insecure_compare (short-circuit ==)")

    print("\nStep 3 -- same attack against the constant-time comparison:")
    safe = recover(secure_compare, "hmac.compare_digest (constant time)")

    print("\n" + "=" * 72)
    print("Take-aways:")
    print(f"  * Short-circuit compare: {'leaked the secret' if stolen else 'held'} "
          f"in ~256 x {len(SECRET)} guesses, not 256^{len(SECRET)}.")
    print(f"  * Constant-time compare: attack {'failed' if not safe else 'succeeded'} "
          "-- timing no longer tracks correctness, so the byte-by-byte")
    print("    recovery finds a wrong prefix and nothing completes the match.")
    print("  * ALWAYS compare secrets (MACs, tokens, password hashes) with a")
    print("    constant-time function: hmac.compare_digest in Python.")
    print("  * A correct algorithm with a careless comparison is still broken.")
    print("=" * 72)
