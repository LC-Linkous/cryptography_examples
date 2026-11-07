#!/usr/bin/python3
"""
demo_two_time_pad.py -- The One-Time Pad is unbreakable. The TWO-time pad is a
gift to the attacker.

The repo's OTP material says perfect secrecy requires a key that is NEVER
reused, and the OTP decrypt class even has a `demonstrate_key_reuse` hook.
This demo carries that all the way through: it encrypts two messages with the
SAME keystream and then recovers BOTH plaintexts without ever knowing the key.

The whole attack rests on one line of algebra. If
    C1 = P1 XOR K
    C2 = P2 XOR K      (same K -- the fatal mistake)
then
    C1 XOR C2 = P1 XOR P2
The key cancels out completely. The attacker is left with the XOR of two
English sentences and no key in sight -- and English XOR English is very far
from random.

Technique: "crib-dragging." Guess a word that probably appears in one message
(a "crib"), XOR it against C1 XOR C2 at every position, and read off what the
OTHER message would contain there. When the output is readable English, the
guess was right, and you have just learned a slice of both messages at once.

Run:  python demo_two_time_pad.py
Standard library only.
"""
import os

# A crib reveals a slice of the OTHER plaintext. Real English text, lower-case,
# is letters and spaces with vowels in it; restricting to that cuts almost all
# of the random-looking noise that crib-dragging throws off at wrong offsets.
LOWER_SPACE = set("abcdefghijklmnopqrstuvwxyz ")
VOWELS = set("aeiou")


# Two messages the sender foolishly encrypts under the same pad.
MSG1 = b"the treasure is buried beneath the old oak tree by the river bend"
MSG2 = b"meet me at dawn behind the mill and come alone or the deal is off"

# Cribs the attacker tries -- common words and guessed fragments. In a real
# attack you iterate: each confirmed fragment suggests the next crib.
CRIBS = [b" the ", b"meet", b"treasure", b"dawn", b" and ", b" is ", b"river"]

# Short, very common words. A revealed fragment containing one of these is the
# strong signal an analyst's eye locks onto -- the same cue, mechanized, so the
# demo can point at the real hits without ever peeking at the answer.
COMMON_WORDS = ("the", "me", "at", "and", "is", "by", "on", "of", "to", "be")


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def looks_like_text(data):
    """Keep only clean lower-case English-ish fragments (letters/spaces with a
    vowel). Tight on purpose: it is better to miss a real hit than to drown
    the obvious ones in noise."""
    text = "".join(chr(b) for b in data)
    if not all(ch in LOWER_SPACE for ch in text):
        return False
    return any(ch in VOWELS for ch in text)


def crib_drag(combined, crib):
    """Slide `crib` across `combined` (= C1 XOR C2 = P1 XOR P2).

    At each offset, crib XOR combined reveals what the OTHER plaintext holds
    at that offset IF the crib really sits in one of the messages there.
    """
    hits = []
    for offset in range(len(combined) - len(crib) + 1):
        window = combined[offset:offset + len(crib)]
        revealed = xor(crib, window)
        if looks_like_text(revealed):
            hits.append((offset, revealed))
    return hits


def main():
    # ---- the sender's mistake: one keystream, two messages ----
    n = min(len(MSG1), len(MSG2))
    keystream = os.urandom(n)
    c1 = xor(MSG1[:n], keystream)
    c2 = xor(MSG2[:n], keystream)

    print("=" * 70)
    print("The attacker sees only two ciphertexts (hex). No key.")
    print("=" * 70)
    print(f"  C1: {c1.hex()}")
    print(f"  C2: {c2.hex()}")

    # ---- step 1: cancel the key ----
    combined = xor(c1, c2)
    print("\nStep 1 -- XOR the two ciphertexts together. The key CANCELS:")
    print("  C1 XOR C2 == P1 XOR P2  (the attacker now has this, key-free)")
    print(f"  {combined.hex()}")

    # ---- step 2: crib-drag ----
    print("\nStep 2 -- Drag likely words across it. A readable result means the")
    print("crib sits in one message and we just read the OTHER message there:")
    def has_common_word(text):
        tokens = text.split()
        for w in COMMON_WORDS:
            if w in tokens:                       # standalone word, any length
                return True
            if len(w) >= 3 and w in text:         # 3+ letters may match inside
                return True
        return False

    for crib in CRIBS:
        hits = crib_drag(combined, crib)
        # Readable hits (containing a common word) first, so they stand out.
        hits.sort(key=lambda h: not has_common_word(h[1].decode("ascii")))
        for offset, revealed in hits:
            text = revealed.decode("ascii")
            flag = "  <-- readable English" if has_common_word(text) else ""
            print(f"  crib {crib!r:11} @ offset {offset:2d}  ->  other msg reads {text!r}{flag}")

    # ---- step 3: full recovery ----
    # Once the attacker is confident about a stretch of ONE message, XOR it
    # back into that ciphertext to recover the keystream for those positions,
    # then decrypt the same positions of the OTHER message for free.
    print("\nStep 3 -- Confirm a full guess for ONE message, recover the keystream,")
    print("then both messages fall out. Suppose the analyst has pieced together P1:")
    guess_p1 = MSG1[:n]  # the analyst's reconstructed guess for message 1
    recovered_key = xor(c1, guess_p1)         # K = C1 XOR P1
    recovered_p2 = xor(c2, recovered_key)     # P2 = C2 XOR K
    print(f"  recovered P1: {guess_p1.decode()}")
    print(f"  recovered P2: {recovered_p2.decode()}")
    assert recovered_p2 == MSG2[:n]

    print("\n" + "=" * 70)
    print("Take-aways:")
    print("  * The pad was information-theoretically PERFECT -- used once.")
    print("  * Reused once, the key algebraically cancels and secrecy is gone.")
    print("  * Nothing here brute-forces a key; the attack never needs it.")
    print("  * This is not academic: it broke the Soviet VENONA traffic and")
    print("    Microsoft's PPTP/MS-CHAP among others. 'Number used ONCE' is")
    print("    the entire ball game for stream ciphers (hello, ChaCha20 nonce).")
    print("=" * 70)


if __name__ == "__main__":
    main()
