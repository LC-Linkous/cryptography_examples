#!/usr/bin/python3
"""
demo_ecb_vs_cbc.py -- Why a good block cipher is not enough: modes of operation.

The repo's Feistel example encrypts ONE block. Real messages are many blocks,
and HOW you chain the blocks matters as much as the cipher itself.

    ECB (Electronic Codebook): encrypt each block independently.
        identical plaintext blocks -> identical ciphertext blocks.
    CBC (Cipher Block Chaining):  XOR each block with the previous ciphertext
        block before encrypting (first block uses a random IV).
        identical plaintext blocks -> different ciphertext blocks.

We draw a small two-tone picture, encrypt it both ways with the SAME key and
the SAME cipher, and look at the result. ECB leaks the picture. CBC does not.
(This is the classic "ECB penguin" demonstration with an original image.)

Run:  python demo_ecb_vs_cbc.py
Writes: plain.pgm, ecb.pgm, cbc.pgm  (open with any image viewer / GIMP)
No dependencies beyond the standard library.
"""
import hashlib
import os
import struct

BLOCK = 8          # bytes per block (64-bit block, like DES)
ROUNDS = 8


# ----------------------------------------------------------------- the cipher
# A toy 64-bit Feistel network. The round function is keyed SHA-256, which is
# overkill but keeps the demo honest: the block cipher itself is NOT the weak
# link here. The weakness we are about to see is entirely the MODE.

def round_function(half, round_key):
    return hashlib.sha256(round_key + half).digest()[:4]


def feistel_encrypt_block(block, key):
    assert len(block) == BLOCK
    left, right = block[:4], block[4:]
    for r in range(ROUNDS):
        round_key = key + bytes([r])
        f = round_function(right, round_key)
        left, right = right, bytes(a ^ b for a, b in zip(left, f))
    return right + left     # final swap, standard Feistel convention


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


# ------------------------------------------------------------------ the modes

def ecb_encrypt(data, key):
    return b''.join(feistel_encrypt_block(data[i:i + BLOCK], key)
                    for i in range(0, len(data), BLOCK))


def cbc_encrypt(data, key, iv):
    out, prev = [], iv
    for i in range(0, len(data), BLOCK):
        c = feistel_encrypt_block(xor_bytes(data[i:i + BLOCK], prev), key)
        out.append(c)
        prev = c
    return b''.join(out)


# ------------------------------------------------------------------ the image
W, H = 48, 32   # width is a multiple of BLOCK so rows align with blocks


def make_image():
    """A bold, geometric picture: a frame, a diagonal bar and a filled disc.

    Two tones only (0 and 255). Large uniform regions are exactly what ECB
    cannot hide, because every 8 identical pixels encrypt to the same block.
    """
    px = bytearray(W * H)
    cx, cy, r = 34, 16, 9
    for y in range(H):
        for x in range(W):
            on = False
            if x < 2 or x >= W - 2 or y < 2 or y >= H - 2:        # frame
                on = True
            if abs((x - 4) - (y * 1.2)) < 2.5:                     # diagonal bar
                on = True
            if (x - cx) ** 2 + (y - cy) ** 2 <= r * r:             # disc
                on = True
            px[y * W + x] = 255 if on else 0
    return bytes(px)


def write_pgm(path, data):
    with open(path, 'wb') as f:
        f.write(f"P5\n{W} {H}\n255\n".encode())
        f.write(data)


def ascii_render(data, title):
    print(f"\n{title}")
    print("+" + "-" * W + "+")
    for y in range(H):
        row = data[y * W:(y + 1) * W]
        # Threshold each ciphertext byte so the picture is 2-tone like the input.
        print("|" + ''.join('#' if b >= 128 else ' ' for b in row) + "|")
    print("+" + "-" * W + "+")


def count_repeated_blocks(data):
    blocks = [data[i:i + BLOCK] for i in range(0, len(data), BLOCK)]
    return len(blocks) - len(set(blocks)), len(blocks)


# ----------------------------------------------------------------------- main
if __name__ == "__main__":
    key = os.urandom(16)
    iv = os.urandom(BLOCK)
    plain = make_image()

    ecb = ecb_encrypt(plain, key)
    cbc = cbc_encrypt(plain, key, iv)

    write_pgm("plain.pgm", plain)
    write_pgm("ecb.pgm", ecb)
    write_pgm("cbc.pgm", cbc)

    ascii_render(plain, "PLAINTEXT image")
    ascii_render(ecb, "ECB ciphertext (same key, same cipher) -- the picture leaks")
    ascii_render(cbc, "CBC ciphertext (same key, same cipher) -- nothing to see")

    print("\nWhy: ECB maps equal plaintext blocks to equal ciphertext blocks.")
    for name, buf in (("plaintext", plain), ("ECB", ecb), ("CBC", cbc)):
        rep, total = count_repeated_blocks(buf)
        print(f"  {name:>9}: {rep:4d} of {total} blocks are repeats of an earlier block")

    print("\nTake-aways:")
    print("  * The block cipher was identical in both runs. Only the MODE changed.")
    print("  * ECB is a substitution cipher on 8-byte 'letters' -- frequency")
    print("    analysis works on it just like on the Caesar cipher.")
    print("  * CBC needs an IV; it must be unpredictable and sent with the message.")
    print("  * Neither mode detects tampering. Real systems use authenticated")
    print("    modes (AES-GCM, ChaCha20-Poly1305) -- see demo_hybrid_encryption.py.")
    print("\nWrote plain.pgm, ecb.pgm, cbc.pgm")
