#!/usr/bin/python3
"""
demo_ecdh_mitm.py -- Elliptic-Curve Diffie-Hellman gives two strangers a shared
secret over an open wire. But if nobody checks WHO is on the other end, an
attacker in the middle gets a shared secret with each of them -- and reads
everything. The fix is authentication (a signature), which is the gap the
hybrid demo's MAC only half-closed.

The math of ECDH is not broken here. Mallory never solves the elliptic-curve
discrete log; she simply substitutes her own public key for the one in transit.
Raw key exchange has no notion of identity, so Alice cannot tell Mallory's key
from Bob's.

  Honest run:   Alice <--------- public keys ---------> Bob
                both derive the SAME secret, Mallory (passive) learns nothing.

  Active MITM:  Alice <---> [ Mallory ] <---> Bob
                Mallory swaps keys, holds TWO secrets (one per side),
                decrypts/re-encrypts in the middle. Neither victim notices.

  With auth:    Alice SIGNS her ephemeral key with a long-term key Bob already
                trusts. Mallory can swap the key but cannot forge the signature,
                so Bob's verification fails and the swap is detected.

Uses the real secp256k1 curve (so the discrete-log problem is genuinely hard --
this demo is emphatically NOT breaking that) and a compact Schnorr signature on
the same curve for the authentication step. Standard library only.
"""
import hashlib
import os

# --------------------------------------------------- secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # group order


# ----------------------------------------------------------- curve point math
def inv_mod(k, m):
    return pow(k, -1, m)


def point_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % P == 0:
        return None                      # P + (-P) = point at infinity
    if p1 == p2:
        s = (3 * x1 * x1 + A) * inv_mod(2 * y1, P) % P
    else:
        s = (y2 - y1) * inv_mod(x2 - x1, P) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return (x3, y3)


def scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def random_scalar():
    return 1 + int.from_bytes(os.urandom(32), "big") % (N - 1)


# ------------------------------------------------------------- ECDH + a cipher
def derive_key(shared_point):
    """Turn a shared curve point into symmetric key bytes (KDF)."""
    x, _ = shared_point
    return hashlib.sha256(b"ecdh-demo-kdf" + x.to_bytes(32, "big")).digest()


def stream(key, nonce, length):
    out = bytearray()
    c = 0
    while len(out) < length:
        out.extend(hashlib.sha256(key + nonce + c.to_bytes(8, "big")).digest())
        c += 1
    return bytes(out[:length])


def encrypt(key, msg):
    nonce = os.urandom(12)
    return nonce + bytes(a ^ b for a, b in zip(msg, stream(key, nonce, len(msg))))


def decrypt(key, blob):
    nonce, ct = blob[:12], blob[12:]
    return bytes(a ^ b for a, b in zip(ct, stream(key, nonce, len(ct))))


# -------------------------------------------------- Schnorr signatures on the curve
def schnorr_sign(priv, pub, message):
    k = random_scalar()
    R = scalar_mult(k, G)
    e = int.from_bytes(hashlib.sha256(
        R[0].to_bytes(32, "big") + pub[0].to_bytes(32, "big") + message).digest(), "big") % N
    s = (k + e * priv) % N
    return (R, s)


def schnorr_verify(pub, message, sig):
    R, s = sig
    e = int.from_bytes(hashlib.sha256(
        R[0].to_bytes(32, "big") + pub[0].to_bytes(32, "big") + message).digest(), "big") % N
    # valid iff  s*G == R + e*pub
    return scalar_mult(s, G) == point_add(R, scalar_mult(e, pub))


def pub_bytes(point):
    return point[0].to_bytes(32, "big") + point[1].to_bytes(32, "big")


# ============================================================================
def honest_exchange():
    print("=" * 72)
    print("1. Honest ECDH -- no attacker in the path")
    print("=" * 72)
    a = random_scalar(); A_pub = scalar_mult(a, G)
    b = random_scalar(); B_pub = scalar_mult(b, G)
    # Each side multiplies its own secret by the other's public key.
    alice_secret = derive_key(scalar_mult(a, B_pub))
    bob_secret = derive_key(scalar_mult(b, A_pub))
    print(f"  Alice derives key: {alice_secret.hex()[:32]}...")
    print(f"  Bob   derives key: {bob_secret.hex()[:32]}...")
    print(f"  match: {alice_secret == bob_secret}  (a*B == b*A, the ECDH identity)")


def active_mitm():
    print("\n" + "=" * 72)
    print("2. Active man-in-the-middle -- Mallory sits between them")
    print("=" * 72)
    a = random_scalar(); A_pub = scalar_mult(a, G)      # Alice
    b = random_scalar(); B_pub = scalar_mult(b, G)      # Bob
    m = random_scalar(); M_pub = scalar_mult(m, G)      # Mallory's single key

    # Mallory intercepts both public keys and sends HERS to each side instead.
    # Alice thinks M_pub is Bob's; Bob thinks M_pub is Alice's.
    alice_key = derive_key(scalar_mult(a, M_pub))       # Alice <-> Mallory
    mallory_with_alice = derive_key(scalar_mult(m, A_pub))
    bob_key = derive_key(scalar_mult(b, M_pub))         # Bob <-> Mallory
    mallory_with_bob = derive_key(scalar_mult(m, B_pub))

    print(f"  Alice's key   == Mallory's Alice-side key : {alice_key == mallory_with_alice}")
    print(f"  Bob's key     == Mallory's Bob-side key   : {bob_key == mallory_with_bob}")

    # Alice sends a message "to Bob". Mallory decrypts, reads, re-encrypts to Bob.
    plaintext = b"ship the funds to account 4471 at midnight"
    on_wire = encrypt(alice_key, plaintext)
    seen_by_mallory = decrypt(mallory_with_alice, on_wire)
    forwarded = encrypt(mallory_with_bob, seen_by_mallory)
    received_by_bob = decrypt(bob_key, forwarded)

    print(f"\n  Alice sends : {plaintext.decode()}")
    print(f"  Mallory reads: {seen_by_mallory.decode()}   <-- fully exposed")
    print(f"  Bob receives : {received_by_bob.decode()}")
    print("  Neither Alice nor Bob sees anything wrong.")


def authenticated_exchange():
    print("\n" + "=" * 72)
    print("3. The fix: Alice authenticates her ephemeral key")
    print("=" * 72)
    # Alice has a LONG-TERM signing key that Bob already trusts (a cert, a
    # pinned key, a prior in-person exchange -- modelled here as pre-shared).
    alice_longterm = random_scalar()
    alice_verify = scalar_mult(alice_longterm, G)       # Bob has this already

    a = random_scalar(); A_pub = scalar_mult(a, G)      # fresh ephemeral key
    sig = schnorr_sign(alice_longterm, alice_verify, pub_bytes(A_pub))

    # Honest path: Bob verifies the signature over the key he received.
    print(f"  Bob verifies Alice's real key : {schnorr_verify(alice_verify, pub_bytes(A_pub), sig)}")

    # Mallory swaps in her own key but cannot re-sign with Alice's long-term key.
    m = random_scalar(); M_pub = scalar_mult(m, G)
    tampered_ok = schnorr_verify(alice_verify, pub_bytes(M_pub), sig)
    print(f"  Bob verifies Mallory's swap   : {tampered_ok}   <-- rejected, MITM caught")
    # Mallory's best alternative -- sign with her OWN key -- also fails, because
    # Bob checks against ALICE's trusted verification key, not whoever signed.
    forged = schnorr_sign(m, scalar_mult(m, G), pub_bytes(M_pub))
    print(f"  Bob verifies Mallory's forgery: {schnorr_verify(alice_verify, pub_bytes(M_pub), forged)}"
          "   <-- still rejected")


if __name__ == "__main__":
    honest_exchange()
    active_mitm()
    authenticated_exchange()
    print("\n" + "=" * 72)
    print("Take-aways:")
    print("  * ECDH gives you a shared secret, not a verified PARTNER.")
    print("  * Without authentication, the secret may be shared with an attacker.")
    print("  * The ECDLP was never touched -- only identity was. Hard math does")
    print("    not save a protocol that never checks who it is talking to.")
    print("  * Real protocols bind keys to identities: signed key exchange (TLS),")
    print("    certificates, or a short authentication string the humans compare.")
    print("=" * 72)
