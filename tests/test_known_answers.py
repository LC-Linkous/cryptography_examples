"""Known-answer tests against published worked examples.

Round-trip tests only prove that decrypt undoes encrypt; two matching
mistakes (like the old Caesar shift or ChaCha20 counter) still round-trip.
These vectors come from outside the repo, so they catch that kind of drift.
Sources: Wikipedia's worked examples for each classical cipher, the RC4
test vectors on Wikipedia, and the small textbook elliptic curve
y^2 = x^3 + 2x + 2 (mod 17) with G = (5, 1) of order 19.
"""
import contextlib
import io

import pytest

UPPER = [chr(i) for i in range(65, 91)]


def quiet(fn, *args, **kwargs):
    """Call fn with its demo printing suppressed."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


# ------------------------------------------------------------- substitution

def test_affine(load_module, opts):
    enc = load_module('substitution/affine/encrypt.py').encrypt(None, opts(A=5, B=8))
    dec = load_module('substitution/affine/decrypt.py').decrypt(None, opts(A=5, B=8))
    assert enc.encrypt_message("AFFINE CIPHER") == "IHHWVC SWFRCP"
    assert dec.decrypt_message("IHHWVC SWFRCP") == "AFFINE CIPHER"


def test_autokey(load_module, opts):
    enc = load_module('substitution/autokey/encrypt.py').encrypt(None, opts(PRIMER='QUEENLY', KEEP_SPACES=False))
    dec = load_module('substitution/autokey/decrypt.py').decrypt(None, opts(PRIMER='QUEENLY'))
    assert enc.encrypt_message("ATTACKATDAWN") == "QNXEPVYTWTWP"
    assert dec.decrypt_message("QNXEPVYTWTWP") == "ATTACKATDAWN"


def test_beaufort(load_module, opts):
    pt, ct = "DEFENDTHEEASTWALLOFTHECASTLE", "CKMPVCPVWPIWUJOGIUAPVWRIWUUK"
    enc = load_module('substitution/beaufort/encrypt.py').encrypt(None, opts(KEYWORD='FORTIFICATION', KEEP_SPACES=False))
    dec = load_module('substitution/beaufort/decrypt.py').decrypt(None, opts(KEYWORD='FORTIFICATION'))
    assert enc.encrypt_message(pt) == ct
    assert dec.decrypt_message(ct) == pt


@pytest.mark.parametrize("variant_24, letter, code", [
    (False, "K", "ABABA"),   # 26-letter: K is the 11th letter, 01010
    (True, "K", "ABAAB"),    # 24-letter: I/J share a code, so K is 01001
    (True, "J", "ABAAA"),    # ...and J encodes the same as I
])
def test_bacon(load_module, opts, variant_24, letter, code):
    enc = load_module('substitution/bacon/encrypt.py').encrypt(
        UPPER, opts(SYMBOL_A='A', SYMBOL_B='B', VARIANT_24=variant_24))
    enc.create_encryption_dictionary()
    assert enc.encrypt_message(letter).replace(' ', '') == code


# ------------------------------------------------------------ transposition

def test_rail_fence(load_module, opts):
    enc = load_module('transposition/rail_fence/encrypt.py').encrypt(None, opts(NUM_RAILS=3))
    assert enc.encrypt_message("WE ARE DISCOVERED FLEE AT ONCE") == "WECRLTEERDSOEEFEAOCAIVDEN"
    dec = load_module('transposition/rail_fence/decrypt.py').decrypt()
    assert dec.decrypt_rail_fence("WECRLTEERDSOEEFEAOCAIVDEN", 3) == "WEAREDISCOVEREDFLEEATONCE"


# --------------------------------------------------------------------- grid

def test_adfgvx_roundtrip(load_module, opts):
    o = opts(GRID_KEYWORD='PRIVACY', TRANS_KEYWORD='GERMAN')
    ct = quiet(load_module('grid/ADFGVX/encrypt.py').encrypt(None, o).encrypt_message, "ATTACK AT 1200AM")
    assert set(ct) <= set("ADFGVX")
    assert load_module('grid/ADFGVX/decrypt.py').decrypt(None, o).decrypt_message(ct) == "ATTACKAT1200AM"


# ------------------------------------------------------------------- stream

@pytest.mark.parametrize("key, pt, ct", [
    ("Key", "Plaintext", "BBF316E8D940AF0AD3"),
    ("Wiki", "pedia", "1021BF0420"),
    ("Secret", "Attack at dawn", "45A01F645FC35B383552544B9BF5"),
])
def test_rc4(load_module, opts, key, pt, ct):
    enc = load_module('stream/RC4/encrypt.py').encrypt(None, opts(KEY=key))
    assert enc.encrypt_message(pt).replace(' ', '').upper() == ct
    assert load_module('stream/RC4/decrypt.py').decrypt(None, opts(KEY=key)).decrypt_message(ct) == pt


def test_otp_mod26_roundtrip(load_module, opts):
    enc = load_module('stream/otp/encrypt.py').encrypt(None, opts(MODE='mod26'))
    ct = enc.encrypt_message("HELLO")
    dec = load_module('stream/otp/decrypt.py').decrypt(None, opts(MODE='mod26'))
    assert dec.decrypt_message(ct, enc.get_last_key()) == "HELLO"


# -------------------------------------------------------------------- block

@pytest.mark.parametrize("msg", ["", "A", "12345678", "1234567812345678", "héllo wörld ✓"])
def test_block_cipher_roundtrip_and_pkcs7(load_module, opts, msg):
    # Includes exact multiples of the 8-byte block, where PKCS#7 must add a
    # whole extra block, and multi-byte UTF-8.
    enc = load_module('block/feistel/encrypt.py').encrypt(None, opts(KEY_HEX='0123456789abcdef'))
    ct = enc.encrypt_message(msg)
    assert len(bytes.fromhex(ct)) == (len(msg.encode()) // 8 + 1) * 8
    assert enc.decrypt_message(ct) == msg


# --------------------------------------------------------------- asymmetric

def test_rsa_with_65537(load_module, opts):
    enc = load_module('asymmetric/RSA/encrypt.py').encrypt(None, opts(P=1009, Q=1013, E=65537, OUTPUT_FORMAT='LIST'))
    enc.generate_keypair()
    ct = enc.encrypt_message("Hello, World! ~")
    dec = load_module('asymmetric/RSA/decrypt.py').decrypt(None, opts(N=enc.n, E=65537, D=enc.d, INPUT_FORMAT='LIST'))
    assert dec.decrypt_message(ct) == "Hello, World! ~"


@pytest.mark.parametrize("k, point", [(1, (5, 1)), (2, (6, 3)), (3, (10, 6)), (18, (5, 16)), (19, None)])
def test_ecdh_textbook_curve_points(load_module, opts, k, point):
    ec = load_module('asymmetric/ECDH/encrypt.py').encrypt(None, opts())
    assert ec.scalar_mult(k, (5, 1)) == point


def test_ecdh_attacks_recover_the_scalar(load_module, opts):
    ec = load_module('asymmetric/ECDH/encrypt.py').encrypt(None, opts())
    public = ec.scalar_mult(13, (5, 1))
    naive = load_module('asymmetric/ECDH/decrypt.py').decrypt(None, opts())
    bsgs = load_module('asymmetric/ECDH/decrypt_improved.py').decrypt_improved(None, opts())
    assert quiet(naive.brute_force_decrypt, public) == 13
    assert quiet(bsgs.brute_force_decrypt, public) == 13
