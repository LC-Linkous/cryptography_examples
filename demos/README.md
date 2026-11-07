# demos

Cross-cutting demonstrations that connect the per-algorithm examples in `src/`.

Where the `src/<category>/<cipher>/` folders each teach **one** algorithm, these
scripts sit a level up: they show what happens when algorithms are *combined*,
*misused*, or *compared* — the ideas that only appear once you have more than one
primitive in hand. Each is a single self-contained file, standard-library only
(no `numpy`/`pandas`, no repo imports), so any one can be dropped into a lecture
or an assignment on its own.

Run any of them directly:

```bash
python demos/demo_ecb_vs_cbc.py
```

| demo | one-line idea | ties back to |
|------|---------------|--------------|
| `demo_ecb_vs_cbc.py` | A good block cipher isn't enough — the *mode* leaks structure (the "ECB penguin"). | `block/feistel` |
| `demo_password_hashing.py` | Storing a hash isn't enough — salt kills precomputed tables, a slow KDF makes guessing expensive. | `hashing/*` |
| `demo_hybrid_encryption.py` | How RSA + a stream cipher + a MAC combine into the TLS/PGP/age pattern. | `asymmetric/RSA`, `stream/*`, `hashing/sha256` |
| `demo_two_time_pad.py` | The one-time pad is perfect used *once*; reuse the key and both messages fall out by crib-dragging. | `stream/otp`, `stream/chacha20` |
| `demo_birthday_collisions.py` | Collisions cost ~2^(n/2), not 2^n — which is exactly how MD5 and SHA-1 fell. | `hashing/md5`, `hashing/sha1`, `hashing/sha256` |
| `demo_ecdh_mitm.py` | A shared secret is not a verified partner: unauthenticated ECDH falls to a man-in-the-middle, and a signature stops it. | `asymmetric/ECDH` |
| `demo_timing_attack.py` | A short-circuiting `==` on a secret leaks it through the clock, one byte at a time; `hmac.compare_digest` doesn't. | `hashing/*` (MAC/token checks) |

## Notes for course use

* **Stand-ins, not production.** Several demos use a deliberately simple primitive
  in place of a vetted one (a toy Feistel, a SHA-256 counter-mode keystream,
  textbook RSA). The *assembly* is faithful; the primitive is not secure. Each
  file says so in its header. This matches the repo's existing "the math being
  right is not the same as the system being secure" teaching note on RSA.
* **Assignment spoilers.** These were written independently of the non-public
  group assignments. If an assignment asks students to discover one of these
  ideas themselves (e.g. the ECB weakness, or building up a hybrid scheme),
  keep that demo out of the students' copy until after.
* **Level.** These are a step up from the classical ciphers — modes of
  operation, KDF work factors, authenticate-then-decrypt, the birthday bound.
  They work well as "second half of the unit" or stretch material.
* **Output.** `demo_ecb_vs_cbc.py` also writes `plain.pgm` / `ecb.pgm` /
  `cbc.pgm`, viewable in any image viewer, alongside its ASCII rendering.
* **Runtime.** All are near-instant except `demo_timing_attack.py` (~15-20s,
  since it actually measures timing over many rounds) and
  `demo_birthday_collisions.py` (a few seconds at the 40-bit row).
* **Timing stability.** `demo_timing_attack.py` measures the wall clock, so on
  a heavily loaded machine the per-byte recovery can wobble. It is tuned to be
  reliable on an ordinary idle laptop; if a run misbehaves, raise `ROUNDS` or
  `WORK` at the top of the file.
