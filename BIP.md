```
BIP: ?
Layer: Applications
Title: ECDSA nonce standard for Bitcoin wallets
Authors: D++ <email@example.com>
         MrHodl <email@example.com>
         Wicked <email@example.com>
         PortlandHODL <email@example.com>
Status: Draft
Type: Specification
Assigned: ?
License: BSD-2-Clause
Discussion: ?
Requires: 174
```

## Abstract

Every ECDSA signature needs a one-time secret number, the nonce `k`. This document
standardises how a Bitcoin signer chooses it.

The first part covers a signer working alone, such as a software wallet: derive `k` with
RFC 6979 from the key and the message, optionally mixed with fresh randomness, and retry
with a counter until the signature is its minimum size ("low-R grinding").

The second part is an optional protocol for the common two-device setup, a software wallet
driving a hardware signer. The wallet contributes randomness to the signer's nonce and can
verify afterwards that it was really used, so even a malicious signer cannot smuggle data
out through its signatures. This "anti-exfil" protocol is the one Blockstream Jade and the
BitBox02 already ship, written down in one place, plus the PSBT fields needed to run it
between any wallet and any signer.

## Motivation

The nonce is the most fragile part of ECDSA:

- If `k` repeats across two signatures with the same key, the key falls out with school
  algebra.
- If `k` is even slightly biased, the key falls out with lattice methods.
- If `k` is chosen by malicious signing code, the signatures themselves become a covert
  channel. Dark Skippy (2024) recovered a whole 12-word seed from two signatures made by a
  tampered signer.

RFC 6979 fixes the first two by deriving `k` deterministically from the key and the
message. Most Bitcoin wallets do something close to it — but only close, because nothing
says exactly what a compliant signer does. Bitcoin Core and Electrum mix a counter into the
derivation to grind for smaller signatures; libsecp256k1 accepts an extra 32-byte input
that most callers leave empty; some wallets still take `k` straight from the system RNG.
Two honest wallets can sign the same input and produce different signatures, and a user has
no way to tell that mismatch from a backdoor.

Full determinism is not the end state either. A device that signs the exact same way every
time is a device an attacker can run twice — under a glitched clock, or a power probe — and
compare runs. BIP 340 answers this for Schnorr by mixing fresh randomness (`aux_rand`) into
the nonce; ECDSA has no written equivalent.

And no amount of determinism helps against a signer that lies, because the user cannot see
inside the device. The practical defence is to let a second device contribute randomness to
the nonce and then check that it was used. That protocol, anti-exfil, has shipped in
hardware since 2021 — and is specified nowhere outside library source and blog posts, with
no PSBT representation and therefore no interoperability.

This document covers all three: one nonce function, one optional extra input, and one
protocol for host-verifiable nonces.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", and "MAY" are to
be interpreted as described in RFC 2119.

This document applies to ECDSA over secp256k1. Schnorr signatures are out of scope: BIP 340
already specifies a hedged nonce derivation.

### Notation

- `n` is the order of the secp256k1 group; `G` is the generator.
- `sk` is a signing key, an integer in `[1, n-1]`.
- `msg` is the 32-byte message hash being signed (for transactions, the sighash).
- `bytes(x)` is the 32-byte big-endian encoding of the integer `x`.
- `cbytes(P)` is the 33-byte compressed SEC encoding of the curve point `P`.
- `int(b)` is the integer whose big-endian encoding is the byte string `b`.
- `LE32(i)` is the 4-byte little-endian encoding of the integer `i`.
- `||` is byte concatenation.
- `tagged_hash(tag, m)` is `SHA256(SHA256(tag) || SHA256(tag) || m)`, as defined in
  BIP 340, where `tag` is the UTF-8 encoding of the given string.
- `HMAC(K, m)` is HMAC-SHA256.

### Nonce derivation

A compliant signer MUST derive `k` as `nonce(sk, msg, aux)`, where `aux` is either absent
or a 32-byte string:

```
keydata = bytes(sk) || msg        (append aux, if present)

V = 0x01 repeated 32 times
K = 0x00 repeated 32 times
K = HMAC(K, V || 0x00 || keydata)
V = HMAC(K, V)
K = HMAC(K, V || 0x01 || keydata)
V = HMAC(K, V)

loop:
    V = HMAC(K, V)
    k = int(V)
    if 1 <= k < n:
        return k
    K = HMAC(K, V || 0x00)
    V = HMAC(K, V)
```

This is RFC 6979's HMAC_DRBG (section 3.2) with the additional input of section 3.6, fixed
to secp256k1 and SHA-256. It is byte-for-byte what `secp256k1_nonce_function_rfc6979` in
libsecp256k1 computes when `ndata` is set to `aux` and `algo16` is null, so a signer built
on libsecp256k1 is compliant without new code.

Two details, both required:

- `msg` is used as given. A literal reading of RFC 6979 would reduce it modulo `n` first
  (`bits2octets`); the two differ only for hashes at least `n`, probability about 2^-128.
  Implementations MUST NOT reduce, so that all signers agree.
- An out-of-range candidate MUST go back through the loop, never be reduced modulo `n`.
  Reducing introduces exactly the bias RFC 6979 exists to remove.

### Auxiliary input

`aux` is where anything beyond the key and the message enters. Three profiles are defined.
A signer MUST document which it implements, and MAY implement more than one.

**Profile D — deterministic.** `aux` is absent. Signatures are a pure function of key and
message and can be reproduced on other hardware. SHOULD be offered as an option for users
who want to cross-check devices; SHOULD NOT be the default (see Rationale).

**Profile H — hedged.** `aux` is 32 fresh bytes from a cryptographically secure RNG for
each signature. The RECOMMENDED default for software wallets. If the RNG silently fails,
this degrades to Profile D — never to a repeated nonce.

**Profile X — anti-exfil.** `aux` is the 32-byte host commitment `c` from the extension
below, which is only meaningful together with the nonce tweak defined there.

In every profile: an `aux` value MUST NOT be reused across two signing attempts that share
a key and message but differ in anything else, and `aux` MUST NOT be derived from any
secret except by the constructions in this document — it is salt, not a second key.
Implementations SHOULD compute the derivation in constant time with respect to `sk` and
`k`.

### Low-R grinding

DER encodes the `r` component of a signature as a signed integer, so an `r` whose leading
byte is `0x80` or higher costs one extra padding byte. Grinding retries the nonce until
`r` is below 2^255 (leading byte under `0x80`), making every signature its minimum,
predictable size.

Under Profiles D and H, a signer MUST grind. Let `aux_0` be the profile's auxiliary input,
or 32 zero bytes under Profile D. For `i = 0, 1, 2, ...`:

```
aux_i = tagged_hash("HedgedNonce/grind", aux_0 || LE32(i))
k_i   = nonce(sk, msg, aux_i)
```

The signer signs with the first `k_i` whose `R = k_i G` has a low x-coordinate. Expected
attempts: two. The signer MUST NOT cap the loop and fall back to a high `R`.

Note that grinding hashes `aux_0` even at `i = 0`, so Profile D passes a (fixed) `aux`
rather than none. Profile D stays reproducible — every signer following this document
derives the same `k` — but its signatures differ from bare RFC 6979 with no extra input.

Under Profile X the signer MUST NOT grind: it signs once, with the tweaked nonce from the
protocol below, and no low-`R` check. To the host, "retry until I like the R" and "abort
until the nonce leaks the bit I want" are the same observable behaviour, so a protocol that
permits one cannot detect the other. Anti-exfil signatures are therefore one byte larger
about half the time. This is the intended trade, and it is already how the shipping
implementations behave (see Rationale).

### Anti-exfil extension

This section is OPTIONAL. It applies when signing is split between a *host* (the wallet
software building the transaction) and a *signer* (the device holding the key), and it
assumes an honest host checking a possibly-dishonest signer.

Define:

```
host_commit(rho)    = tagged_hash("s2c/ecdsa/data", rho)
nonce_tweak(R, rho) = tagged_hash("s2c/ecdsa/point", cbytes(R) || rho)
```

These two constants are not new: they are adopted byte-for-byte from the `ecdsa_s2c` module
of libsecp256k1-zkp, which is the code Blockstream Jade and the BitBox02 run. The Rationale
records the exact provenance.

The protocol:

1. **Host commits.** The host draws `rho`, 32 bytes from a cryptographically secure RNG,
   sends `c = host_commit(rho)` to the signer, and keeps `rho` secret for now.

2. **Signer commits.** The signer computes `k = nonce(sk, msg, c)` and `R = kG`, and
   returns `cbytes(R)` to the host as its *opening*. It stores nothing; step 4 recomputes
   this.

3. **Host reveals.** The host sends `rho`.

4. **Signer signs.** The signer recomputes `c = host_commit(rho)`, `k = nonce(sk, msg, c)`
   and `R = kG`, then tweaks its nonce:

   ```
   t  = int(nonce_tweak(R, rho))
   k' = (k + t) mod n
   ```

   If `t >= n` or `k' = 0` (probability about 2^-128) the signer MUST fail rather than
   substitute another nonce. Otherwise it returns the ECDSA signature `(r, s)` made with
   nonce `k'`.

5. **Host verifies.** The host checks that `(r, s)` is a valid signature on `msg` under
   the expected public key, recomputes `t = int(nonce_tweak(R, rho))` from the opening,
   and checks:

   ```
   x(R + tG) mod n == r
   ```

   Only the x-coordinate is compared, because the y-coordinate is not part of an ECDSA
   signature. If either check fails, the host MUST treat the signature as untrusted, MUST
   NOT broadcast it, and MUST warn the user.

Because everything is re-derived from `rho`, the signer needs no per-session state, and
re-running the protocol with the same `rho` yields the same `R`.

Each half of the commit-reveal blocks one attack. If the signer saw `rho` before fixing
`R`, it could keep re-deriving until the final nonce carried a bit it wants to leak. If the
host saw `R` before committing to `rho`, it could re-run the signer with different `rho`
values against the same `R` and solve for the key algebraically.

#### Handling failures

A malicious signer's last freedom is refusing to sign when the nonce does not leak what it
wants. The host's failure handling is therefore part of the protocol, not an implementation
detail:

- After any failure or disconnection past step 1, the host MUST retry with **the same**
  `rho` and MUST check that the signer returns **the same** `R`. Retrying with fresh `rho`
  turns the protocol into a working exfiltration channel.
- A different `R` for the same `rho`, or a signature that fails verification, MUST be
  surfaced to the user in plain language — not a silent retry, not a generic error toast.
- Hosts SHOULD keep a persistent per-device failure count. Leaking a key by selective
  aborts needs on the order of a hundred of them, accumulated for as long as the keys stay
  the same. A host SHOULD recommend sweeping to fresh keys once the count reaches a small
  number, on the order of twenty.

### PSBT fields

Anti-exfil needs two round trips, so a PSBT-based flow passes the transaction to the signer
twice. Three per-input fields are defined; type numbers are TBD pending assignment.

| Name | Type | Key data | Value data |
| --- | --- | --- | --- |
| `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT` | TBD | 33-byte compressed public key of the key expected to sign | 32-byte `c` |
| `PSBT_IN_ANTI_EXFIL_SIGNER_OPENING` | TBD | 33-byte compressed public key | 33-byte `cbytes(R)` |
| `PSBT_IN_ANTI_EXFIL_HOST_NONCE` | TBD | 33-byte compressed public key | 32-byte `rho` |

First pass: the host adds `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT`; the signer adds
`PSBT_IN_ANTI_EXFIL_SIGNER_OPENING` and no signature. Second pass: the host adds
`PSBT_IN_ANTI_EXFIL_HOST_NONCE`; the signer adds `PSBT_IN_PARTIAL_SIG` as usual.

The host MUST remove all three fields before finalizing, and MUST NOT persist `rho` after
verification. A signer that receives `PSBT_IN_ANTI_EXFIL_HOST_NONCE` without a matching
commitment field MUST refuse to sign.

### What this does and does not protect against

In scope: nonce reuse and bias from a weak or broken RNG (all profiles); fault and
side-channel attacks that rely on the signer repeating a nonce (Profiles H and X); a
malicious signer leaking key material through its nonces, given an honest host (Profile X).

Out of scope: a seed that was generated with bad entropy in the first place; a signer and
host that are both compromised; the bounded leak achievable by selective aborting (see
Handling failures); anything about Schnorr or taproot.

## Rationale

**Why not simply mandate plain RFC 6979?** Determinism trades one attack class for
another: a device that signs identically every time is a device an attacker can glitch and
compare across runs. Hedging removes that at no cost — an attacker who fully controls the
RNG just faces Profile D, the security we had anyway. Same reasoning as BIP 340's
`aux_rand` and the IRTF's hedged-signatures draft, and why hedged is the default here and
reproducible the option.

**Why put the extra input inside the HMAC rather than tweak the key or message?** Because
`secp256k1_nonce_function_rfc6979` already takes it there. Profile H is a pointer that
stops being null.

**Why require grinding rather than allow it?** Core, Electrum, Sparrow, NBitcoin — and
Jade — all grind already, but each with its own counter scheme, so their signatures still
do not match each other, and a user comparing two wallets sees a mismatch that looks like
tampering. One mandatory derivation makes that comparison meaningful again, and it costs a
byte of witness weight per signature not to grind. The expected cost is one extra scalar
multiplication per signature. Hashing the counter together with `aux_0`, rather than using
Core's bare little-endian counter, is what lets grinding and hedging compose — a bare
counter would overwrite the hedging randomness or need a second input slot. See Backward
Compatibility.

**Why forbid grinding under anti-exfil?** Grinding is "discard nonces I don't like" — the
exact behaviour the protocol exists to catch. This is also already the shipped rule, not a
new constraint: libwally-core refuses `EC_FLAG_GRIND_R` combined with caller-supplied
entropy (`src/sign.c`: `return WALLY_EINVAL; /* Can't use grinding if aux_rand
provided */`), and Jade's signing code documents the same behaviour.

**Why does the signer recompute rather than remember?** Statelessness: no stored nonce to
defend, no abandoned-session cleanup. This follows secp256k1-zkp's design.

**Why not a zero-knowledge proof of correct nonce derivation?** It would work and needs no
host randomness, but proving an HMAC-SHA256 computation is far beyond what a hardware
wallet can do in the time a user will wait.

**Why is this ECDSA-only?** BIP 340 already specifies hedged Schnorr nonces. A Schnorr
anti-exfil analogue exists only as a prototype and deserves its own proposal.

**Where the constants come from.** The tags `s2c/ecdsa/data` and `s2c/ecdsa/point` are
adopted verbatim from libsecp256k1-zkp's `ecdsa_s2c` module, read at commit
`10366dbbbfeb11457f2aae3b23e154ab7d6a1fe4` of
<https://github.com/BlockstreamResearch/secp256k1-zkp>:

- `host_commit` matches `secp256k1_ecdsa_anti_exfil_host_commit`
  (`src/modules/ecdsa_s2c/main_impl.h`): a BIP340-style tagged hash — the code carries the
  midstate of `SHA256("s2c/ecdsa/data") || SHA256("s2c/ecdsa/data")` — over the 32-byte
  `rho`.
- `nonce_tweak` matches `secp256k1_ec_commit_tweak` (`src/eccommit_impl.h`) as invoked by
  the module: SHA-256 from the `s2c/ecdsa/point` tagged midstate over the 33-byte
  compressed serialization of `R` followed by the 32-byte `rho`.
- The signer feeds `c` directly as the RFC 6979 additional input
  (`secp256k1_ecdsa_anti_exfil_signer_commit`); the opening serializes as a plain 33-byte
  compressed point (`secp256k1_ecdsa_s2c_opening_serialize`); host verification compares
  only the x-coordinate of `R + tG`, reduced modulo `n`, against `r`
  (`secp256k1_ecdsa_s2c_verify_commit`).

Jade reaches this code through libwally-core's `wally_ae_*` wrappers (`src/anti_exfil.c`,
read at commit `069441d936748bceae65098eede567d019ff883f` of
<https://github.com/ElementsProject/libwally-core>). The BitBox02 compiles the same module
into its firmware (`ENABLE_MODULE_ECDSA_S2C` in `src/rust/bitbox-secp256k1/build.rs`, with
bindings to the same `anti_exfil` functions in `src/lib.rs`, read at commit
`bc33699516415d7ef28a93222a9a51f5a8044295` of
<https://github.com/BitBoxSwiss/bitbox02-firmware>). The `HedgedNonce/grind` tag has no
shipping counterpart to adopt: the grinding derivation is new in this proposal.

## Backward Compatibility

Everything here produces ordinary ECDSA signatures. Verifiers, nodes and consensus rules
are unaffected, and no coordination or activation is required; a signer can adopt this
unilaterally.

Existing behaviour, surveyed at the commits recorded above (Jade read at commit
`15ce915a20898dda4ca0e3d7ba55ca556f5271f2` of <https://github.com/Blockstream/Jade>):

- **Bitcoin Core** grinds low `R` using a bare 32-byte little-endian counter as the
  RFC 6979 extra input, with no extra input at all on the first attempt. Same goal,
  different bytes: aligning with this document would change the signatures Core produces,
  but not their validity, size, or anything a verifier sees.
- **Electrum, Sparrow, NBitcoin** and other grinding wallets are in the same position.
- **Blockstream Jade** grinds: its plain ECDSA path passes
  `EC_FLAG_ECDSA | EC_FLAG_GRIND_R` to libwally (`main/wallet.c:1185`; likewise
  `main/process/sign_psbt.c:1095`), and libwally's grinder (`src/sign.c`) uses the same
  bare-counter scheme as Core. Jade's plain signatures therefore match Core's rule, not
  this document's derivation — while its anti-exfil signatures match this document as
  written.
- **Hardware signers that do not grind** produce a signature one byte larger than this
  document requires about half the time. Adopting costs roughly one extra scalar
  multiplication per signature and brings their output into line with the software wallets
  driving them.
- **Wallets that take `k` directly from the system RNG** are not compliant and SHOULD move
  to Profile H, a strictly smaller trust assumption.
- **Jade's and the BitBox02's anti-exfil** already uses the constants specified here —
  they are where the constants come from. What both lack is the PSBT transport; each
  currently drives the protocol over its own wire format.

Users who verify a device by reproducing its signatures on a second machine rely on
Profile D. A signer that moves its default to Profile H SHOULD keep Profile D available
and SHOULD say plainly in its release notes that signatures stop being reproducible by
default, so the change is not mistaken for tampering.

## Reference Implementation

Not yet written. Required before this proposal can move to Complete:

- A reference implementation of `nonce()` and of both sides of the anti-exfil extension.
- Test vectors covering, at minimum: `nonce()` with `aux` absent and present, agreement
  with `secp256k1_nonce_function_rfc6979`, a candidate that fails the range check and
  forces the retry loop, a full anti-exfil transcript with its verification, a transcript
  whose opening does not match, and a grinding sequence.
- A PSBT round-trip fixture once field type numbers are assigned.

Test vectors are to be published under CC0-1.0.

## Copyright

This BIP is licensed under the BSD 2-Clause License.
