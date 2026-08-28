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

This document specifies how a Bitcoin signer should derive the per-signature secret nonce
`k` used in ECDSA signatures over secp256k1.

It defines a single nonce function based on RFC 6979 that takes an optional 32-byte
auxiliary input, and it defines three ways to fill that input: leave it out (fully
deterministic), fill it with fresh randomness (hedged), or fill it with a commitment
supplied by a separate host device.

It also defines an optional extension in which the signer additionally tweaks its nonce
point by a sign-to-contract commitment to host-supplied randomness, so that the host can
check afterwards that the nonce was not chosen to leak key material. This extension is the
"anti-exfil" protocol already shipped by Blockstream Jade and the BitBox02, written down
here in one place, plus the PSBT fields needed to carry it between wallets.

## Motivation

ECDSA needs a secret nonce `k` for every signature. `k` is the most fragile part of the
scheme:

- If `k` repeats across two signatures with the same key, the key falls out with school
  algebra.
- If `k` is biased, even by a bit or two, the key falls out with lattice methods.
- If `k` is chosen by an adversary who also controls the signing code, `k` becomes a
  covert channel that can carry the seed itself. Dark Skippy (2024) showed a whole 12-word
  seed being recovered from two signatures this way.

RFC 6979 fixes the first two problems by deriving `k` from the key and the message with
HMAC-SHA256 instead of from a random number generator. Almost every Bitcoin wallet already
does something close to this, but "something close" is doing a lot of work: there is no
Bitcoin-specific document that says what a compliant signer does, so implementations differ
in ways that are invisible until someone tries to reproduce a signature. Bitcoin Core and
Electrum feed a counter into the nonce derivation to grind for a low `R`; libsecp256k1's
RFC 6979 function accepts an extra 32-byte input that most callers ignore; some wallets
still take `k` straight from the system RNG.

Full determinism is also not the end state. Deterministic signing makes fault-injection and
differential power analysis easier: an attacker who can get the same nonce used twice under
slightly different conditions can compare the two runs. The IRTF's work on hedged signatures
and BIP 340's `aux_rand` both respond to this by mixing fresh randomness back in, in a way
that does not depend on that randomness being good. ECDSA in Bitcoin has no equivalent
written down.

Finally, determinism does nothing at all against a malicious signer, because the person
holding the device cannot check that the device did what it claimed. The only practical
defence is to let a second device contribute to the nonce and then verify that its
contribution was used. That is what anti-exfil does. It has been deployed since 2021, and it
still has no specification outside a library header and two blog posts, no PSBT
representation, and therefore no way for an arbitrary wallet to drive an arbitrary signer.

This proposal covers all three: one nonce function, one place to put extra input, and one
optional protocol for host-verifiable nonces.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", and "MAY" are to be
interpreted as described in RFC 2119.

This document applies to ECDSA signatures over secp256k1. Schnorr signatures are out of
scope: BIP 340 already specifies a hedged nonce derivation.

### Notation

- `n` is the order of the secp256k1 group; `G` is the generator.
- `sk` is a signing key, an integer in `[1, n-1]`.
- `msg` is the 32-byte message hash being signed (for transactions, the sighash).
- `bytes(x)` is the 32-byte big-endian encoding of the integer `x`.
- `cbytes(P)` is the 33-byte compressed SEC encoding of the curve point `P`.
- `int(b)` is the integer whose big-endian encoding is the byte string `b`.
- `LE32(i)` is the 4-byte little-endian encoding of the integer `i`.
- `||` is byte concatenation.
- `tagged_hash(tag, m)` is `SHA256(SHA256(tag) || SHA256(tag) || m)`, as defined in BIP 340,
  where `tag` is the UTF-8 encoding of the given string.
- `HMAC(K, m)` is HMAC-SHA256.

### Nonce derivation

A compliant signer MUST derive `k` as `nonce(sk, msg, aux)`, where `aux` is either absent or
a 32-byte string, defined as follows.

Let `keydata = bytes(sk) || msg`, with `|| aux` appended if `aux` is present.

```
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

This is the HMAC_DRBG construction of RFC 6979 section 3.2 with the additional input of
section 3.6, specialised to secp256k1 and SHA-256. It is byte-for-byte the behaviour of
`secp256k1_nonce_function_rfc6979` in libsecp256k1 when `ndata` is set to `aux` and `algo16`
is null, so a signer built on libsecp256k1 is compliant without new code.

Note that `msg` is used as given. A literal reading of RFC 6979 applies `bits2octets`, which
reduces the message hash modulo `n` before use. The two differ only when the message hash is
numerically at least `n`, which happens with probability about 2^-128 and has never been
observed on mainnet. Implementations MUST follow the pseudocode above rather than reducing,
so that all signers agree.

### Auxiliary input

The `aux` input is where a signer adds anything beyond the key and the message. Three
profiles are defined. A signer MUST document which profile it implements, and MAY implement
more than one.

**Profile D — deterministic.** `aux` is absent. Signatures are a pure function of key and
message, so they can be reproduced on other hardware. This profile SHOULD be offered as a
non-default option for users who want to compare signers, and SHOULD NOT be the default
(see Rationale).

**Profile H — hedged.** `aux` is 32 bytes read from a cryptographically secure RNG,
freshly for each signature. This is the RECOMMENDED default for software wallets. If the RNG
fails or returns a constant, the result degrades to Profile D rather than to a repeated
nonce, so no new failure mode is introduced.

**Profile X — anti-exfil.** `aux` is the 32-byte host commitment `c` defined below. This
profile is only meaningful together with the nonce tweak in the next section.

### Low-R grinding

Under Profiles D and H, a signer MUST grind for a low `R` value. `R = kG` is low if the
x-coordinate of `R` is less than 2^255, that is, if its 32-byte big-endian encoding has a
leading byte below `0x80`. A low `R` serialises in DER as 32 bytes rather than 33, saving one
byte of witness weight per signature, and it makes signature size predictable for fee
estimation.

Let `aux_0` be the auxiliary input for the chosen profile, or 32 zero bytes under Profile D.
The signer computes, for `i = 0, 1, 2, ...`:

```
aux_i = tagged_hash("HedgedNonce/grind", aux_0 || LE32(i))
k_i   = nonce(sk, msg, aux_i)
```

and signs with the first `k_i` whose `R = k_i G` is low. The expected number of attempts is
two. A signer MUST NOT cap the loop at a fixed small number and fall back to a high `R`; it
MUST keep incrementing `i`.

Note that under Profile D this makes `aux` present rather than absent, since `aux_0` is
hashed even at `i = 0`. Profile D remains reproducible — any signer following this document
derives the same `k` — but the resulting signatures differ from those of a signer that calls
RFC 6979 with no additional input at all.

Under Profile X the signer MUST NOT grind, and MUST sign with the nonce derived at `i = 0`
without a low-`R` check. Grinding and selective aborting look identical to the host, so a
signer permitted to grind is a signer permitted to bias its nonce. Anti-exfil signatures will
therefore be one byte larger about half the time. This is the intended trade.

The following are forbidden in every profile:

- Reusing an `aux` value across two signatures that share a key and a message hash but
  differ in anything else. Doing so produces the same nonce for two different signing
  attempts.
- Deriving `aux` from anything secret other than by the construction above. `aux` is not a
  second key; it is salt.
- Skipping the loop's range check and reducing an out-of-range candidate modulo `n`. That
  introduces exactly the bias RFC 6979 exists to avoid.

Implementations SHOULD compute the derivation in constant time with respect to `sk` and `k`.

### Anti-exfil extension

This section is OPTIONAL and applies when signing is split between a *host* (the wallet
software choosing the transaction) and a *signer* (the device holding the key). It assumes
the host is honest and the signer may not be. It gives the host a way to check, after the
fact, that the signer's nonce was not chosen freely.

Define:

```
host_commit(rho) = tagged_hash("HedgedNonce/host", rho)
nonce_tweak(R, rho) = tagged_hash("HedgedNonce/point", cbytes(R) || rho)
```

The protocol runs as follows.

1. **Host commits.** The host draws `rho`, 32 bytes from a cryptographically secure RNG,
   computes `c = host_commit(rho)`, and sends `c` to the signer. It MUST NOT reveal `rho`
   yet.

2. **Signer commits.** The signer computes `k = nonce(sk, msg, c)` and `R = kG`, and returns
   `cbytes(R)` to the host as its *opening*. The signer stores nothing; step 4 recomputes
   this.

3. **Host reveals.** The host sends `rho`.

4. **Signer signs.** The signer recomputes `c' = host_commit(rho)`, `k = nonce(sk, msg, c')`
   and `R = kG`. It computes `t = int(nonce_tweak(R, rho))` and `k' = (k + t) mod n`. If
   `t >= n` or `k' = 0`, the signer MUST abort. Otherwise it produces the ECDSA signature
   `(r, s)` using `k'` as the nonce and returns it.

5. **Host verifies.** The host checks that `(r, s)` is a valid signature on `msg` under the
   expected public key, parses `R` from the opening, recomputes
   `t = int(nonce_tweak(R, rho))`, and checks that the x-coordinate of `R + tG`, reduced
   modulo `n`, equals `r`. If the check fails, the host MUST treat the signature as
   untrusted, MUST NOT broadcast it, and MUST warn the user.

Because the signer re-derives its nonce from `rho` in step 4 rather than remembering it, a
signer needs no per-session state, and a host that restarts the protocol with the same `rho`
gets the same `R`.

#### Handling failures

Steps 2 through 5 are where a malicious signer retains its last sliver of freedom: it can
refuse to sign whenever the resulting nonce does not carry the bit it wants to leak. The
host's response to a failure is therefore part of the security of this protocol, not an
implementation detail.

- On any failure or disconnection after step 1, the host MUST retry with **the same** `rho`,
  and MUST check that the signer returns **the same** `R`. Retrying with fresh `rho` converts
  the protocol into a working exfiltration channel.
- If the signer returns a different `R` for the same `rho`, or fails to produce a verifying
  signature, the host MUST surface this to the user in plain language, not as a silent retry
  or a generic error toast.
- Hosts SHOULD keep a persistent count of such failures per device. Leaking a key this way
  needs on the order of a hundred aborts, and those aborts accumulate across device
  replacements as long as the keys stay the same. A host SHOULD recommend sweeping to fresh
  keys once the count reaches a small number, on the order of twenty.

### PSBT fields

Anti-exfil needs two round trips, so a PSBT-based flow passes the transaction to the signer
twice. Three per-input fields are defined. Field type numbers are marked TBD pending
assignment.

| Name | Type | Key data | Value data |
| --- | --- | --- | --- |
| `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT` | TBD | 33-byte compressed public key of the key expected to sign | 32-byte `c` |
| `PSBT_IN_ANTI_EXFIL_SIGNER_OPENING` | TBD | 33-byte compressed public key | 33-byte `cbytes(R)` |
| `PSBT_IN_ANTI_EXFIL_HOST_NONCE` | TBD | 33-byte compressed public key | 32-byte `rho` |

First pass: the host adds `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT`. The signer adds
`PSBT_IN_ANTI_EXFIL_SIGNER_OPENING` and adds no signature.

Second pass: the host adds `PSBT_IN_ANTI_EXFIL_HOST_NONCE` and returns the PSBT. The signer
adds `PSBT_IN_PARTIAL_SIG` as usual.

The host MUST remove all three fields before finalizing, and MUST NOT persist `rho` after
verification. A signer that receives `PSBT_IN_ANTI_EXFIL_HOST_NONCE` without a matching
commitment field MUST refuse to sign.

### What this does and does not protect against

In scope:

- Nonce reuse and nonce bias from a weak or broken RNG (all profiles).
- Fault and side-channel attacks that depend on the signer repeating a nonce (Profiles H
  and X).
- A malicious or backdoored signer leaking key material through its nonces, given an honest
  host (Profile X).

Out of scope:

- A signer that generated the user's seed with bad entropy in the first place. Nonce
  handling cannot help there.
- A signer and host that are both compromised.
- Nonce bias achieved through selective aborting, which is bounded rather than eliminated;
  see Handling failures.
- Anything about Schnorr or taproot signatures.

## Rationale

**Why not simply mandate plain RFC 6979?** Because plain determinism is now understood to
trade one class of attack for another. A device that produces the same signature every time
is a device an attacker can run twice under a glitched clock and compare. Hedging removes
that without giving up anything: an attacker who controls the RNG completely is left facing
Profile D, which is the security we would have had anyway. This is the same reasoning behind
BIP 340's `aux_rand` and behind the IRTF's hedged-signatures draft, and it is why hedged is
the default here and reproducible is the option.

**Why put the extra input inside the HMAC rather than tweaking the key or the message?**
Because `secp256k1_nonce_function_rfc6979` already takes it there. Every wallet in the
ecosystem that uses libsecp256k1 gets Profile H by passing a pointer it is currently passing
as null.

**Why require grinding rather than allow it?** Low-`R` grinding is already what Bitcoin
Core, Electrum, Sparrow and NBitcoin do, so most of the ecosystem grinds and most hardware
signers do not. That split is the main reason a user who compares two wallets' signatures for
the same input sees a mismatch and reasonably concludes their device is backdoored. Making
grinding part of the specification rather than a local optimisation makes that comparison
meaningful again, and it costs a byte of witness weight per signature not to. The expected
cost is one extra scalar multiplication per signature, which is negligible on a phone and
tolerable on a microcontroller.

Note that Core's current rule differs: it uses a bare little-endian counter as the extra
entropy rather than a hash of it, and it makes its first attempt with no extra entropy at
all. Hashing the counter together with the profile's `aux_0` is what lets grinding and
hedging compose — a bare counter would either overwrite the hedging randomness or need a
second input slot. See Backward Compatibility.

**Why forbid grinding under anti-exfil?** A grinding signer discards nonces it does not like
and tries again. A signer leaking key material through selective aborts also discards nonces
it does not like and tries again. From the host's side these are the same behaviour, so a
protocol that permits the first cannot detect the second. Since anti-exfil exists precisely
to make nonce selection observable, grinding has to go. One byte of witness weight roughly
half the time is a small price for the only property this extension offers.

**Why does the signer recompute rather than remember?** Statelessness. A signer that stores
`k` between two messages has to defend that storage, and has to decide what to do when a
session is abandoned. Re-deriving from `rho` removes the question. This follows the design
already used in secp256k1-zkp.

**Why the commit-reveal, instead of the host just sending randomness?** Two separate
attacks. If the signer learned `rho` before committing to `R`, it could grind `R` so the
final nonce still carries its bit. If the host learned `R` before committing to `rho`, it
could re-run the signer three times with the same `R` and different `rho` and solve for the
key algebraically. Each half of the exchange blocks one of these.

**Why not a zero-knowledge proof of correct nonce derivation?** It works, and it needs no
host randomness, but proving an HMAC-SHA256 computation is far beyond what a hardware wallet
can do in the time a user will wait.

**Why is this ECDSA-only?** BIP 340 already specifies hedged Schnorr nonces. An anti-exfil
analogue for Schnorr has been prototyped but not deployed, and folding a second, unreviewed
scheme into this document would make it harder to review either. It should be a separate
proposal.

**Open item: tag strings.** The tag strings `HedgedNonce/host`, `HedgedNonce/point` and
`HedgedNonce/grind` are placeholders. Blockstream's secp256k1-zkp `ecdsa_s2c` module already
uses its own domain-separated hashes for the equivalent values, and Jade and the BitBox02
ship them. Before this proposal reaches Complete these tags MUST be reconciled with the
constants in that module, either by adopting them verbatim or by documenting deliberately
that the two are not interoperable. Getting this wrong means a spec-compliant host cannot
verify a shipping device.

## Backward Compatibility

Signatures produced under this proposal are ordinary ECDSA signatures. Verifiers, nodes and
consensus rules are unaffected, and no coordination or activation is required. A signer can
adopt this unilaterally.

The following existing behaviours are not compliant as written:

- **Bitcoin Core** uses RFC 6979 with a 32-byte extra-entropy value that is a plain
  little-endian counter, incremented until the signature has a low `R`. It reaches the same
  goal by a different route: the nonce function matches, the grinding rule does not. Aligning
  would change the signatures Core produces for a given key and message; it would not change
  their validity, their size, or anything a verifier sees.
- **Wallets that grind low `R` with their own counter scheme** (Electrum, Sparrow, NBitcoin
  and others) are in the same position.
- **Signers that do not grind at all**, which is most hardware wallets, would produce
  signatures one byte larger than this document requires about half the time. Adopting the
  grinding rule costs them roughly one extra scalar multiplication per signature and brings
  their output into line with the software wallets driving them.
- **Wallets that take `k` directly from the system RNG** are not compliant and SHOULD move
  to Profile H, which is a strictly smaller trust assumption.
- **Blockstream Jade and the BitBox02** implement an anti-exfil protocol with the same
  structure as the extension above but with their own hash constants and their own transport,
  not PSBT. Whether they become compliant depends on the tag reconciliation noted in the
  Rationale.

Users who currently verify a hardware wallet by reproducing its signatures on a second
machine rely on Profile D. Any signer that moves its default to Profile H SHOULD keep
Profile D available and SHOULD say plainly in its release notes that signatures will no
longer be reproducible by default, so that this is not mistaken for tampering.

## Reference Implementation

Not yet written. Required before this proposal can move to Complete:

- A reference implementation of `nonce()` and of both sides of the anti-exfil extension.
- Test vectors covering, at minimum: `nonce()` with `aux` absent and present, agreement with
  `secp256k1_nonce_function_rfc6979`, a candidate that fails the range check and forces the
  retry loop, a full anti-exfil transcript with its verification, a transcript whose opening
  does not match, and a grinding sequence.
- A PSBT round-trip fixture once field type numbers are assigned.

Test vectors are to be published under CC0-1.0.

## Copyright

This BIP is licensed under the BSD 2-Clause License.
