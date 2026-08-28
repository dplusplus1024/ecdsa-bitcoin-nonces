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
Created: 2026-08-28
License: BSD-2-Clause
Discussion: ?
Requires: 174
```

## Abstract

Every ECDSA signature needs a one-time secret number, the nonce `k`. This document
standardises how a Bitcoin signer chooses it.

The first part covers a signer working alone, such as a software wallet: derive `k` from
the key and the message with RFC 6979, with no added randomness, and retry with a counter
until the signature is its minimum size ("low-R grinding"). This is what software wallets
such as Bitcoin Core already do; writing it down bit-for-bit makes every signature
reproducible, and therefore auditable.

The second part is an optional nonce tweak ("anti-exfil") for a two-device setup — a
software wallet driving a hardware signer. The wallet supplies randomness that is tweaked
into the signer's nonce point, and it can verify afterwards that the tweak was really
applied, so even a malicious signer cannot smuggle data out through its signatures. The
protocol is the one Blockstream Jade and the BitBox02 already ship, written down in one
place, plus new PSBT fields to run it between any wallet and any signer.

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
says exactly what a compliant signer does. Bitcoin Core grinds for smaller signatures with
a counter; other wallets grind with their own variations; some still take `k` straight from
the system RNG. Two honest wallets can sign the same input and produce different
signatures, and a user has no way to tell that mismatch from a backdoor. Pinning down one
derivation turns "compare two devices' signatures" into a real audit.

Determinism still does nothing against a malicious signer, because the user cannot see
inside the device. The practical defence is to let a second device contribute randomness to
the nonce and then check that it was used. That protocol, anti-exfil, has shipped in
hardware since 2021 — and is specified nowhere outside library source and blog posts, with
no standard PSBT representation and therefore no interoperability.

This document covers both: one deterministic derivation for a signer working alone, and one
protocol for adding verifiable entropy when two devices share the job.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", and "MAY" are to
be interpreted as described in RFC 2119.

This document applies to ECDSA over secp256k1. Schnorr signatures are out of scope: BIP 340
already specifies its own nonce derivation. A signer MUST NOT claim compliance with this
document for taproot/BIP 340 inputs. A transaction that anti-exfils its ECDSA inputs and
uses an unspecified nonce for its Schnorr inputs is only half-protected.

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

The `aux` input has exactly two defined uses: the grinding counter in the next section, and
the host commitment in the anti-exfil extension. A signer MUST NOT put anything else in it
— no RNG output, no device identifiers, no second secret. Local randomness in the nonce
destroys reproducibility, and unverifiable entropy is exactly what this document exists to
remove; a wallet that wants extra randomness in the nonce should use the anti-exfil tweak,
where its use can be checked.
Implementations SHOULD compute the derivation in constant time with respect to `sk` and
`k`.

### Low-R grinding and low-S normalisation

DER encodes the `r` component of a signature as a signed integer, so an `r` whose most
significant bit is set costs one extra padding byte. `r` is *low* if and only if
`r < 2^255`, equivalently if `bytes(r)` starts with a byte below `0x80`. That is the check
Bitcoin Core's `SigHasLowR` performs on the 32-byte compact serialisation of `r`. Grinding
retries the nonce until `r` is low, making every signature its minimum, predictable size.

Outside the anti-exfil extension, a signer MUST sign as follows:

```
k_0 = nonce(sk, msg)                                    (aux absent)
k_i = nonce(sk, msg, LE32(i) || 28 zero bytes)          for i = 1, 2, 3, ...
```

and use the first `k_i` that yields a usable signature:

- `r ≠ 0` and `s ≠ 0`
- `r` is low (`r < 2^255`)
- `s` is low: if `s > n/2`, replace `s` with `n - s`

The expected number of grind attempts is two. The signer MUST NOT cap the loop and fall
back to a high `r`. Passing 32 zero bytes is not the same as omitting `aux`; the first
attempt MUST omit `aux`.

This is, deliberately, the exact grinding that Bitcoin Core ships, plus the low-S
normalisation Core and network policy already apply (see Rationale for provenance). No
randomness is involved, so any two compliant signers produce identical signatures for the
same key and message, which is what lets a user check one device against another.

Under the anti-exfil extension the signer MUST NOT grind: it signs once, with the tweaked
nonce from the protocol below, and no low-`r` check. If `r = 0` or `s = 0` (probability
about 2^-256) it MUST fail rather than retry. If `s > n/2` it MUST replace `s` with
`n - s`. To the host, "retry until I like the R" and "abort until the nonce leaks the bit
I want" are the same observable behaviour, so a protocol that permits one cannot detect
the other. Anti-exfil signatures are therefore one DER byte larger about half the time.
This is the intended trade, and it is already how the shipping implementations behave
(see Rationale).

### Anti-exfil extension

This section is OPTIONAL. It applies when signing is split between a *host* (the wallet
software building the transaction) and a *signer* (the device holding the key), and it
assumes an honest host checking a possibly-dishonest signer. The mechanism is a tweak:
the signer's nonce point is shifted by a hash of host-supplied randomness, and the host
checks that shift in the final signature.

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
   fresh for every signature request. It sends `c = host_commit(rho)` to the signer and
   keeps `rho` secret for now.

2. **Signer commits.** The signer computes `k = nonce(sk, msg, c)` and `R = kG`, and
   returns `cbytes(R)` to the host as its *opening*. It stores nothing; step 4 recomputes
   this. The signer MUST NOT produce a signature in this step.

3. **Host reveals.** The host sends `rho`.

4. **Signer signs.** The signer computes `c' = host_commit(rho)`. If this signing attempt
   is bound to a previously received `c` (including via the matching PSBT commitment
   field), the signer MUST reject the attempt unless `c' = c`. It then computes
   `k = nonce(sk, msg, c')` and `R = kG`, then tweaks its nonce:

   ```
   t  = int(nonce_tweak(R, rho))
   k' = (k + t) mod n
   ```

   `t` is the integer value of the 32-byte tagged hash; it MUST NOT be reduced modulo `n`
   before the range check. If `t >= n` or `k' = 0` (probability about 2^-128) the signer
   MUST fail rather than substitute another nonce. This matches
   `secp256k1_ec_seckey_tweak_add_helper`, which rejects a tweak `≥ n`. Otherwise the
   signer returns the ECDSA signature `(r, s)` made with nonce `k'`, with `s` normalised
   low as above.

5. **Host verifies.** The host checks that `(r, s)` is a valid signature on `msg` under
   the expected public key, recomputes `t = int(nonce_tweak(R, rho))` from the opening
   (the full 33-byte `R`, so the y-coordinate that went into the tweak is fixed),
   and checks:

   ```
   x(R + tG) mod n == r
   ```

   Only the x-coordinate is compared, because the y-coordinate is not part of an ECDSA
   signature. The reduction modulo `n` is required: `x(R + tG)` lives in `[0, p)` and
   can in principle exceed `n`. If either check fails, the host MUST treat the signature
   as untrusted, MUST NOT broadcast it, and MUST warn the user.

Because everything is re-derived from `rho`, the signer needs no per-session state, and
re-running the protocol with the same `rho` yields the same `R`.

Each half of the commit-reveal blocks one attack. If the signer saw `rho` before fixing
`R`, it could keep re-deriving until the final nonce carried a bit it wants to leak. If the
host saw `R` before committing to `rho`, it could re-run the signer with different `rho`
values against the same `R` and solve for the key algebraically. Fresh `rho` per signature
matters for the same reason: a `rho` the signer has seen before is a `rho` it knew before
committing.

The two-round shape is deliberate. A one-round "host sends `rho`, signer tweaks" protocol
is cheaper on air-gapped QR transports and has been proposed (Moonsettler, Delving
Bitcoin). It leaves a grind channel: the signer can resample its inner nonce until the
tweaked `R` leaks a bit. This document specifies the deployed two-round protocol and
MUST NOT be "flattened" to one round for transport convenience.

#### Handling failures

A malicious signer's last freedom is refusing to sign when the nonce does not leak what it
wants. The host's failure handling is therefore part of the protocol, not an implementation
detail:

- After any transport failure or disconnection past step 1, the host MUST retry with
  **the same** `rho` and MUST check that the signer returns **the same** `R`. Retrying
  with fresh `rho` turns the protocol into a working exfiltration channel.
- A different `R` for the same `rho`, or a signature that fails verification, MUST abort
  the attempt. The host MUST show the user that the signer returned a nonce or signature
  that did not match the protocol, MUST NOT silently retry, and MUST NOT treat it as a
  generic I/O error.
- Hosts SHOULD keep a persistent per-device abort count covering verification failures
  and `R`-mismatch failures, not ordinary transport retries of the same `rho`.
  Blockstream's 2021 write-up estimates that leaking a key by selective abort needs on
  the order of forty user-visible failures while the keys stay the same. A host SHOULD
  recommend sweeping to fresh keys once the count reaches a small number, on the order
  of twenty, and SHOULD treat that recommendation as a security event, not a settings
  tooltip.

### PSBT fields

Anti-exfil needs two round trips, so a PSBT-based flow passes the transaction to the signer
twice. Three per-input fields are defined; type numbers are TBD pending assignment in the
BIP 174 field registry.

| Name | Type | Key data | Value data |
| --- | --- | --- | --- |
| `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT` | TBD | 33-byte compressed public key of the key expected to sign | 32-byte `c` |
| `PSBT_IN_ANTI_EXFIL_SIGNER_OPENING` | TBD | 33-byte compressed public key | 33-byte `cbytes(R)` |
| `PSBT_IN_ANTI_EXFIL_HOST_NONCE` | TBD | 33-byte compressed public key | 32-byte `rho` |

First pass: the host adds `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT`; the signer adds
`PSBT_IN_ANTI_EXFIL_SIGNER_OPENING` and MUST NOT add `PSBT_IN_PARTIAL_SIG` for that
key. Second pass: the host adds `PSBT_IN_ANTI_EXFIL_HOST_NONCE`; the signer adds
`PSBT_IN_PARTIAL_SIG` as usual.

A signer that receives `PSBT_IN_ANTI_EXFIL_HOST_NONCE` MUST refuse to sign unless a
matching `PSBT_IN_ANTI_EXFIL_HOST_COMMITMENT` for the same key is present and
`host_commit(rho)` equals that commitment. A signer that receives
`PSBT_IN_ANTI_EXFIL_HOST_NONCE` on an input that already carries
`PSBT_IN_PARTIAL_SIG` for the same key MUST refuse (the device signed early).

The host MUST remove all three fields before finalizing. The host MUST zeroize `rho`
after verification and MUST NOT write `rho` to disk, to logs, or to any PSBT that
will be archived or uploaded. A PSBT is not a secret-storage format.

Until standard type numbers are assigned, implementers MAY carry the same three values
in BIP 174 proprietary fields. An experimental mapping already in use on a Jade fork
and in Sparrow issue discussion uses identifier `ae` (`0xFC 0x02 "ae"`) with subtypes
`0x00` host commitment, `0x01` signer opening, `0x02` host entropy, keyed by the
33-byte compressed signer public key. A later revision of this document SHOULD either
adopt that mapping or define a one-time conversion.

### What this does and does not protect against

In scope: nonce reuse and nonce bias — the nonce never touches an RNG in standard signing;
silent divergence between implementations, since any two compliant signers can be checked
against each other; and a malicious signer leaking key material through its nonces, given
an honest host (anti-exfil).

Out of scope: a seed that was generated with bad entropy in the first place; a signer and
host that are both compromised; the bounded leak achievable by selective aborting (see
Handling failures); fault-injection and power-analysis attacks on a standalone signer,
which fully deterministic signing deliberately accepts (see Rationale); Schnorr, taproot,
or any claim that installing this BIP makes a hardware wallet "trusted."

## Rationale

**Why fully deterministic — didn't BIP 340 decide mixing in randomness was better?**
Hedging the nonce with local randomness defends an honest device against fault and
power-analysis attacks, but it costs the one audit an ordinary user can actually perform:
reproducing a signature on independent hardware and comparing. It also defends against
nothing when the signer itself is the adversary, since a malicious device can put whatever
it likes in its "randomness". This document keeps the standalone path reproducible and puts
entropy where it can be verified — the anti-exfil protocol, where the randomness is the
host's and its use is checked. A hedged mode could be added later as a separate,
clearly-labelled profile without disturbing either part.

**Why require grinding rather than allow it?** Bitcoin Core and most software wallets
already grind, so the low-`R` size is already the de facto standard; a signer that does not
grind just produces signatures that cost one byte more, half the time, and that cannot be
compared against a grinding wallet's. Making the rule universal makes the comparison
meaningful. The expected cost is one extra signing attempt per signature.

**Why this exact counter?** Because it is the one already deployed. Bitcoin Core grinds
with a 32-byte extra input holding a little-endian counter, nothing on the first attempt,
and libwally-core independently implements the identical scheme. Adopting the shipped
bytes means existing software wallets are compliant as-is, and a document with no novel
cryptography in it is a document that is easy to check.

**Why require low-S in the same breath?** The goal is byte-identical signatures. Low-R
without low-S still allows `(r, s)` versus `(r, n-s)`. Bitcoin Core normalises S, and
BIP 62/146 made low-S standard network policy. Omitting it would make the audit claim
false.

**Why forbid grinding under anti-exfil?** Grinding is "discard nonces I don't like" — the
exact behaviour the protocol exists to catch. This is also already the shipped rule, not a
new constraint: libwally-core refuses `EC_FLAG_GRIND_R` combined with caller-supplied
entropy (`src/sign.c`: `return WALLY_EINVAL; /* Can't use grinding if aux_rand
provided */`), and Jade's signing code documents the same behaviour.

**Why does the signer recompute rather than remember?** Statelessness: no stored nonce to
defend, no abandoned-session cleanup. This follows secp256k1-zkp's design.

**Why bind `rho` to the step-1 commitment at sign time?** A stateless signer that only
recomputes from the revealed `rho` will happily sign a second-pass PSBT whose `rho` does
not hash to the first-pass `c`. The host would catch that on verify if the host is
honest and still has the original `c`. Binding the two on the signer as well stops a
confused-deputy pass-2 and matches how a two-pass PSBT is actually built.

**Why not a zero-knowledge proof of correct nonce derivation?** It would work and needs no
host randomness, but proving an HMAC-SHA256 computation is far beyond what a hardware
wallet can do in the time a user will wait.

**Why is this ECDSA-only?** BIP 340 already specifies Schnorr nonces. A Schnorr anti-exfil
analogue exists only as a prototype and deserves its own proposal. Leaving taproot out of
scope is not the same as claiming taproot inputs are protected.

**Relation to BIP 461.** Liam Gilligan's Informational draft "Deterministic ECDSA
Signatures" (BIP 461, `bitcoin/bips#2224`) documents Core's RFC 6979 + low-R grind +
low-S construction for the same reproducibility reason. This document keeps that
construction as its standalone baseline so the anti-exfil extension has a well-defined
starting point, and defers to 461 for the historical write-up of the grind. The two
should not fork the counter encoding.

**Where the constants come from.** Nothing in this document is newly invented except the
PSBT fields; every constant was read from shipping code.

The grinding scheme is Bitcoin Core's, from `CKey::Sign` (`src/key.cpp`): no extra input
on the first attempt, then a zero-padded 32-byte little-endian counter starting at 1.
libwally-core implements the identical scheme in `wally_ec_sig_from_bytes_aux`
(`src/sign.c`, read at commit `069441d936748bceae65098eede567d019ff883f` of
<https://github.com/ElementsProject/libwally-core>).

The tags `s2c/ecdsa/data` and `s2c/ecdsa/point` are adopted verbatim from
libsecp256k1-zkp's `ecdsa_s2c` module, read at commit
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
same commit as above). The BitBox02 compiles the same module into its firmware
(`ENABLE_MODULE_ECDSA_S2C` in `src/rust/bitbox-secp256k1/build.rs`, with bindings to the
same `anti_exfil` functions in `src/lib.rs`, read at commit
`bc33699516415d7ef28a93222a9a51f5a8044295` of
<https://github.com/BitBoxSwiss/bitbox02-firmware>).

## Backward Compatibility

Everything here produces ordinary ECDSA signatures. Verifiers, nodes and consensus rules
are unaffected, and no coordination or activation is required; a signer can adopt this
unilaterally.

Existing behaviour, surveyed at the commits recorded above (Jade read at commit
`15ce915a20898dda4ca0e3d7ba55ca556f5271f2` of <https://github.com/Blockstream/Jade>):

- **Bitcoin Core** is compliant as written: the grinding scheme above is Core's own,
  adopted deliberately, and Core normalises S.
- **Blockstream Jade**'s anti-exfil is the secp256k1-zkp module this document adopts, so
  it matches the extension as written. When driven without anti-exfil, its fallback ECDSA
  path grinds via libwally (`EC_FLAG_ECDSA | EC_FLAG_GRIND_R`, `main/wallet.c:1185`;
  likewise `main/process/sign_psbt.c:1095`), so it happens to match the first part as
  well.
- **The BitBox02's anti-exfil** likewise matches as written — it is one of the two
  deployments the constants were taken from. Like Jade, what it lacks is the standard
  PSBT transport; both devices currently run the protocol over their own wire formats.
- **Electrum** aligned its grind counter with Core (Electrum PR 4655, completed in
  PR 5820). Other software wallets that grind low `R` (Sparrow, NBitcoin, and others)
  are byte-for-byte compliant exactly if their `aux` encoding matches Core's — a
  statement to check with test vectors, not one this draft has verified.
- **Hardware signers that do not grind** produce a signature one byte larger than this
  document requires about half the time. Adopting costs roughly one extra signing attempt
  per signature and brings their output into line with the software wallets driving them.
- **Wallets that take `k` from the system RNG**, or mix local randomness into RFC 6979,
  are not compliant and SHOULD adopt this derivation, which removes the RNG from the nonce
  path entirely.

Because standard-mode signatures are deterministic, a user can verify any compliant signer
by replaying the same key and message on independent software and comparing bytes. That
check is the point of pinning the derivation down; anti-exfil signatures, which
intentionally differ, are verified through the protocol instead. Two QR rounds on an
air-gapped signer is the cost of anti-exfil; that cost is why one-round variants keep
getting proposed, and why this document refuses them.

## Reference Implementation

Not yet written. Required before this proposal can move from Draft:

- A reference implementation of `nonce()`, the grinding loop, and both sides of the
  anti-exfil extension.
- Test vectors covering, at minimum: `nonce()` with `aux` absent and present, agreement
  with `secp256k1_nonce_function_rfc6979`, a candidate that fails the range check and
  forces the retry loop, a grinding sequence that needs several attempts, a low-S flip,
  a full anti-exfil transcript with its verification, a transcript whose opening does
  not match, a second-pass `rho` that does not hash to `c`, and a second-pass PSBT that
  already carries a partial signature.
- A PSBT round-trip fixture once field type numbers are assigned.

Test vectors are to be published under CC0-1.0.

## References

- RFC 6979, Deterministic Usage of DSA and ECDSA
- RFC 2119, Key words for use in RFCs to Indicate Requirement Levels
- BIP 62 / BIP 146, low-S
- BIP 174, PSBT
- BIP 340, Schnorr Signatures for secp256k1
- Bitcoin Core PR 13666, Always create signatures with Low R values
- BIP 461 draft, Deterministic ECDSA Signatures, `bitcoin/bips#2224`
- Blockstream, "Anti-Exfil: Stopping Key Exfiltration", 2021
- Dark Skippy, 2024, https://darkskippy.com/
- Moonsettler, "Non interactive anti-exfil (airgap compatible)", Delving Bitcoin,
  https://delvingbitcoin.org/t/non-interactive-anti-exfil-airgap-compatible/1081
- libsecp256k1-zkp `ecdsa_s2c` module
- Sparrow issue #2062 / Jade issue #332, experimental PSBT `ae` fields

## Copyright

This BIP is licensed under the BSD 2-Clause License.
