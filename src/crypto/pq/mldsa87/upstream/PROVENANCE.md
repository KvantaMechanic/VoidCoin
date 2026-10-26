# Provenance — vendored CRYSTALS-Dilithium (ML-DSA-87 / Dilithium5) reference implementation

This directory vendors the `ref/` reference implementation of CRYSTALS-Dilithium
from the upstream pq-crystals project. This file pins the exact upstream revision,
records every local modification, and anchors a SHA256 manifest that the build
verifies on every configure/build so drift or tampering fails the build.

## Upstream source

- **Project:** pq-crystals/dilithium
- **URL:** https://github.com/pq-crystals/dilithium
- **Pinned commit:** `d35ba3fe5449bee3e6d43e1f296c3ca818bd36be`
- **Parameter set:** Dilithium5 (`DILITHIUM_MODE=5`), NIST ML-DSA-87 security level 5
- **Implementation:** `ref` (portable C reference)
- **Vendored on:** 2026-07-16
- **Verified by:** byte-for-byte diff of every vendored file against
  `https://raw.githubusercontent.com/pq-crystals/dilithium/d35ba3fe5449bee3e6d43e1f296c3ca818bd36be/ref/<file>`.
  All files are identical to that commit **except** the two files listed under
  "Local modifications" below, whose diffs are exactly the documented additions
  and nothing else.

The commit above was the tip of `master` at vendoring time. Do not re-point the
`Dilithium5_META.yml` `version:` field at a bare `.../tree/master` — always pin a
commit. If you bump the upstream revision, update the commit hash here, re-run the
manifest regeneration command below, and re-confirm the diff.

## Local modifications (audit VC-18 disclosure)

Only two files diverge from upstream `d35ba3f`, and only to add a single
deterministic, seed-derived keygen entry point used by the VoidCoin wallet. No
upstream algorithm code, constant, or control flow was altered.

| File | Change |
|------|--------|
| `ref/api.h`  | Adds the declaration `int crypto_sign_keypair_from_seed(uint8_t *pk, uint8_t *sk, const uint8_t seed[32]);` (1 line). |
| `ref/sign.c` | Adds the definition of `crypto_sign_keypair_from_seed()` (55 lines). It mirrors upstream `crypto_sign_keypair()` verbatim but replaces the internal `randombytes(seedbuf, SEEDBYTES)` call with a caller-supplied 32-byte seed, so wallet keys are BIP32/seed-recoverable. All domain-separation bytes (`K`, `L`) and the SHAKE256 expansion are kept identical to upstream. |

Rationale: the stock upstream `crypto_sign_keypair()` draws its seed from
`randombytes` and discards it, producing non-recoverable keys — unsuitable for a
deterministic wallet. The wallet keygen path uses only
`MLDSA87GenerateKeypairFromSeed()` → `crypto_sign_keypair_from_seed()`.

## Integrity manifest

`SHA256SUMS` lists the SHA-256 of every vendored file (paths relative to this
directory). It pins the tree **as vendored** — i.e. it already accounts for the
two local modifications above — so it is the authoritative drift/tamper anchor,
independent of network access to upstream.

The build verifies it automatically: `src/crypto/CMakeLists.txt` runs
`VerifyPqProvenance.cmake` as a build dependency of the `voidcoin_mldsa87`
static library, and registers it as the `pq_provenance` CTest. Any added,
removed, or byte-changed vendored file fails the build with a `FATAL_ERROR`
naming the offending path.

Manual check (from this directory):

```
sha256sum -c SHA256SUMS
```

### Regenerating the manifest (only when intentionally updating the vendored tree)

```
cd src/crypto/pq/mldsa87/upstream
find . -type f ! -name SHA256SUMS ! -name PROVENANCE.md -print0 \
  | sort -z | xargs -0 sha256sum | sed 's#\./##' > SHA256SUMS
```

Then update the pinned commit + local-modification table above and re-run the
upstream diff verification.

## License

Upstream is released under Apache-2.0 OR public-domain (CC0); see `LICENSE` in
this directory (vendored unchanged from the pinned commit).
