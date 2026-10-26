# Third-Party and Upstream Attributions

VoidCoin Core builds on, and gratefully credits, the following upstream work.
Each component remains under its own license; inclusion here does not
relicense it.

## 1. Base node software — Bitcoin Core
- **Authors:** The Bitcoin Core developers and contributors.
- **Source:** https://github.com/bitcoin/bitcoin
- **License:** MIT.
- VoidCoin Core is derived from Bitcoin Core and reuses its networking,
  storage, serialization, hashing, and script framework.

## 2. Fork lineage — Kvanta5-Core
- **Authors:** Kvanta5 Core Developers.
- **Source:** https://github.com/Kvanta-Organization/Kvanta5-Core
- **License:** MIT (as distributed at the time VoidCoin forked it, 2026-06-29).
- VoidCoin Core forked Kvanta5-Core, which is itself derived from Bitcoin Core.
  VoidCoin's P2QR consensus and script sources
  (`src/consensus/voidcoinp2qr.*`, `src/script/voidcoin_p2qr.*`) are derived
  from Kvanta5-Core's P2QR implementation and then modified by VoidCoin
  (notably O(N) precomputed sighashing and the P2QR time-lock output).
  Kvanta5-Core's copyright notice is retained in `COPYING` and in those file
  headers, in addition to VoidCoin's own.

## 3. Post-quantum signatures — ML-DSA-87 (FIPS 204)
- **Standard:** NIST FIPS 204 (Module-Lattice-Based Digital Signature
  Standard) — the standardized form of CRYSTALS-Dilithium at security level 5.
- **Reference implementation:** pq-crystals / CRYSTALS-Dilithium,
  https://github.com/pq-crystals/dilithium — built with `DILITHIUM_MODE=5`
  and vendored at `src/crypto/pq/mldsa87/upstream/`.
- **Authors of CRYSTALS-Dilithium:** Vadim Lyubashevsky (principal submitter);
  Shi Bai, Léo Ducas, Eike Kiltz, Tancrède Lepoint, Peter Schwabe,
  Gregor Seiler, and Damien Stehlé (co-submitters).
- **License:** Released to the public domain (CC0 1.0); also available under
  Apache-2.0 or GPL-2.0. See `src/crypto/pq/mldsa87/upstream/LICENSE`.
- **Parameters:** public key 2592 bytes, signature 4627 bytes, secret key
  4896 bytes.

## 4. Quantum-resistant output design — BIP-360
- The Pay-to-Quantum-Resistant output concept follows the approach documented
  in BIP-360 (QuBit / P2QR), author **Hunter Beast**.
- **Source:** https://github.com/bitcoin/bips/blob/master/bip-0360.mediawiki

## 5. Difficulty adjustment — DarkGravityWave
- VoidCoin's retargeting (`src/pow.cpp`) implements DarkGravityWave (v3),
  originally authored by **Evan Duffield** for Dash (formerly Darkcoin).
- **Source:** https://github.com/dashpay/dash
- **License:** MIT.

## 6. Linear-time sighashing — BIP-143 / BIP-341
- The P2QR sighash is computed with per-transaction precomputed subhashes
  (O(N) instead of O(N²)). This precomputed approach is the established public
  precedent introduced in **BIP-143** (authors **Johnson Lau** and
  **Pieter Wuille**) to address the quadratic transaction-hashing
  denial-of-service issue **CVE-2013-2292**, and extended in **BIP-341**
  (Taproot) to commit to all spent amounts and scriptPubKeys. Bitcoin Core
  implements it as `PrecomputedTransactionData`.

---

The VoidCoin P2QR wire format is specified normatively in
[`VCIP-2.md`](./VCIP-2.md). The consensus code implementing it is an
independent implementation written against that specification and the bytes
present on the VoidCoin chain.
