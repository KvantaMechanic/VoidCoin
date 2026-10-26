# VoidCoin Core — VCIP-3 Release (v2.0.0)

VoidCoin Core is the reference full node and wallet for **VoidCoin (VOID)**, a proof-of-work
UTXO cryptocurrency in the Bitcoin Core lineage, extended with **post-quantum signatures**
via Pay-to-Quantum-Resistant (P2QR) outputs backed by **ML-DSA-87 (NIST FIPS 204)**.

This release ships the **VCIP-3 consensus upgrade** together with a set of non-consensus
hardening and correctness changes. It is a **mandatory upgrade** for all node operators and
miners.

---

## ⚠️ Consensus notice — VCIP-3 activates at block 32,000

VCIP-3 is a **hard fork** with a fixed activation height:

```
VCIP-3 activation height (mainnet): block 32,000
```

- **Before block 32,000**, every consensus rule in this build is **byte-identical** to the
  previous release; the existing chain validates unchanged.
- **At block 32,000**, the new consensus rules (below) engage simultaneously on all upgraded
  nodes.
- **Every node and miner must be running this release (or a later compatible build) before
  block 32,000.** A node still on an older build at that height will follow different rules and
  **separate from the network permanently.**

Operators should upgrade well ahead of the activation height. See **Upgrading** below.

---

## What's in this release

### 1. VCIP-3 consensus changes (activate at block 32,000)

| Rule | Summary |
|---|---|
| **Hard supply cap (231,000,000 VOID)** | Cumulative issuance is clamped so realized supply can never exceed `MAX_MONEY = 231,000,000 × COIN`. The clamp is a deterministic function of the header chain (per-index `nChainSupply` accumulator), enforced identically in block connection and block assembly. This aligns the code with the stated 231M maximum-supply policy. |
| **Per-block ML-DSA verification budget** | A block may require at most `MAX_BLOCK_MLDSA_VERIFICATIONS = 8000` ML-DSA-87 signature verifications. Blocks exceeding the budget are rejected (`bad-blk-mldsa-verifications`). The budget is deliberately set above the maximum number of verifications that can physically fit under the block-size limit, bounding worst-case block-validation cost. |
| **Multisig spend push-cap alignment (PA-06)** | The spend-side script push limit is raised so that any P2QR multisig policy which can be *funded* validly (up to 1024-of-1024, either committed format) can also be *spent*. Closes an edge where a validly-funded large multisig could otherwise become unspendable. Legacy push limits are byte-identical before activation. |
| **P2QR time-lock outputs** | Completes the P2QR *time-lock* output type as a spendable, versioned output under the coordinated upgrade. A time-lock output commits to the same 32-byte P2QR program as a native P2QR output, plus a 10-byte descriptor (`version ‖ lock_type ‖ lock_value`); it becomes spendable only once (a) VCIP-3 has activated **and** (b) its lock has matured — either an absolute block height (`lock_type 0`) or an absolute median-time-past (BIP-113, `lock_type 1`). Before activation the type is uncreatable and unspendable, byte-identical to prior behavior: creation is refused for ordinary transactions **and for the coinbase** alike (`bad-txns-timelock-output-premature`). Unsupported descriptor versions/lock-types fail closed, and `lock_value` is an unsigned 64-bit field. |

All four rules key off the single `nVCIP3ActivationHeight` and are per-block deterministic, so
activation is atomic across the network.

### 2. Non-consensus hardening and correctness

These changes are **consensus-neutral** (output byte-identical, or wallet/policy/RPC only) and
take effect on upgrade, independent of the fork height.

- **O(N) signature-hash computation (performance).** VoidCoin inherited a signature-hash
  routine that recomputed the transaction-wide subhashes (prevouts, sequences, outputs, spent
  amounts, spent scripts) for *each* input — O(N²) work in the input count. This release computes
  those subhashes **once per transaction** and reuses them across every input, the standard
  BIP-143 pattern. The resulting sighash is **byte-identical**, so the change is consensus-neutral;
  it is purely a performance optimization, not a fix for any exploitable condition — a
  transaction's input count is already bounded by the block-weight limit and the VCIP-3 per-block
  ML-DSA-87 verification budget, so the cost was never unbounded. The saving is real at the
  practical maximum: fully validating a ~4,000-input single transaction is roughly **58% faster**.
  Verified byte-for-byte against the prior computation and against live chain history.
- **Post-quantum wallet-key encryption.** P2QR (ML-DSA-87) seed material is now encrypted under
  the wallet master key on the same footing as ordinary keys: new keys are stored encrypted on
  an encrypted wallet, pre-existing wallets are migrated on unlock (with a database rewrite so
  no plaintext lingers in free pages), and P2QR keys are unusable while the wallet is locked. A
  wallet minimum-version marker is set so older builds fail closed rather than silently ignoring
  the encrypted records.
- **P2QR multisig vault.** The M-of-N P2QR multisig "vault" and its create → approve → broadcast
  spend workflow are fully supported in this release: a multisig policy can be created, funded,
  and spent end-to-end (validated in the functional test suite). This is distinct from the
  time-lock output type below.
- **Address decoding.** P2QR time-lock addresses (`vqt1…`, bech32m) decode as valid time-lock
  destinations and expose their `lock_type`/`lock_value` through
  `validateaddress`/`getaddressinfo`; a Base58-first routing fix prevents a valid Base58 address
  from being misrouted into the bech32 time-lock branch.
- **Networking.** The v2 (BIP-324) transport fragment-reassembly reserve is bounded to the true
  maximum message size.
- **Index.** The `-coinstatsindex` database carries a format version and rebuilds automatically
  if it predates the supply-accounting change.
- **RPC.** `validateaddress`/`getaddressinfo` result schemas now enumerate the P2QR fields; the
  PSBT paths return a clear, specific error for native P2QR inputs (which are spent directly, not
  via PSBT).

---

## Chain parameters (mainnet)

| Parameter | Value |
|---|---|
| Ticker | VOID |
| Consensus model | Proof-of-work, UTXO (Bitcoin Core lineage) |
| Difficulty adjustment | DarkGravityWave v3 (per-block retarget) |
| Target block spacing | 60 seconds |
| Block subsidy | 50 VOID (halving every 2,100,000 blocks) |
| Maximum supply | 231,000,000 VOID (enforced from block 32,000) |
| Genesis block | `00000000238e081320ba119856513b2c9dfb82ee6a917f178cfbb7ac0e4adeaa` |
| P2P magic | `0xD3ADC0DE` |
| Default P2P port | 7777 |
| P2P transport | v1 and v2 (BIP-324) |
| Native P2QR address prefix (bech32m) | `vqr1…` |
| P2QR time-lock address prefix (bech32m) | `vqt1…` (spendable from block 32,000) |
| SegWit / legacy P2PKH | Not supported (P2QR-only: outputs may only be native P2QR, P2QR time-lock, or P2SH-wrapped P2QR) |
| Decimals | 8 (1 VOID = 100,000,000 units) |

Testnet uses prefixes `tnqr`/`tbqr`; regtest uses `bcrtqr`. VCIP-3 on non-mainnet networks is
gated by each network's own `nVCIP3ActivationHeight`.

---

## Post-quantum (P2QR) specification

- **Signature scheme:** ML-DSA-87 (NIST FIPS 204), reference implementation from
  `pq-crystals/CRYSTALS-Dilithium` (vendored under `src/crypto/pq/mldsa87/`, not relicensed).
  Public key **2,592 bytes**, signature **4,627 bytes**.
- **Output design:** based on BIP-360 (Pay-to-Quantum-Resistant-Hash). The native output commits
  to a 32-byte program (hash of the ML-DSA public key, or of the multisig policy); a
  P2SH-carried wrapper is provided for exchange/mining compatibility.
- **Signature hash:** BIP-143-style preimage over a fixed field layout, epoch `0`, hash type
  `SIGHASH_ALL`, with the input amount committed. Computed once per transaction (see hardening
  above).
- **Multisig vault:** M-of-N up to **1024-of-1024**, in a committed-pubkey format and a
  committed signer-program format, with a create → approve → broadcast spend workflow for
  coordinated multi-party signing. Funded and spent end-to-end.
- **Time-lock outputs:** a versioned output that wraps the P2QR program with a 10-byte lock
  descriptor — an absolute block height, or an absolute median-time-past (BIP-113). Created with
  `getnewtimelockaddress "height"|"time" <value>` and spent through the native-P2QR ML-DSA-87
  path once VCIP-3 has activated and the lock has matured (see the VCIP-3 table above).
- **Wallet:** ML-DSA-87 keys are generated per address and held in the wallet database
  (encrypted at rest on encrypted wallets; see hardening above). Because ML-DSA-87 is a
  post-quantum scheme with **no BIP-32 hierarchical derivation**, P2QR keys — including those
  behind long-dated time-lock outputs — are recoverable only from a **`wallet.dat` backup**, not
  from a mnemonic seed phrase. Back up the wallet file after creating P2QR or time-lock addresses.

---

## Upgrading

This is a **mandatory** upgrade ahead of block 32,000.

1. Stop the running node cleanly (`voidcoin-cli stop`, or SIGTERM).
2. Replace the binaries with this release.
3. Start the node. No `-reindex` is required for the consensus changes; the chain validates
   unchanged up to the activation height. Operators running `-coinstatsindex` will see a one-time
   automatic index rebuild.
4. Confirm the node is on this version (`voidcoin-cli getnetworkinfo`) and syncing normally
   **before** block 32,000.

No wallet action is required. Encrypted wallets are migrated automatically on first unlock.

---

## Building from source

VoidCoin Core uses the CMake build system and a self-contained `depends` tree.

```bash
# 1) Build dependencies (example: 64-bit Linux)
make -C depends -j"$(nproc)" HOST=x86_64-pc-linux-gnu

# 2) Configure and build
cmake -B build --toolchain depends/x86_64-pc-linux-gnu/toolchain.cmake
cmake --build build -j"$(nproc)"

# Binaries: build/bin/voidcoind, voidcoin-cli, voidcoin-wallet, voidcoin-qt (if enabled)
```

For other hosts, set `HOST` and the matching toolchain file accordingly. See `depends/README.md`
and `doc/build-*.md` for platform specifics.

---

## Testing and validation

This release was validated with:

- **Unit tests** (`build/bin/test_voidcoin`): P2QR script recognition/encoding, ML-DSA-87
  primitive and wrapper, signature-hash equivalence and byte-identity, supply-cap enforcement,
  ML-DSA verification-budget boundary (8000/8001), multisig push-cap boundary (up to 1024/1024),
  wallet encryption and migration, and the P2QR time-lock spend/gate suite (output-creation gate,
  absolute-height and absolute-MTP lock enforcement, unsigned `lock_value` boundary, and
  fail-closed on unsupported descriptor versions/lock-types).
- **Functional / regtest tests** (`test/functional/`): VCIP-3 activation atomicity and
  off-by-one boundary, 231M supply-cap clamp, native P2QR fund/spend (single- and multi-input),
  multisig fund/spend, address decoding, wallet minimum-version behavior, coinstatsindex
  versioning, a multi-node network test (block/mempool propagation, reorg convergence, v2
  BIP-324 transport), and the full P2QR time-lock lifecycle — pre-activation creation refused,
  absolute-height and absolute-MTP locks funded / rejected-while-premature / spent-at-maturity,
  the pre-activation **coinbase** creation gate, and reorg-driven mempool eviction of a
  now-premature time-lock spend under `-checkmempool`.
- **Replay validation:** the O(N) sighash change was confirmed byte-identical by re-validating
  live chain history and comparing tip and checkpoints against the prior build.

---

## Attribution

VoidCoin Core is built on prior work and retains the corresponding notices:

- **Bitcoin Core** — base node/wallet (MIT). https://github.com/bitcoin/bitcoin
- **DarkGravityWave v3** — the difficulty-adjustment algorithm, originally authored by Evan
  Duffield for Dash (MIT). https://github.com/dashpay/dash
- **CRYSTALS-Dilithium / ML-DSA-87** — post-quantum signature reference implementation from
  `pq-crystals` (public domain / permissive; vendored, not relicensed). NIST FIPS 204.
- **BIP-360 (P2QRH)** — Pay-to-Quantum-Resistant output design (Hunter Beast).

See `COPYRIGHT`, `ATTRIBUTIONS.md`, and per-file headers for details.

---

## License

Distributed under the MIT software license. See `COPYING`.
