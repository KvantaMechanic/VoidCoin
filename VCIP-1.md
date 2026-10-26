# VCIP-1: P2QR-TIMELOCK — Native Quantum-Resistant Time-Locked Outputs

| Field | Value |
|---|---|
| VCIP | 1 |
| Title | P2QR-TIMELOCK: Native Quantum-Resistant Time-Locked Outputs |
| Author | VoidCoin Development Team |
| Status | Draft |
| Created | 2026-07-03 |
| Activation | Block 10,000 (mainnet) |

## Abstract

This proposal introduces a new native output type, `VOIDCOIN_P2QR_TIMELOCK`, which combines ML-DSA-87 quantum-resistant signatures with protocol-level time-locking. Coins sent to a `vqt1...` address cannot be spent until a specified block height, enforced at the consensus layer by every full node.

No other proof-of-work blockchain implements native quantum-resistant time-locked outputs. This is VoidCoin's original contribution to the post-quantum blockchain space.

## Motivation

Existing approaches to time-locked outputs on other chains suffer from one or both of the following problems:

1. **Not quantum-resistant** — Bitcoin's `OP_CHECKLOCKTIMEVERIFY` enforces timelocks but uses ECDSA signatures, which a sufficiently powerful quantum computer can forge. A quantum attacker could steal time-locked funds before the timelock expires.

2. **Not protocol-native** — Software tools (web apps, pre-signed transactions) can simulate timelocks but rely on the user correctly storing and broadcasting a transaction at the right time. They offer no consensus-layer guarantee.

VoidCoin's P2QR-TIMELOCK solves both problems simultaneously:
- **Quantum-resistant**: Uses ML-DSA-87 (NIST FIPS 204) — the same signature scheme as native P2QR outputs
- **Protocol-native**: The timelock is enforced by every full node at the consensus layer — no software tool or third party required

## Use Cases

- **Inheritance**: Lock VOID to heirs' `vqr1...` addresses until a future block height
- **Savings vault**: Lock your own coins for a fixed period — protected even against quantum attackers
- **Vesting**: Create vesting schedules for team or community allocations
- **Dead man's switch**: Coins automatically become spendable by a designated heir if the owner stops spending before a target height

## Specification

### Address Format

P2QR-TIMELOCK addresses use bech32 encoding with the following HRPs:

| Network | HRP |
|---|---|
| Mainnet | `vqt` |
| Testnet5 | `tnqt` |
| Testnet | `tbqt` |
| Regtest | `bcrtqt` |

Example mainnet address: `vqt1...`

### scriptPubKey Format
OP_QuantumQuark (0x50) <32-byte-program> <4-byte-lockheight-LE>
Total size: **38 bytes**

- `OP_QuantumQuark` (1 byte): Same opcode as native P2QR (0x50 = OP_RESERVED at script byte level)
- `<32-byte-program>` (32 bytes): SHA3-256 hash of the ML-DSA-87 public key (same as P2QR)
- `<4-byte-lockheight-LE>` (4 bytes): Little-endian uint32 block height before which the output is unspendable

### Spending Rules

A `VOIDCOIN_P2QR_TIMELOCK` output may only be spent when:

1. The current block height `nSpendHeight` is **strictly greater than** the encoded `lockHeight`
2. The spending input provides a valid ML-DSA-87 signature and public key matching the committed program hash (same validation as native P2QR)

If either condition fails, the transaction is rejected with:
- `bad-txns-p2qr-timelock-not-yet-spendable` — if height condition not met
- `bad-txns-p2qr-timelock-malformed` — if lockheight bytes are malformed

### Activation

P2QR-TIMELOCK activates at block **10,000** on mainnet. Before this height, `vqt1...` outputs are treated as non-standard and rejected by mempool policy.

### Comparison with Existing Approaches

| Feature | Bitcoin CLTV | KV5 P2QR | VoidCoin P2QR-TIMELOCK |
|---|---|---|---|
| Quantum-resistant | ❌ ECDSA | ✅ ML-DSA-87 | ✅ ML-DSA-87 |
| Protocol-native timelock | ✅ | ❌ | ✅ |
| Native address type | ❌ | ❌ | ✅ vqt1... |
| Consensus enforced | ✅ | N/A | ✅ |
| No third party needed | ✅ | ❌ (web tool) | ✅ |

## Reference Implementation

Branch: `feature/p2qr-timelock`
Repository: `https://github.com/VoidHash-Crypto/VoidCoin-Core`

Files changed:
- `src/script/solver.h` — `TxoutType::VOIDCOIN_P2QR_TIMELOCK` + size constants
- `src/script/solver.cpp` — Script recognition
- `src/consensus/tx_verify.cpp` — Lockheight enforcement
- `src/consensus/params.h` — `nP2QRTimelockActivationHeight`
- `src/kernel/chainparams.h` — `bech32_qrt_hrp` field and accessor
- `src/kernel/chainparams.cpp` — HRP assignments and activation heights

## Copyright

This document is placed in the public domain.
