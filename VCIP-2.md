# VCIP-2 — VoidCoin Pay-to-Quantum-Resistant (P2QR) Consensus Specification

> Normative wire-format specification for the VoidCoin P2QR output type: output/redeem encoding, single- and multi-signature validation, the sighash preimage, canonical encodings, and consensus limits. The consensus code in `src/consensus/voidcoinp2qr.*` and `src/script/voidcoin_p2qr.*` is an independent implementation written against this specification. Cryptography: ML-DSA-87 (NIST FIPS 204 / pq-crystals). Output-design lineage: BIP-360. See ATTRIBUTIONS.md.

---

# VoidCoin P2QR — Authoritative Wire-Format & Consensus-Validation Specification

**Status: Normative. Consensus-critical for a LIVE chain.** This document is the single authoritative merge of the six prior P2QR spec sections (native/P2SH output format, sighash preimage, single-sig validation, legacy-pubkey multisig, signer-address multisig, and encodings/limits/routing). A reimplementation conforms **iff** it accepts and rejects every `(transaction, input, spent-output-set)` triple **byte-for-byte** as specified here. Where this text says "reject", the input is consensus-invalid and any block containing it is invalid. There is no soft-acceptance path. Every byte offset, integer width, endianness, hash domain, and check is load-bearing; any deviation is a chain split.

All multi-byte integers are **little-endian (LE)** unless stated otherwise. "Program" always means the 32-byte P2QR commitment.

---

## 1. Constants (frozen; live-chain invariants)

| Name | Value | Meaning |
|---|---|---|
| `OP_RESERVED` | `0x50` | P2QR version/marker byte. Aliased in source as `OP_QuantumQuark` / `OP_VOIDCOIN_P2QR`. |
| `PROGRAM_SIZE` | `32` | Committed program / signer-program length (exact) |
| `PUBKEY_SIZE` | `2592` | ML-DSA-87 (FIPS 204, level 5) public key length (exact) |
| `SIGNATURE_SIZE` | `4627` | ML-DSA-87 signature length (exact) |
| Native P2QR scriptPubKey length | `34` | exact |
| Native P2QR redeem-script length | `34` | exact (identical body to native scriptPubKey) |
| **P2SH scriptPubKey length** | **`23`** | exact — see §14 flag D1 |
| `MAX_KEYS` (`n` ceiling) | `1024` | |
| `MAX_SIGNATURES` (`m` ceiling) | `1024` | |
| `MAX_PUSHES` (native) | `3074` | `= 2·MAX_SIGNATURES + MAX_KEYS + 2` |
| `MAX_PUSHES_P2SH` | `3075` | `= MAX_PUSHES + 1` (one extra push for the appended redeem) |
| Legacy multisig domain tag | ASCII `VOID:P2QR:MSIG:v1` (17 bytes, CompactSize prefix `0x11`) | |
| Signer-address multisig domain tag | ASCII `VOID:P2QR:MSIG:ADDR:v1` (22 bytes, CompactSize prefix `0x16`) | |
| Sighash tag | ASCII `VoidCoinP2QRSighash` (19 bytes) | |
| Sighash `epoch` / `hashType` | `0` / `1` (SIGHASH_ALL only) | |
| Activation flag | `SCRIPT_VERIFY_VOIDCOIN_P2QR`, set for inputs at height `≥ nP2QRActivationHeight` | |

These sizes are **exact-match**: a signature not exactly 4627 bytes, a pubkey not exactly 2592 bytes, or a program push not exactly 32 bytes is rejected. No tolerance.

---

## 2. Hash and serialization primitives

**Hash primitives** (must be bit-exact; Bitcoin-Core-compatible):

- `SHA256(x)` — single SHA-256.
- `Hash256(x)` (Bitcoin Core `Hash()` / `CHash256`) — **double** SHA-256: `SHA256(SHA256(x))`. Used for the **single-key program** (§4.1) and for **signer-address per-signer binding** (§4.3, §10.3).
- `HASH160(x)` = `RIPEMD160(SHA256(x))`. A P2SH script hash is `HASH160(redeem_script_bytes)`.
- **HashWriter stream** — serialized fields are streamed in; `GetSHA256()` finalizes as a **single** SHA-256 over everything streamed. Used for the five sighash subhashes, both multisig-program commitments, and the final sighash. (Single, not double — deliberate and consensus-critical.)
- `TaggedHash(tag, m)` = `SHA256( SHA256(tag) || SHA256(tag) || m )` (BIP-340 style). Implemented by priming a HashWriter with `t || t` where `t = SHA256(tag_ascii_bytes)`, streaming `m`, then a single `GetSHA256()`. The outer function is a **single** SHA-256.

**Byte-order comparison** (all "strictly increasing" rules): unsigned lexicographic comparison from the first stored byte forward (`memcmp` over the full width). Nothing is byte-reversed at any point. "Strictly increasing" = each element `memcmp`-greater than its predecessor (⇒ distinct **and** ascending).

**Serialization** (Bitcoin-Core `operator<<`; reproduce exactly):

- `uint8` → 1 byte. `uint16` → 2 LE. `uint32`/`int32` → 4 LE. `int64` (`CAmount`) → 8 LE.
- `CompactSize(len)`: `len ≤ 0xFC` → 1 byte; `0xFD ≤ len ≤ 0xFFFF` → `0xFD` + `uint16` LE; `0x10000 ≤ len ≤ 0xFFFFFFFF` → `0xFE` + `uint32` LE; larger → `0xFF` + `uint64` LE. (E.g. `CompactSize(2592) = FD 20 0A`; `CompactSize(17) = 11`; `CompactSize(22) = 16`; `CompactSize(34) = 22`; `CompactSize(23) = 17`.)
- byte-vector / string / `CScript` → `CompactSize(length) || raw bytes`.
- `uint256` → 32 raw bytes in stored order, **no** length prefix.
- `COutPoint` → `uint256 hash` (32 bytes, stored order) `|| uint32 n` (4 LE) = 36 bytes.
- `CTxOut` → `int64 nValue` (8 LE) `|| CScript scriptPubKey` (CompactSize + bytes).

---

## 3. Output, redeem, and P2SH byte layouts

### 3.1 Native P2QR scriptPubKey — exactly 34 bytes

```
offset  size  value
0       1     0x50            OP_RESERVED (P2QR version byte)
1       1     0x20            canonical push length = 32
2..33   32    <program>       the 32-byte P2QR commitment (any 32 bytes)
```
No trailing bytes. **Recognition** (`IsNativeP2QROutput`): `len == 34` AND `spk[0]==0x50` AND `spk[1]==0x20`; `program := spk[2..34)`. Any other length, leading byte, or length prefix ⇒ not native P2QR.

> **Disambiguation:** a separate `VOIDCOIN_P2QR_TIMELOCK` type (`0x50 0x20 <32 program> <4-byte LE lock-height>`, 38 bytes) shares the prefix. The native recognizer MUST require length **exactly 34**, so a 38-byte timelock output is never mis-recognized as native P2QR. Timelock is out of scope.

### 3.2 P2QR redeem script — exactly 34 bytes

Byte-identical to §3.1 (`0x50 0x20 <32 program>`). `IsRedeemScript` ≡ `IsNativeP2QROutput`.

### 3.3 P2SH-wrapped scriptPubKey — exactly 23 bytes (standard BIP-16 P2SH)

```
offset  size  value
0       1     0xA9            OP_HASH160
1       1     0x14            push length = 20
2..21   20    <script_id>     script_id = HASH160(redeem_script_bytes)
22      1     0x87            OP_EQUAL
```
`redeem_script_bytes` is the 34-byte script of §3.2. **Recognition** (`IsP2SHOutput`): `len==23`, `spk[0]==0xA9`, `spk[1]==0x14`, `spk[22]==0x87`; `script_id := spk[2..22)`. The prevout commits only to `HASH160(redeem)`; the 32-byte program is not revealed until spend time.

The P2SH form is a compatibility carrier only (e.g. for systems accepting only base58 P2SH addresses). It is validated through the native P2QR path (§9–§10) and is never spendable via ordinary P2SH script evaluation (§11).

---

## 4. The 32-byte program — three constructions

The output commits only the 32 bytes; which construction applies is determined at **spend time** by what the spender reveals. Consensus does not require any particular preimage at commitment time — the binding is checked at spend.

### 4.1 Single-key program
```
program = Hash256(pubkey)                  # double SHA-256 over the exact 2592-byte pubkey
```

### 4.2 Multisig program — legacy pubkey policy (`VOID:P2QR:MSIG:v1`)
Stream into a fresh untagged HashWriter, finalize with a single `GetSHA256()`:
```
CompactSize(17) 0x11 || "VOID:P2QR:MSIG:v1"        # 18 bytes total
uint16_LE(required = m)                             # 2 bytes
uint16_LE(total    = n)                             # 2 bytes  (n = number of pubkeys)
for each pubkey in ascending byte order:
    CompactSize(2592)=FD 20 0A || <2592 pubkey bytes>   # 2595 bytes each
program = GetSHA256()
```
Preimage length = `22 + 2595·n` bytes. Finalize is **single** SHA-256.

### 4.3 Multisig program — signer-address policy (`VOID:P2QR:MSIG:ADDR:v1`)
Same construction, different tag, and members are **32-byte signer programs** streamed as raw `uint256` with **no** length prefix:
```
CompactSize(22) 0x16 || "VOID:P2QR:MSIG:ADDR:v1"
uint16_LE(required = m)
uint16_LE(total    = n)                             # n = number of signer programs
for each signer_program in ascending byte order:
    <32 raw bytes>                                  # uint256, NO length prefix
program = GetSHA256()
```
Finalize is **single** SHA-256. Each `signer_program[i]` is, by wallet convention, itself a single-key program `Hash256(signer_pubkey_i)`, but consensus does not require that at commitment time (only at spend, §10.3).

The commitment binds `(m, n, sorted member set)` inseparably: because members are supplied strictly sorted (§7), a given set has exactly one valid ordering ⇒ one preimage ⇒ one program. The two multisig policies are mutually exclusive within a spend (§10): a spend reveals legacy pubkeys **or** signer programs, never both, never neither.

---

## 5. Canonical scriptSig push encoding

Native and P2SH-wrapped P2QR spends **never execute Bitcoin Script**. The `scriptSig` is parsed by a dedicated canonical-push reader into an ordered list of data-push payloads (opcode framing discarded). `MAX_SCRIPT_ELEMENT_SIZE` (520) is **not** applied — 2592-byte and 4627-byte pushes are legal and required. The input's `scriptWitness` MUST be null.

### 5.1 Reader (`ReadCanonicalP2QRPushes(script, max_pushes)`) — reject if any of:
1. script is **empty**;
2. script is **not push-only** (any opcode value `> OP_PUSHDATA4` (0x4E) present anywhere — this includes `OP_1NEGATE` (0x4F), `OP_RESERVED` (0x50), and `OP_1..OP_16` (0x51–0x60));
3. any push fails to decode (truncated / runs past end);
4. any push is **non-canonical** (not the minimal opcode for its data length, §5.2);
5. the running push count **exceeds** `max_pushes`;
6. zero pushes result.

### 5.2 Canonical minimal-push mapping (per push of `L` bytes)
| `L` | Required opcode | on-wire |
|---|---|---|
| `0` | `OP_0` (`0x00`) | `00` |
| `1..75` | direct push, opcode value `== L` (`0x01`..`0x4B`) | `<L> <data>` |
| `76..255` | `OP_PUSHDATA1` (`0x4C`) | `4c <L:u8> <data>` |
| `256..65535` | `OP_PUSHDATA2` (`0x4D`) | `4d <L:u16 LE> <data>` |
| `≥65536` | `OP_PUSHDATA4` (`0x4E`) | `4e <L:u32 LE> <data>` |

Accepted opcode set is exactly `{0x00} ∪ [0x01..0x4B] ∪ {0x4C, 0x4D, 0x4E}`, each only at its canonical length. **Integers `m`, `n`, `signer_index` are byte-vector data pushes — never `OP_1..OP_16`.** (E.g. `m=2` → `01 02`; `n=1024=0x0400` → push `02 00 04`.)

### 5.3 Push caps
`max_pushes` = `3074` for a native spend, `3075` for a P2SH spend (includes the redeem push). This is a hard consensus DoS bound **stricter than `MAX_KEYS`/`MAX_SIGNATURES` alone**: a signer-address spend (`3m+n+2` pushes) whose `(m,n)` exceed the cap is unrepresentable and invalid even when `m ≤ 1024` and `n ≤ 1024` individually. Comparison is `count > cap ⇒ reject`.

### 5.4 Minimal integer encodings inside the scriptSig

**Minimal `uint16`, nonzero** — used for `m` and `n`:
- length 0 or `>2` ⇒ reject;
- length 1: byte `≠ 0x00`; value = the byte (range 1..255);
- length 2: bytes `[lo, hi]` with `hi ≠ 0x00` **and** value `> 255`; value = `lo | (hi<<8)` (range 256..65535).
- Zero is not representable. A 1-byte `0x00`, an empty push, or a 2-byte value ≤255 is rejected.

**Minimal `uint16`, zero-allowed** — used for each `signer_index`: identical, except a single-byte `0x00` is **accepted** and decodes to `0`. Index `0` MUST be the 1-byte push `{0x00}`; an empty push (`OP_0`) is **not** a valid index.

Resulting ranges: `m ∈ [1,1024]`, `n ∈ [1,1024]`, `signer_index ∈ [0, n-1]`.

---

## 6. scriptSig envelope layouts

Pushes listed index 0 = first/bottom on the wire. The last two pushes of the native portion are always `m` then `n`.

| Form | Pushes (in order) | Count |
|---|---|---|
| Native single-sig | `sig(4627), pubkey(2592)` | 2 |
| P2SH single-sig | `sig, pubkey, redeem(34)` | 3 |
| Native legacy multisig | `sig×m, signer_index×m, pubkey×n, m, n` | `2m+n+2` |
| Native signer-address multisig | `sig×m, signer_index×m, signing_pubkey×m, signer_program×n, m, n` | `3m+n+2` |
| P2SH multisig | corresponding native list `+ redeem(34)` as final push | native+1 |

For P2SH forms the 34-byte redeem is always the **last** push; the checker pops and validates it first (§9.2), then treats the remaining pushes exactly as the native stack.

**Form disambiguation** (parser): read `n` (top push) then `m` (second-from-top); validate threshold (§7); then select **purely by exact stack size**: `2m+n+2` ⇒ legacy; `3m+n+2` ⇒ signer-address; anything else ⇒ reject. Because `m ≥ 1`, the two sizes never coincide, so classification is unambiguous. Legacy is tested first. There is no heuristic and no other signal.

---

## 7. Threshold, limit, and strictly-increasing invariants

After decoding `m` and `n`:
- `m ≥ 1`, `n ≥ 1`, `m ≤ n` (else reject);
- `n ≤ MAX_KEYS` (1024); `m ≤ MAX_SIGNATURES` (1024) (else reject);
- push-cap interaction (§5.3) further bounds `3m+n+2 ≤ 3074` (native) / after redeem removal ≤ 3074 (P2SH); a spend exceeding it is rejected at the push-reading stage.

Three vectors MUST be **strictly increasing** (each strictly greater than its predecessor ⇒ distinct + ascending; any equal-or-decreasing adjacent pair ⇒ reject):
1. `signer_index[0..m-1]` — compared as integers; additionally each `< n` (index `≥ n` ⇒ reject). Strict increase ⇒ no committed signer is used twice.
2. `pubkey[0..n-1]` (legacy policy) — compared as raw 2592-byte vectors (lexicographic).
3. `signer_program[0..n-1]` (signer-address policy) — compared as 32-byte values (lexicographic, wire order).

The strict ordering of the members is what makes the program commitment (§4.2/§4.3) canonical.

Count consistency (any mismatch ⇒ reject): `|sig| = m`, `|signer_index| = m`; legacy: `|pubkey| = n`; signer-address: `|signing_pubkey| = m`, `|signer_program| = n`.

---

## 8. Sighash algorithm (SIGHASH_ALL only, epoch 0)

Every ML-DSA-87 signature in an input — single or multisig, native or P2SH-wrapped — signs the **same** 32-byte message for that input. The digest is passed directly as the 32-byte message to the ML-DSA-87 verifier (ML-DSA-87 does its own internal hashing; the consensus layer applies no further transform). It is **independent of native-vs-P2SH wrapping**: for a P2SH-carried spend, the "spent scriptPubKey" committed (field 14 and `hashSpentScripts`) is the actual **23-byte P2SH output script**, never the redeem script and never the 34-byte native script. The redeem script never enters the sighash.

### 8.1 Finalization
```
sighash = TaggedHash("VoidCoinP2QRSighash", preimage)
        = SHA256( t || t || preimage ),   t = SHA256("VoidCoinP2QRSighash")
```
Implemented as a HashWriter primed with `t || t`, streamed with the preimage fields, single `GetSHA256()`.

### 8.2 Preimage field order (exact)
| # | Field | Type / encoding | Bytes |
|---|---|---|---|
| 1 | epoch | `uint8` = `0x00` | 1 |
| 2 | tx.version | 4 LE (see §14 flag D2 for the int32/uint32 label) | 4 |
| 3 | tx.nLockTime | `uint32` LE | 4 |
| 4 | hashType | `int32` LE = `1` → `01 00 00 00` | 4 |
| 5 | input_index | `uint32` LE (0-based) | 4 |
| 6 | hashPrevouts | `uint256` | 32 |
| 7 | hashSequences | `uint256` | 32 |
| 8 | hashOutputs | `uint256` | 32 |
| 9 | hashSpentAmounts | `uint256` | 32 |
| 10 | hashSpentScripts | `uint256` | 32 |
| 11 | this input's prevout | `COutPoint` (32 hash + 4 LE n) | 36 |
| 12 | this input's nSequence | `uint32` LE | 4 |
| 13 | this input's spent nValue | `int64` LE | 8 |
| 14 | this input's spent scriptPubKey | `CScript` = CompactSize(len) + bytes | variable |

Fields 1–13 are a fixed **225 bytes**. Field 14 adds `CompactSize(len)+len`. Worked totals: native prevout (34-byte script) → `0x22`+34=35 → **preimage = 260 bytes**; P2SH prevout (23-byte script) → `0x17`+23=24 → **preimage = 249 bytes**.

The preimage does **not** commit to any input's `scriptSig` or to witness data.

### 8.3 The five whole-transaction subhashes
Each is a **single** SHA-256 over a fresh untagged HashWriter, ranging over the **entire** transaction / spent-output set in ascending index order. `spent[i]` is the coin consumed by `vin[i]`; the caller MUST supply `spent` for **every** input (including non-P2QR inputs).

- `hashPrevouts` = `SHA256( for each vin i: serialize(COutPoint prevout_i) )`
- `hashSequences` = `SHA256( for each vin i: uint32_LE nSequence_i )`
- `hashOutputs` = `SHA256( for each vout j: serialize(CTxOut_j) )`  (int64 nValue + CScript scriptPubKey)
- `hashSpentAmounts` = `SHA256( for each input i (in vin order): int64_LE spent[i].nValue )`
- `hashSpentScripts` = `SHA256( for each input i (in vin order): serialize_as_CScript(spent[i].scriptPubKey) )` (amount **not** included here)

These five depend only on the transaction and its spent-output set, never on `input_index`; they are identical across all inputs of the transaction.

### 8.4 Mandatory O(N)-precompute (consensus-neutral)
The five subhashes MUST be computed **once per transaction** and reused across all inputs (Bitcoin-Core `PrecomputedTransactionData` / BIP-143 style), yielding O(N) instead of the reference implementation's per-input O(N²) recompute. This MUST be **byte-identical** to the naive per-input computation for every input; it is purely a performance change and consensus-neutral. Any deviation in resulting sighash bytes is a chain-split bug and must be caught by fixed vectors (§13).

---

## 9. Per-input routing and dispatch

Per-input script checking (`CScriptCheck` equivalent) MUST perform P2QR routing **before** any ordinary `VerifyScript`, in this exact priority order. Detection is **independent of** the activation flag; the flag only gates whether a detected P2QR spend is validated (active) or rejected as inactive.

### 9.1 Dispatch order
```
1. if IsNativeP2QROutput(prevout.spk):
     if SCRIPT_VERIFY_VOIDCOIN_P2QR not set for this input:  REJECT (bad-opcode)   # pre-activation, fail-closed
     if spent_outputs unavailable:                           REJECT (missing-spent-outputs)
     return CheckSpend(tx, i, prevout, spent_outputs)        # VerifyScript never runs; success bypasses it
2. else if IsP2SHWrappedSpendCandidate(prevout.spk, scriptSig_i):
     same activation gate → REJECT (bad-opcode) if inactive
     same spent-outputs gate
     return CheckSpendP2SHWrapped(tx, i, prevout, spent_outputs)   # VerifyScript never runs
3. else:
     return VerifyScript(scriptSig_i, prevout.spk, ...)      # ordinary path
```
The three branches are mutually exclusive by construction.

### 9.2 `IsP2SHWrappedSpendCandidate(spk, scriptSig)` — true iff all hold:
1. `IsP2SHOutput(spk)` (yields `script_id`);
2. `ReadCanonicalP2QRPushes(scriptSig, 3075)` succeeds with ≥1 push;
3. the **last** push, as a CScript, is a valid P2QR redeem (`0x50 0x20 <32>`, §3.2);
4. `HASH160(last_push_bytes) == script_id`.

If any fails, the input is not a candidate and falls through to ordinary `VerifyScript` (§11).

### 9.3 Common preconditions (both `CheckSpend` and `CheckSpendP2SHWrapped`) — reject if:
- `input_index ≥ tx.vin.size()`;
- `spent_outputs.size() ≠ tx.vin.size()`;
- the input's `scriptWitness` is **not** null;
- (native) prevout not native P2QR; (P2SH) prevout not the 23-byte P2SH form.

Then `ReadCanonicalP2QRPushes` the scriptSig under the applicable cap. For the P2SH case additionally: ≥1 push; pop the **last** push as `redeem`; `IsRedeemScript(redeem)` must hold (yielding `committed_program`); `HASH160(redeem) == script_id`. For native, `committed_program` is the program from §3.1.

### 9.4 Dispatch by remaining push count
- remaining `== 2` → **single-sig** (§10.1);
- else → **multisig** (§10.2). Multisig requires `≥5` remaining pushes; counts of 3 or 4 reach the multisig parser and are rejected (stack-too-small).

---

## 10. Validation

All checks below are applied in the order given; a spend is accepted only if it reaches the end. `committed_program` is from §9.3. `sighash` is §8.

### 10.1 Single-sig — `pushes = [sig, pubkey]`
1. `len(sig) == 4627` (else reject);
2. `len(pubkey) == 2592` (else reject);
3. `Hash256(pubkey) == committed_program` (else reject — **program binding**);
4. `MLDSA87Verify(pubkey, sighash, sig)` succeeds (else reject);
5. accept.

### 10.2 Multisig — parse the native portion
Reject if `< 5` pushes. Read `n := minimal-u16-nonzero(pushes[last])`, `m := minimal-u16-nonzero(pushes[last-1])`; reject on invalid encoding. Reject if `m>n`, `n>1024`, or `m>1024`. Select policy by exact size: `2m+n+2` ⇒ legacy; `3m+n+2` ⇒ signer-address; else reject. Then all §5.4/§7 encoding/ordering/count checks apply.

**Legacy pubkey policy** — `pushes[0..m)` = signatures, `pushes[m..2m)` = signer_indexes, `pushes[2m..2m+n)` = pubkeys:
- each signature `len == 4627`;
- each signer_index minimal-u16-allow-zero, `< n`, strictly increasing;
- each pubkey `len == 2592`; pubkeys strictly increasing (byte-lex);
- recompute `MultisigProgram_legacy(m, pubkeys)` (§4.2) `== committed_program` (else reject — **program binding**);
- for each approval `i ∈ [0,m)`: `k = signer_index[i]`; `MLDSA87Verify(pubkeys[k], sighash, sig[i])` (else reject);
- accept.

### 10.3 Signer-address policy — `pushes[2m..3m)` = signing_pubkeys, `pushes[3m..3m+n)` = signer_programs:
- each signature `len == 4627`;
- each signer_index minimal-u16-allow-zero, `< n`, strictly increasing;
- each signing_pubkey `len == 2592`; each signer_program `len == 32`; signer_programs strictly increasing (32-byte memcmp, wire order);
- recompute `MultisigProgram_addr(m, signer_programs)` (§4.3) `== committed_program` (else reject — **program binding**);
- for each approval `i ∈ [0,m)`: `k = signer_index[i]`; `Hash256(signing_pubkey[i]) == signer_program[k]` (else reject — **per-signer address binding**) **and** `MLDSA87Verify(signing_pubkey[i], sighash, sig[i])` (else reject);
- accept.

A spend MUST carry exactly one policy family (never both, never neither); the exact-length disambiguation (§6) guarantees this. Signature `i` is bound to `signing_pubkey[i]`, bound to `signer_program[signer_index[i]]`; position `i` is authoritative and there is no "try each pubkey" fallback. The ML-DSA-87 message is exactly the 32-byte `sighash`, not re-hashed or domain-wrapped again.

---

## 11. Fail-closed rationale (why `OP_RESERVED` is load-bearing)

A native P2QR or P2SH-wrapped-P2QR output can be spent **only** via the native path; it can never be satisfied by ordinary evaluation or become anyone-can-spend:

- In ordinary P2SH evaluation the node verifies `HASH160(redeem)==script_id` then **executes** the redeem, whose first opcode is `OP_RESERVED` (0x50) — a reserved/invalid opcode that aborts an executed branch immediately with `SCRIPT_ERR_BAD_OPCODE`. No truthy value can remain.
- The exact condition that presents the correct redeem (last push = committed redeem, hash matches) is precisely the routing predicate (§9.2), which diverts the input to the native path **before** the interpreter runs. So ordinary evaluation is reached only when the redeem is absent/wrong — where it fails at `OP_EQUAL`/`HASH160` mismatch, or aborts at `OP_RESERVED`.
- For bare native P2QR: upgraded nodes route to native validation; non-upgraded nodes execute the scriptPubKey and abort at `OP_RESERVED`.

Pre-activation (flag unset), both forms are rejected `bad-opcode`; they become spendable only once the flag is active for the input. Behavior is fail-closed on both sides of activation.

---

## 12. Single ordered list of validation rules (master, per input)

An input is **valid iff it passes every applicable rule below in order**; the first failure rejects the input (and its transaction/block). Rules are grouped by phase; within a phase they are applied top-to-bottom.

**Phase A — framing / context**
1. `input_index < tx.vin.size()`.
2. `spent_outputs.size() == tx.vin.size()`.
3. input `scriptWitness` is null.

**Phase B — output recognition & routing**
4. Prevout is native P2QR (§3.1) → native path; else prevout is 23-byte P2SH (§3.3) **and** `IsP2SHWrappedSpendCandidate` holds (§9.2) → P2SH path; else this is not a P2QR spend (ordinary `VerifyScript`, out of scope). A prevout that is P2QR/P2SH-P2QR but whose `SCRIPT_VERIFY_VOIDCOIN_P2QR` flag is unset at this height → reject (bad-opcode).

**Phase C — scriptSig canonical decode** (cap 3074 native / 3075 P2SH)
5. scriptSig non-empty.
6. push-only (no opcode `> OP_PUSHDATA4`; rejects `OP_1NEGATE`, `OP_RESERVED`, `OP_1..OP_16`).
7. every push decodes (no truncation).
8. every push is canonical/minimal for its length (§5.2).
9. push count does not exceed the cap.
10. ≥1 push results.

**Phase D — P2SH redeem binding** (P2SH path only)
11. ≥1 push present; pop last push as `redeem`.
12. `redeem` is a valid 34-byte P2QR redeem (`0x50 0x20 <32>`); extract `committed_program`.
13. `HASH160(redeem) == prevout.script_id`.

**Phase E — shape dispatch**
14. remaining push count `== 2` ⇒ single-sig; `≥5` ⇒ multisig; 3 or 4 ⇒ reject (stack-too-small).

**Phase F — single-sig** (if dispatched)
15. `len(sig) == 4627`.
16. `len(pubkey) == 2592`.
17. `Hash256(pubkey) == committed_program`.
18. `MLDSA87Verify(pubkey, sighash, sig)` succeeds.

**Phase G — multisig threshold & format** (if dispatched)
19. `n` = minimal-u16-nonzero(top push); valid encoding.
20. `m` = minimal-u16-nonzero(second-from-top); valid encoding.
21. `m ≤ n`; `n ≤ 1024`; `m ≤ 1024`.
22. remaining size equals exactly one of `2m+n+2` (legacy) or `3m+n+2` (signer-address); else reject.

**Phase H — multisig fields, ordering, binding, verify**
23. each of the `m` signature pushes has `len == 4627`.
24. each of the `m` signer_index pushes is minimal-u16-allow-zero, `< n`, and the sequence is strictly increasing.
25. **legacy:** each of the `n` pubkey pushes `len == 2592`; pubkeys strictly increasing (byte-lex).
    **signer-address:** each of the `m` signing_pubkey pushes `len == 2592`; each of the `n` signer_program pushes `len == 32`; signer_programs strictly increasing (32-byte memcmp).
26. exactly one policy family present (not both, not neither).
27. recomputed program (§4.2 legacy / §4.3 signer-address) `== committed_program`.
28. for each approval `i ∈ [0,m)`, `k = signer_index[i]`:
    - **signer-address only:** `Hash256(signing_pubkey[i]) == signer_program[k]`;
    - **legacy:** `MLDSA87Verify(pubkey[k], sighash, sig[i])`; **signer-address:** `MLDSA87Verify(signing_pubkey[i], sighash, sig[i])`.

If no rule fires, the input is **valid**.

---

## 13. Consensus-compatibility test plan

Purpose: **prove** a reimplementation validates the existing live chain byte-identically — every historical P2QR / P2SH-wrapped / multisig spend validates identically, and a curated malformed corpus rejects identically. Run all of the following; a single mismatch blocks release.

### 13.1 Full historical replay (the primary proof)
- **T1 — Reindexing IBD from genesis.** Sync the reimplementation from genesis to current tip with `-reindex` (re-validate every block, do not trust the existing chainstate). PASS = identical active-chain tip hash and identical `getblockchaininfo` at every checkpoint height; any block the reference accepted that the reimplementation rejects (or vice versa) is a hard fail. This is the only test that covers *all* historical inputs including ones no synthetic vector anticipated.
- **T2 — Per-spend differential ledger.** Instrument both implementations to log, for every input at every height `≥ nP2QRActivationHeight`, a tuple `(txid, vin_index, detected_type ∈ {native-single, native-legacy-msig, native-addr-msig, p2sh-single, p2sh-legacy-msig, p2sh-addr-msig, ordinary}, accept/reject, computed sighash for each approval)`. Diff the two logs. PASS = zero differences across the entire chain. This catches a spend that both accept but for the *wrong reason* (e.g. mis-detected type, different sighash that still verified) — a latent split.
- **T3 — Coverage assertion.** From T2's ledger, assert every P2QR shape actually occurs on-chain at least once (native single; native legacy `m`-of-`n`; native signer-address `m`-of-`n`; and each P2SH-wrapped counterpart). For any shape with zero historical occurrences, mark it and rely on the synthetic vectors (§13.3–§13.5) as the sole proof, and note it explicitly in the release record. Include the known historical vault spend at block 13153 (legacy `VOID:P2QR:MSIG:v1`) as a named required case.
- **T4 — Mempool differential.** Replay the last N days of mempool-observed transactions (accepted and rejected) through `testmempoolaccept` on both implementations. PASS = identical accept/reject and identical reject reason class for every tx.

### 13.2 Sighash byte-vectors (frozen, byte-for-byte)
- **T5 — Fixed sighash vectors.** A committed set of `(tx, input_index, spent_outputs) → sighash` vectors, each asserting the exact 32-byte digest. MUST include: 1-input native; 1-input P2SH-wrapped (proves the 23-byte P2SH script — not the redeem — is committed in fields 10/14); a ≥8-input transaction mixing P2QR and non-P2QR inputs (proves all `spent[]` are covered and non-P2QR inputs contribute to the subhashes); and one vector per preimage-length case (native → 260 bytes, P2SH → 249 bytes).
- **T6 — O(N)↔O(N²) equivalence.** For a large multi-input transaction, assert the precomputed-subhash sighash equals the naive per-input-recompute sighash for **every** input, bit-for-bit. This is the guard on the mandatory §8.4 optimization.
- **T7 — Negative sighash sensitivity.** Mutate one field at a time (reorder fields; big-endian any integer; wrong width; double/tag a subhash; omit or nonzero epoch; hashType ≠ 1; byte-reverse a uint256/txid; non-minimal CompactSize; commit the redeem instead of the P2SH script; iterate spent outputs out of input order; put an amount into `hashSpentScripts`) and assert the digest **changes** (and thus a previously valid signature would fail). Confirms none of these are silently tolerated.

### 13.3 Program-derivation vectors
- **T8 — Single-key program:** `Hash256(pubkey) == program` for a fixed 2592-byte pubkey.
- **T9 — Legacy multisig program:** fixed `(m, n, sorted pubkeys)` → exact 32-byte program, asserting the `0x11`-prefixed 17-byte tag, `u16 m`, `u16 n`, and `FD 20 0A`-prefixed pubkeys, single-SHA256 finalize.
- **T10 — Signer-address program:** fixed `(m, n, sorted signer_programs)` → exact program, asserting the `0x16`-prefixed 22-byte tag and **unprefixed** 32-byte members. T9 vs T10 together prove the two policies are not interchangeable and that single-SHA256 (not double) is used.

### 13.4 Canonical-push and encoding vectors (accept + reject)
- **T11 — Canonical push accept:** the 34-byte redeem push (`22 …`), the 4627-byte sig (`4D 13 12 …`), the 2592-byte pubkey (`4D 20 0A …`), and the exact envelope byte counts (native single-sig scriptSig = 7225 bytes; P2SH single-sig = 7260 bytes).
- **T12 — Push reject corpus** (each must reject): empty scriptSig; non-push opcode present (`OP_1`, `OP_1NEGATE`, `OP_RESERVED`, `OP_CHECKSIG`); truncated PUSHDATA; non-minimal push (`OP_PUSHDATA1` for a 10-byte payload; `OP_PUSHDATA2` for a 5-byte payload; a direct opcode whose value ≠ actual length); push count exactly cap+1 (3075 native / 3076 P2SH).
- **T13 — Integer-encoding boundary vectors** (reject unless noted): `m`/`n` as empty push; `m`/`n` as 1-byte `0x00`; value 255 as `FF` (accept) vs value 255 as 2 bytes `FF 00` (reject, non-minimal); value 256 as `00 01` (accept) vs `00 01 00` (reject, >2 bytes); `n=1024` as `00 04` (accept); 2-byte value with high byte `0x00` (reject). `signer_index=0` as `{0x00}` (accept) vs empty push (reject). `signer_index=300` as `2C 01` (accept).

### 13.5 Malformed-spend reject corpus (one vector per reject rule)
Construct, for each numbered rule in §12 that can be isolated, a spend that is otherwise valid but violates exactly that rule, and assert **reject on both implementations with the same reason class**. Minimum required set:
- **Framing:** input_index out of range; `spent_outputs` count mismatch; non-null witness.
- **Output/redeem:** native output of length 33/35/38 (timelock) not recognized as native P2QR; P2SH prevout not 23 bytes; last push not a 34-byte P2QR redeem; `HASH160(redeem) ≠ script_id`.
- **Shape:** 3-push and 4-push native stacks (stack-too-small); a 2-push stack always taken as single-sig regardless of push sizes.
- **Single-sig:** sig length 4626/4628; pubkey length 2591/2593; `Hash256(pubkey) ≠ program`; a size-valid but cryptographically invalid signature (`MLDSA87Verify` false).
- **Multisig threshold/format:** `<5` pushes; `m=0`/`n=0`; `m>n`; `n=1025`; `m=1025`; stack size equal to neither `2m+n+2` nor `3m+n+2` (off by one item).
- **Multisig indexes:** an index `≥ n`; a duplicate adjacent index; a descending pair; index encoded as empty push.
- **Legacy:** a pubkey of length ≠ 2592; two equal adjacent pubkeys; adjacent pubkeys out of order; recomputed program ≠ committed; one approval whose ML-DSA-87 verify fails.
- **Signer-address:** signing_pubkey length ≠ 2592; signer_program length ≠ 32; two equal/out-of-order signer_programs; recomputed program ≠ committed; `Hash256(signing_pubkey[i]) ≠ signer_program[k]`; one approval whose verify fails.
- **Policy mixing:** a stack contrived to look like it carries both pubkeys and signer_programs, and one that matches neither policy size — both reject.

### 13.6 Fail-closed / routing checks
- **T14 — Pre-activation.** At a height `< nP2QRActivationHeight`, a native and a P2SH-wrapped P2QR spend both reject (bad-opcode) on both implementations.
- **T15 — Ordinary-path abort.** A P2SH-wrapped P2QR spend whose redeem hash does **not** match the prevout (so §9.2 fails) falls through to `VerifyScript` and fails there by executing `OP_RESERVED` (bad-opcode) — assert identical failure. Likewise a bare native P2QR output routed to `VerifyScript` on a non-upgraded node aborts at `OP_RESERVED`.
- **T16 — Missing spent-outputs.** With `spent_outputs.size() ≠ vin.size()`, validation returns a missing-spent-outputs error (not a pass) on both.

### 13.7 Differential fuzzing (residual-risk sweep)
- **T17 — Structured fuzzer.** Generate random-but-well-typed P2QR spends (random `m,n` within limits and push cap; random valid/invalid sizes; random orderings; native and P2SH; both policies) plus random raw scriptSig bytes, and feed identical inputs to both implementations. PASS = identical accept/reject (and, for accepts, identical sighash) on every input over a large run. This is the catch-all for reject-ordering and edge interactions not enumerated above.

**Release gate:** T1–T4 (historical replay + mempool differential) must be green with zero diffs; T5–T17 must all pass; any T3 shape with zero historical coverage is documented and covered only by synthetic vectors.

---

## 14. Where the six sections disagreed

- **D1 — P2SH output byte length (substantive; resolved to 23).** Section 3 ("single-sig-validation") states the P2SH output is the **"25-byte standard form"** in four places (§4.2, §4.5, §4.7, §4.11), while giving a byte layout (`OP_HASH160 0x14 <20> OP_EQUAL`) that sums to 23. Sections 1, 2, 5, and 6 all say **23 bytes**, and the arithmetic (1+1+20+1) is 23. Verified against the referenced source `src/script/script.cpp` `CScript::IsPayToScriptHash()`: `size() == 23 && [0]==OP_HASH160 && [1]==0x14 && [22]==OP_EQUAL`. **Section 3's "25" is an error; this document uses 23.** (Section 3's `0x14`/`0x87` bytes are otherwise correct, so the recognition logic still works; only the stated length is wrong. A reimplementer who copied "25" would reject every valid P2SH-wrapped P2QR spend — a chain split — so this is the most important flag.)

- **D2 — `tx.version` field type label (cosmetic; byte-identical).** In the sighash preimage, Sections 1, 3, 4, 5, and 6 label field 2 as `int32 tx.version`, while Section 2 labels it `uint32` and explicitly notes the codebase declares it `uint32_t`. Verified against source `src/primitives/transaction.h`: `const uint32_t version;`. All six agree it serializes as **4 bytes little-endian**, so the on-wire bytes are identical regardless of the signed/unsigned label. **Non-material**; this document notes both labels and pins the encoding as "4 LE". (`hashType` is genuinely an `int32` literal `1` in all six — no disagreement there; and `nLockTime` is `uint32` in all six.)

- **No other substantive disagreements.** All six agree byte-for-byte on: the 34-byte native layout and `0x50 0x20` prefix; the exact sizes 32 / 2592 / 4627; `Hash256` = double-SHA-256 for the single-key program and for signer-address per-signer binding; single-SHA-256 finalize for both multisig program commitments; the two domain tags and their CompactSize prefixes (`0x11`/17, `0x16`/22) with legacy pubkeys length-prefixed (`FD 20 0A`) and signer-address members raw/unprefixed; the sighash tag `VoidCoinP2QRSighash` (19 bytes), `epoch=0`, `hashType=1` (SIGHASH_ALL only), the field order and five single-SHA-256 subhashes; the canonical minimal-push rules and the rejection of `OP_1..OP_16` for integers; minimal-`uint16` nonzero (`m`,`n`) vs zero-allowed (`signer_index`) encodings; strictly-increasing invariants for indexes, pubkeys, and signer-programs; `MAX_KEYS`/`MAX_SIGNATURES` = 1024 and the push caps 3074 / 3075 (stricter than the key/sig limits for large multisig); the routing/dispatch order and the `OP_RESERVED` fail-closed guarantee; and the mandatory consensus-neutral O(N²)→O(N) sighash precompute. (Section 3 additionally, correctly, reports native single-sig scriptSig = 7225 bytes and P2SH single-sig = 7260 bytes; no other section contradicts these.)