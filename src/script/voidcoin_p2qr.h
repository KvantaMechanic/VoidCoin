// Copyright (c) 2026 The VoidCoin Core developers
// Copyright (c) 2026 Kvanta5 Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VoidCoin Pay-to-Quantum-Resistant (P2QR) script recognition and encoding.
// Derived from the Kvanta5-Core P2QR implementation, used under the MIT
// License as distributed at the time of the fork, and modified by VoidCoin;
// specified in VCIP-2 (/VCIP-2.md).
// Built on Bitcoin Core (MIT). Design lineage: BIP-360 (P2QR output design,
// Hunter Beast); ML-DSA-87 / NIST FIPS 204 via the pq-crystals/CRYSTALS-
// Dilithium reference implementation (src/crypto/pq/mldsa87/upstream/, not
// relicensed). The wire format is defined solely by VCIP-2 and by the bytes
// present on the VoidCoin chain.
//
//Liam's false Copyright claims end here. 
//
//All Original P2QR implementations are Copyright (c) 2026 The Kvanta5 Organization. 
//Whatever other ridiculous nonsense Liam did before he abandoned the chain is Copyright (c) 2026 Liam/Void/Whatever
//
//A note from KvantaMechanic: This is a good example for why people shouldn't be "vibe coding" blockchains. 
//Liam claims Kvanta5's P2QR implementation is derived from Hunter Beast's Pay-to-Merkle-Root (P2MR).
//He doesn't understand what he's claiming, at all. 
//Kvanta5's P2QR implements a native Pay-to-Quantum-Resistant (P2QR) output type using opcode 0x50 (Bitcoin's former OP_RESERVED), with ML-DSA-87 signature verification.


#ifndef VOIDCOIN_SCRIPT_VOIDCOIN_P2QR_H
#define VOIDCOIN_SCRIPT_VOIDCOIN_P2QR_H

#include <script/script.h>
#include <uint256.h>
#include <script/solver.h>
#include <crypto/pq/mldsa87/mldsa87.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

static constexpr size_t VOIDCOIN_P2QR_PUBKEY_SIZE = MLDSA87_PUBLIC_KEY_SIZE;
static constexpr size_t VOIDCOIN_P2QR_SIGNATURE_SIZE = MLDSA87_SIGNATURE_SIZE;

static constexpr unsigned int VOIDCOIN_P2QR_MULTISIG_MAX_KEYS = 1024;
static constexpr unsigned int VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES = 1024;

// Structural upper bound on the number of canonical pushes a well-formed P2QR
// multisig spend envelope can contain. Any scriptSig with more pushes than this
// cannot be a valid P2QR spend, so a bounded reader that bails at this limit
// rejects garbage without materializing an unbounded push vector.
//
//   <sig[m]> <signer_index[m]> <pubkey[n]> <m> <n>
//     = MAX_SIGNATURES (sigs) + MAX_SIGNATURES (indexes) + MAX_KEYS (pubkeys) + 2
//
// The P2SH-carried variant appends one more push (the redeemScript).
static constexpr size_t VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES =
    VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES +
    VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES +
    VOIDCOIN_P2QR_MULTISIG_MAX_KEYS +
    2;

static constexpr size_t VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES =
    VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES + 1;

// --- PA-06 / VCIP-3: raised multisig spend-side push caps --------------------
//
// The legacy caps above bound the legacy pubkey-policy spend envelope
// (2m + n + 2 pushes). They are NOT large enough for a large *new-format*
// signer-program multisig spend, whose envelope is:
//
//   <sig[m]> <signer_index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
//     = 3m + n + 2 pushes
//
// The create side (VoidCoinIsCanonicalP2QRMultisigPolicy) admits any policy with
// required (m) <= MAX_SIGNATURES and total (n) <= MAX_KEYS for BOTH formats, so a
// validly-committed signer-program multisig can require up to 3*MAX_SIGNATURES +
// MAX_KEYS + 2 spend pushes. With only the legacy cap enforced on the spend side,
// such an output funds fine but its spend is rejected as "too many pushes" -- the
// coins are permanently unspendable (PA-06). The VCIP-3 caps below are sized to
// that maximum (which also dominates the legacy 2m + n + 2 bound), so any
// validly-committed multisig of either format is spendable once VCIP-3 activates.
static constexpr size_t VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3 =
    VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + // signatures      (m)
    VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + // signer indexes  (m)
    VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + // signing pubkeys (m)
    VOIDCOIN_P2QR_MULTISIG_MAX_KEYS +       // signer programs (n)
    2;                                      // m, n

static constexpr size_t VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES_VCIP3 =
    VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3 + 1;

// Create/spend consistency invariant (PA-06 regression tripwire). If a future
// edit to the key/signature limits makes the raised spend cap too small to hold
// the maximal validly-committed policy of EITHER format, coins become strandable
// again -- so fail the build here instead.
static_assert(
    VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3 >=
        2 * VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + VOIDCOIN_P2QR_MULTISIG_MAX_KEYS + 2,
    "VCIP-3 push cap must cover the maximal legacy-format multisig spend");
static_assert(
    VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3 >=
        3 * VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + VOIDCOIN_P2QR_MULTISIG_MAX_KEYS + 2,
    "VCIP-3 push cap must cover the maximal signer-program-format multisig spend");
// The legacy cap must remain exactly the historical value for pre-fork parity.
static_assert(
    VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES ==
        2 * VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + VOIDCOIN_P2QR_MULTISIG_MAX_KEYS + 2,
    "pre-VCIP-3 push cap must not change (byte-identical pre-fork behavior)");

// Select the effective native / P2SH multisig push cap for a spend given the
// VCIP-3 activation state at the spending height. false -> legacy (pre-fork)
// cap, byte-identical to today; true -> raised (post-fork) cap.
constexpr size_t VoidCoinP2QRMultisigMaxPushes(bool vcip3_active)
{
    return vcip3_active ? VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3
                        : VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES;
}

constexpr size_t VoidCoinP2QRMultisigP2SHMaxPushes(bool vcip3_active)
{
    return vcip3_active ? VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES_VCIP3
                        : VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES;
}

struct VoidCoinP2QRMultisigSpend
{
    uint16_t required{0};
    uint16_t total{0};

    std::vector<std::vector<unsigned char>> signatures;
    std::vector<uint16_t> signer_indexes;

    // Legacy/live-chain pubkey-policy format:
    // <sig[m]> <signer_index[m]> <pubkey[n]> <m> <n>
    std::vector<std::vector<unsigned char>> pubkeys;

    // New signer-address/program-policy format:
    // <sig[m]> <signer_index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
    std::vector<std::vector<unsigned char>> signing_pubkeys;
    std::vector<uint256> signer_programs;
};

uint256 VoidCoinP2QRSingleProgram(const std::vector<unsigned char>& pubkey);

uint256 VoidCoinP2QRMultisigProgram(
    uint16_t required,
    const std::vector<uint256>& signer_programs);
    
uint256 VoidCoinP2QRMultisigProgram(
    uint16_t required,
    const std::vector<std::vector<unsigned char>>& pubkeys);

bool VoidCoinIsCanonicalP2QRMultisigPolicy(
    uint16_t required,
    const std::vector<std::vector<unsigned char>>& pubkeys,
    std::string* error = nullptr);

bool VoidCoinIsCanonicalP2QRMultisigPolicy(
    uint16_t required,
    const std::vector<uint256>& signer_programs,
    std::string* error = nullptr);

bool VoidCoinParseP2QRMultisigSpend(
    const std::vector<std::vector<unsigned char>>& stack,
    VoidCoinP2QRMultisigSpend& out,
    std::string* error = nullptr);

CScript VoidCoinMakeP2QRScriptPubKey(const uint256& program);

// --- VCIP-3 versioned P2QR time-lock -----------------------------------------
//
// Time-lock output scriptPubKey:
//   OP_RESERVED <program[32]> <lock_descriptor[10]>
// The 10-byte lock_descriptor is:
//   version(1) || lock_type(1) || lock_value(uint64 little-endian, 8)
//
// The `program` is the SAME P2QR policy commitment used by native P2QR (a single
// ML-DSA-87 key or an M-of-N multisig), so the spend-authorization path is a
// direct extension of native-P2QR CheckSpend. The lock is committed to by the
// output scriptPubKey (which the P2QR sighash already covers), so no sighash
// change is required.

//! Only version 0x01 is defined. Any other value is unspendable at consensus
//! (reserved for future rules).
static constexpr uint8_t VOIDCOIN_P2QR_TIMELOCK_VERSION = 0x01;

//! lock_type values.
static constexpr uint8_t VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT = 0x00; //!< absolute block height
static constexpr uint8_t VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP    = 0x01; //!< absolute median-time-past (unix seconds)
//! 0x02 / 0x03 are reserved for future relative locks: they are parsed
//! structurally but are unspendable at consensus for now.
static constexpr uint8_t VOIDCOIN_P2QR_TIMELOCK_TYPE_RESERVED_REL_HEIGHT = 0x02;
static constexpr uint8_t VOIDCOIN_P2QR_TIMELOCK_TYPE_RESERVED_REL_MTP    = 0x03;

//! Parsed VCIP-3 time-lock descriptor.
struct VoidCoinP2QRTimeLock {
    uint8_t version{VOIDCOIN_P2QR_TIMELOCK_VERSION};
    uint8_t lock_type{VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT};
    uint64_t lock_value{0};
};

//! True if (version, lock_type) is a currently-supported, spendable combination:
//! version == 0x01 and lock_type in {HEIGHT, MTP}. Reserved/unknown values are
//! parsed but not spendable (fail-closed, reserved for a future fork).
bool VoidCoinIsSupportedP2QRTimeLock(const VoidCoinP2QRTimeLock& lock);

//! Serialize the 10-byte lock_descriptor.
std::vector<unsigned char> VoidCoinEncodeP2QRTimeLockDescriptor(const VoidCoinP2QRTimeLock& lock);

//! Structurally parse a 10-byte lock_descriptor into version/lock_type/lock_value
//! (uint64 LE). Requires exactly VOIDCOIN_P2QR_TIMELOCK_DESCRIPTOR_SIZE bytes.
//! Does NOT enforce that version/lock_type are supported; callers apply the
//! consensus/policy rule via VoidCoinIsSupportedP2QRTimeLock().
bool VoidCoinDecodeP2QRTimeLockDescriptor(
    const std::vector<unsigned char>& descriptor,
    VoidCoinP2QRTimeLock& out,
    std::string* error = nullptr);

//! Build the versioned time-lock scriptPubKey:
//!   OP_RESERVED <program[32]> <lock_descriptor[10]>
CScript VoidCoinMakeP2QRTimeLockScriptPubKey(const uint256& program, const VoidCoinP2QRTimeLock& lock);

bool VoidCoinIsCanonicalP2QRPush(opcodetype opcode, const std::vector<unsigned char>& data);

bool VoidCoinReadCanonicalP2QRPushes(
    const CScript& script,
    std::vector<std::vector<unsigned char>>& pushes_out,
    std::string* error = nullptr,
    size_t max_pushes = 0);

#endif // VOIDCOIN_SCRIPT_VOIDCOIN_P2QR_H
