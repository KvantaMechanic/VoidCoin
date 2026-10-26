// Copyright (c) 2026 The VoidCoin Core developers
// Copyright (c) 2026 Kvanta5 Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VoidCoin Pay-to-Quantum-Resistant (P2QR) consensus validation.
//
// Derived from the Kvanta5-Core P2QR implementation, used under the MIT
// License as distributed at the time of the fork (2026-06-29), and then
// modified by VoidCoin (notably O(N) precomputed sighashing and the P2QR
// time-lock output). Specified normatively in VCIP-2 (see /VCIP-2.md). Built
// on the Bitcoin Core codebase (https://github.com/bitcoin/bitcoin, MIT);
// reuses Bitcoin Core's serialization, hashing (HashWriter / TaggedHash), and
// script primitives.
//
// Design lineage (public, documented sources):
//   * Quantum-resistant output construction follows BIP-360
//     (Pay-to-Quantum-Resistant / "QuBit"; author Hunter Beast).
//   * Post-quantum signatures use ML-DSA-87 as standardized by NIST in
//     FIPS 204, via the pq-crystals/CRYSTALS-Dilithium reference
//     implementation vendored under src/crypto/pq/mldsa87/upstream/
//     (see that directory's LICENSE; not relicensed here).
//   * Linear-time O(N) sighashing via per-transaction precomputed subhashes
//     is the established public precedent from BIP-143 (Johnson Lau, Pieter
//     Wuille), which resolved the O(N^2) transaction-hashing DoS CVE-2013-2292,
//     extended by BIP-341 (Taproot); realized in Bitcoin Core as
//     PrecomputedTransactionData.
//
// The wire format is defined solely by VCIP-2 and by the serialized bytes
// present on the VoidCoin chain; this file was written against that spec.
//Liam's false Copyright claims end here. 
//
//All Original P2QR implementations are Copyright (c) 2026 The Kvanta5 Organization. 
//Whatever other ridiculous nonsense Liam did before he abandoned the chain is Copyright (c) 2026 Liam/Void/Whatever
//
//A note from KvantaMechanic: This is a good example for why people shouldn't be "vibe coding" blockchains. 
//Liam claims Kvanta5's P2QR implementation is derived from Hunter Beast's Pay-to-Merkle-Root (P2MR).
//He doesn't understand what he's claiming, at all. 
//Kvanta5's P2QR implements a native Pay-to-Quantum-Resistant (P2QR) output type using opcode 0x50 (Bitcoin's former OP_RESERVED), with ML-DSA-87 signature verification.

#include <consensus/voidcoinp2qr.h>

#include <crypto/pq/mldsa87/mldsa87.h>
#include <hash.h>
#include <script/voidcoin_p2qr.h>
#include <script/solver.h>
#include <span.h>
#include <tinyformat.h>

#include <algorithm>
#include <limits>
#include <stdexcept>

namespace consensus::voidcoinp2qr {
namespace {

static const HashWriter HASHER_VoidCoinP2QR_SIGHASH{TaggedHash("VoidCoinP2QRSighash")};

static constexpr size_t VOIDCOIN_P2QR_SINGLE_PUSHES = 2;
static constexpr size_t VOIDCOIN_P2QR_SINGLE_P2SH_PUSHES = 3;

// VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES / VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES
// are the shared structural push bounds, defined in <script/voidcoin_p2qr.h>
// so relay-policy pre-checks (validation.cpp) reuse the same limit.

std::vector<unsigned char> ToByteVector(const uint256& value)
{
    return std::vector<unsigned char>(value.begin(), value.end());
}

uint256 HashPrevouts(const CTransaction& tx)
{
    HashWriter ss{};
    for (const CTxIn& txin : tx.vin) {
        ss << txin.prevout;
    }
    return ss.GetSHA256();
}

uint256 HashSequences(const CTransaction& tx)
{
    HashWriter ss{};
    for (const CTxIn& txin : tx.vin) {
        ss << txin.nSequence;
    }
    return ss.GetSHA256();
}

uint256 HashOutputs(const CTransaction& tx)
{
    HashWriter ss{};
    for (const CTxOut& txout : tx.vout) {
        ss << txout;
    }
    return ss.GetSHA256();
}

uint256 HashSpentAmounts(const std::vector<CTxOut>& spent_outputs)
{
    HashWriter ss{};
    for (const CTxOut& txout : spent_outputs) {
        ss << txout.nValue;
    }
    return ss.GetSHA256();
}

uint256 HashSpentScripts(const std::vector<CTxOut>& spent_outputs)
{
    HashWriter ss{};
    for (const CTxOut& txout : spent_outputs) {
        ss << txout.scriptPubKey;
    }
    return ss.GetSHA256();
}

bool ReadPushesOnly(
    const CScript& script,
    std::vector<std::vector<unsigned char>>& pushes_out,
    std::string& error_out,
    const size_t max_pushes)
{
    pushes_out.clear();

    std::string push_error;

    if (!VoidCoinReadCanonicalP2QRPushes(script, pushes_out, &push_error, max_pushes)) {
        error_out = strprintf("VOIDCOIN_P2QR scriptSig push format invalid: %s", push_error);
        return false;
    }

    return true;
}

uint256 SignatureHashInternal(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate)
{
    assert(input_index < tx.vin.size());
    assert(spent_outputs.size() == tx.vin.size());

    // The five whole-transaction subhashes (preimage fields 6..10) MUST have
    // been precomputed once for THIS transaction. There is no per-input
    // recompute fallback: a missing or foreign midstate is a programming error,
    // not a slow path. The txid binding guarantees the cached subhashes belong
    // to `tx`; otherwise we would produce a sighash for a different transaction
    // (a chain split). Bitcoin Core builds always keep assert() enabled.
    assert(midstate.m_ready);
    assert(midstate.m_txid == tx.GetHash());

    HashWriter ss{HASHER_VoidCoinP2QR_SIGHASH};

    static constexpr uint8_t VOIDCOIN_P2QR_SIGHASH_EPOCH = 0;
    static constexpr int32_t VOIDCOIN_P2QR_HASH_TYPE = 1; // SIGHASH_ALL

    ss << VOIDCOIN_P2QR_SIGHASH_EPOCH;

    ss << tx.version;
    ss << tx.nLockTime;
    ss << VOIDCOIN_P2QR_HASH_TYPE;
    ss << input_index;

    // Byte-identical to the per-input recompute: each of these equals
    // HashPrevouts(tx)/HashSequences(tx)/HashOutputs(tx)/
    // HashSpentAmounts(spent_outputs)/HashSpentScripts(spent_outputs),
    // which are pure functions of (tx, spent_outputs) and input-index
    // independent. BuildSighashMidstate() computes exactly those.
    ss << midstate.m_hash_prevouts;
    ss << midstate.m_hash_sequences;
    ss << midstate.m_hash_outputs;
    ss << midstate.m_hash_spent_amounts;
    ss << midstate.m_hash_spent_scripts;

    ss << tx.vin[input_index].prevout;
    ss << tx.vin[input_index].nSequence;
    ss << spent_output.nValue;
    ss << spent_output.scriptPubKey;

    return ss.GetSHA256();
}

bool CheckSignatureAndProgram(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    const uint256& committed_program,
    const std::vector<unsigned char>& signature,
    const std::vector<unsigned char>& pubkey,
    std::string& error_out)
{
    if (signature.size() != MLDSA87_SIGNATURE_SIZE) {
        error_out = "VOIDCOIN_P2QR signature has invalid size";
        return false;
    }

    if (pubkey.size() != MLDSA87_PUBLIC_KEY_SIZE) {
        error_out = "VOIDCOIN_P2QR public key has invalid size";
        return false;
    }

    const uint256 pubkey_hash = Hash(pubkey);
    if (pubkey_hash != committed_program) {
        error_out = "VOIDCOIN_P2QR public key does not match committed program";
        return false;
    }

    const uint256 sighash = SignatureHashInternal(tx, input_index, spent_output, spent_outputs, midstate);

    if (!MLDSA87Verify(
            Span<const unsigned char>(pubkey.data(), pubkey.size()),
            Span<const unsigned char>(sighash.begin(), sighash.size()),
            Span<const unsigned char>(signature.data(), signature.size()))) {
        error_out = "VOIDCOIN_P2QR ML-DSA-87 signature verification failed";
        return false;
    }

    return true;
}

bool CheckMultisigProgramAndSignatures(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    const uint256& committed_program,
    const VoidCoinP2QRMultisigSpend& spend,
    std::string& error_out)
{
    const bool has_legacy_pubkey_policy = !spend.pubkeys.empty();
    const bool has_signer_program_policy = !spend.signer_programs.empty();

    if (has_legacy_pubkey_policy && has_signer_program_policy) {
        error_out = "VOIDCOIN_P2QR multisig spend mixes legacy pubkey policy and signer address policy";
        return false;
    }

    if (!has_legacy_pubkey_policy && !has_signer_program_policy) {
        error_out = "VOIDCOIN_P2QR multisig spend has no signer policy";
        return false;
    }

    if (spend.required == 0 || spend.total == 0 || spend.required > spend.total) {
        error_out = "VOIDCOIN_P2QR multisig invalid threshold";
        return false;
    }

    if (spend.signatures.size() != spend.required ||
        spend.signer_indexes.size() != spend.required) {
        error_out = "VOIDCOIN_P2QR multisig approval vectors are inconsistent";
        return false;
    }

    const uint256 sighash = SignatureHashInternal(tx, input_index, spent_output, spent_outputs, midstate);

    /*
     * Legacy/live-chain multisig format:
     *
     *   <sig[m]> <signer_index[m]> <pubkey[n]> <m> <n>
     *
     * This must remain valid forever so existing historical blocks, including
     * the old-format vault spend at height 13153, continue to validate.
     */
    if (has_legacy_pubkey_policy) {
        if (spend.pubkeys.size() != spend.total) {
            error_out = "VOIDCOIN_P2QR legacy multisig pubkey count does not match total";
            return false;
        }

        const uint256 expected_program = VoidCoinP2QRMultisigProgram(spend.required, spend.pubkeys);

        if (expected_program != committed_program) {
            error_out = "VOIDCOIN_P2QR legacy multisig pubkey policy does not match committed program";
            return false;
        }

        for (size_t i = 0; i < spend.signatures.size(); ++i) {
            const uint16_t signer_index = spend.signer_indexes[i];

            if (signer_index >= spend.pubkeys.size()) {
                error_out = "VOIDCOIN_P2QR legacy multisig signer index out of range";
                return false;
            }

            const std::vector<unsigned char>& pubkey = spend.pubkeys[signer_index];
            const std::vector<unsigned char>& signature = spend.signatures[i];

            if (pubkey.size() != VOIDCOIN_P2QR_PUBKEY_SIZE) {
                error_out = "VOIDCOIN_P2QR legacy multisig bad pubkey size";
                return false;
            }

            if (!MLDSA87Verify(
                    Span<const unsigned char>(pubkey.data(), pubkey.size()),
                    Span<const unsigned char>(sighash.begin(), sighash.size()),
                    Span<const unsigned char>(signature.data(), signature.size()))) {
                error_out = "VOIDCOIN_P2QR legacy multisig ML-DSA-87 signature verification failed";
                return false;
            }
        }

        return true;
    }

    /*
     * New signer-address/program multisig format:
     *
     *   <sig[m]> <signer_index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
     *
     * The policy commits to signer programs. Signing pubkeys are revealed only
     * by actual approving signers, then checked against their committed signer
     * program before signature verification.
     */
    if (spend.signatures.size() != spend.required ||
        spend.signer_indexes.size() != spend.required ||
        spend.signing_pubkeys.size() != spend.required) {
        error_out = "VOIDCOIN_P2QR multisig approval vectors are inconsistent";
        return false;
    }

    if (spend.signer_programs.size() != spend.total) {
        error_out = "VOIDCOIN_P2QR multisig signer program count does not match total";
        return false;
    }

    const uint256 expected_program = VoidCoinP2QRMultisigProgram(spend.required, spend.signer_programs);

    if (expected_program != committed_program) {
        error_out = "VOIDCOIN_P2QR multisig signer address policy does not match committed program";
        return false;
    }

    for (size_t i = 0; i < spend.signatures.size(); ++i) {
        const uint16_t signer_index = spend.signer_indexes[i];

        if (signer_index >= spend.signer_programs.size()) {
            error_out = "VOIDCOIN_P2QR multisig signer index out of range";
            return false;
        }

        const std::vector<unsigned char>& pubkey = spend.signing_pubkeys[i];
        const std::vector<unsigned char>& signature = spend.signatures[i];

        if (pubkey.size() != VOIDCOIN_P2QR_PUBKEY_SIZE) {
            error_out = "VOIDCOIN_P2QR multisig bad signing pubkey size";
            return false;
        }

        const uint256 derived_signer_program = VoidCoinP2QRSingleProgram(pubkey);
        if (derived_signer_program != spend.signer_programs[signer_index]) {
            error_out = "VOIDCOIN_P2QR multisig signing pubkey does not match committed signer address";
            return false;
        }

        if (!MLDSA87Verify(
                Span<const unsigned char>(pubkey.data(), pubkey.size()),
                Span<const unsigned char>(sighash.begin(), sighash.size()),
                Span<const unsigned char>(signature.data(), signature.size()))) {
            error_out = "VOIDCOIN_P2QR multisig ML-DSA-87 signature verification failed";
            return false;
        }
    }

    return true;
}

} // namespace

bool IsOutput(const CScript& script_pubkey, uint256& program_out)
{
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(script_pubkey, solutions) != TxoutType::VOIDCOIN_P2QR) {
        return false;
    }

    if (solutions.size() != 1 || solutions[0].size() != 32) {
        return false;
    }

    std::copy(solutions[0].begin(), solutions[0].end(), program_out.begin());
    return true;
}

bool IsRedeemScript(const CScript& redeem_script, uint256& program_out)
{
    return IsOutput(redeem_script, program_out);
}

bool IsTimeLockOutput(const CScript& script_pubkey, uint256& program_out, VoidCoinP2QRTimeLock& lock_out)
{
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(script_pubkey, solutions) != TxoutType::VOIDCOIN_P2QR_TIMELOCK) {
        return false;
    }

    if (solutions.size() != 2 ||
        solutions[0].size() != VOIDCOIN_P2QR_PROGRAM_SIZE ||
        solutions[1].size() != VOIDCOIN_P2QR_TIMELOCK_DESCRIPTOR_SIZE) {
        return false;
    }

    if (!VoidCoinDecodeP2QRTimeLockDescriptor(solutions[1], lock_out)) {
        return false;
    }

    std::copy(solutions[0].begin(), solutions[0].end(), program_out.begin());
    return true;
}

CScript MakeRedeemScript(const uint256& program)
{
    return CScript() << OP_RESERVED << ToByteVector(program);
}

CScript MakeP2SHScriptPubKey(const uint256& program)
{
    const CScript redeem_script = MakeRedeemScript(program);
    const CScriptID script_id(redeem_script);

    return CScript()
        << OP_HASH160
        << std::vector<unsigned char>(script_id.begin(), script_id.end())
        << OP_EQUAL;
}

bool IsP2SHOutput(const CScript& script_pubkey, CScriptID& script_id_out)
{
    std::vector<std::vector<unsigned char>> solutions;
    if (Solver(script_pubkey, solutions) != TxoutType::SCRIPTHASH) {
        return false;
    }

    if (solutions.size() != 1 || solutions[0].size() != 20) {
        return false;
    }

    std::copy(solutions[0].begin(), solutions[0].end(), script_id_out.begin());
    return true;
}

bool IsP2SHWrappedSpendCandidate(
    const CScript& spent_script_pubkey,
    const CScript& script_sig,
    bool vcip3_pushcap_active)
{
    CScriptID expected_script_id;
    if (!IsP2SHOutput(spent_script_pubkey, expected_script_id)) {
        return false;
    }

    std::string error;
    std::vector<std::vector<unsigned char>> pushes;
    if (!ReadPushesOnly(script_sig, pushes, error,
                        VoidCoinP2QRMultisigP2SHMaxPushes(vcip3_pushcap_active))) {
        return false;
    }

    if (pushes.empty()) {
        return false;
    }

    const CScript redeem_script(pushes.back().begin(), pushes.back().end());

    uint256 program;
    if (!IsRedeemScript(redeem_script, program)) {
        return false;
    }

    const CScriptID actual_script_id(redeem_script);
    return actual_script_id == expected_script_id;
}

bool SpendsAnyP2QR(const std::vector<CTxOut>& spent_outputs)
{
    uint256 program;
    for (const CTxOut& spent_output : spent_outputs) {
        if (IsOutput(spent_output.scriptPubKey, program)) {
            return true;
        }
    }
    return false;
}

P2QRSighashMidstate BuildSighashMidstate(
    const CTransaction& tx,
    const std::vector<CTxOut>& spent_outputs)
{
    // Header-exposed helper: enforce the vin-alignment precondition with a hard
    // throw rather than an assert() that NDEBUG would erase. A mis-sized
    // spent_outputs vector must fail loudly, never silently build a midstate
    // that hashes the wrong set of spent outputs.
    if (spent_outputs.size() != tx.vin.size()) {
        throw std::invalid_argument(
            "VOIDCOIN_P2QR BuildSighashMidstate: spent_outputs must be vin-aligned");
    }

    P2QRSighashMidstate midstate;
    // The five whole-transaction subhashes, computed exactly once. Each uses the
    // very same helper the per-input path used before this refactor, so the
    // cached values are byte-identical to a per-input recompute.
    midstate.m_hash_prevouts = HashPrevouts(tx);
    midstate.m_hash_sequences = HashSequences(tx);
    midstate.m_hash_outputs = HashOutputs(tx);
    midstate.m_hash_spent_amounts = HashSpentAmounts(spent_outputs);
    midstate.m_hash_spent_scripts = HashSpentScripts(spent_outputs);
    midstate.m_txid = tx.GetHash();
    midstate.m_ready = true;
    return midstate;
}

uint256 SignatureHash(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate)
{
    // Header-exposed helper: preconditions are enforced with hard throws, not
    // NDEBUG-erased assert(), so a misuse fails loudly in release builds instead
    // of computing a digest against out-of-bounds or foreign-transaction state.
    if (input_index >= tx.vin.size()) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHash: input_index out of range");
    }
    if (spent_outputs.size() != tx.vin.size()) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHash: spent_outputs must be vin-aligned");
    }

    uint256 program;
    if (!IsOutput(spent_output.scriptPubKey, program)) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHash: spent_output is not a native P2QR output");
    }
    if (!midstate.m_ready || midstate.m_txid != tx.GetHash()) {
        throw std::invalid_argument(
            "VOIDCOIN_P2QR SignatureHash: midstate is missing or not bound to this transaction");
    }

    return SignatureHashInternal(tx, input_index, spent_output, spent_outputs, midstate);
}

uint256 SignatureHashP2SHWrapped(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate)
{
    // Header-exposed helper: hard throws instead of NDEBUG-erased assert().
    if (input_index >= tx.vin.size()) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHashP2SHWrapped: input_index out of range");
    }
    if (spent_outputs.size() != tx.vin.size()) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHashP2SHWrapped: spent_outputs must be vin-aligned");
    }

    CScriptID script_id;
    if (!IsP2SHOutput(spent_output.scriptPubKey, script_id)) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHashP2SHWrapped: spent_output is not a P2SH output");
    }
    if (!midstate.m_ready || midstate.m_txid != tx.GetHash()) {
        throw std::invalid_argument(
            "VOIDCOIN_P2QR SignatureHashP2SHWrapped: midstate is missing or not bound to this transaction");
    }

    return SignatureHashInternal(tx, input_index, spent_output, spent_outputs, midstate);
}

uint256 SignatureHashTimeLock(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate)
{
    // Header-exposed helper: hard throws instead of NDEBUG-erased assert().
    if (input_index >= tx.vin.size()) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHashTimeLock: input_index out of range");
    }
    if (spent_outputs.size() != tx.vin.size()) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHashTimeLock: spent_outputs must be vin-aligned");
    }

    uint256 program;
    VoidCoinP2QRTimeLock lock;
    if (!IsTimeLockOutput(spent_output.scriptPubKey, program, lock)) {
        throw std::invalid_argument("VOIDCOIN_P2QR SignatureHashTimeLock: spent_output is not a P2QR time-lock output");
    }
    if (!midstate.m_ready || midstate.m_txid != tx.GetHash()) {
        throw std::invalid_argument(
            "VOIDCOIN_P2QR SignatureHashTimeLock: midstate is missing or not bound to this transaction");
    }

    // Byte-identical to SignatureHash(): the SIGHASH_ALL preimage's field 14
    // hashes the full spent scriptPubKey, so the lock descriptor is already
    // committed without any preimage-layout change.
    return SignatureHashInternal(tx, input_index, spent_output, spent_outputs, midstate);
}

bool ParseSpendData(
    const CScript& script_sig,
    std::vector<unsigned char>& signature_out,
    std::vector<unsigned char>& pubkey_out,
    std::string& error_out)
{
    signature_out.clear();
    pubkey_out.clear();
    error_out.clear();

    std::vector<std::vector<unsigned char>> pushes;
    if (!ReadPushesOnly(script_sig, pushes, error_out, 2)) {
        return false;
    }

    if (pushes.size() != 2) {
        error_out = "VOIDCOIN_P2QR scriptSig must contain exactly signature and public key";
        return false;
    }

    signature_out = std::move(pushes[0]);
    pubkey_out = std::move(pushes[1]);

    if (signature_out.size() != MLDSA87_SIGNATURE_SIZE) {
        error_out = "VOIDCOIN_P2QR signature has invalid size";
        return false;
    }

    if (pubkey_out.size() != MLDSA87_PUBLIC_KEY_SIZE) {
        error_out = "VOIDCOIN_P2QR public key has invalid size";
        return false;
    }

    return true;
}

bool ParseP2SHWrappedSpendData(
    const CScript& script_sig,
    std::vector<unsigned char>& signature_out,
    std::vector<unsigned char>& pubkey_out,
    CScript& redeem_script_out,
    uint256& program_out,
    std::string& error_out)
{
    signature_out.clear();
    pubkey_out.clear();
    redeem_script_out.clear();
    program_out.SetNull();
    error_out.clear();

    std::vector<std::vector<unsigned char>> pushes;
    if (!ReadPushesOnly(script_sig, pushes, error_out, 3)) {
        return false;
    }

    if (pushes.size() != 3) {
        error_out = "VOIDCOIN_P2QR P2SH scriptSig must contain signature, public key, and redeem script";
        return false;
    }

    signature_out = std::move(pushes[0]);
    pubkey_out = std::move(pushes[1]);
    redeem_script_out = CScript(pushes[2].begin(), pushes[2].end());

    if (!IsRedeemScript(redeem_script_out, program_out)) {
        error_out = "VOIDCOIN_P2QR P2SH redeem script is not a P2QR redeem script";
        return false;
    }

    if (signature_out.size() != MLDSA87_SIGNATURE_SIZE) {
        error_out = "VOIDCOIN_P2QR signature has invalid size";
        return false;
    }

    if (pubkey_out.size() != MLDSA87_PUBLIC_KEY_SIZE) {
        error_out = "VOIDCOIN_P2QR public key has invalid size";
        return false;
    }

    return true;
}

bool CheckSpend(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    std::string& error_out,
    bool vcip3_pushcap_active)
{
    error_out.clear();

    if (input_index >= tx.vin.size()) {
        error_out = "VOIDCOIN_P2QR input index out of range";
        return false;
    }

    if (spent_outputs.size() != tx.vin.size()) {
        error_out = "VOIDCOIN_P2QR validation requires all spent outputs";
        return false;
    }

    // The sighash midstate MUST be populated and bound to THIS transaction.
    // A missing or cross-transaction midstate would silently produce a sighash
    // for a different transaction (a chain split), so fail loudly here with a
    // hard return rather than relying on an NDEBUG-erased assert() downstream.
    if (!midstate.m_ready || midstate.m_txid != tx.GetHash()) {
        error_out = "VOIDCOIN_P2QR sighash midstate is missing or not bound to this transaction";
        return false;
    }

    // The caller-supplied spent_output must be the exact output this input
    // spends. Both are indexed by the same vin position; a mismatch would sign
    // over the wrong amount/scriptPubKey (preimage fields 13/14).
    if (!(spent_output == spent_outputs[input_index])) {
        error_out = "VOIDCOIN_P2QR spent_output does not match spent_outputs[input_index]";
        return false;
    }

    const CTxIn& txin = tx.vin[input_index];

    if (!txin.scriptWitness.IsNull()) {
        error_out = "VOIDCOIN_P2QR spends must not contain witness data";
        return false;
    }

    uint256 committed_program;
    if (!IsOutput(spent_output.scriptPubKey, committed_program)) {
        error_out = "VOIDCOIN_P2QR validation called for non-P2QR output";
        return false;
    }

    std::vector<std::vector<unsigned char>> pushes;
    if (!ReadPushesOnly(txin.scriptSig, pushes, error_out,
                        VoidCoinP2QRMultisigMaxPushes(vcip3_pushcap_active))) {
        return false;
    }

    if (pushes.size() == VOIDCOIN_P2QR_SINGLE_PUSHES) {
        const std::vector<unsigned char>& signature = pushes[0];
        const std::vector<unsigned char>& pubkey = pushes[1];

        return CheckSignatureAndProgram(
            tx,
            input_index,
            spent_output,
            spent_outputs,
            midstate,
            committed_program,
            signature,
            pubkey,
            error_out);
    }

    VoidCoinP2QRMultisigSpend multisig_spend;
    std::string parse_error;

    if (!VoidCoinParseP2QRMultisigSpend(pushes, multisig_spend, &parse_error)) {
        error_out = strprintf("VOIDCOIN_P2QR multisig spend invalid: %s", parse_error);
        return false;
    }

    return CheckMultisigProgramAndSignatures(
        tx,
        input_index,
        spent_output,
        spent_outputs,
        midstate,
        committed_program,
        multisig_spend,
        error_out);
}

bool CheckSpendP2SHWrapped(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    std::string& error_out,
    bool vcip3_pushcap_active)
{
    error_out.clear();

    if (input_index >= tx.vin.size()) {
        error_out = "VOIDCOIN_P2QR P2SH input index out of range";
        return false;
    }

    if (spent_outputs.size() != tx.vin.size()) {
        error_out = "VOIDCOIN_P2QR P2SH validation requires all spent outputs";
        return false;
    }

    // Midstate must be populated and bound to THIS transaction (see CheckSpend).
    if (!midstate.m_ready || midstate.m_txid != tx.GetHash()) {
        error_out = "VOIDCOIN_P2QR P2SH sighash midstate is missing or not bound to this transaction";
        return false;
    }

    // spent_output must be exactly the output this input spends (see CheckSpend).
    if (!(spent_output == spent_outputs[input_index])) {
        error_out = "VOIDCOIN_P2QR P2SH spent_output does not match spent_outputs[input_index]";
        return false;
    }

    const CTxIn& txin = tx.vin[input_index];

    if (!txin.scriptWitness.IsNull()) {
        error_out = "VOIDCOIN_P2QR P2SH spends must not contain witness data";
        return false;
    }

    CScriptID expected_script_id;
    if (!IsP2SHOutput(spent_output.scriptPubKey, expected_script_id)) {
        error_out = "VOIDCOIN_P2QR P2SH validation called for non-P2SH output";
        return false;
    }

    std::vector<std::vector<unsigned char>> pushes;
    if (!ReadPushesOnly(txin.scriptSig, pushes, error_out,
                        VoidCoinP2QRMultisigP2SHMaxPushes(vcip3_pushcap_active))) {
        return false;
    }

    if (pushes.empty()) {
        error_out = "VOIDCOIN_P2QR P2SH scriptSig is missing redeem script";
        return false;
    }

    const CScript redeem_script(pushes.back().begin(), pushes.back().end());
    pushes.pop_back();

    uint256 committed_program;
    if (!IsRedeemScript(redeem_script, committed_program)) {
        error_out = "VOIDCOIN_P2QR P2SH redeem script is not a P2QR redeem script";
        return false;
    }

    const CScriptID actual_script_id(redeem_script);
    if (actual_script_id != expected_script_id) {
        error_out = "VOIDCOIN_P2QR P2SH redeem script hash does not match prevout";
        return false;
    }

    if (pushes.size() == VOIDCOIN_P2QR_SINGLE_PUSHES) {
        const std::vector<unsigned char>& signature = pushes[0];
        const std::vector<unsigned char>& pubkey = pushes[1];

        return CheckSignatureAndProgram(
            tx,
            input_index,
            spent_output,
            spent_outputs,
            midstate,
            committed_program,
            signature,
            pubkey,
            error_out);
    }

    VoidCoinP2QRMultisigSpend multisig_spend;
    std::string parse_error;

    if (!VoidCoinParseP2QRMultisigSpend(pushes, multisig_spend, &parse_error)) {
        error_out = strprintf("VOIDCOIN_P2QR P2SH multisig spend invalid: %s", parse_error);
        return false;
    }

    return CheckMultisigProgramAndSignatures(
        tx,
        input_index,
        spent_output,
        spent_outputs,
        midstate,
        committed_program,
        multisig_spend,
        error_out);
}

bool CheckSpendTimeLock(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    std::string& error_out,
    bool vcip3_pushcap_active)
{
    error_out.clear();

    if (input_index >= tx.vin.size()) {
        error_out = "VOIDCOIN_P2QR_TIMELOCK input index out of range";
        return false;
    }

    if (spent_outputs.size() != tx.vin.size()) {
        error_out = "VOIDCOIN_P2QR_TIMELOCK validation requires all spent outputs";
        return false;
    }

    // The sighash midstate MUST be populated and bound to THIS transaction
    // (see CheckSpend). A missing or cross-transaction midstate would silently
    // produce a sighash for a different transaction (a chain split).
    if (!midstate.m_ready || midstate.m_txid != tx.GetHash()) {
        error_out = "VOIDCOIN_P2QR_TIMELOCK sighash midstate is missing or not bound to this transaction";
        return false;
    }

    // The caller-supplied spent_output must be the exact output this input spends.
    if (!(spent_output == spent_outputs[input_index])) {
        error_out = "VOIDCOIN_P2QR_TIMELOCK spent_output does not match spent_outputs[input_index]";
        return false;
    }

    const CTxIn& txin = tx.vin[input_index];

    if (!txin.scriptWitness.IsNull()) {
        error_out = "VOIDCOIN_P2QR_TIMELOCK spends must not contain witness data";
        return false;
    }

    // Recover the SAME 32-byte P2QR program the native path commits to, from the
    // versioned time-lock output. The lock descriptor itself is enforced (version,
    // lock_type, height/MTP) by Consensus::CheckTxInputs; here we only authorize
    // the spend against the committed program. Because the P2QR sighash commits to
    // spent_output.scriptPubKey (which contains the full lock_descriptor), the lock
    // is already bound into the signature -- no sighash change is needed.
    uint256 committed_program;
    VoidCoinP2QRTimeLock lock;
    if (!IsTimeLockOutput(spent_output.scriptPubKey, committed_program, lock)) {
        error_out = "VOIDCOIN_P2QR_TIMELOCK validation called for non-timelock output";
        return false;
    }

    // The time-lock spend envelope in scriptSig is byte-for-byte the native P2QR
    // envelope (single-key <sig> <pubkey>, or the dual-format multisig), so it is
    // read and dispatched with the identical push cap and parser.
    std::vector<std::vector<unsigned char>> pushes;
    if (!ReadPushesOnly(txin.scriptSig, pushes, error_out,
                        VoidCoinP2QRMultisigMaxPushes(vcip3_pushcap_active))) {
        return false;
    }

    if (pushes.size() == VOIDCOIN_P2QR_SINGLE_PUSHES) {
        const std::vector<unsigned char>& signature = pushes[0];
        const std::vector<unsigned char>& pubkey = pushes[1];

        return CheckSignatureAndProgram(
            tx,
            input_index,
            spent_output,
            spent_outputs,
            midstate,
            committed_program,
            signature,
            pubkey,
            error_out);
    }

    VoidCoinP2QRMultisigSpend multisig_spend;
    std::string parse_error;

    if (!VoidCoinParseP2QRMultisigSpend(pushes, multisig_spend, &parse_error)) {
        error_out = strprintf("VOIDCOIN_P2QR_TIMELOCK multisig spend invalid: %s", parse_error);
        return false;
    }

    return CheckMultisigProgramAndSignatures(
        tx,
        input_index,
        spent_output,
        spent_outputs,
        midstate,
        committed_program,
        multisig_spend,
        error_out);
}

unsigned int CountSpendVerifications(
    const CScript& script_sig,
    const CScript& spent_script_pubkey,
    bool vcip3_pushcap_active)
{
    // NATIVE VOIDCOIN_P2QR. Mirror CheckSpend()'s structural dispatch exactly:
    // same (activation-aware, PA-06) push cap, same 2-push single-key branch,
    // same multisig parser. The number of MLDSA87Verify() calls equals 1 for a
    // single-key spend, or the number of revealed signatures (== committed
    // threshold) for a multisig.
    uint256 program;
    if (IsOutput(spent_script_pubkey, program)) {
        std::vector<std::vector<unsigned char>> pushes;
        std::string error;
        if (!ReadPushesOnly(script_sig, pushes, error,
                            VoidCoinP2QRMultisigMaxPushes(vcip3_pushcap_active))) {
            return 0;
        }

        if (pushes.size() == VOIDCOIN_P2QR_SINGLE_PUSHES) {
            return 1;
        }

        VoidCoinP2QRMultisigSpend multisig_spend;
        std::string parse_error;
        if (!VoidCoinParseP2QRMultisigSpend(pushes, multisig_spend, &parse_error)) {
            return 0;
        }
        return static_cast<unsigned int>(multisig_spend.signatures.size());
    }

    // VOIDCOIN_P2QR_TIMELOCK (VCIP-3). The spend envelope is byte-identical to the
    // native single/multisig envelope, so mirror CheckSpendTimeLock()'s dispatch:
    // the committed program comes from the versioned time-lock output, but the
    // number of MLDSA87Verify() calls is the same function of the scriptSig.
    uint256 tl_program;
    VoidCoinP2QRTimeLock tl_lock;
    if (IsTimeLockOutput(spent_script_pubkey, tl_program, tl_lock)) {
        std::vector<std::vector<unsigned char>> pushes;
        std::string error;
        if (!ReadPushesOnly(script_sig, pushes, error,
                            VoidCoinP2QRMultisigMaxPushes(vcip3_pushcap_active))) {
            return 0;
        }

        if (pushes.size() == VOIDCOIN_P2QR_SINGLE_PUSHES) {
            return 1;
        }

        VoidCoinP2QRMultisigSpend multisig_spend;
        std::string parse_error;
        if (!VoidCoinParseP2QRMultisigSpend(pushes, multisig_spend, &parse_error)) {
            return 0;
        }
        return static_cast<unsigned int>(multisig_spend.signatures.size());
    }

    // P2SH-CARRIED VOIDCOIN_P2QR. Mirror CheckSpendP2SHWrapped(): read pushes,
    // pop and validate the trailing redeem script (must be the native P2QR
    // marker whose hash matches the prevout), then dispatch on the remaining
    // pushes the same way as the native path.
    CScriptID expected_script_id;
    if (IsP2SHOutput(spent_script_pubkey, expected_script_id)) {
        std::vector<std::vector<unsigned char>> pushes;
        std::string error;
        if (!ReadPushesOnly(script_sig, pushes, error,
                            VoidCoinP2QRMultisigP2SHMaxPushes(vcip3_pushcap_active))) {
            return 0;
        }

        if (pushes.empty()) {
            return 0;
        }

        const CScript redeem_script(pushes.back().begin(), pushes.back().end());
        pushes.pop_back();

        uint256 committed_program;
        if (!IsRedeemScript(redeem_script, committed_program)) {
            return 0;
        }
        if (CScriptID(redeem_script) != expected_script_id) {
            return 0;
        }

        if (pushes.size() == VOIDCOIN_P2QR_SINGLE_PUSHES) {
            return 1;
        }

        VoidCoinP2QRMultisigSpend multisig_spend;
        std::string parse_error;
        if (!VoidCoinParseP2QRMultisigSpend(pushes, multisig_spend, &parse_error)) {
            return 0;
        }
        return static_cast<unsigned int>(multisig_spend.signatures.size());
    }

    return 0;
}

} // namespace consensus::voidcoinp2qr
