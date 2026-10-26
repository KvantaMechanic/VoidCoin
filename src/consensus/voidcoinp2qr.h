// Copyright (c) 2026 The VoidCoin Core developers
// Copyright (c) 2026 Kvanta5 Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VoidCoin Pay-to-Quantum-Resistant (P2QR) consensus validation.
// Derived from the Kvanta5-Core P2QR implementation, used under the MIT
// License as distributed at the time of the fork, and modified by VoidCoin;
// specified in VCIP-2 (/VCIP-2.md).
// Built on Bitcoin Core (MIT). Design lineage: BIP-360 (P2QR output design,
// Hunter Beast); ML-DSA-87 / NIST FIPS 204 via the pq-crystals/CRYSTALS-
// Dilithium reference implementation (src/crypto/pq/mldsa87/upstream/, not
// relicensed); O(N) precomputed sighashing per BIP-143 (Lau, Wuille) /
// BIP-341, realized in Bitcoin Core as PrecomputedTransactionData.

//Liam's false Copyright claims end here. 
//
//All Original P2QR implementations are Copyright (c) 2026 The Kvanta5 Organization. 
//Whatever other ridiculous nonsense Liam did before he abandoned the chain is Copyright (c) 2026 Liam/Void/Whatever
//
//A note from KvantaMechanic: This is a good example for why people shouldn't be "vibe coding" blockchains. 
//Liam claims Kvanta5's P2QR implementation is derived from Hunter Beast's Pay-to-Merkle-Root (P2MR).
//He doesn't understand what he's claiming, at all. 
//Kvanta5's P2QR implements a native Pay-to-Quantum-Resistant (P2QR) output type using opcode 0x50 (Bitcoin's former OP_RESERVED), with ML-DSA-87 signature verification.

#ifndef VOIDCOIN_CONSENSUS_VoidCoinP2QR_H
#define VOIDCOIN_CONSENSUS_VoidCoinP2QR_H

#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/voidcoin_p2qr.h>
#include <uint256.h>

#include <cstdint>
#include <string>
#include <vector>

/**
 * Native VOID P2QR consensus validation.
 *
 * VOIDCOIN_P2QR outputs are identified by:
 *
 *   OP_QuantumQuark / OP_RESERVED <32-byte p2qr_program>
 *
 * Spending native VOIDCOIN_P2QR is not Bitcoin Script execution. The spending input
 * carries native P2QR spend data in scriptSig as a strict two-push envelope:
 *
 *   <ML-DSA-87 signature> <ML-DSA-87 public key>
 *
 * P2SH-carried VOIDCOIN_P2QR compatibility outputs are identified by:
 *
 *   OP_HASH160 HASH160(<p2qr_redeem_script>) OP_EQUAL
 *
 * where:
 *
 *   p2qr_redeem_script = OP_QuantumQuark / OP_RESERVED <32-byte p2qr_program>
 *
 * Spending a P2SH-carried VOIDCOIN_P2QR output carries a strict three-push envelope:
 *
 *   <ML-DSA-87 signature> <ML-DSA-87 public key> <p2qr_redeem_script>
 *
 * P2SH-carried P2QR is only a compatibility container. Once detected, it must
 * route to native VOIDCOIN_P2QR consensus validation and must not succeed by normal
 * legacy P2SH script evaluation.
 */
namespace consensus::voidcoinp2qr {

/** Return true if script_pubkey is native VOIDCOIN_P2QR and extract the 32-byte program. */
bool IsOutput(const CScript& script_pubkey, uint256& program_out);

/** Return true if redeem_script is the native VOIDCOIN_P2QR redeem marker and extract the 32-byte program. */
bool IsRedeemScript(const CScript& redeem_script, uint256& program_out);

/**
 * Return true if script_pubkey is a native VOIDCOIN_P2QR_TIMELOCK output (VCIP-3
 * versioned form), and extract the 32-byte program plus the structurally-parsed
 * 10-byte lock descriptor.
 *
 * This is purely structural: it does NOT validate that the descriptor's
 * version/lock_type are supported, and it does NOT enforce the lock. The lock
 * (height / MTP) and version/type validity are enforced by
 * Consensus::CheckTxInputs; the ML-DSA-87 signature authorization is validated by
 * CheckSpendTimeLock().
 */
bool IsTimeLockOutput(const CScript& script_pubkey, uint256& program_out, VoidCoinP2QRTimeLock& lock_out);

/** Build the canonical P2QR redeem script: OP_RESERVED <32-byte p2qr_program>. */
CScript MakeRedeemScript(const uint256& program);

/** Build a P2SH-compatible scriptPubKey that carries the canonical P2QR redeem script. */
CScript MakeP2SHScriptPubKey(const uint256& program);

/** Return true if script_pubkey is P2SH and extract the script hash. */
bool IsP2SHOutput(const CScript& script_pubkey, CScriptID& script_id_out);

/**
 * Return true if this input appears to be a P2SH-carried VOIDCOIN_P2QR spend.
 *
 * This only detects the wrapper/redeemScript routing condition. Full signature,
 * public key, program, and sighash validation is done by CheckSpendP2SHWrapped().
 *
 * `vcip3_pushcap_active` selects the multisig push cap used while reading the
 * scriptSig for routing: it MUST match the value passed to the corresponding
 * CheckSpendP2SHWrapped() call (i.e. whether the VCIP-3 hard fork is active at
 * the spending height), or a large-but-valid signer-program P2SH multisig
 * would route inconsistently. See CheckSpend() for the cap definition.
 */
bool IsP2SHWrappedSpendCandidate(
    const CScript& spent_script_pubkey,
    const CScript& script_sig,
    bool vcip3_pushcap_active = false);

/** Return true if any spent output is native VOIDCOIN_P2QR. */
bool SpendsAnyP2QR(const std::vector<CTxOut>& spent_outputs);

/**
 * VC-14: the number of ML-DSA-87 signature verifications that validating this
 * input's spend of `spent_script_pubkey` would perform.
 *
 * The result mirrors the verification path exactly (CheckSpend /
 * CheckSpendP2SHWrapped): a well-formed native or P2SH-carried single-key spend
 * returns 1; a well-formed multisig spend returns the number of revealed
 * signatures (== the committed threshold `required`), i.e. the count of
 * MLDSA87Verify() calls that spend triggers. Any input that is not a
 * structurally well-formed P2QR/P2SH-P2QR spend of a P2QR output returns 0 (such
 * a spend cannot validate, so the containing block/tx is rejected by the normal
 * script-check path regardless). This is a pure, deterministic function of the
 * scriptSig and the spent scriptPubKey; it performs no cryptographic work and
 * never over-counts a valid spend, so it can never reject an otherwise-valid
 * block.
 *
 * `vcip3_pushcap_active` MUST match the activation state passed to CheckSpend /
 * CheckSpendP2SHWrapped at the same height, so the structural push-cap this
 * counter applies is identical to the one the verifier applies (PA-06 raises the
 * multisig spend-side push cap at VCIP-3). Since the budget is only enforced
 * once VCIP-3 has activated, callers pass true in that regime.
 *
 * Used by the per-block ML-DSA-87 verification budget
 * (MAX_BLOCK_MLDSA_VERIFICATIONS), enforced in ConnectBlock once VCIP-3 has
 * activated, and by the mempool per-transaction pre-check.
 */
unsigned int CountSpendVerifications(
    const CScript& script_sig,
    const CScript& spent_script_pubkey,
    bool vcip3_pushcap_active);

/**
 * Per-transaction sighash precompute: the five whole-transaction subhashes of
 * the VOIDCOIN_P2QR SIGHASH_ALL preimage (fields 6..10).
 *
 * These five values are pure functions of (tx, spent_outputs) and are
 * independent of input_index, so they are computed ONCE per transaction and
 * reused for every input. This turns the reference implementation's per-input
 * O(N) whole-transaction rehash into an amortized O(1), eliminating the
 * O(N^2) sighash cost across a transaction's inputs.
 *
 * This is a pure performance change: the resulting sighash is byte-identical to
 * the naive per-input recompute. It is consensus-neutral and requires no fork
 * or activation change.
 *
 * m_txid binds this midstate to the exact transaction it was built for. Every
 * consumer asserts the binding, so a midstate built for one transaction can
 * never be silently applied to another (which would be a chain split). There is
 * no per-input fallback: consumers require a populated, matching midstate.
 */
struct P2QRSighashMidstate {
    uint256 m_hash_prevouts;       //!< field 6:  SHA256(all vin prevouts)
    uint256 m_hash_sequences;      //!< field 7:  SHA256(all vin nSequence)
    uint256 m_hash_outputs;        //!< field 8:  SHA256(all vout)
    uint256 m_hash_spent_amounts;  //!< field 9:  SHA256(all spent nValue, vin order)
    uint256 m_hash_spent_scripts;  //!< field 10: SHA256(all spent scriptPubKey, vin order)
    Txid m_txid;                   //!< binding: GetHash() of the tx this was built for
    bool m_ready{false};           //!< false until BuildSighashMidstate() populates it
};

/**
 * Build the per-transaction P2QR sighash midstate (the five whole-tx subhashes)
 * exactly once. `spent_outputs` MUST be vin-aligned and cover every input
 * (including non-P2QR inputs), matching the sighash preimage requirement.
 *
 * Callers that validate/sign more than one input MUST call this once per
 * transaction and pass the result to every per-input SignatureHash/CheckSpend
 * call, so the quadratic subhash recompute is not reintroduced.
 */
P2QRSighashMidstate BuildSighashMidstate(
    const CTransaction& tx,
    const std::vector<CTxOut>& spent_outputs);

/**
 * Native VOIDCOIN_P2QR sighash.
 *
 * v1 deliberately supports SIGHASH_ALL only. This avoids inheriting legacy,
 * witness, or Taproot sighash corner cases.
 *
 * `midstate` is REQUIRED: it must be a populated P2QRSighashMidstate built for
 * `tx` via BuildSighashMidstate(). There is no defaulted/nullptr midstate and
 * no O(N)-per-input fallback.
 */
uint256 SignatureHash(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate);

/**
 * Native VOIDCOIN_P2QR sighash for a P2SH-carried P2QR spend.
 *
 * The spent_output is the actual P2SH prevout. The wrapper is only a carrier;
 * the signature still commits through the VOIDCOIN_P2QR tagged hash path.
 *
 * `midstate` is REQUIRED (see SignatureHash()).
 */
uint256 SignatureHashP2SHWrapped(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate);

/**
 * Native VOIDCOIN_P2QR sighash for a VOIDCOIN_P2QR_TIMELOCK spend (VCIP-3).
 *
 * The preimage is BYTE-IDENTICAL to SignatureHash()'s: it is the same
 * SIGHASH_ALL preimage, and because field 14 hashes the full spent scriptPubKey,
 * it already commits to the 10-byte lock descriptor embedded in the time-lock
 * output. This wrapper differs from SignatureHash() only in that it accepts a
 * time-lock output (rather than asserting a bare native-P2QR output), so wallet
 * signers can produce a signature the consensus CheckSpendTimeLock() will accept.
 *
 * `midstate` is REQUIRED (see SignatureHash()).
 */
uint256 SignatureHashTimeLock(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate);


/**
 * Parse native VOIDCOIN_P2QR spend envelope from scriptSig.
 *
 * Expected scriptSig:
 *
 *   <4627-byte ML-DSA-87 signature> <2592-byte ML-DSA-87 public key>
 *
 * This parser does not execute script and does not apply MAX_SCRIPT_ELEMENT_SIZE.
 */
bool ParseSpendData(
    const CScript& script_sig,
    std::vector<unsigned char>& signature_out,
    std::vector<unsigned char>& pubkey_out,
    std::string& error_out);

/**
 * Parse P2SH-carried VOIDCOIN_P2QR spend envelope from scriptSig.
 *
 * Expected scriptSig:
 *
 *   <4627-byte ML-DSA-87 signature>
 *   <2592-byte ML-DSA-87 public key>
 *   <p2qr_redeem_script = OP_RESERVED <32-byte p2qr_program>>
 *
 * This parser does not execute script and does not apply MAX_SCRIPT_ELEMENT_SIZE.
 */
bool ParseP2SHWrappedSpendData(
    const CScript& script_sig,
    std::vector<unsigned char>& signature_out,
    std::vector<unsigned char>& pubkey_out,
    CScript& redeem_script_out,
    uint256& program_out,
    std::string& error_out);

/**
 * Validate one native VOIDCOIN_P2QR input spend.
 *
 * This assumes activation has already been checked by the caller.
 *
 * `midstate` is REQUIRED: it must be a populated P2QRSighashMidstate built for
 * `tx` via BuildSighashMidstate(). Callers validating multiple inputs build it
 * once per transaction and pass it to every input, so the sighash cost stays
 * O(N) overall instead of O(N^2).
 *
 * `vcip3_pushcap_active` is the VCIP-3 hard fork gate for the multisig
 * spend-side push cap (PA-06). It MUST be derived from the spending block
 * height by the consensus caller: false before the VCIP-3 activation height
 * (legacy cap, byte-identical to pre-fork behavior), true at/after it (raised
 * cap that accommodates the maximal validly-committed signer-program multisig).
 * It defaults to false so any caller that omits it gets the strict legacy cap.
 */
bool CheckSpend(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    std::string& error_out,
    bool vcip3_pushcap_active = false);

/**
 * Validate one P2SH-carried VOIDCOIN_P2QR input spend.
 *
 * This assumes activation has already been checked by the caller.
 *
 * The P2SH wrapper is only a carrier. The spend must validate through the same
 * native ML-DSA-87 P2QR consensus path.
 *
 * `midstate` is REQUIRED (see CheckSpend()).
 *
 * `vcip3_pushcap_active` is the VCIP-3 push-cap hard fork gate (see CheckSpend()).
 * It MUST match the value passed to the IsP2SHWrappedSpendCandidate() routing
 * check for the same input.
 */
bool CheckSpendP2SHWrapped(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    std::string& error_out,
    bool vcip3_pushcap_active = false);

/**
 * Validate the ML-DSA-87 signature authorization of one VOIDCOIN_P2QR_TIMELOCK
 * input spend (VCIP-3).
 *
 * This is the signature-authorization half of the time-lock spend rule. It is a
 * direct extension of native-P2QR CheckSpend(): it extracts the SAME 32-byte
 * program committed by the output, reads the identical native/P2QR scriptSig
 * envelope, and validates the single-key or multisig ML-DSA-87 signature(s)
 * against that program using the very same sighash and verification code. The
 * only difference from CheckSpend() is that the committed program is recovered
 * from the versioned time-lock output (via IsTimeLockOutput) rather than the bare
 * native-P2QR output.
 *
 * The lock itself (absolute height / MTP) and the version/lock_type validity are
 * NOT checked here; they are enforced by Consensus::CheckTxInputs before script
 * checks run. Both must pass for the spend to be valid.
 *
 * This assumes VCIP-3 activation has already been checked by the caller (the
 * spend flag SCRIPT_VERIFY_VOIDCOIN_VCIP3 is set at/after nVCIP3ActivationHeight).
 * `midstate` is REQUIRED (see CheckSpend()). `vcip3_pushcap_active` is the
 * VCIP-3 push-cap gate (see CheckSpend()); once the time-lock type is spendable
 * VCIP-3 has by definition activated, so callers pass true.
 */
bool CheckSpendTimeLock(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs,
    const P2QRSighashMidstate& midstate,
    std::string& error_out,
    bool vcip3_pushcap_active = false);

} // namespace consensus::voidcoinp2qr

#endif // VOIDCOIN_CONSENSUS_VoidCoinP2QR_H
