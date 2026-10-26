// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VOIDCOIN_CONSENSUS_CONSENSUS_H
#define VOIDCOIN_CONSENSUS_CONSENSUS_H

#include <cstdlib>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 32000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 128000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** VC-14 (VCIP-3): the per-block ML-DSA-87 signature-verification budget (network rule).
 *
 * Each native/P2SH-carried P2QR input contributes one verification per revealed
 * ML-DSA-87 signature: a single-key spend counts 1; an m-of-n multisig spend
 * counts m (the number of revealed signatures actually verified). A block whose
 * transactions' cumulative ML-DSA-87 verifications exceed this cap is invalid,
 * but ONLY once VCIP-3 has activated (Consensus::Params::nVCIP3ActivationHeight).
 * Before activation the cap is not enforced, so every already-mined block
 * validates byte-for-byte unchanged and upgraded/non-upgraded nodes agree.
 *
 * Rationale / calibration: the block serialized-size limit
 * (MAX_BLOCK_SERIALIZED_SIZE = 32,000,000) already bounds the count, because
 * every verification requires its own 4627-byte signature AND a >=2592-byte
 * public key present in the block -- no signature or key can be shared across
 * verifications, and an m-of-n multisig must reveal >= m public keys for its m
 * signatures. The densest possible packing is therefore ~7.2 kB per
 * verification, i.e. at most ~4404 verifications in a completely full 32 MB
 * block. This cap is set to 8000: comfortably above the ~4404 that any block
 * (honest or adversarial) can physically contain under the current size limit
 * -- so no valid block is ever newly rejected -- while turning the ML-DSA-87 CPU
 * cost into an explicit, auditable consensus bound (~1.2 s/block worst case at
 * ~0.15 ms/verify) that stays enforced independently of the block-size limit and
 * the P2QR weight discount, either of which a future fork could raise. */
static const int64_t MAX_BLOCK_MLDSA_VERIFICATIONS = 8000;

/** VC-14: the exact predicate the block-connection and mempool-acceptance paths
 *  use to enforce the ML-DSA-87 verification budget. Returns true (over budget /
 *  reject) only once VCIP-3 has activated at `height` AND `cumulative_verifications`
 *  exceeds MAX_BLOCK_MLDSA_VERIFICATIONS. Before activation it always returns
 *  false, so behavior is byte-identical to pre-VCIP-3. Pure and deterministic. */
static inline bool MLDSAVerificationBudgetExceeded(int height, int vcip3_activation_height, int64_t cumulative_verifications)
{
    return height >= vcip3_activation_height && cumulative_verifications > MAX_BLOCK_MLDSA_VERIFICATIONS;
}
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
static constexpr int64_t MAX_TIMEWARP = 600;

#endif // VOIDCOIN_CONSENSUS_CONSENSUS_H
