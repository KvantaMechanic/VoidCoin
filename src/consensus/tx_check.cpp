// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_check.h>

#include <consensus/amount.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>

#include <set>

static bool IsVoidCoinAllowedOutputScript(const CScript& script_pub_key)
{
    /*
     * VoidCoin strict output enforcement.
     *
     * Allowed output forms:
     *
     * 1. Native P2QR:
     *      OP_RESERVED <32-byte P2QR program>
     *      Hex: 50 20 <32 bytes>
     *
     * 2. Wrapped P2SH compatibility:
     *      OP_HASH160 <20-byte script hash> OP_EQUAL
     *      Hex: a9 14 <20 bytes> 87
     *
     * Everything else is rejected:
     *   - OP_RETURN / nulldata
     *   - legacy P2PKH
     *   - SegWit v0 P2WPKH/P2WSH
     *   - Taproot v1
     *   - future witness versions
     *   - bare inscription-style scripts
     *   - arbitrary nonstandard scripts
     */

    if (script_pub_key.size() == 34 &&
        script_pub_key[0] == OP_RESERVED &&
        script_pub_key[1] == 0x20) {
        return true;
    }

    if (script_pub_key.size() == 23 &&
        script_pub_key[0] == OP_HASH160 &&
        script_pub_key[1] == 0x14 &&
        script_pub_key[22] == OP_EQUAL) {
        return true;
    }

    /*
     * 3. VCIP-3 versioned P2QR time-lock:
     *      OP_RESERVED <32-byte P2QR program> <10-byte lock_descriptor>
     *      Hex: 50 20 <32 bytes> 0a <10 bytes>   (45 bytes)
     *
     * The leading 34 bytes are the SAME native-P2QR commitment; the trailing
     * push is the 10-byte lock descriptor (version || lock_type || lock_value).
     * This context-free rule only permits the STRUCTURE. Whether a time-lock
     * output may be CREATED is gated on the VCIP-3 activation height by
     * Consensus::CheckTxInputs (which has block context); its SPEND is authorized
     * by consensus::voidcoinp2qr::CheckSpendTimeLock once VCIP-3 is active.
     */
    if (script_pub_key.size() == 45 &&
        script_pub_key[0] == OP_RESERVED &&
        script_pub_key[1] == 0x20 &&
        script_pub_key[34] == 0x0a) {
        return true;
    }

    return false;
}

bool CheckTransaction(const CTransaction& tx, TxValidationState& state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vin-empty");
    }

    if (tx.vout.empty()) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-empty");
    }

    // Size limits (this doesn't take the witness into account, as that hasn't been checked for malleability)
    if (::GetSerializeSize(TX_NO_WITNESS(tx)) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-oversize");
    }

    // Check for negative or overflow output values (see CVE-2010-5139)
    CAmount nValueOut = 0;
    for (const auto& txout : tx.vout) {
        if (txout.nValue < 0) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-negative");
        }

        if (txout.nValue > MAX_MONEY) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-vout-toolarge");
        }

        /*
         * VoidCoin strict output rule:
         *
         * Transactions may only create:
         *   - native P2QR outputs, or
         *   - wrapped P2SH compatibility outputs.
         *
         * This is intentionally consensus-level and context-free.
         */
        if (!IsVoidCoinAllowedOutputScript(txout.scriptPubKey)) {
            return state.Invalid(
                TxValidationResult::TX_CONSENSUS,
                "bad-txns-forbidden-output",
                "VoidCoin transactions may only create native P2QR or wrapped P2SH-compatible outputs"
            );
        }

        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-txouttotal-toolarge");
        }
    }

    // Check for duplicate inputs (see CVE-2018-17144)
    // While Consensus::CheckTxInputs does check if all inputs of a tx are available, and UpdateCoins marks all inputs
    // of a tx as spent, it does not check if the tx has duplicate inputs.
    // Failure to run this check will result in either a crash or an inflation bug, depending on the implementation of
    // the underlying coins database.
    std::set<COutPoint> vInOutPoints;
    for (const auto& txin : tx.vin) {
        if (!vInOutPoints.insert(txin.prevout).second) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputs-duplicate");
        }
    }

    if (tx.IsCoinBase()) {
        if (tx.vin[0].scriptSig.size() < 2 || tx.vin[0].scriptSig.size() > 100) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-cb-length");
        }
    } else {
        for (const auto& txin : tx.vin) {
            if (txin.prevout.IsNull()) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-prevout-null");
            }
        }
    }

    return true;
}
