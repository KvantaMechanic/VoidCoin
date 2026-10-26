
// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/tx_verify.h>
#include <script/solver.h>

#include <chain.h>
#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/validation.h>
#include <consensus/voidcoinp2qr.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/voidcoin_p2qr.h>
#include <util/check.h>
#include <util/moneystr.h>

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (tx.nLockTime == 0)
        return true;
    if ((int64_t)tx.nLockTime < ((int64_t)tx.nLockTime < LOCKTIME_THRESHOLD ? (int64_t)nBlockHeight : nBlockTime))
        return true;

    // Even if tx.nLockTime isn't satisfied by nBlockHeight/nBlockTime, a
    // transaction is still considered final if all inputs' nSequence ==
    // SEQUENCE_FINAL (0xffffffff), in which case nLockTime is ignored.
    //
    // Because of this behavior OP_CHECKLOCKTIMEVERIFY/CheckLockTime() will
    // also check that the spending input's nSequence != SEQUENCE_FINAL,
    // ensuring that an unsatisfied nLockTime value will actually cause
    // IsFinalTx() to return false here:
    for (const auto& txin : tx.vin) {
        if (!(txin.nSequence == CTxIn::SEQUENCE_FINAL))
            return false;
    }
    return true;
}

std::pair<int, int64_t> CalculateSequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    assert(prevHeights.size() == tx.vin.size());

    // Will be set to the equivalent height- and time-based nLockTime
    // values that would be necessary to satisfy all relative lock-
    // time constraints given our view of block chain history.
    // The semantics of nLockTime are the last invalid height/time, so
    // use -1 to have the effect of any height or time being valid.
    int nMinHeight = -1;
    int64_t nMinTime = -1;

    bool fEnforceBIP68 = tx.version >= 2 && flags & LOCKTIME_VERIFY_SEQUENCE;

    // Do not enforce sequence numbers as a relative lock time
    // unless we have been instructed to
    if (!fEnforceBIP68) {
        return std::make_pair(nMinHeight, nMinTime);
    }

    for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
        const CTxIn& txin = tx.vin[txinIndex];

        // Sequence numbers with the most significant bit set are not
        // treated as relative lock-times, nor are they given any
        // consensus-enforced meaning at this point.
        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) {
            // The height of this input is not relevant for sequence locks
            prevHeights[txinIndex] = 0;
            continue;
        }

        int nCoinHeight = prevHeights[txinIndex];

        if (txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG) {
            const int64_t nCoinTime{Assert(block.GetAncestor(std::max(nCoinHeight - 1, 0)))->GetMedianTimePast()};
            // NOTE: Subtract 1 to maintain nLockTime semantics
            // BIP 68 relative lock times have the semantics of calculating
            // the first block or time at which the transaction would be
            // valid. When calculating the effective block time or height
            // for the entire transaction, we switch to using the
            // semantics of nLockTime which is the last invalid block
            // time or height. Thus we subtract 1 from the calculated
            // time or height.

            // Time-based relative lock-times are measured from the
            // smallest allowed timestamp of the block containing the
            // txout being spent, which is the median time past of the
            // block prior.
            nMinTime = std::max(nMinTime, nCoinTime + (int64_t)((txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) << CTxIn::SEQUENCE_LOCKTIME_GRANULARITY) - 1);
        } else {
            nMinHeight = std::max(nMinHeight, nCoinHeight + (int)(txin.nSequence & CTxIn::SEQUENCE_LOCKTIME_MASK) - 1);
        }
    }

    return std::make_pair(nMinHeight, nMinTime);
}

bool EvaluateSequenceLocks(const CBlockIndex& block, std::pair<int, int64_t> lockPair)
{
    assert(block.pprev);
    int64_t nBlockTime = block.pprev->GetMedianTimePast();
    if (lockPair.first >= block.nHeight || lockPair.second >= nBlockTime)
        return false;

    return true;
}

bool SequenceLocks(const CTransaction &tx, int flags, std::vector<int>& prevHeights, const CBlockIndex& block)
{
    return EvaluateSequenceLocks(block, CalculateSequenceLocks(tx, flags, prevHeights, block));
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    for (const auto& txin : tx.vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    for (const auto& txout : tx.vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}

unsigned int GetP2SHSigOpCount(const CTransaction& tx, const CCoinsViewCache& inputs)
{
    if (tx.IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(tx.vin[i].scriptSig);
    }
    return nSigOps;
}

int64_t GetTransactionSigOpCost(const CTransaction& tx, const CCoinsViewCache& inputs, uint32_t flags)
{
    int64_t nSigOps = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;

    if (tx.IsCoinBase())
        return nSigOps;

    if (flags & SCRIPT_VERIFY_P2SH) {
        nSigOps += GetP2SHSigOpCount(tx, inputs) * WITNESS_SCALE_FACTOR;
    }

    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        const Coin& coin = inputs.AccessCoin(tx.vin[i].prevout);
        assert(!coin.IsSpent());
        const CTxOut &prevout = coin.out;
        nSigOps += CountWitnessSigOps(tx.vin[i].scriptSig, prevout.scriptPubKey, &tx.vin[i].scriptWitness, flags);
    }
    return nSigOps;
}

bool Consensus::CheckTxInputs(const CTransaction& tx, TxValidationState& state, const CCoinsViewCache& inputs, int nSpendHeight, CAmount& txfee, int nVCIP3ActivationHeight, int64_t nSpendMedianTimePast)
{
    // are the actual inputs available?
    if (!inputs.HaveInputs(tx)) {
        return state.Invalid(TxValidationResult::TX_MISSING_INPUTS, "bad-txns-inputs-missingorspent",
                         strprintf("%s: inputs missing/spent", __func__));
    }

    // VCIP-3 (rebuilt from VCIP-1): P2QR-TIMELOCK output CREATION gate.
    //
    // Creating a versioned time-lock output is only permitted at/after the VCIP-3
    // activation height. Before activation the type is refused, byte-for-byte
    // equivalent in outcome to the pre-fork strict-output rule (which rejected it
    // as bad-txns-forbidden-output): the context-free CheckTransaction() now
    // structurally permits the 45-byte form, and this height-aware gate is what
    // keeps a time-lock output uncreatable (and thus the whole feature dormant)
    // until the fork. At/after activation the output may be created and later
    // spent via CheckSpendTimeLock once its lock (height/MTP) matures. This gate is
    // consensus, not policy: it is enforced identically in the mempool
    // (nSpendHeight = tip+1) and in ConnectBlock.
    if (nSpendHeight < nVCIP3ActivationHeight) {
        for (const CTxOut& txout : tx.vout) {
            uint256 tl_program;
            VoidCoinP2QRTimeLock tl_lock;
            if (consensus::voidcoinp2qr::IsTimeLockOutput(txout.scriptPubKey, tl_program, tl_lock)) {
                return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-timelock-output-premature",
                    "P2QR-TIMELOCK: output creation is not enabled until the VCIP-3 activation height");
            }
        }
    }

    CAmount nValueIn = 0;
    for (unsigned int i = 0; i < tx.vin.size(); ++i) {
        const COutPoint& prevout = tx.vin[i].prevout;
        const Coin& coin = inputs.AccessCoin(prevout);
        assert(!coin.IsSpent());

        // Coinbase maturity: a coinbase output may not be spent until it is
        // COINBASE_MATURITY (100) blocks deep. This standard rule is present in
        // upstream Kvanta5/Bitcoin Core and in VoidCoin v1.0.0, but was dropped
        // when this input loop was rebuilt for the P2QR time-lock, so
        // v1.0.5..v2.0.2 let immature coinbase outputs -- including Void Collapse
        // Bounty coinbases -- be spent at a single confirmation (a reorg
        // double-spend surface and a split versus any node that enforces the
        // rule). Restored here, gated to activate with the rest of VCIP-3 at
        // nVCIP3ActivationHeight: the (violation-free) pre-activation chain stays
        // byte-identical and every node begins enforcing at the same height.
        if (nSpendHeight >= nVCIP3ActivationHeight &&
            coin.IsCoinBase() && nSpendHeight - coin.nHeight < COINBASE_MATURITY) {
            return state.Invalid(TxValidationResult::TX_PREMATURE_SPEND, "bad-txns-premature-spends-coinbase",
                strprintf("tried to spend coinbase at depth %d", nSpendHeight - coin.nHeight));
        }

        // VCIP-3 (rebuilt from VCIP-1): P2QR-TIMELOCK lock enforcement.
        //
        // If the output being spent is a VOIDCOIN_P2QR_TIMELOCK output, parse its
        // 10-byte lock descriptor (version || lock_type || uint64 LE lock_value)
        // and enforce it:
        //   - version must be 0x01 (any other value is reserved for future rules
        //     and is unspendable here -> fail closed);
        //   - lock_type 0x00 (absolute height): spendable once nSpendHeight
        //     >= lock_value (CLTV "locked until block N" convention);
        //   - lock_type 0x01 (absolute MTP): spendable once the connecting block's
        //     median-time-past >= lock_value;
        //   - any other lock_type (e.g. reserved relative locks 0x02/0x03) is
        //     unspendable here -> fail closed.
        //
        // This gate is only active at/after nVCIP3ActivationHeight. Before that
        // the time-lock type is unspendable at the script layer anyway (the
        // leading OP_RESERVED fails), so the gate is inert and byte-identical to
        // pre-fork behavior. The retired int32 lockHeight (and its VC-08
        // sign-wrap hazard) is replaced by an unsigned uint64 lock_value.
        if (nSpendHeight >= nVCIP3ActivationHeight) {
            uint256 tl_program;
            VoidCoinP2QRTimeLock lock;
            if (consensus::voidcoinp2qr::IsTimeLockOutput(coin.out.scriptPubKey, tl_program, lock)) {
                if (lock.version != VOIDCOIN_P2QR_TIMELOCK_VERSION) {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-timelock-bad-version",
                        strprintf("P2QR-TIMELOCK: unsupported descriptor version %d", lock.version));
                }
                if (lock.lock_type == VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT) {
                    // nSpendHeight is non-negative; compare unsigned so a
                    // lock_value above INT_MAX cannot wrap and unlock early.
                    if (static_cast<uint64_t>(nSpendHeight) < lock.lock_value) {
                        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-timelock-not-met",
                            strprintf("P2QR-TIMELOCK: locked until block %d, spend height %d", lock.lock_value, nSpendHeight));
                    }
                } else if (lock.lock_type == VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP) {
                    // nSpendMedianTimePast is non-negative; compare unsigned.
                    if (static_cast<uint64_t>(nSpendMedianTimePast) < lock.lock_value) {
                        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-timelock-not-met",
                            strprintf("P2QR-TIMELOCK: locked until MTP %d, spend MTP %d", lock.lock_value, nSpendMedianTimePast));
                    }
                } else {
                    return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-timelock-bad-type",
                        strprintf("P2QR-TIMELOCK: unsupported lock_type %d", lock.lock_type));
                }
            }
        }
        // Check for negative or overflow input values
        nValueIn += coin.out.nValue;
        if (!MoneyRange(coin.out.nValue) || !MoneyRange(nValueIn)) {
            return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-inputvalues-outofrange");
        }
    }

    const CAmount value_out = tx.GetValueOut();
    if (nValueIn < value_out) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-in-belowout",
            strprintf("value in (%s) < value out (%s)", FormatMoney(nValueIn), FormatMoney(value_out)));
    }

    // Tally transaction fees
    const CAmount txfee_aux = nValueIn - value_out;
    if (!MoneyRange(txfee_aux)) {
        return state.Invalid(TxValidationResult::TX_CONSENSUS, "bad-txns-fee-outofrange");
    }

    txfee = txfee_aux;
    return true;
}
