// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// VC-14 (VCIP-3): per-block ML-DSA-87 verification budget.
//
// This suite pins three properties of the anti-DoS verification budget:
//
//   1. GetP2QRVerifyCount() / CountSpendVerifications() count exactly the number
//      of ML-DSA-87 verifications a spend performs: 1 for a single-key native or
//      P2SH-carried P2QR input, and `required` (the number of revealed
//      signatures) for an m-of-n multisig input, and 0 for a non-P2QR input.
//      This is the same structural dispatch the consensus verifier
//      (CheckSpend / CheckSpendP2SHWrapped) uses.
//
//   2. MLDSAVerificationBudgetExceeded() -- the exact predicate ConnectBlock and
//      mempool acceptance use -- rejects iff VCIP-3 has activated at the block
//      height AND the cumulative verification count exceeds
//      MAX_BLOCK_MLDSA_VERIFICATIONS. Before activation it never rejects, so
//      pre-fork blocks (and the entire already-mined chain) validate unchanged.
//
//   3. Composing (1) and (2): replaying a block's per-transaction real counts
//      through the real accumulate-and-check loop, an over-budget block is
//      rejected post-activation while an honest block passes, and neither is
//      rejected pre-activation.
//
// Note on scale: a block that actually performs 8001 ML-DSA-87 verifications is
// ~55 MB of signatures+keys (each verification requires its own 4627-byte
// signature and >=2592-byte public key), which is impractical to synthesize in a
// unit test. Property (3) therefore drives the *real* per-transaction counter
// and the *real* budget predicate over an accumulator, which is the exact logic
// ConnectBlock runs -- so the end-to-end guarantee is exercised without
// materializing a 55 MB block.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/consensus.h>
#include <consensus/voidcoinp2qr.h>
#include <crypto/pq/mldsa87/mldsa87.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/voidcoin_p2qr.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_mldsa_budget_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(size_t len, unsigned int seed)
{
    std::vector<unsigned char> v(len);
    for (size_t i = 0; i < len; ++i) {
        v[i] = static_cast<unsigned char>((seed + i) & 0xff);
    }
    if (len > 0) v[0] = static_cast<unsigned char>((seed & 0xff) | 0x01);
    return v;
}

std::vector<unsigned char> ValidPubKey(unsigned int seed) { return Bytes(VOIDCOIN_P2QR_PUBKEY_SIZE, seed); }
std::vector<unsigned char> ValidSignature(unsigned int seed) { return Bytes(VOIDCOIN_P2QR_SIGNATURE_SIZE, seed); }

std::vector<unsigned char> SmallInt(unsigned int value)
{
    if (value <= 0xff) return std::vector<unsigned char>{static_cast<unsigned char>(value)};
    return std::vector<unsigned char>{
        static_cast<unsigned char>(value & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff)};
}

struct Signer {
    std::vector<unsigned char> pubkey;
    uint256 program;
};

Signer MakeSigner(unsigned int seed)
{
    Signer s;
    s.pubkey = ValidPubKey(seed);
    s.program = VoidCoinP2QRSingleProgram(s.pubkey);
    return s;
}

std::vector<Signer> MakeSigners(unsigned int first_seed, unsigned int count)
{
    std::vector<Signer> signers;
    signers.reserve(count);
    for (unsigned int i = 0; i < count; ++i) signers.push_back(MakeSigner(first_seed + i));
    std::sort(signers.begin(), signers.end(),
              [](const Signer& a, const Signer& b) { return a.program < b.program; });
    return signers;
}

// Build the signer-program-format multisig spend push vector (the same shape the
// live parser accepts): <sig[m]> <idx[m]> <signing_pubkey[m]> <program[n]> <m> <n>.
std::vector<std::vector<unsigned char>> BuildMultisigPushes(
    const std::vector<Signer>& signers,
    const std::vector<uint16_t>& signer_indexes)
{
    const uint16_t required = static_cast<uint16_t>(signer_indexes.size());
    const uint16_t total = static_cast<uint16_t>(signers.size());

    std::vector<std::vector<unsigned char>> pushes;
    for (uint16_t i = 0; i < required; ++i) pushes.push_back(ValidSignature(1000 + i));
    for (const uint16_t idx : signer_indexes) pushes.push_back(SmallInt(idx));
    for (const uint16_t idx : signer_indexes) pushes.push_back(signers[idx].pubkey);
    for (const Signer& s : signers) pushes.push_back(std::vector<unsigned char>(s.program.begin(), s.program.end()));
    pushes.push_back(SmallInt(required));
    pushes.push_back(SmallInt(total));
    return pushes;
}

CScript PushesToScript(const std::vector<std::vector<unsigned char>>& pushes)
{
    CScript s;
    for (const auto& p : pushes) s << p;
    return s;
}

// The committed multisig program for a signer set at threshold `required`.
uint256 MultisigProgram(uint16_t required, const std::vector<Signer>& signers)
{
    std::vector<uint256> programs;
    programs.reserve(signers.size());
    for (const Signer& s : signers) programs.push_back(s.program);
    return VoidCoinP2QRMultisigProgram(required, programs);
}

} // namespace

// -------------------------------------------------------------------------
// Property 1: the counter equals the number of ML-DSA-87 verifications.
// -------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(verify_count_single_and_multisig)
{
    namespace vp = consensus::voidcoinp2qr;

    // Single-key native P2QR: exactly one verification.
    {
        const std::vector<unsigned char> pk = ValidPubKey(7);
        const std::vector<unsigned char> sig = ValidSignature(7);
        const uint256 program = VoidCoinP2QRSingleProgram(pk);
        const CScript spk = VoidCoinMakeP2QRScriptPubKey(program);
        CScript scriptsig;
        scriptsig << sig << pk;
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, true), 1u);
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, false), 1u);
    }

    // Single-key P2SH-carried P2QR: exactly one verification.
    {
        const std::vector<unsigned char> pk = ValidPubKey(9);
        const std::vector<unsigned char> sig = ValidSignature(9);
        const uint256 program = VoidCoinP2QRSingleProgram(pk);
        const CScript redeem = vp::MakeRedeemScript(program);
        const CScript spk = vp::MakeP2SHScriptPubKey(program);
        CScript scriptsig;
        scriptsig << sig << pk << std::vector<unsigned char>(redeem.begin(), redeem.end());
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, true), 1u);
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, false), 1u);
    }

    // m-of-n native multisig: exactly `required` verifications (revealed sigs).
    // These envelopes are well under both the legacy and the raised (PA-06) push
    // caps, so the count is invariant to the activation flag.
    for (const uint16_t required : {1, 2, 3, 5}) {
        const std::vector<Signer> signers = MakeSigners(100 + required, 5);
        std::vector<uint16_t> idx;
        for (uint16_t i = 0; i < required; ++i) idx.push_back(i);
        const auto pushes = BuildMultisigPushes(signers, idx);
        const CScript scriptsig = PushesToScript(pushes);
        const CScript spk = VoidCoinMakeP2QRScriptPubKey(MultisigProgram(required, signers));
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, true), required);
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, false), required);
    }

    // P2SH-carried multisig: `required` verifications, redeem script appended.
    {
        const uint16_t required = 2;
        const std::vector<Signer> signers = MakeSigners(500, 3);
        const uint256 program = MultisigProgram(required, signers);
        const CScript redeem = vp::MakeRedeemScript(program);
        const CScript spk = vp::MakeP2SHScriptPubKey(program);
        auto pushes = BuildMultisigPushes(signers, {0, 2});
        pushes.push_back(std::vector<unsigned char>(redeem.begin(), redeem.end()));
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(PushesToScript(pushes), spk, true), required);
    }

    // A non-P2QR output contributes zero.
    {
        const CScript spk = CScript() << OP_DUP << OP_HASH160
                                      << std::vector<unsigned char>(20, 0x01) << OP_EQUALVERIFY << OP_CHECKSIG;
        CScript scriptsig;
        scriptsig << ValidSignature(1) << ValidPubKey(1);
        BOOST_CHECK_EQUAL(vp::CountSpendVerifications(scriptsig, spk, true), 0u);
    }
}

// GetP2QRVerifyCount() sums per-input counts over a whole transaction and
// ignores coinbases.
BOOST_AUTO_TEST_CASE(getp2qrverifycount_sums_over_inputs)
{
    namespace vp = consensus::voidcoinp2qr;

    // Input 0: single-key native -> 1.
    const std::vector<unsigned char> pk = ValidPubKey(11);
    const std::vector<unsigned char> sig = ValidSignature(11);
    const uint256 s_program = VoidCoinP2QRSingleProgram(pk);
    const CScript single_spk = VoidCoinMakeP2QRScriptPubKey(s_program);
    CScript single_ss; single_ss << sig << pk;
    const COutPoint op0{Txid::FromUint256(uint256{1}), 0};

    // Input 1: 3-of-4 native multisig -> 3.
    const uint16_t required = 3;
    const std::vector<Signer> signers = MakeSigners(2000, 4);
    const CScript ms_spk = VoidCoinMakeP2QRScriptPubKey(MultisigProgram(required, signers));
    const CScript ms_ss = PushesToScript(BuildMultisigPushes(signers, {0, 1, 3}));
    const COutPoint op1{Txid::FromUint256(uint256{2}), 0};

    // Input 2: ordinary non-P2QR output -> 0.
    const CScript legacy_spk = CScript() << OP_TRUE;
    const COutPoint op2{Txid::FromUint256(uint256{3}), 0};

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(op0); mtx.vin.back().scriptSig = single_ss;
    mtx.vin.emplace_back(op1); mtx.vin.back().scriptSig = ms_ss;
    mtx.vin.emplace_back(op2);
    mtx.vout.emplace_back(1 * COIN, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    CCoinsView root;
    CCoinsViewCache view{&root};
    view.AddCoin(op0, Coin{CTxOut{2 * COIN, single_spk}, 1, false}, false);
    view.AddCoin(op1, Coin{CTxOut{2 * COIN, ms_spk}, 1, false}, false);
    view.AddCoin(op2, Coin{CTxOut{2 * COIN, legacy_spk}, 1, false}, false);

    BOOST_CHECK_EQUAL(GetP2QRVerifyCount(tx, view, /*vcip3_pushcap_active=*/true), 1 + 3 + 0);

    // A coinbase contributes nothing.
    CMutableTransaction cb;
    cb.vin.emplace_back(COutPoint{}, CScript() << OP_0 << OP_0);
    cb.vout.emplace_back(50 * COIN, CScript() << OP_TRUE);
    BOOST_CHECK(CTransaction{cb}.IsCoinBase());
    BOOST_CHECK_EQUAL(GetP2QRVerifyCount(CTransaction{cb}, view, /*vcip3_pushcap_active=*/true), 0);
}

// -------------------------------------------------------------------------
// Property 2: the budget predicate is correctly activation-gated.
// -------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(budget_predicate_activation_gating)
{
    const int64_t cap = MAX_BLOCK_MLDSA_VERIFICATIONS;
    const int act = 60000; // an arbitrary activation height

    // Pre-activation: never over budget, no matter how large the count.
    for (const int64_t n : {int64_t{0}, cap, cap + 1, 100 * cap}) {
        BOOST_CHECK(!MLDSAVerificationBudgetExceeded(act - 1, act, n));
        BOOST_CHECK(!MLDSAVerificationBudgetExceeded(0, act, n));
    }

    // At/after activation: over budget iff count > cap.
    BOOST_CHECK(!MLDSAVerificationBudgetExceeded(act, act, 0));
    BOOST_CHECK(!MLDSAVerificationBudgetExceeded(act, act, cap - 1));
    BOOST_CHECK(!MLDSAVerificationBudgetExceeded(act, act, cap));       // exactly at cap: allowed
    BOOST_CHECK(MLDSAVerificationBudgetExceeded(act, act, cap + 1));     // one over: rejected
    BOOST_CHECK(MLDSAVerificationBudgetExceeded(act + 5000, act, cap + 1));
}

// -------------------------------------------------------------------------
// Property 3: end-to-end -- an over-budget block is rejected post-activation,
// an honest block passes, and neither is rejected pre-activation. Uses the real
// per-transaction counter as the accumulation unit and the real predicate, i.e.
// exactly the loop ConnectBlock runs.
// -------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(over_budget_block_rejected_post_activation_honest_passes)
{
    const int act = 60000;
    const int64_t cap = MAX_BLOCK_MLDSA_VERIFICATIONS;

    // A real 3-of-5 multisig transaction: its true verification count is 3.
    const uint16_t required = 3;
    const std::vector<Signer> signers = MakeSigners(9000, 5);
    const CScript ms_spk = VoidCoinMakeP2QRScriptPubKey(MultisigProgram(required, signers));
    const CScript ms_ss = PushesToScript(BuildMultisigPushes(signers, {0, 2, 4}));

    CMutableTransaction mtx;
    mtx.version = 2;
    const COutPoint op{Txid::FromUint256(uint256{42}), 0};
    mtx.vin.emplace_back(op); mtx.vin.back().scriptSig = ms_ss;
    mtx.vout.emplace_back(1 * COIN, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    CCoinsView root;
    CCoinsViewCache view{&root};
    view.AddCoin(op, Coin{CTxOut{2 * COIN, ms_spk}, 1, false}, false);

    const int64_t per_tx = GetP2QRVerifyCount(tx, view, /*vcip3_pushcap_active=*/true);
    BOOST_CHECK_EQUAL(per_tx, required); // the real, verified unit count

    // Replay a block as a stream of these transactions through the exact
    // accumulate-and-check loop from ConnectBlock. `mineHeight` chooses whether
    // VCIP-3 is active.
    auto connect_block = [&](int mineHeight, int64_t num_txs) -> int64_t {
        // returns the tx index (0-based) at which the block is rejected, or -1.
        int64_t cumulative = 0;
        for (int64_t i = 0; i < num_txs; ++i) {
            cumulative += per_tx;
            if (MLDSAVerificationBudgetExceeded(mineHeight, act, cumulative)) return i;
        }
        return -1;
    };

    // Honest block: cumulative stays at/under the cap -> accepted post-activation.
    const int64_t honest_txs = cap / per_tx;           // 8000 / 3 = 2666 -> 7998 <= cap
    BOOST_CHECK_LE(honest_txs * per_tx, cap);
    BOOST_CHECK_EQUAL(connect_block(act, honest_txs), -1);

    // Over-budget block: one transaction too many -> rejected post-activation, at
    // the transaction that tips cumulative over the cap.
    const int64_t over_txs = honest_txs + 1;           // 7998 + 3 = 8001 > cap
    BOOST_CHECK_GT(over_txs * per_tx, cap);
    const int64_t reject_at = connect_block(act, over_txs);
    BOOST_CHECK_EQUAL(reject_at, over_txs - 1);         // trips on the last tx

    // Pre-activation: the same over-budget block is NOT rejected (no cap yet), so
    // the already-mined chain and any pre-fork block validate unchanged.
    BOOST_CHECK_EQUAL(connect_block(act - 1, over_txs), -1);
    BOOST_CHECK_EQUAL(connect_block(0, over_txs), -1);
}

BOOST_AUTO_TEST_SUITE_END()
