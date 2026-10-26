// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Consensus regression tests for the VCIP-1 P2QR-TIMELOCK spend-height gate in
// Consensus::CheckTxInputs (audit finding VC-08). They pin down three
// properties of the gate:
//   (1) it is inert below nP2QRTimelockActivationHeight (documented activation),
//   (2) it does not two's-complement-wrap for high-bit lockheights (the coin
//       stays locked instead of becoming immediately spendable), and
//   (3) the "locked until block N" boundary is spendable at height == N.
//
// These tests only exercise the branch through a hand-built VOIDCOIN_P2QR_TIMELOCK
// coin placed directly in a CCoinsViewCache. No such output exists on-chain (they
// are non-standard and unfundable through the gated wallet path), so this branch
// is dead on the live chain and correcting it changes no already-mined block.

#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/voidcoin_p2qr.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(voidcoin_timelock_gate_tests, BasicTestingSetup)

static uint256 SampleProgram()
{
    uint256 p;
    for (size_t i = 0; i < p.size(); ++i) p.begin()[i] = static_cast<unsigned char>(0x11 + i);
    return p;
}

//! VCIP-3 versioned time-lock scriptPubKey:
//!   OP_QuantumQuark(0x50) 0x20 <32-byte program> 0x0a <10-byte descriptor>
//! descriptor = version || lock_type || lock_value(uint64 LE).
static CScript MakeTimelockScript(uint8_t version, uint8_t lock_type, uint64_t lock_value)
{
    VoidCoinP2QRTimeLock lock;
    lock.version = version;
    lock.lock_type = lock_type;
    lock.lock_value = lock_value;
    return VoidCoinMakeP2QRTimeLockScriptPubKey(SampleProgram(), lock);
}

//! Convenience: a supported absolute-block-height lock (version 1, type 0).
static CScript MakeHeightLock(uint64_t lockheight)
{
    return MakeTimelockScript(VOIDCOIN_P2QR_TIMELOCK_VERSION,
                              VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, lockheight);
}

//! Convenience: a supported absolute-MTP lock (version 1, type 1).
static CScript MakeMTPLock(uint64_t mtp_seconds)
{
    return MakeTimelockScript(VOIDCOIN_P2QR_TIMELOCK_VERSION,
                              VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, mtp_seconds);
}

//! Run CheckTxInputs against a single coin with scriptPubKey `spk`, spending at
//! nSpendHeight / nSpendMTP with the given VCIP-3 activation height. Returns true
//! if the spend is accepted; on rejection, `reject` receives the reject reason.
static bool SpendCoinAt(const CScript& spk, int nSpendHeight, int nActivationHeight, std::string& reject, int64_t nSpendMTP = 0)
{
    const COutPoint outpoint{Txid::FromUint256(SampleProgram()), 0};
    const CAmount in_value{1000};

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    coins.AddCoin(outpoint, Coin{CTxOut{in_value, spk}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false}, /*possible_overwrite=*/false);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(outpoint);
    mtx.vout.emplace_back(in_value - 100 /*fee*/, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    TxValidationState state;
    CAmount fee{0};
    const bool ok = Consensus::CheckTxInputs(tx, state, coins, nSpendHeight, fee, nActivationHeight, nSpendMTP);
    if (!ok) reject = state.GetRejectReason();
    return ok;
}

//! Run CheckTxInputs on a (non-coinbase) tx that CREATES a time-lock output
//! `spk`, spending a plain coin at nSpendHeight with the given VCIP-3 activation
//! height. Returns true if accepted; on rejection `reject` receives the reason.
static bool CreateOutputAt(const CScript& spk, int nSpendHeight, int nActivationHeight, std::string& reject)
{
    const COutPoint outpoint{Txid::FromUint256(SampleProgram()), 0};
    const CAmount in_value{1000};

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    coins.AddCoin(outpoint, Coin{CTxOut{in_value, CScript() << OP_TRUE}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false}, /*possible_overwrite=*/false);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(outpoint);
    mtx.vout.emplace_back(in_value - 100 /*fee*/, spk);
    const CTransaction tx{mtx};

    TxValidationState state;
    CAmount fee{0};
    const bool ok = Consensus::CheckTxInputs(tx, state, coins, nSpendHeight, fee, nActivationHeight, /*nSpendMTP=*/0);
    if (!ok) reject = state.GetRejectReason();
    return ok;
}

// (1) Below the activation (VCIP-3) height the gate is inert: a coin whose
// lockheight is in the future is still passed by CheckTxInputs, matching the
// documented "activates at height N". (Spendability is still gated at the script
// layer by SCRIPT_VERIFY_VOIDCOIN_VCIP3, so this is not a spend.)
BOOST_AUTO_TEST_CASE(gate_inert_before_activation)
{
    std::string reject;
    // activation 5000, spend at 200, lockheight 4000 -> 200 < 5000 so gate off.
    BOOST_CHECK(SpendCoinAt(MakeHeightLock(4000), /*spend=*/200, /*activation=*/5000, reject));
}

// (2) At/after activation the gate enforces the lock: spending before the
// lockheight is rejected.
BOOST_AUTO_TEST_CASE(gate_rejects_before_lockheight)
{
    std::string reject;
    BOOST_CHECK(!SpendCoinAt(MakeHeightLock(5000), /*spend=*/4999, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
}

// (2b) Spendable at the lockheight boundary (CLTV "locked until block N").
BOOST_AUTO_TEST_CASE(gate_spendable_at_lockheight)
{
    std::string reject;
    BOOST_CHECK(SpendCoinAt(MakeHeightLock(5000), /*spend=*/5000, /*activation=*/100, reject));
    BOOST_CHECK(SpendCoinAt(MakeHeightLock(5000), /*spend=*/5001, /*activation=*/100, reject));
}

// (3) VC-08 core regression: a high-bit lock_value (>= 0x80000000), or one beyond
// the 32-bit range entirely, must NOT wrap and become immediately spendable. With
// the uint64 lock_value it simply stays locked at any realistic spend height.
BOOST_AUTO_TEST_CASE(gate_no_signwrap_on_highbit_lockheight)
{
    std::string reject;
    const uint64_t high_lock = 0x80000000ull; // ~2.147e9, old-int32 high bit set
    BOOST_CHECK(!SpendCoinAt(MakeHeightLock(high_lock), /*spend=*/200, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
    // A value beyond uint32 likewise stays locked (retired int32 decode).
    BOOST_CHECK(!SpendCoinAt(MakeHeightLock(0x1'0000'0000ull), /*spend=*/1000000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
}

// (4) Absolute-MTP lock (lock_type 0x01): enforced against the spend MTP, not the
// height. Locked while spend MTP < lock_value; spendable at/after it.
BOOST_AUTO_TEST_CASE(gate_mtp_lock_enforced_against_mtp)
{
    std::string reject;
    const uint64_t t = 1'800'000'000ull;
    // Before the MTP: rejected (height is irrelevant for an MTP lock).
    BOOST_CHECK(!SpendCoinAt(MakeMTPLock(t), /*spend=*/1'000'000, /*activation=*/100, reject, /*mtp=*/t - 1));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
    // At/after the MTP: accepted.
    BOOST_CHECK(SpendCoinAt(MakeMTPLock(t), /*spend=*/1, /*activation=*/100, reject, /*mtp=*/t));
    BOOST_CHECK(SpendCoinAt(MakeMTPLock(t), /*spend=*/1, /*activation=*/100, reject, /*mtp=*/t + 1));
}

// (5) An unsupported descriptor version is unspendable (fail-closed, reserved for
// future rules).
BOOST_AUTO_TEST_CASE(gate_rejects_unknown_version)
{
    std::string reject;
    const CScript spk = MakeTimelockScript(/*version=*/0x02, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*value=*/0);
    BOOST_CHECK(!SpendCoinAt(spk, /*spend=*/1'000'000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-bad-version");
}

// (6) An unsupported/reserved lock_type (e.g. relative 0x02) is unspendable even
// when version is 1 -- fail-closed until a future fork defines it.
BOOST_AUTO_TEST_CASE(gate_rejects_reserved_lock_type)
{
    std::string reject;
    const CScript spk = MakeTimelockScript(VOIDCOIN_P2QR_TIMELOCK_VERSION,
                                           VOIDCOIN_P2QR_TIMELOCK_TYPE_RESERVED_REL_HEIGHT, /*value=*/0);
    BOOST_CHECK(!SpendCoinAt(spk, /*spend=*/1'000'000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-bad-type");
}

// A non-timelock output is never affected by the gate at any height.
BOOST_AUTO_TEST_CASE(gate_ignores_non_timelock_output)
{
    std::string reject;
    const CScript plain = CScript() << OP_TRUE;
    BOOST_CHECK(SpendCoinAt(plain, /*spend=*/1, /*activation=*/0, reject));
    BOOST_CHECK(SpendCoinAt(plain, /*spend=*/1000000, /*activation=*/0, reject));
}

// (7) VCIP-3 output-CREATION gate: creating a time-lock output before the
// activation height is rejected (byte-for-byte the pre-fork strict-output
// refusal, which returned bad-txns-forbidden-output); at/after activation the
// output may be created. This is the SAME height gate the coinbase path enforces
// separately in ConnectBlock (the coinbase never reaches CheckTxInputs); that
// coinbase branch is covered end-to-end by feature_voidcoin_timelock_coinbase.py.
BOOST_AUTO_TEST_CASE(creation_gate_before_activation)
{
    std::string reject;
    // Below activation: creating a time-lock output is refused.
    BOOST_CHECK(!CreateOutputAt(MakeHeightLock(6000), /*spend=*/4999, /*activation=*/5000, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-output-premature");
    // At/after activation: creation permitted (structural check only; the coin's
    // later spend is still gated by the lock via CheckSpendTimeLock/CheckTxInputs).
    BOOST_CHECK(CreateOutputAt(MakeHeightLock(6000), /*spend=*/5000, /*activation=*/5000, reject));
    BOOST_CHECK(CreateOutputAt(MakeHeightLock(6000), /*spend=*/6000, /*activation=*/5000, reject));
}

// (7b) The creation gate keys off the output SHAPE, not the descriptor contents:
// even an unsupported-version time-lock output is uncreatable before activation
// (its (un)supportedness only matters at spend time, post-fork).
BOOST_AUTO_TEST_CASE(creation_gate_applies_to_any_timelock_shape)
{
    std::string reject;
    const CScript spk = MakeTimelockScript(/*version=*/0x02, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*value=*/0);
    BOOST_CHECK(!CreateOutputAt(spk, /*spend=*/99, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-output-premature");
}

BOOST_AUTO_TEST_SUITE_END()
