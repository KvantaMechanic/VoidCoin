// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VCIP-3 P2QR time-lock: consolidated Stage-3 acceptance tests.
//
// The old VCIP-1 timelock type led with OP_RESERVED but had NO spend path, so
// coins sent to it were permanently frozen. VCIP-3 rebuilds it as a versioned,
// SPENDABLE output:
//
//     OP_QuantumQuark <program[32]> <lock_descriptor[10]>
//     lock_descriptor = version(1) || lock_type(1) || lock_value(uint64 LE, 8)
//
// where `program` is the SAME P2QR policy commitment used by native P2QR (single
// ML-DSA-87 key OR M-of-N multisig). This file drives the two consensus halves of
// the rebuilt type with REAL ML-DSA-87 keys and signatures and asserts the full
// contract the rebuild promised:
//
//   * the versioned output round-trips through Solver()/IsTimeLockOutput();
//   * a valid single-key AND a valid multisig time-lock spend authorize through
//     consensus::voidcoinp2qr::CheckSpendTimeLock() (the signature half);
//   * the lock itself (absolute height and absolute MTP) is enforced by
//     Consensus::CheckTxInputs(): a spend before the lock is "bad-txns-timelock-
//     not-met"; a spend at/after it passes;
//   * an invalid or absent signature is rejected by the authorization path;
//   * an unsupported descriptor version and an unknown/reserved lock_type are
//     rejected (fail-closed);
//   * before the VCIP-3 activation height the output cannot even be CREATED
//     (bad-txns-timelock-output-premature), so it is dormant/unspendable, exactly
//     byte-for-byte as the disabled type behaved.
//
// The signature-authorization path (CheckSpendTimeLock) and the lock/version/type
// gate (CheckTxInputs) are independent; a valid spend requires BOTH to pass, which
// is why several cases exercise them together.

#include <coins.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <consensus/voidcoinp2qr.h>
#include <crypto/pq/mldsa87/mldsa87.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/voidcoin_p2qr.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace vp = consensus::voidcoinp2qr;

using vp::BuildSighashMidstate;
using vp::CheckSpendTimeLock;
using vp::IsTimeLockOutput;
using vp::P2QRSighashMidstate;
using vp::SignatureHashTimeLock;

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_timelock_tests, BasicTestingSetup)

namespace {

// A real, recoverable ML-DSA-87 signer plus its P2QR single-key program (the
// 32-byte commitment the output binds to).
struct RealSigner {
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> seckey;
    uint256 program;
};

RealSigner MakeSigner(unsigned int seed)
{
    std::vector<unsigned char> s(MLDSA87_SEED_SIZE, 0x00);
    s[0] = static_cast<unsigned char>(seed & 0xff);
    s[1] = static_cast<unsigned char>((seed >> 8) & 0xff);
    s[2] = static_cast<unsigned char>((seed >> 16) & 0xff);
    s[3] = static_cast<unsigned char>((seed >> 24) & 0xff);

    RealSigner k;
    BOOST_REQUIRE(MLDSA87GenerateKeypairFromSeed(
        Span<const unsigned char>(s.data(), s.size()), k.pubkey, k.seckey));
    BOOST_REQUIRE_EQUAL(k.pubkey.size(), MLDSA87_PUBLIC_KEY_SIZE);
    k.program = VoidCoinP2QRSingleProgram(k.pubkey);
    return k;
}

// `count` distinct signers, sorted by program (the canonical multisig ordering).
std::vector<RealSigner> MakeSigners(unsigned int base_seed, unsigned int count)
{
    std::vector<RealSigner> signers;
    signers.reserve(count);
    for (unsigned int i = 0; i < count; ++i) signers.push_back(MakeSigner(base_seed + i));
    std::sort(signers.begin(), signers.end(),
              [](const RealSigner& a, const RealSigner& b) { return a.program < b.program; });
    for (size_t i = 1; i < signers.size(); ++i) {
        BOOST_REQUIRE(signers[i - 1].program < signers[i].program);
    }
    return signers;
}

CScript TimeLockSpk(const uint256& program, uint8_t lock_type, uint64_t lock_value,
                    uint8_t version = VOIDCOIN_P2QR_TIMELOCK_VERSION)
{
    VoidCoinP2QRTimeLock lock;
    lock.version = version;
    lock.lock_type = lock_type;
    lock.lock_value = lock_value;
    return VoidCoinMakeP2QRTimeLockScriptPubKey(program, lock);
}

std::vector<unsigned char> ProgramBytes(const uint256& program)
{
    return std::vector<unsigned char>(program.begin(), program.end());
}

std::vector<unsigned char> EncodeUInt16Minimal(unsigned int value)
{
    if (value <= 0xff) return std::vector<unsigned char>{static_cast<unsigned char>(value)};
    return std::vector<unsigned char>{static_cast<unsigned char>(value & 0xff),
                                      static_cast<unsigned char>((value >> 8) & 0xff)};
}

// A one-input tx spending `spent`. Its scriptSig is filled by the caller; the
// P2QR SIGHASH_ALL preimage does not read scriptSig, so the sighash over the
// unsigned tx is what the signed tx commits to.
CMutableTransaction MakeSpendingTx(const CTxOut& spent)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(spent.nValue - 1000, CScript() << OP_TRUE);
    return mtx;
}

// Sign the time-lock sighash of `mtx` input 0 (spending single-key output
// `spent`) with `seckey`, and attach the native single-key envelope
// <sig> <pubkey_for_scriptsig>.
CTransaction SignSingleKey(CMutableTransaction mtx, const CTxOut& spent,
                           const std::vector<unsigned char>& seckey,
                           const std::vector<unsigned char>& pubkey_for_scriptsig)
{
    const std::vector<CTxOut> spent_outputs{spent};
    const CTransaction unsigned_tx{mtx};
    const P2QRSighashMidstate mid = BuildSighashMidstate(unsigned_tx, spent_outputs);
    const uint256 sighash = SignatureHashTimeLock(unsigned_tx, 0, spent, spent_outputs, mid);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(MLDSA87Sign(Span<const unsigned char>(seckey.data(), seckey.size()),
                              Span<const unsigned char>(sighash.begin(), sighash.size()), sig));
    mtx.vin[0].scriptSig = CScript() << sig << pubkey_for_scriptsig;
    return CTransaction{mtx};
}

// Build a new-format signer-program multisig scriptSig revealing signers
// 0..required-1 of `signers`, signing the time-lock sighash of `mtx`.
//   <sig[m]> <signer_index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
CTransaction SignMultisig(CMutableTransaction mtx, const CTxOut& spent,
                          const std::vector<RealSigner>& signers, unsigned int required)
{
    const std::vector<CTxOut> spent_outputs{spent};
    const CTransaction unsigned_tx{mtx};
    const P2QRSighashMidstate mid = BuildSighashMidstate(unsigned_tx, spent_outputs);
    const uint256 sighash = SignatureHashTimeLock(unsigned_tx, 0, spent, spent_outputs, mid);

    const unsigned int total = static_cast<unsigned int>(signers.size());
    CScript script_sig;
    for (unsigned int i = 0; i < required; ++i) {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(MLDSA87Sign(
            Span<const unsigned char>(signers[i].seckey.data(), signers[i].seckey.size()),
            Span<const unsigned char>(sighash.begin(), sighash.size()), sig));
        script_sig << sig;
    }
    for (unsigned int i = 0; i < required; ++i) script_sig << EncodeUInt16Minimal(i);
    for (unsigned int i = 0; i < required; ++i) script_sig << signers[i].pubkey;
    for (unsigned int i = 0; i < total; ++i) script_sig << ProgramBytes(signers[i].program);
    script_sig << EncodeUInt16Minimal(required);
    script_sig << EncodeUInt16Minimal(total);

    mtx.vin[0].scriptSig = script_sig;
    return CTransaction{mtx};
}

// Run Consensus::CheckTxInputs against a single coin with scriptPubKey `spk`,
// spending at height/MTP with VCIP-3 activation at `activation`. Returns success;
// on rejection, `reject` gets the reason. This exercises the LOCK / version /
// type / creation gate (not the signature authorization).
bool CheckInputsAt(const CScript& spk, int spend_height, int activation,
                   std::string& reject, int64_t spend_mtp = 0)
{
    const COutPoint outpoint{Txid::FromUint256(uint256::ONE), 0};
    const CAmount in_value{COIN};

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    coins.AddCoin(outpoint, Coin{CTxOut{in_value, spk}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false},
                  /*possible_overwrite=*/false);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(outpoint);
    mtx.vout.emplace_back(in_value - 1000, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    TxValidationState state;
    CAmount fee{0};
    const bool ok = Consensus::CheckTxInputs(tx, state, coins, spend_height, fee, activation, spend_mtp);
    if (!ok) reject = state.GetRejectReason();
    return ok;
}

// CheckTxInputs against a tx that CREATES a time-lock OUTPUT `spk` (spending a
// plain coin), at `spend_height` with activation `activation`. Exercises the
// pre-activation creation gate.
bool CheckCreateOutputAt(const CScript& spk, int spend_height, int activation, std::string& reject)
{
    const COutPoint outpoint{Txid::FromUint256(uint256::ONE), 0};
    const CAmount in_value{COIN};

    CCoinsView dummy;
    CCoinsViewCache coins(&dummy);
    coins.AddCoin(outpoint, Coin{CTxOut{in_value, CScript() << OP_TRUE}, /*nHeightIn=*/1, /*fCoinBaseIn=*/false},
                  /*possible_overwrite=*/false);

    CMutableTransaction mtx;
    mtx.vin.emplace_back(outpoint);
    mtx.vout.emplace_back(in_value - 1000, spk); // create the time-lock output
    const CTransaction tx{mtx};

    TxValidationState state;
    CAmount fee{0};
    const bool ok = Consensus::CheckTxInputs(tx, state, coins, spend_height, fee, activation, /*mtp=*/0);
    if (!ok) reject = state.GetRejectReason();
    return ok;
}

} // namespace

// ---------------------------------------------------------------------------
// (A) The versioned output round-trips through the solver and IsTimeLockOutput.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_output_roundtrips_through_solver)
{
    const uint256 program = MakeSigner(0x100).program;

    for (const auto& tc : {std::pair<uint8_t, uint64_t>{VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 123456ull},
                           std::pair<uint8_t, uint64_t>{VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, 1'893'456'000ull}}) {
        const CScript spk = TimeLockSpk(program, tc.first, tc.second);
        BOOST_CHECK_EQUAL(spk.size(), VOIDCOIN_P2QR_TIMELOCK_SCRIPT_SIZE);

        std::vector<std::vector<unsigned char>> solutions;
        BOOST_CHECK(Solver(spk, solutions) == TxoutType::VOIDCOIN_P2QR_TIMELOCK);
        BOOST_REQUIRE_EQUAL(solutions.size(), 2u);
        BOOST_CHECK_EQUAL(solutions[0].size(), VOIDCOIN_P2QR_PROGRAM_SIZE);
        BOOST_CHECK_EQUAL(solutions[1].size(), VOIDCOIN_P2QR_TIMELOCK_DESCRIPTOR_SIZE);
        BOOST_CHECK(std::equal(program.begin(), program.end(), solutions[0].begin()));

        uint256 got_program;
        VoidCoinP2QRTimeLock got_lock;
        BOOST_CHECK(IsTimeLockOutput(spk, got_program, got_lock));
        BOOST_CHECK(got_program == program);
        BOOST_CHECK_EQUAL(got_lock.version, VOIDCOIN_P2QR_TIMELOCK_VERSION);
        BOOST_CHECK_EQUAL(got_lock.lock_type, tc.first);
        BOOST_CHECK_EQUAL(got_lock.lock_value, tc.second);
    }

    // A native (34-byte) P2QR output is NOT recognized as a time-lock output.
    uint256 p;
    VoidCoinP2QRTimeLock l;
    BOOST_CHECK(!IsTimeLockOutput(VoidCoinMakeP2QRScriptPubKey(program), p, l));
}

// ---------------------------------------------------------------------------
// (B) A valid single-key time-lock spend authorizes AND the (satisfied) lock
//     passes CheckTxInputs.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_single_key_spend_valid_when_lock_satisfied)
{
    const RealSigner key = MakeSigner(0x200);
    const uint64_t lock_height = 50'000;
    const CTxOut spent{100 * COIN, TimeLockSpk(key.program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, lock_height)};

    // Signature authorization half.
    const CTransaction tx = SignSingleKey(MakeSpendingTx(spent), spent, key.seckey, key.pubkey);
    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);
    std::string err;
    BOOST_CHECK_MESSAGE(
        CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true),
        "valid single-key time-lock spend rejected: " << err);

    // Lock half: at/after the lock height CheckTxInputs accepts.
    std::string reject;
    BOOST_CHECK(CheckInputsAt(spent.scriptPubKey, /*height=*/(int)lock_height, /*activation=*/100, reject));
    BOOST_CHECK(CheckInputsAt(spent.scriptPubKey, /*height=*/(int)lock_height + 1, /*activation=*/100, reject));
}

// ---------------------------------------------------------------------------
// (C) A valid M-of-N multisig time-lock spend authorizes AND its (satisfied)
//     lock passes CheckTxInputs. This is the key new coverage: the time-lock
//     program can be a full multisig policy, spent through the identical native
//     signer-program envelope.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_multisig_spend_valid_when_lock_satisfied)
{
    const unsigned int required = 2, total = 3;
    const std::vector<RealSigner> signers = MakeSigners(0x300, total);

    std::vector<uint256> signer_programs;
    for (const RealSigner& s : signers) signer_programs.push_back(s.program);
    std::string policy_err;
    BOOST_REQUIRE_MESSAGE(
        VoidCoinIsCanonicalP2QRMultisigPolicy(static_cast<uint16_t>(required), signer_programs, &policy_err),
        policy_err);
    const uint256 program = VoidCoinP2QRMultisigProgram(static_cast<uint16_t>(required), signer_programs);

    const uint64_t lock_height = 12'345;
    const CTxOut spent{80 * COIN, TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, lock_height)};

    const CTransaction tx = SignMultisig(MakeSpendingTx(spent), spent, signers, required);
    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);
    std::string err;
    BOOST_CHECK_MESSAGE(
        CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true),
        "valid 2-of-3 multisig time-lock spend rejected: " << err);

    std::string reject;
    BOOST_CHECK(CheckInputsAt(spent.scriptPubKey, /*height=*/(int)lock_height, /*activation=*/100, reject));
}

// ---------------------------------------------------------------------------
// (D) Spending BEFORE the lock is met is rejected -- both lock types.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_spend_before_height_lock_rejected)
{
    const uint256 program = MakeSigner(0x400).program;
    const CScript spk = TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/5'000);

    std::string reject;
    BOOST_CHECK(!CheckInputsAt(spk, /*height=*/4'999, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
    // Boundary: spendable exactly at the lock height.
    BOOST_CHECK(CheckInputsAt(spk, /*height=*/5'000, /*activation=*/100, reject));
}

BOOST_AUTO_TEST_CASE(timelock_spend_before_time_lock_rejected)
{
    const uint256 program = MakeSigner(0x401).program;
    const uint64_t lock_time = 1'800'000'000ull;
    const CScript spk = TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, lock_time);

    std::string reject;
    // Height is irrelevant for an MTP lock; MTP below the lock is rejected.
    BOOST_CHECK(!CheckInputsAt(spk, /*height=*/9'000'000, /*activation=*/100, reject, /*mtp=*/lock_time - 1));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
    // At/after the MTP: accepted.
    BOOST_CHECK(CheckInputsAt(spk, /*height=*/1, /*activation=*/100, reject, /*mtp=*/lock_time));
    BOOST_CHECK(CheckInputsAt(spk, /*height=*/1, /*activation=*/100, reject, /*mtp=*/lock_time + 1));
}

// A high-bit / >32-bit lock_value must NOT wrap and unlock early (retired VC-08
// int32 decode).
BOOST_AUTO_TEST_CASE(timelock_highbit_lock_value_no_signwrap)
{
    const uint256 program = MakeSigner(0x402).program;
    std::string reject;
    BOOST_CHECK(!CheckInputsAt(TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 0x8000'0000ull),
                               /*height=*/1'000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
    BOOST_CHECK(!CheckInputsAt(TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 0x1'0000'0000ull),
                               /*height=*/2'000'000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-not-met");
}

// ---------------------------------------------------------------------------
// (E) An invalid or absent signature is rejected by the authorization path.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_invalid_signature_rejected)
{
    const RealSigner key = MakeSigner(0x500);
    const CTxOut spent{100 * COIN, TimeLockSpk(key.program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 50'000)};

    // Correctly-shaped envelope, but the signature bytes are garbage (all zero):
    // structurally 2 pushes with the right sizes, so it reaches the ML-DSA verify,
    // which must fail.
    CMutableTransaction mtx = MakeSpendingTx(spent);
    const std::vector<unsigned char> zero_sig(VOIDCOIN_P2QR_SIGNATURE_SIZE, 0x00);
    mtx.vin[0].scriptSig = CScript() << zero_sig << key.pubkey;
    const CTransaction tx{mtx};

    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);
    std::string err;
    BOOST_CHECK(!CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true));
    BOOST_CHECK_MESSAGE(err.find("signature verification failed") != std::string::npos,
                        "unexpected error: " << err);
}

BOOST_AUTO_TEST_CASE(timelock_absent_signature_rejected)
{
    const RealSigner key = MakeSigner(0x501);
    const CTxOut spent{100 * COIN, TimeLockSpk(key.program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 50'000)};

    // No spend data at all: empty scriptSig -> 0 pushes -> not a valid single-key
    // or multisig envelope -> rejected before any crypto.
    CMutableTransaction mtx = MakeSpendingTx(spent);
    mtx.vin[0].scriptSig = CScript();
    const CTransaction tx{mtx};

    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);
    std::string err;
    BOOST_CHECK(!CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true));
    BOOST_CHECK(!err.empty());
}

// A revealed pubkey that does not hash to the committed program is rejected
// before the signature check.
BOOST_AUTO_TEST_CASE(timelock_wrong_pubkey_rejected)
{
    const RealSigner key = MakeSigner(0x502);
    const RealSigner wrong = MakeSigner(0x503);
    const CTxOut spent{100 * COIN, TimeLockSpk(key.program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 50'000)};

    // Sign with the right key but reveal the wrong pubkey.
    const CTransaction tx = SignSingleKey(MakeSpendingTx(spent), spent, key.seckey, wrong.pubkey);
    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);
    std::string err;
    BOOST_CHECK(!CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true));
    BOOST_CHECK_MESSAGE(err.find("does not match committed program") != std::string::npos,
                        "unexpected error: " << err);
}

// Malleation: the lock lives inside the output scriptPubKey, which the P2QR
// sighash commits to. A signature made over one lock_value must not validate
// against an output whose lock_value differs by one.
BOOST_AUTO_TEST_CASE(timelock_altered_lock_value_breaks_signature)
{
    const RealSigner key = MakeSigner(0x504);
    const CTxOut signed_over{100 * COIN, TimeLockSpk(key.program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 50'000)};
    const CTransaction tx = SignSingleKey(MakeSpendingTx(signed_over), signed_over, key.seckey, key.pubkey);

    const CTxOut altered{100 * COIN, TimeLockSpk(key.program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 50'001)};
    const std::vector<CTxOut> spent_outputs{altered};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);
    std::string err;
    BOOST_CHECK(!CheckSpendTimeLock(tx, 0, altered, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true));
    BOOST_CHECK_MESSAGE(err.find("signature verification failed") != std::string::npos,
                        "unexpected error: " << err);
}

// ---------------------------------------------------------------------------
// (F) version != 1 and unknown/reserved lock_type are rejected (fail-closed).
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_unknown_version_rejected)
{
    const uint256 program = MakeSigner(0x600).program;
    std::string reject;
    const CScript spk = TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*value=*/0, /*version=*/0x02);
    BOOST_CHECK(!CheckInputsAt(spk, /*height=*/1'000'000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-bad-version");

    BOOST_CHECK(!VoidCoinIsSupportedP2QRTimeLock(VoidCoinP2QRTimeLock{0x02, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 0}));
}

BOOST_AUTO_TEST_CASE(timelock_unknown_lock_type_rejected)
{
    const uint256 program = MakeSigner(0x601).program;
    std::string reject;
    // Reserved relative-height lock type (0x02): parsed but unspendable for now.
    const CScript spk = TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_RESERVED_REL_HEIGHT, /*value=*/0);
    BOOST_CHECK(!CheckInputsAt(spk, /*height=*/1'000'000, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-bad-type");

    BOOST_CHECK(!VoidCoinIsSupportedP2QRTimeLock(
        VoidCoinP2QRTimeLock{VOIDCOIN_P2QR_TIMELOCK_VERSION, VOIDCOIN_P2QR_TIMELOCK_TYPE_RESERVED_REL_HEIGHT, 0}));
    BOOST_CHECK(VoidCoinIsSupportedP2QRTimeLock(
        VoidCoinP2QRTimeLock{VOIDCOIN_P2QR_TIMELOCK_VERSION, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 0}));
    BOOST_CHECK(VoidCoinIsSupportedP2QRTimeLock(
        VoidCoinP2QRTimeLock{VOIDCOIN_P2QR_TIMELOCK_VERSION, VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, 0}));
}

// ---------------------------------------------------------------------------
// (G) Before the VCIP-3 activation height the output cannot be CREATED (so it
//     is dormant/unspendable, byte-for-byte as the disabled type behaved), and
//     the lock gate is inert below activation.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(timelock_output_creation_refused_before_activation)
{
    const uint256 program = MakeSigner(0x700).program;
    const CScript spk = TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/10);

    std::string reject;
    // Creating the output below the activation height is refused.
    BOOST_CHECK(!CheckCreateOutputAt(spk, /*height=*/99, /*activation=*/100, reject));
    BOOST_CHECK_EQUAL(reject, "bad-txns-timelock-output-premature");
    // At/after activation, creation is permitted.
    BOOST_CHECK(CheckCreateOutputAt(spk, /*height=*/100, /*activation=*/100, reject));
    BOOST_CHECK(CheckCreateOutputAt(spk, /*height=*/101, /*activation=*/100, reject));
}

BOOST_AUTO_TEST_CASE(timelock_lock_gate_inert_before_activation)
{
    const uint256 program = MakeSigner(0x701).program;
    // A future-dated lock, but spending below activation: the lock gate is inert
    // (spendability is withheld at the script layer, not here), so CheckTxInputs
    // does not reject on the lock.
    const CScript spk = TimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/4'000);
    std::string reject;
    BOOST_CHECK(CheckInputsAt(spk, /*height=*/200, /*activation=*/5'000, reject));
}

BOOST_AUTO_TEST_SUITE_END()
