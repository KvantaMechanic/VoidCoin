// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// End-to-end consensus tests for the rebuilt VCIP-3 VOIDCOIN_P2QR_TIMELOCK spend
// authorization. These generate a REAL ML-DSA-87 keypair, build a versioned
// time-lock output, sign the time-lock sighash, and assert that the consensus
// authorization path (consensus::voidcoinp2qr::CheckSpendTimeLock) accepts a
// valid spend and rejects tampering. This proves the type is genuinely spendable
// (not merely well-formed): the whole reason for the rebuild.
//
// The LOCK itself (height / MTP) and the descriptor's version/lock_type validity
// are enforced separately in Consensus::CheckTxInputs and are covered by
// voidcoin_timelock_gate_tests.cpp. This file exercises only the signature-
// authorization half.

#include <consensus/voidcoinp2qr.h>
#include <crypto/pq/mldsa87/mldsa87.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/voidcoin_p2qr.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

using consensus::voidcoinp2qr::BuildSighashMidstate;
using consensus::voidcoinp2qr::CheckSpendTimeLock;
using consensus::voidcoinp2qr::P2QRSighashMidstate;
using consensus::voidcoinp2qr::SignatureHashTimeLock;

BOOST_FIXTURE_TEST_SUITE(voidcoin_timelock_spend_tests, BasicTestingSetup)

namespace {

struct MLDSAKey {
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> seckey;
};

MLDSAKey MakeKey(unsigned char seed_byte)
{
    std::vector<unsigned char> seed(MLDSA87_SEED_SIZE, seed_byte);
    MLDSAKey k;
    BOOST_REQUIRE(MLDSA87GenerateKeypairFromSeed(seed, k.pubkey, k.seckey));
    BOOST_REQUIRE_EQUAL(k.pubkey.size(), MLDSA87_PUBLIC_KEY_SIZE);
    return k;
}

CScript MakeTimeLockSpk(const uint256& program, uint8_t lock_type, uint64_t lock_value)
{
    VoidCoinP2QRTimeLock lock;
    lock.version = VOIDCOIN_P2QR_TIMELOCK_VERSION;
    lock.lock_type = lock_type;
    lock.lock_value = lock_value;
    return VoidCoinMakeP2QRTimeLockScriptPubKey(program, lock);
}

// Build a single-input tx spending `spent` (a time-lock output), sign the
// time-lock sighash with `seckey`, and attach the native single-key P2QR
// envelope <sig> <pubkey_for_scriptsig>. Returns the fully-signed tx. The P2QR
// sighash does not read scriptSig, so signing over the unsigned tx yields a
// signature the verifier reproduces over the signed tx.
CTransaction BuildSignedSpend(const CTxOut& spent,
                              const std::vector<unsigned char>& seckey,
                              const std::vector<unsigned char>& pubkey_for_scriptsig)
{
    const std::vector<CTxOut> spent_outputs{spent};

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(COutPoint(Txid::FromUint256(uint256::ONE), 0));
    mtx.vout.emplace_back(spent.nValue - 1000, CScript() << OP_TRUE);

    const CTransaction unsigned_tx{mtx};
    const P2QRSighashMidstate mid = BuildSighashMidstate(unsigned_tx, spent_outputs);
    const uint256 sighash = SignatureHashTimeLock(unsigned_tx, 0, spent, spent_outputs, mid);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(MLDSA87Sign(seckey,
                              Span<const unsigned char>(sighash.begin(), sighash.size()),
                              sig));

    mtx.vin[0].scriptSig = CScript() << sig << pubkey_for_scriptsig;
    return CTransaction{mtx};
}

} // namespace

// A real ML-DSA-87 single-key spend of an absolute-height time-lock output is
// accepted by the consensus authorization path.
BOOST_AUTO_TEST_CASE(timelock_height_single_key_spend_is_valid)
{
    const MLDSAKey key = MakeKey(0x01);
    const uint256 program = VoidCoinP2QRSingleProgram(key.pubkey);
    const CTxOut spent{100 * COIN,
                       MakeTimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/50'000)};

    const CTransaction tx = BuildSignedSpend(spent, key.seckey, key.pubkey);
    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);

    std::string err;
    BOOST_CHECK_MESSAGE(
        CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true),
        "valid height-lock spend rejected: " << err);
}

// The signature path is identical for an absolute-MTP lock: a real spend of a
// lock_type 0x01 output also validates.
BOOST_AUTO_TEST_CASE(timelock_mtp_single_key_spend_is_valid)
{
    const MLDSAKey key = MakeKey(0x02);
    const uint256 program = VoidCoinP2QRSingleProgram(key.pubkey);
    const CTxOut spent{7 * COIN,
                       MakeTimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, /*mtp=*/1'900'000'000ull)};

    const CTransaction tx = BuildSignedSpend(spent, key.seckey, key.pubkey);
    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);

    std::string err;
    BOOST_CHECK_MESSAGE(
        CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true),
        "valid MTP-lock spend rejected: " << err);
}

// Malleation guard: the lock descriptor lives INSIDE the output scriptPubKey,
// which the P2QR sighash commits to (field 14). Presenting the same signature
// against an output whose lock_value differs by one must fail -- proving the lock
// is bound into the signed message with no sighash-layout change.
BOOST_AUTO_TEST_CASE(timelock_altered_lock_value_breaks_signature)
{
    const MLDSAKey key = MakeKey(0x03);
    const uint256 program = VoidCoinP2QRSingleProgram(key.pubkey);
    const CTxOut signed_over{100 * COIN,
                             MakeTimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/50'000)};

    // Sign over the original lock, then present the SAME tx/signature against an
    // output that differs only in lock_value.
    const CTransaction tx = BuildSignedSpend(signed_over, key.seckey, key.pubkey);

    const CTxOut altered{100 * COIN,
                         MakeTimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/50'001)};
    const std::vector<CTxOut> spent_outputs{altered};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);

    std::string err;
    BOOST_CHECK(!CheckSpendTimeLock(tx, 0, altered, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true));
    BOOST_CHECK(err.find("signature verification failed") != std::string::npos);
}

// A revealed public key that does not hash to the committed program is rejected
// before any signature check.
BOOST_AUTO_TEST_CASE(timelock_wrong_pubkey_is_rejected)
{
    const MLDSAKey key = MakeKey(0x04);
    const MLDSAKey wrong = MakeKey(0x05);
    const uint256 program = VoidCoinP2QRSingleProgram(key.pubkey);
    const CTxOut spent{100 * COIN,
                       MakeTimeLockSpk(program, VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, /*height=*/50'000)};

    // Sign with the correct key but reveal the WRONG pubkey in the scriptSig.
    const CTransaction tx = BuildSignedSpend(spent, key.seckey, wrong.pubkey);
    const std::vector<CTxOut> spent_outputs{spent};
    const P2QRSighashMidstate mid = BuildSighashMidstate(tx, spent_outputs);

    std::string err;
    BOOST_CHECK(!CheckSpendTimeLock(tx, 0, spent, spent_outputs, mid, err, /*vcip3_pushcap_active=*/true));
    BOOST_CHECK(err.find("does not match committed program") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
