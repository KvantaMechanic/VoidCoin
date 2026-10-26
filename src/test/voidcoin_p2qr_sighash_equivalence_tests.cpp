// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VCIP-2 test vector T6 -- permanent CI guard for the O(N)->O(N^2) sighash
// refactor.
//
// The consensus path now precomputes the five whole-transaction subhashes of
// the VOIDCOIN_P2QR SIGHASH_ALL preimage exactly once per transaction
// (consensus::voidcoinp2qr::BuildSighashMidstate) and reuses them for every
// input, instead of recomputing them per input (the old O(N^2) behaviour).
//
// This is asserted to be a pure performance change: the resulting sighash must
// be BYTE-IDENTICAL to the naive per-input recompute for every input, so it is
// consensus-neutral and needs no fork/activation. Because the change is
// byte-neutral by construction, the ordinary functional suite cannot see it --
// this vector is the guard that a future edit does not silently perturb the
// digest, and (via the mandatory, non-defaulted midstate) that the optimized
// path is the one actually exercised.
//
// Structure:
//   * REFERENCE ORACLE (OracleSighash): an independent, clean-room
//     recomputation of the sighash the OLD way -- it recomputes all five
//     whole-tx subhashes from (tx, spent_outputs) on every single call and
//     never touches P2QRSighashMidstate. This is the O(N^2) reference.
//   * NEW PATH: BuildSighashMidstate() once, then SignatureHash() /
//     SignatureHashP2SHWrapped() per input (both consume the mandatory
//     midstate).
//   * The test builds one multi-input transaction that mixes single-sig,
//     legacy multisig, signer-address multisig, and P2SH-wrapped P2QR inputs,
//     and asserts OracleSighash(i) == NewPath(i) byte-for-byte for every i.

#include <consensus/voidcoinp2qr.h>
#include <script/voidcoin_p2qr.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using consensus::voidcoinp2qr::BuildSighashMidstate;
using consensus::voidcoinp2qr::P2QRSighashMidstate;

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_sighash_equivalence_tests, BasicTestingSetup)

namespace {

// ---------------------------------------------------------------------------
// REFERENCE ORACLE
//
// A deliberately independent transcription of the VOIDCOIN_P2QR SIGHASH_ALL
// preimage. It is written to mirror the historical per-input implementation:
// the five whole-transaction subhashes (preimage fields 6..10) are recomputed
// FROM SCRATCH on every call (O(N) work per input => O(N^2) across the tx).
//
// This must NOT share code with, or use, P2QRSighashMidstate. Its only job is
// to be a trustworthy, obviously-correct baseline that the optimized path is
// compared against. If the optimized path ever diverges by a single byte, this
// oracle disagrees and the guard fails.
// ---------------------------------------------------------------------------

// The tagged-hash domain separator MUST match
// consensus/voidcoinp2qr.cpp's HASHER_VoidCoinP2QR_SIGHASH.
const std::string VOIDCOIN_P2QR_SIGHASH_TAG = "VoidCoinP2QRSighash";

uint256 OracleHashPrevouts(const CTransaction& tx)
{
    HashWriter ss{};
    for (const CTxIn& txin : tx.vin) {
        ss << txin.prevout;
    }
    return ss.GetSHA256();
}

uint256 OracleHashSequences(const CTransaction& tx)
{
    HashWriter ss{};
    for (const CTxIn& txin : tx.vin) {
        ss << txin.nSequence;
    }
    return ss.GetSHA256();
}

uint256 OracleHashOutputs(const CTransaction& tx)
{
    HashWriter ss{};
    for (const CTxOut& txout : tx.vout) {
        ss << txout;
    }
    return ss.GetSHA256();
}

uint256 OracleHashSpentAmounts(const std::vector<CTxOut>& spent_outputs)
{
    HashWriter ss{};
    for (const CTxOut& txout : spent_outputs) {
        ss << txout.nValue;
    }
    return ss.GetSHA256();
}

uint256 OracleHashSpentScripts(const std::vector<CTxOut>& spent_outputs)
{
    HashWriter ss{};
    for (const CTxOut& txout : spent_outputs) {
        ss << txout.scriptPubKey;
    }
    return ss.GetSHA256();
}

// Recompute the sighash for one input the OLD, per-input way. Fields 6..10 are
// recomputed here every call; nothing is cached across inputs.
uint256 OracleSighash(
    const CTransaction& tx,
    uint32_t input_index,
    const CTxOut& spent_output,
    const std::vector<CTxOut>& spent_outputs)
{
    BOOST_REQUIRE(input_index < tx.vin.size());
    BOOST_REQUIRE(spent_outputs.size() == tx.vin.size());

    HashWriter ss{TaggedHash(VOIDCOIN_P2QR_SIGHASH_TAG)};

    const uint8_t epoch = 0;
    const int32_t hash_type = 1; // SIGHASH_ALL

    ss << epoch;

    ss << tx.version;
    ss << tx.nLockTime;
    ss << hash_type;
    ss << input_index;

    // Fields 6..10 -- recomputed here, per input (the O(N^2) baseline).
    ss << OracleHashPrevouts(tx);
    ss << OracleHashSequences(tx);
    ss << OracleHashOutputs(tx);
    ss << OracleHashSpentAmounts(spent_outputs);
    ss << OracleHashSpentScripts(spent_outputs);

    // Fields 11..14 -- this input's prevout/sequence and the spent
    // amount/script it redeems.
    ss << tx.vin[input_index].prevout;
    ss << tx.vin[input_index].nSequence;
    ss << spent_output.nValue;
    ss << spent_output.scriptPubKey;

    return ss.GetSHA256();
}

// ---------------------------------------------------------------------------
// Fixture builders (mirroring the conventions in
// voidcoin_p2qr_multisig_tests.cpp -- deterministic fake keys/sigs).
// ---------------------------------------------------------------------------

std::vector<unsigned char> FakePubKey(unsigned int seed)
{
    std::vector<unsigned char> pubkey(VOIDCOIN_P2QR_PUBKEY_SIZE, 0x00);
    pubkey[0] = static_cast<unsigned char>((seed >> 24) & 0xff);
    pubkey[1] = static_cast<unsigned char>((seed >> 16) & 0xff);
    pubkey[2] = static_cast<unsigned char>((seed >> 8) & 0xff);
    pubkey[3] = static_cast<unsigned char>(seed & 0xff);
    for (size_t i = 4; i < pubkey.size(); ++i) {
        pubkey[i] = static_cast<unsigned char>((seed + i) & 0xff);
    }
    return pubkey;
}

std::vector<unsigned char> FakeSignature(unsigned int seed)
{
    std::vector<unsigned char> sig(VOIDCOIN_P2QR_SIGNATURE_SIZE);
    for (size_t i = 0; i < sig.size(); ++i) {
        sig[i] = static_cast<unsigned char>((seed + i) & 0xff);
    }
    return sig;
}

std::vector<unsigned char> SmallInt(unsigned int value)
{
    if (value <= 0xff) {
        return std::vector<unsigned char>{static_cast<unsigned char>(value)};
    }
    return std::vector<unsigned char>{
        static_cast<unsigned char>(value & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff),
    };
}

CScript PushesToScriptSig(const std::vector<std::vector<unsigned char>>& pushes)
{
    CScript script_sig;
    for (const std::vector<unsigned char>& push : pushes) {
        script_sig << push;
    }
    return script_sig;
}

COutPoint FakeOutPoint(unsigned int seed, uint32_t n)
{
    // A distinct, deterministic prevout hash per input so preimage field 11
    // differs across inputs and the vector actually exercises input_index.
    HashWriter ss{};
    ss << seed;
    return COutPoint(Txid::FromUint256(ss.GetSHA256()), n);
}

} // namespace

// ---------------------------------------------------------------------------
// T6: NEW precomputed sighash == OLD per-input recompute, byte-for-byte, for
// every input of a mixed-type multi-input transaction.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(voidcoin_p2qr_t6_sighash_precompute_equals_per_input_recompute)
{
    // --- Programs / spent scriptPubKeys for the four input flavours ---------

    // Input 0: single-sig native P2QR.
    const std::vector<unsigned char> single_pubkey = FakePubKey(0x11111111);
    const uint256 single_program = VoidCoinP2QRSingleProgram(single_pubkey);
    const CScript single_spk = VoidCoinMakeP2QRScriptPubKey(single_program);

    // Input 1: legacy (pubkey-policy) multisig native P2QR, 2-of-3.
    std::vector<std::vector<unsigned char>> legacy_pubkeys{
        FakePubKey(0x22220001),
        FakePubKey(0x22220002),
        FakePubKey(0x22220003),
    };
    const uint256 legacy_program = VoidCoinP2QRMultisigProgram(2, legacy_pubkeys);
    const CScript legacy_spk = VoidCoinMakeP2QRScriptPubKey(legacy_program);

    // Input 2: signer-address (program-policy) multisig native P2QR, 2-of-3.
    const std::vector<unsigned char> signer_pk_a = FakePubKey(0x33330001);
    const std::vector<unsigned char> signer_pk_b = FakePubKey(0x33330002);
    const std::vector<unsigned char> signer_pk_c = FakePubKey(0x33330003);
    std::vector<uint256> signer_programs{
        VoidCoinP2QRSingleProgram(signer_pk_a),
        VoidCoinP2QRSingleProgram(signer_pk_b),
        VoidCoinP2QRSingleProgram(signer_pk_c),
    };
    // Signer programs must be strictly increasing for a canonical policy.
    std::sort(signer_programs.begin(), signer_programs.end());
    const uint256 signer_program_policy = VoidCoinP2QRMultisigProgram(2, signer_programs);
    const CScript signer_spk = VoidCoinMakeP2QRScriptPubKey(signer_program_policy);

    // Input 3: P2SH-wrapped native P2QR (spent scriptPubKey is a P2SH output).
    const std::vector<unsigned char> wrapped_pubkey = FakePubKey(0x44444444);
    const uint256 wrapped_program = VoidCoinP2QRSingleProgram(wrapped_pubkey);
    const CScript wrapped_spk =
        consensus::voidcoinp2qr::MakeP2SHScriptPubKey(wrapped_program);
    const CScript wrapped_redeem =
        consensus::voidcoinp2qr::MakeRedeemScript(wrapped_program);

    // --- Spent outputs (vin-aligned), distinct amounts ----------------------
    std::vector<CTxOut> spent_outputs;
    spent_outputs.emplace_back(1000 * COIN, single_spk);
    spent_outputs.emplace_back(2500 * COIN, legacy_spk);
    spent_outputs.emplace_back( 777 * COIN, signer_spk);
    spent_outputs.emplace_back(4242 * COIN, wrapped_spk);

    // --- Build the transaction ----------------------------------------------
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0x1234abcd;

    // Distinct prevouts + sequences so per-input fields (11/12) vary.
    mtx.vin.emplace_back(FakeOutPoint(0xA0, 0), CScript(), 0xfffffffd);
    mtx.vin.emplace_back(FakeOutPoint(0xB1, 7), CScript(), 0xfffffffe);
    mtx.vin.emplace_back(FakeOutPoint(0xC2, 3), CScript(), 0x00000001);
    mtx.vin.emplace_back(FakeOutPoint(0xD3, 1), CScript(), 0xffffffff);

    // Two outputs so field 8 (HashOutputs) is non-trivial.
    const uint256 payout_program = VoidCoinP2QRSingleProgram(FakePubKey(0x9001));
    mtx.vout.emplace_back(500 * COIN, VoidCoinMakeP2QRScriptPubKey(payout_program));
    mtx.vout.emplace_back(300 * COIN, CScript() << OP_RETURN << std::vector<unsigned char>{'T', '6'});

    // Realistic scriptSigs for each flavour. Note: the sighash preimage does
    // NOT read scriptSig, so these do not affect the digest -- they are set so
    // the transaction is a genuine mixed-type tx rather than a placeholder.
    mtx.vin[0].scriptSig = PushesToScriptSig({FakeSignature(1), single_pubkey});

    {
        // Legacy multisig spend stack: <sig[m]> <idx[m]> <pubkey[n]> <m> <n>
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(FakeSignature(101));
        stack.push_back(FakeSignature(102));
        stack.push_back(SmallInt(0));
        stack.push_back(SmallInt(2));
        for (const std::vector<unsigned char>& pk : legacy_pubkeys) stack.push_back(pk);
        stack.push_back(SmallInt(2));
        stack.push_back(SmallInt(3));
        mtx.vin[1].scriptSig = PushesToScriptSig(stack);
    }

    {
        // Signer-address multisig spend stack:
        // <sig[m]> <idx[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
        std::vector<std::vector<unsigned char>> stack;
        stack.push_back(FakeSignature(201));
        stack.push_back(FakeSignature(202));
        stack.push_back(SmallInt(0));
        stack.push_back(SmallInt(1));
        stack.push_back(signer_pk_a);
        stack.push_back(signer_pk_b);
        for (const uint256& sp : signer_programs) {
            stack.push_back(std::vector<unsigned char>(sp.begin(), sp.end()));
        }
        stack.push_back(SmallInt(2));
        stack.push_back(SmallInt(3));
        mtx.vin[2].scriptSig = PushesToScriptSig(stack);
    }

    // P2SH-wrapped single: <sig> <pubkey> <redeem_script>
    mtx.vin[3].scriptSig = PushesToScriptSig({
        FakeSignature(3),
        wrapped_pubkey,
        std::vector<unsigned char>(wrapped_redeem.begin(), wrapped_redeem.end()),
    });

    const CTransaction tx{mtx};
    BOOST_REQUIRE_EQUAL(spent_outputs.size(), tx.vin.size());

    // --- NEW PATH: build the per-tx midstate exactly once -------------------
    const P2QRSighashMidstate midstate = BuildSighashMidstate(tx, spent_outputs);

    // The midstate must be populated and bound to THIS transaction.
    BOOST_CHECK(midstate.m_ready);
    BOOST_CHECK(midstate.m_txid == tx.GetHash());

    // Pin the cached subhashes to the independent per-input recompute. This is
    // what guarantees byte-identity of fields 6..10 regardless of the streaming
    // above, and localizes any future divergence to a specific subhash.
    BOOST_CHECK(midstate.m_hash_prevouts == OracleHashPrevouts(tx));
    BOOST_CHECK(midstate.m_hash_sequences == OracleHashSequences(tx));
    BOOST_CHECK(midstate.m_hash_outputs == OracleHashOutputs(tx));
    BOOST_CHECK(midstate.m_hash_spent_amounts == OracleHashSpentAmounts(spent_outputs));
    BOOST_CHECK(midstate.m_hash_spent_scripts == OracleHashSpentScripts(spent_outputs));

    // --- Byte-for-byte equivalence for EVERY input --------------------------
    for (uint32_t i = 0; i < tx.vin.size(); ++i) {
        const CTxOut& spent = spent_outputs[i];

        const uint256 oracle = OracleSighash(tx, i, spent, spent_outputs);

        // Native inputs (0,1,2) go through SignatureHash; the P2SH-wrapped
        // input (3) goes through SignatureHashP2SHWrapped. Both consume the
        // mandatory midstate and must reproduce the oracle exactly.
        uint256 optimized;
        if (i < 3) {
            optimized = consensus::voidcoinp2qr::SignatureHash(
                tx, i, spent, spent_outputs, midstate);
        } else {
            optimized = consensus::voidcoinp2qr::SignatureHashP2SHWrapped(
                tx, i, spent, spent_outputs, midstate);
        }

        BOOST_CHECK_MESSAGE(
            optimized == oracle,
            "T6 sighash mismatch at input " << i
                << ": optimized=" << optimized.ToString()
                << " oracle=" << oracle.ToString());
    }
}

// ---------------------------------------------------------------------------
// T6 guard, part 2: the optimization cannot be silently bypassed.
//
// Closes the "tests can't tell whether the optimization is active" finding:
// the midstate parameter is mandatory (non-defaulted -> compile error to
// omit), bound to its transaction by txid, and has NO O(N)-per-input fallback.
// A midstate built for a different transaction must be REJECTED, not silently
// accepted via a recompute path.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(voidcoin_p2qr_t6_foreign_midstate_is_rejected)
{
    const std::vector<unsigned char> pubkey = FakePubKey(0x55555555);
    const uint256 program = VoidCoinP2QRSingleProgram(pubkey);
    const CScript spk = VoidCoinMakeP2QRScriptPubKey(program);

    // Transaction A.
    CMutableTransaction mtx_a;
    mtx_a.version = 2;
    mtx_a.vin.emplace_back(FakeOutPoint(0xAA, 0), CScript(), 0xffffffff);
    mtx_a.vout.emplace_back(100 * COIN, spk);
    std::vector<CTxOut> spent_a{CTxOut(200 * COIN, spk)};
    const CTransaction tx_a{mtx_a};

    // Transaction B (differs from A: different prevout).
    CMutableTransaction mtx_b = mtx_a;
    mtx_b.vin[0].prevout = FakeOutPoint(0xBB, 0);
    std::vector<CTxOut> spent_b{CTxOut(200 * COIN, spk)};
    const CTransaction tx_b{mtx_b};

    const P2QRSighashMidstate midstate_b = BuildSighashMidstate(tx_b, spent_b);
    BOOST_REQUIRE(midstate_b.m_ready);
    BOOST_REQUIRE(midstate_b.m_txid != tx_a.GetHash());

    // Applying B's midstate to A must fail loudly (binding assertion via a hard
    // throw in the header-exposed wrapper), never fall back to a recompute.
    BOOST_CHECK_THROW(
        consensus::voidcoinp2qr::SignatureHash(tx_a, 0, spent_a[0], spent_a, midstate_b),
        std::invalid_argument);

    // A default-constructed (unready) midstate is likewise rejected -- there is
    // no defaulted/nullptr midstate that silently recomputes per input.
    const P2QRSighashMidstate unready{};
    BOOST_REQUIRE(!unready.m_ready);
    BOOST_CHECK_THROW(
        consensus::voidcoinp2qr::SignatureHash(tx_a, 0, spent_a[0], spent_a, unready),
        std::invalid_argument);

    // The correctly-bound midstate is accepted and reproduces the oracle.
    const P2QRSighashMidstate midstate_a = BuildSighashMidstate(tx_a, spent_a);
    const uint256 optimized =
        consensus::voidcoinp2qr::SignatureHash(tx_a, 0, spent_a[0], spent_a, midstate_a);
    const uint256 oracle = OracleSighash(tx_a, 0, spent_a[0], spent_a);
    BOOST_CHECK(optimized == oracle);
}

BOOST_AUTO_TEST_SUITE_END()
