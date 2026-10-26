// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// VC-06 regression: the P2QR fee-vsize discount (GetP2QRFeeVirtualSize) must be
// consistent with actual verification work. A single-sig P2QR spend keeps its
// intended flat discount; a large multisig P2QR spend must NOT be discounted
// and therefore must require a fee proportional to its real serialized size.

#include <coins.h>
#include <consensus/amount.h>
#include <policy/feerate.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/voidcoin_p2qr.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_fee_vsize_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> FakePubKey(unsigned int seed)
{
    std::vector<unsigned char> pubkey(VOIDCOIN_P2QR_PUBKEY_SIZE, 0x00);
    for (size_t i = 0; i < pubkey.size(); ++i) {
        pubkey[i] = static_cast<unsigned char>((seed + i) & 0xff);
    }
    // Keep the leading byte non-zero so distinct seeds give distinct programs.
    pubkey[0] = static_cast<unsigned char>((seed & 0xff) | 0x01);
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
    if (value == 0) return std::vector<unsigned char>{};
    if (value <= 0xff) return std::vector<unsigned char>{static_cast<unsigned char>(value)};
    return std::vector<unsigned char>{
        static_cast<unsigned char>(value & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff),
    };
}

// Native single-sig P2QR scriptSig: <sig> <pubkey> (the recognized 2-push auth
// envelope that ParseSpendData accepts).
CScript SingleSigScriptSig(const std::vector<unsigned char>& sig,
                           const std::vector<unsigned char>& pubkey)
{
    CScript s;
    s << sig << pubkey;
    return s;
}

// A structurally-plausible native multisig P2QR scriptSig (new signer-program
// format): <sig[m]> <index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>.
// For the fee-vsize computation only its push count/size matter: it has far more
// than two pushes, so ParseSpendData rejects it and it earns no single-sig
// discount. The committed program is derived from the same signer set.
CScript MultisigScriptSig(uint16_t n, uint256& program_out)
{
    std::vector<std::vector<unsigned char>> signing_pubkeys;
    std::vector<uint256> signer_programs;
    signing_pubkeys.reserve(n);
    signer_programs.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        std::vector<unsigned char> pk = FakePubKey(1000u + i);
        signer_programs.push_back(VoidCoinP2QRSingleProgram(pk));
        signing_pubkeys.push_back(std::move(pk));
    }

    program_out = VoidCoinP2QRMultisigProgram(n, signer_programs);

    CScript s;
    for (uint16_t i = 0; i < n; ++i) s << FakeSignature(2000u + i); // m signatures
    for (uint16_t i = 0; i < n; ++i) s << SmallInt(i);              // m signer indexes
    for (uint16_t i = 0; i < n; ++i) s << signing_pubkeys[i];       // m signing pubkeys
    for (uint16_t i = 0; i < n; ++i) {                             // n signer programs
        s << std::vector<unsigned char>(signer_programs[i].begin(), signer_programs[i].end());
    }
    s << SmallInt(n) << SmallInt(n);                               // m, n
    return s;
}

CMutableTransaction MakeSpend(const COutPoint& prevout, const CScript& scriptSig)
{
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(prevout);
    mtx.vin.back().scriptSig = scriptSig;
    mtx.vout.emplace_back(1 * COIN, CScript() << OP_TRUE);
    return mtx;
}

} // namespace

// A legitimate single-sig P2QR input keeps its intended flat discount: its
// multi-kilobyte signature envelope is priced at ~P2QR_POLICY_FEE_VBYTES_PER_INPUT.
BOOST_AUTO_TEST_CASE(single_sig_keeps_discount)
{
    const std::vector<unsigned char> pubkey = FakePubKey(7);
    const std::vector<unsigned char> sig = FakeSignature(7);
    const uint256 program = VoidCoinP2QRSingleProgram(pubkey);
    const CScript spk = VoidCoinMakeP2QRScriptPubKey(program);

    const COutPoint prevout{Txid::FromUint256(uint256::ONE), 0};
    const CMutableTransaction mtx = MakeSpend(prevout, SingleSigScriptSig(sig, pubkey));
    const CTransaction tx{mtx};

    CCoinsView root;
    CCoinsViewCache view{&root};
    view.AddCoin(prevout, Coin{CTxOut{2 * COIN, spk}, 1, false}, false);

    const int64_t actual_vsize = GetVirtualTransactionSize(tx, 0, 0);
    const int64_t fee_vsize = GetP2QRFeeVirtualSize(tx, view, actual_vsize);

    // The ~7.2 KB signature envelope must actually be discounted...
    BOOST_CHECK_GT(actual_vsize, 7000);
    BOOST_CHECK_LT(fee_vsize, actual_vsize);
    // ...down to roughly one flat unit plus fixed tx overhead (a few dozen bytes).
    BOOST_CHECK_LT(fee_vsize, P2QR_POLICY_FEE_VBYTES_PER_INPUT + 200);
    BOOST_CHECK_GE(fee_vsize, P2QR_POLICY_FEE_VBYTES_PER_INPUT);
}

// VC-06: a large multisig P2QR input must NOT receive the single-sig discount.
// Its fee-vsize must equal its real size, so the min-relay-fee gate charges it
// proportionally (closing the ~100,000x underpricing / mempool-flood vector).
BOOST_AUTO_TEST_CASE(multisig_is_not_discounted)
{
    uint256 program;
    const CScript scriptSig = MultisigScriptSig(/*n=*/64, program);
    const CScript spk = VoidCoinMakeP2QRScriptPubKey(program);

    const COutPoint prevout{Txid::FromUint256(uint256{2}), 0};
    const CMutableTransaction mtx = MakeSpend(prevout, scriptSig);
    const CTransaction tx{mtx};

    CCoinsView root;
    CCoinsViewCache view{&root};
    view.AddCoin(prevout, Coin{CTxOut{2 * COIN, spk}, 1, false}, false);

    const int64_t actual_vsize = GetVirtualTransactionSize(tx, 0, 0);
    const int64_t fee_vsize = GetP2QRFeeVirtualSize(tx, view, actual_vsize);

    // Multisig scriptSig is large (64 sigs + 64 pubkeys ~ >450 KB)...
    BOOST_CHECK_GT(actual_vsize, 400000);
    // ...and receives NO discount: fee-vsize is the real size.
    BOOST_CHECK_EQUAL(fee_vsize, actual_vsize);

    // Fee-gate consequence: at the default min relay feerate the required fee is
    // proportional to real size, not the flat ~68-vbyte unit.
    const CFeeRate min_relay{DEFAULT_MIN_RELAY_TX_FEE};
    const CAmount required_fee = min_relay.GetFee(static_cast<uint32_t>(fee_vsize));
    const CAmount flat_unit_fee = min_relay.GetFee(static_cast<uint32_t>(P2QR_POLICY_FEE_VBYTES_PER_INPUT));
    BOOST_CHECK_GT(required_fee, 100 * flat_unit_fee); // ~1000x+ more than the old bypass price
}

// Per-input discrimination: in a tx carrying one single-sig and one multisig
// P2QR input, only the single-sig envelope is discounted; the multisig input
// contributes its full serialized size to the fee-vsize.
BOOST_AUTO_TEST_CASE(mixed_inputs_discount_only_single_sig)
{
    // Single-sig input.
    const std::vector<unsigned char> pubkey = FakePubKey(11);
    const std::vector<unsigned char> sig = FakeSignature(11);
    const uint256 ss_program = VoidCoinP2QRSingleProgram(pubkey);
    const CScript ss_spk = VoidCoinMakeP2QRScriptPubKey(ss_program);
    const COutPoint ss_prevout{Txid::FromUint256(uint256{3}), 0};

    // Multisig input.
    uint256 ms_program;
    const CScript ms_scriptSig = MultisigScriptSig(/*n=*/32, ms_program);
    const CScript ms_spk = VoidCoinMakeP2QRScriptPubKey(ms_program);
    const COutPoint ms_prevout{Txid::FromUint256(uint256{4}), 0};

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(ss_prevout);
    mtx.vin.back().scriptSig = SingleSigScriptSig(sig, pubkey);
    mtx.vin.emplace_back(ms_prevout);
    mtx.vin.back().scriptSig = ms_scriptSig;
    mtx.vout.emplace_back(1 * COIN, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    CCoinsView root;
    CCoinsViewCache view{&root};
    view.AddCoin(ss_prevout, Coin{CTxOut{2 * COIN, ss_spk}, 1, false}, false);
    view.AddCoin(ms_prevout, Coin{CTxOut{2 * COIN, ms_spk}, 1, false}, false);

    const int64_t actual_vsize = GetVirtualTransactionSize(tx, 0, 0);
    const int64_t fee_vsize = GetP2QRFeeVirtualSize(tx, view, actual_vsize);

    // Only the single-sig envelope (~7.2 KB) is removed; the multisig bytes stay.
    const int64_t expected = actual_vsize
        - static_cast<int64_t>(SingleSigScriptSig(sig, pubkey).size())
        + P2QR_POLICY_FEE_VBYTES_PER_INPUT;
    BOOST_CHECK_EQUAL(fee_vsize, expected);

    // The multisig portion still dominates the priced size.
    BOOST_CHECK_GT(fee_vsize, 200000);
}

BOOST_AUTO_TEST_SUITE_END()
