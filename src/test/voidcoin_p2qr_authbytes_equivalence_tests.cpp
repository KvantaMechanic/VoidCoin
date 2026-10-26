// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// VC-06 CONSENSUS-SAFETY regression.
//
// GetP2QRAuthBytes() is on the block-validity path: it feeds
// GetP2QRAdjustedTransactionWeight(), which ConnectBlock enforces against
// MAX_BLOCK_WEIGHT (validation.cpp). The VC-06 fee-vsize change also rewrote the
// P2SH branch of GetP2QRAuthBytes() to recognize the single-sig auth envelope
// with an *inline* size check
//
//     pushes[0].size() == VOIDCOIN_P2QR_SIGNATURE_SIZE &&
//     pushes[1].size() == VOIDCOIN_P2QR_PUBKEY_SIZE
//
// instead of delegating to consensus::voidcoinp2qr::ParseSpendData() on the
// re-serialized two-push script. That is behaviourally identical to every other
// node TODAY only because the policy-facing size aliases equal the ML-DSA-87
// sizes that ParseSpendData enforces:
//
//     VOIDCOIN_P2QR_SIGNATURE_SIZE == MLDSA87_SIGNATURE_SIZE
//     VOIDCOIN_P2QR_PUBKEY_SIZE    == MLDSA87_PUBLIC_KEY_SIZE
//
// If those constants ever decouple, the inline check would accept/reject a
// different set of scriptSigs than ParseSpendData, diverging the P2SH-P2QR
// auth-weight discount and silently splitting the chain. This suite pins the
// equivalence so any such decoupling is caught in CI rather than on a live node.

#include <coins.h>
#include <consensus/amount.h>
#include <consensus/voidcoinp2qr.h>
#include <crypto/pq/mldsa87/mldsa87.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/voidcoin_p2qr.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// Compile-time statement of the invariant the inline GetP2QRAuthBytes() check
// depends on. A future decoupling of these constants fails the build here (and
// in policy.cpp), before the runtime corpus below even runs.
static_assert(VOIDCOIN_P2QR_SIGNATURE_SIZE == MLDSA87_SIGNATURE_SIZE,
              "inline P2QR auth-bytes signature-size check must equal ParseSpendData's");
static_assert(VOIDCOIN_P2QR_PUBKEY_SIZE == MLDSA87_PUBLIC_KEY_SIZE,
              "inline P2QR auth-bytes pubkey-size check must equal ParseSpendData's");

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_authbytes_equivalence_tests, BasicTestingSetup)

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

// A well-formed native single-sig public key of the canonical size, used to
// derive a real P2QR program / redeem script for the end-to-end path.
std::vector<unsigned char> ValidPubKey(unsigned int seed)
{
    return Bytes(VOIDCOIN_P2QR_PUBKEY_SIZE, seed);
}

std::vector<unsigned char> ValidSignature(unsigned int seed)
{
    return Bytes(VOIDCOIN_P2QR_SIGNATURE_SIZE, seed);
}

// The exact inline predicate used inside GetP2QRAuthBytes()'s P2SH branch,
// duplicated here so the test asserts the *code under test* matches
// ParseSpendData -- not merely that two constants are equal.
bool InlineAuthPredicate(const std::vector<unsigned char>& sig,
                         const std::vector<unsigned char>& pubkey)
{
    return sig.size() == VOIDCOIN_P2QR_SIGNATURE_SIZE &&
           pubkey.size() == VOIDCOIN_P2QR_PUBKEY_SIZE;
}

// The reference predicate: does ParseSpendData accept the two pushes once they
// are re-serialized exactly as GetP2QRAuthBytes does (native_spend_script =
// CScript() << pushes[0] << pushes[1])?
bool ParseSpendDataAcceptsReserialized(const std::vector<unsigned char>& sig,
                                       const std::vector<unsigned char>& pubkey)
{
    CScript native_spend_script;
    native_spend_script << sig << pubkey;

    std::vector<unsigned char> out_sig;
    std::vector<unsigned char> out_pubkey;
    std::string err;
    return consensus::voidcoinp2qr::ParseSpendData(native_spend_script, out_sig, out_pubkey, err);
}

} // namespace

// Core theorem: over a corpus of native single-sig two-push envelopes spanning
// the valid sizes and many off-by-N / cross-swapped variants, the inline size
// check inside GetP2QRAuthBytes() accepts a script IFF ParseSpendData() accepts
// the re-serialized two-push script. Both the VOIDCOIN_* alias and the raw
// MLDSA87_* size are exercised as the "valid" length, so a decoupling of the
// two constants in EITHER direction produces a mismatch here.
BOOST_AUTO_TEST_CASE(inline_check_matches_parsespenddata_corpus)
{
    const size_t SIG = VOIDCOIN_P2QR_SIGNATURE_SIZE;
    const size_t PUB = VOIDCOIN_P2QR_PUBKEY_SIZE;

    const std::vector<size_t> sig_lens{
        0, 1, 32, 64, 520,
        MLDSA87_SIGNATURE_SIZE - 1, MLDSA87_SIGNATURE_SIZE, MLDSA87_SIGNATURE_SIZE + 1,
        SIG - 1, SIG, SIG + 1,
        PUB, // a "signature" that is actually pubkey-sized must be rejected
    };
    const std::vector<size_t> pub_lens{
        0, 1, 32, 64, 520,
        MLDSA87_PUBLIC_KEY_SIZE - 1, MLDSA87_PUBLIC_KEY_SIZE, MLDSA87_PUBLIC_KEY_SIZE + 1,
        PUB - 1, PUB, PUB + 1,
        SIG, // a "pubkey" that is actually signature-sized must be rejected
    };

    size_t accepted = 0;
    for (size_t sl : sig_lens) {
        for (size_t pl : pub_lens) {
            const std::vector<unsigned char> sig = Bytes(sl, 0x11);
            const std::vector<unsigned char> pubkey = Bytes(pl, 0x22);

            const bool inl = InlineAuthPredicate(sig, pubkey);
            const bool ref = ParseSpendDataAcceptsReserialized(sig, pubkey);

            BOOST_CHECK_MESSAGE(inl == ref,
                "inline vs ParseSpendData mismatch for sig_len=" << sl
                << " pub_len=" << pl << " (inline=" << inl << " parse=" << ref << ")");

            // The only accepted shape is exactly (SIG, PUB); when accepted the
            // discounted byte count must be the re-serialized two-push size that
            // GetP2QRAuthBytes actually adds.
            if (ref) {
                ++accepted;
                BOOST_CHECK_EQUAL(sl, SIG);
                BOOST_CHECK_EQUAL(pl, PUB);
                CScript native_spend_script;
                native_spend_script << sig << pubkey;
                BOOST_CHECK_GT(native_spend_script.size(), SIG + PUB); // + push opcodes
            }
        }
    }
    // At least the canonical (SIG,PUB) pair (and its MLDSA87-sized duplicate)
    // must have been accepted; a silent all-reject would also be a regression.
    BOOST_CHECK_GE(accepted, 1u);
}

// End-to-end: drive the actual consensus-path function GetP2QRAuthBytes() over
// native and P2SH-wrapped P2QR inputs and assert its result equals a reference
// recomputation built solely on ParseSpendData / ParseP2SHWrappedSpendData.
BOOST_AUTO_TEST_CASE(getp2qrauthbytes_equals_parsespenddata_reference)
{
    namespace vp = consensus::voidcoinp2qr;

    const std::vector<unsigned char> pubkey = ValidPubKey(7);
    const std::vector<unsigned char> sig = ValidSignature(7);
    const uint256 program = VoidCoinP2QRSingleProgram(pubkey);

    // Input 1: native P2QR, valid single-sig 2-push envelope -> discounted.
    const CScript native_spk = VoidCoinMakeP2QRScriptPubKey(program);
    CScript native_scriptsig;
    native_scriptsig << sig << pubkey;
    const COutPoint native_prevout{Txid::FromUint256(uint256{1}), 0};

    // Input 2: P2SH-wrapped P2QR, valid 3-push envelope -> discounted (sig+pubkey
    // only, never the redeem script).
    const CScript redeem = vp::MakeRedeemScript(program);
    const CScript p2sh_spk = vp::MakeP2SHScriptPubKey(program);
    CScript p2sh_scriptsig;
    p2sh_scriptsig << sig << pubkey << std::vector<unsigned char>(redeem.begin(), redeem.end());
    const COutPoint p2sh_prevout{Txid::FromUint256(uint256{2}), 0};

    // Input 3: native P2QR, but a wrong-sized signature -> NOT discounted.
    const std::vector<unsigned char> short_sig = Bytes(VOIDCOIN_P2QR_SIGNATURE_SIZE - 1, 0x33);
    CScript bad_native_scriptsig;
    bad_native_scriptsig << short_sig << pubkey;
    const COutPoint bad_prevout{Txid::FromUint256(uint256{3}), 0};

    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.vin.emplace_back(native_prevout);
    mtx.vin.back().scriptSig = native_scriptsig;
    mtx.vin.emplace_back(p2sh_prevout);
    mtx.vin.back().scriptSig = p2sh_scriptsig;
    mtx.vin.emplace_back(bad_prevout);
    mtx.vin.back().scriptSig = bad_native_scriptsig;
    mtx.vout.emplace_back(1 * COIN, CScript() << OP_TRUE);
    const CTransaction tx{mtx};

    CCoinsView root;
    CCoinsViewCache view{&root};
    view.AddCoin(native_prevout, Coin{CTxOut{2 * COIN, native_spk}, 1, false}, false);
    view.AddCoin(p2sh_prevout, Coin{CTxOut{2 * COIN, p2sh_spk}, 1, false}, false);
    view.AddCoin(bad_prevout, Coin{CTxOut{2 * COIN, native_spk}, 1, false}, false);

    // Reference computation using only the consensus parsers (no inline sizes).
    int64_t ref_auth_bytes = 0;
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);
        if (coin.IsSpent()) continue;

        uint256 prog;
        if (vp::IsOutput(coin.out.scriptPubKey, prog)) {
            std::vector<unsigned char> s, p;
            std::string err;
            if (vp::ParseSpendData(txin.scriptSig, s, p, err)) {
                ref_auth_bytes += static_cast<int64_t>(txin.scriptSig.size());
            }
            continue;
        }
        CScriptID id;
        if (vp::IsP2SHOutput(coin.out.scriptPubKey, id)) {
            std::vector<unsigned char> s, p;
            CScript rs;
            uint256 carried;
            std::string err;
            if (vp::ParseP2SHWrappedSpendData(txin.scriptSig, s, p, rs, carried, err) &&
                CScriptID(rs) == id) {
                CScript native_spend_script;
                native_spend_script << s << p;
                ref_auth_bytes += static_cast<int64_t>(native_spend_script.size());
            }
            continue;
        }
    }

    const int64_t actual_auth_bytes = GetP2QRAuthBytes(tx, view);
    BOOST_CHECK_EQUAL(actual_auth_bytes, ref_auth_bytes);

    // Sanity: the two valid inputs were counted, the wrong-sized one was not.
    CScript native_spend_script;
    native_spend_script << sig << pubkey;
    const int64_t expected =
        static_cast<int64_t>(native_scriptsig.size()) +      // native input, full 2-push scriptSig
        static_cast<int64_t>(native_spend_script.size());    // P2SH input, sig+pubkey only
    BOOST_CHECK_EQUAL(actual_auth_bytes, expected);
    BOOST_CHECK_GT(actual_auth_bytes, 0);
}

BOOST_AUTO_TEST_SUITE_END()
