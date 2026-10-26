// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// PA-06 regression tests: a large-but-VALID signer-program P2QR multisig must
// be fundable AND spendable once the VCIP-3 hard fork activates.
//
// The bug: the spend-side push cap (VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES) was sized
// for the legacy pubkey-policy envelope (2m + n + 2 pushes). The newer
// signer-program envelope is 3m + n + 2 pushes, and the create side admits any
// policy with required (m) <= MAX_SIGNATURES and total (n) <= MAX_KEYS. So a
// signer-program multisig whose spend needs more than the legacy cap funds fine
// but can never be spent -- its scriptSig is rejected as "too many pushes"
// BEFORE any signature check. The coins are permanently irrecoverable.
//
// The fix (activation-gated at VCIP-3): raise the spend-side push cap to
// 3*MAX_SIGNATURES + MAX_KEYS + 2, which is exactly the maximum a maximal
// validly-committed policy can produce (and also dominates the legacy bound).
// Before activation the legacy cap still applies byte-for-byte; after
// activation the raised cap applies. These tests drive the real consensus
// entry point (consensus::voidcoinp2qr::CheckSpend) with real ML-DSA-87 keys
// and signatures and assert:
//
//   * the committed policy is valid at creation time,
//   * the output is a recognized (fundable) native P2QR output,
//   * pre-activation (legacy cap) the spend is rejected specifically for
//     exceeding the push cap, and
//   * post-activation (raised cap) the exact same spend fully validates.

#include <consensus/voidcoinp2qr.h>
#include <script/voidcoin_p2qr.h>

#include <crypto/pq/mldsa87/mldsa87.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

namespace vp = consensus::voidcoinp2qr;

namespace {

// A real ML-DSA-87 signer: recoverable keypair plus its P2QR single program
// (the 32-byte commitment a signer address commits to).
struct RealSigner {
    std::vector<unsigned char> pubkey;
    std::vector<unsigned char> seckey;
    uint256 program;
};

// Generate `count` real signers, deterministically seeded, sorted by program
// (the canonical signer-program ordering the policy commitment requires).
std::vector<RealSigner> MakeRealSigners(unsigned int base_seed, unsigned int count)
{
    std::vector<RealSigner> signers;
    signers.reserve(count);

    for (unsigned int i = 0; i < count; ++i) {
        std::vector<unsigned char> seed(MLDSA87_SEED_SIZE, 0x00);
        const unsigned int s = base_seed + i;
        seed[0] = static_cast<unsigned char>(s & 0xff);
        seed[1] = static_cast<unsigned char>((s >> 8) & 0xff);
        seed[2] = static_cast<unsigned char>((s >> 16) & 0xff);
        seed[3] = static_cast<unsigned char>((s >> 24) & 0xff);

        RealSigner signer;
        BOOST_REQUIRE(MLDSA87GenerateKeypairFromSeed(
            Span<const unsigned char>(seed.data(), seed.size()),
            signer.pubkey, signer.seckey));
        signer.program = VoidCoinP2QRSingleProgram(signer.pubkey);
        signers.push_back(std::move(signer));
    }

    std::sort(signers.begin(), signers.end(),
        [](const RealSigner& a, const RealSigner& b) { return a.program < b.program; });

    // Programs must be strictly increasing for a canonical policy; the seeds are
    // distinct so collisions are cryptographically impossible, but assert it.
    for (size_t i = 1; i < signers.size(); ++i) {
        BOOST_REQUIRE(signers[i - 1].program < signers[i].program);
    }

    return signers;
}

std::vector<unsigned char> ProgramBytes(const uint256& program)
{
    return std::vector<unsigned char>(program.begin(), program.end());
}

// Canonical little-endian minimal encoding of an m/n/index value, matching the
// wallet signing convention the P2QR multisig parser accepts.
std::vector<unsigned char> EncodeUInt16Minimal(unsigned int value)
{
    if (value <= 0xff) {
        return std::vector<unsigned char>{static_cast<unsigned char>(value)};
    }
    return std::vector<unsigned char>{
        static_cast<unsigned char>(value & 0xff),
        static_cast<unsigned char>((value >> 8) & 0xff),
    };
}

// Build the new-format signer-program multisig scriptSig that reveals the first
// `required` signers (indexes 0..required-1) of `signers` (total = size):
//
//   <sig[m]> <signer_index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
CScript BuildSignerProgramScriptSig(
    const std::vector<RealSigner>& signers,
    unsigned int required,
    const uint256& sighash)
{
    const unsigned int total = static_cast<unsigned int>(signers.size());

    CScript script_sig;

    // signatures[m] -- the revealed signers sign the 32-byte P2QR sighash.
    for (unsigned int i = 0; i < required; ++i) {
        std::vector<unsigned char> sig;
        BOOST_REQUIRE(MLDSA87Sign(
            Span<const unsigned char>(signers[i].seckey.data(), signers[i].seckey.size()),
            Span<const unsigned char>(sighash.begin(), sighash.size()),
            sig));
        script_sig << sig;
    }

    // signer_index[m] -- strictly increasing 0..required-1.
    for (unsigned int i = 0; i < required; ++i) {
        script_sig << EncodeUInt16Minimal(i);
    }

    // signing_pubkey[m] -- the revealed signers' public keys.
    for (unsigned int i = 0; i < required; ++i) {
        script_sig << signers[i].pubkey;
    }

    // signer_program[n] -- the full committed signer-program set (sorted).
    for (unsigned int i = 0; i < total; ++i) {
        script_sig << ProgramBytes(signers[i].program);
    }

    // m, n
    script_sig << EncodeUInt16Minimal(required);
    script_sig << EncodeUInt16Minimal(total);

    return script_sig;
}

// Drive one full fund + spend of a `required`-of-`total` signer-program P2QR
// multisig through the real consensus path, and assert the pre/post-activation
// spendability contract. `expected_spend_pushes` documents the envelope size.
void RunFundAndSpendCase(
    unsigned int base_seed,
    unsigned int required,
    unsigned int total,
    size_t expected_spend_pushes,
    uint32_t prevout_index)
{
    BOOST_REQUIRE_LE(required, total);

    const std::vector<RealSigner> signers = MakeRealSigners(base_seed, total);

    // --- committed policy (creation side) ---------------------------------
    std::vector<uint256> signer_programs;
    signer_programs.reserve(total);
    for (const RealSigner& s : signers) signer_programs.push_back(s.program);

    // The policy must be valid at creation time (this is what "validly
    // committed" means; the fix guarantees every such policy is spendable).
    std::string policy_error;
    BOOST_CHECK_MESSAGE(
        VoidCoinIsCanonicalP2QRMultisigPolicy(
            static_cast<uint16_t>(required), signer_programs, &policy_error),
        "committed multisig policy must be valid at creation: " << policy_error);

    const uint256 committed_program =
        VoidCoinP2QRMultisigProgram(static_cast<uint16_t>(required), signer_programs);

    // --- fund: a native P2QR output paying to the committed program -------
    const CScript spk = VoidCoinMakeP2QRScriptPubKey(committed_program);

    uint256 recognized_program;
    BOOST_CHECK_MESSAGE(
        vp::IsOutput(spk, recognized_program),
        "committed multisig output must be a recognized (fundable) P2QR output");
    BOOST_CHECK(recognized_program == committed_program);

    CTxOut spent_output;
    spent_output.nValue = 100000;
    spent_output.scriptPubKey = spk;

    const std::vector<CTxOut> spent_outputs{spent_output};

    // --- build the spending transaction (scriptSig filled after signing) --
    CMutableTransaction mtx;
    mtx.version = 2;
    mtx.nLockTime = 0;
    {
        CTxIn in;
        in.prevout = COutPoint(Txid::FromUint256(uint256::ONE), prevout_index);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        mtx.vin.push_back(in);

        CTxOut out;
        out.nValue = 90000;
        out.scriptPubKey = spk; // any output; sighash commits to it
        mtx.vout.push_back(out);
    }

    // The P2QR SIGHASH_ALL preimage does NOT include scriptSig, so the sighash
    // computed over the (still unsigned) transaction is exactly what the signed,
    // scriptSig-filled transaction commits to. Compute it, sign, then fill.
    const CTransaction unsigned_tx(mtx);
    const vp::P2QRSighashMidstate unsigned_midstate =
        vp::BuildSighashMidstate(unsigned_tx, spent_outputs);
    const uint256 sighash =
        vp::SignatureHash(unsigned_tx, 0, spent_output, spent_outputs, unsigned_midstate);

    mtx.vin[0].scriptSig = BuildSignerProgramScriptSig(signers, required, sighash);

    const CTransaction tx(mtx);
    const vp::P2QRSighashMidstate midstate = vp::BuildSighashMidstate(tx, spent_outputs);

    // Document the envelope size that triggers PA-06.
    BOOST_CHECK_EQUAL(expected_spend_pushes, 3u * required + total + 2u);
    BOOST_CHECK_GT(expected_spend_pushes, VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES);        // exceeds legacy cap
    BOOST_CHECK_LE(expected_spend_pushes, VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3);  // within raised cap

    // --- PRE-activation: legacy cap -> permanently unspendable ------------
    {
        std::string error;
        const bool ok = vp::CheckSpend(
            tx, 0, spent_output, spent_outputs, midstate, error,
            /*vcip3_pushcap_active=*/false);
        BOOST_CHECK_MESSAGE(!ok, "pre-VCIP-3 spend must be rejected (PA-06 stranding)");
        BOOST_CHECK_MESSAGE(
            error.find("too-many-pushes") != std::string::npos,
            "pre-VCIP-3 rejection must be the push-cap limit, got: " << error);
    }

    // --- POST-activation: raised cap -> the same spend fully validates ----
    {
        std::string error;
        const bool ok = vp::CheckSpend(
            tx, 0, spent_output, spent_outputs, midstate, error,
            /*vcip3_pushcap_active=*/true);
        BOOST_CHECK_MESSAGE(
            ok, "post-VCIP-3 spend of a validly-committed multisig must succeed, got: " << error);
    }
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_pa06_pushcap_tests, BasicTestingSetup)

// The raised cap must be EXACTLY the maximal validly-committed spend (no
// off-by-one that would still strand the largest policy, and no create/spend
// mismatch). This mirrors the compile-time invariant in <script/voidcoin_p2qr.h>.
BOOST_AUTO_TEST_CASE(vcip3_cap_matches_maximal_committed_policy)
{
    const size_t maximal_signer_program_pushes =
        3u * VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + VOIDCOIN_P2QR_MULTISIG_MAX_KEYS + 2u;
    const size_t maximal_legacy_pushes =
        2u * VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + VOIDCOIN_P2QR_MULTISIG_MAX_KEYS + 2u;

    // Legacy cap covers only the legacy envelope, NOT the signer-program one.
    BOOST_CHECK_EQUAL(VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES, maximal_legacy_pushes);
    BOOST_CHECK_LT(VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES, maximal_signer_program_pushes);

    // Raised cap covers the maximal committed policy of BOTH formats.
    BOOST_CHECK_EQUAL(VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3, maximal_signer_program_pushes);
    BOOST_CHECK_GE(VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3, maximal_legacy_pushes);

    // The selection helper picks legacy pre-fork and raised post-fork.
    BOOST_CHECK_EQUAL(VoidCoinP2QRMultisigMaxPushes(false), VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES);
    BOOST_CHECK_EQUAL(VoidCoinP2QRMultisigMaxPushes(true), VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3);
    BOOST_CHECK_EQUAL(VoidCoinP2QRMultisigP2SHMaxPushes(false), VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);
    BOOST_CHECK_EQUAL(VoidCoinP2QRMultisigP2SHMaxPushes(true), VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES_VCIP3);
}

// Representative large threshold multisig (700-of-1000): a realistic policy
// whose signer-program spend (3*700 + 1000 + 2 = 3102 pushes) exceeds the
// legacy cap. Stranded pre-fork, spendable post-fork.
BOOST_AUTO_TEST_CASE(large_threshold_signer_program_multisig_funds_and_spends)
{
    RunFundAndSpendCase(
        /*base_seed=*/0x11000000u,
        /*required=*/700,
        /*total=*/1000,
        /*expected_spend_pushes=*/3u * 700u + 1000u + 2u,
        /*prevout_index=*/0);
}

// The absolute maximal committed policy (MAX_SIGNATURES-of-MAX_KEYS). Its spend
// is exactly VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES_VCIP3 pushes -- the tight upper
// boundary the raised cap is sized to. Proves the cap is not too small even at
// the exact maximum.
BOOST_AUTO_TEST_CASE(maximal_signer_program_multisig_funds_and_spends)
{
    RunFundAndSpendCase(
        /*base_seed=*/0x22000000u,
        /*required=*/VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES,
        /*total=*/VOIDCOIN_P2QR_MULTISIG_MAX_KEYS,
        /*expected_spend_pushes=*/
        3u * VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES + VOIDCOIN_P2QR_MULTISIG_MAX_KEYS + 2u,
        /*prevout_index=*/1);
}

BOOST_AUTO_TEST_SUITE_END()
