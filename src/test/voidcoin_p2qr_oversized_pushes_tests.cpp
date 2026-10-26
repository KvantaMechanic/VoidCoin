// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// PA-03 regression tests.
//
// The oversized-P2QR standardness pre-check in AcceptSingleTransaction()
// (validation.cpp) decodes an over-large scriptSig into a push vector before
// classifying it as a native / P2SH-carried VOIDCOIN_P2QR spend. That input can
// legitimately be many megabytes (up to the P2QR tx-weight policy limit), i.e.
// potentially millions of 1-byte pushes. The previous decode was an unbounded
// loop that materialized one std::vector<unsigned char> per push, so a single
// crafted transaction could force a multi-hundred-MB / ~1GB transient allocation
// before any parse rejected it -- a cheap mempool-memory DoS.
//
// The fix routes that decode through VoidCoinReadCanonicalP2QRPushes() bounded by
// VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES -- the structural maximum number of
// pushes any well-formed P2QR spend envelope can contain. These tests pin the
// contract the pre-check now relies on: an oversized-push scriptSig is rejected
// (=> TX_NOT_STANDARD) and the output vector never grows past the bound, i.e.
// the rejection happens WITHOUT a large allocation.

#include <script/script.h>
#include <script/voidcoin_p2qr.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_oversized_pushes_tests, BasicTestingSetup)

// Build a push-only scriptSig consisting of `count` canonical single-byte data
// pushes (opcode 0x01, one payload byte), by emitting raw bytes directly so we
// can cheaply construct scripts with millions of pushes.
static CScript ManyCanonicalSingleBytePushes(size_t count)
{
    std::vector<unsigned char> raw;
    raw.reserve(count * 2);
    for (size_t i = 0; i < count; ++i) {
        raw.push_back(0x01);  // direct 1-byte push opcode
        raw.push_back(0x07);  // arbitrary payload byte
    }
    return CScript(raw.begin(), raw.end());
}

// The bound is a positive, finite structural maximum, and the P2SH-carried
// variant is exactly one push larger (the trailing redeemScript).
BOOST_AUTO_TEST_CASE(bound_constants_are_sane)
{
    BOOST_CHECK_GT(VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES, 0u);
    BOOST_CHECK_EQUAL(VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES,
                      VOIDCOIN_P2QR_MULTISIG_MAX_PUSHES + 1);
}

// Core PA-03 assertion: an oversized-push scriptSig is rejected, and the decode
// stays bounded regardless of how many pushes the attacker crammed in.
BOOST_AUTO_TEST_CASE(oversized_pushes_rejected_without_large_allocation)
{
    // Far more pushes than any legitimate P2QR spend -- and enough that an
    // unbounded decode would allocate millions of vectors. The 10 MB scriptSig
    // stands in for the "millions of tiny pushes" DoS shape.
    const size_t kOversized = 5'000'000;
    BOOST_REQUIRE_GT(kOversized, VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);

    const CScript script_sig = ManyCanonicalSingleBytePushes(kOversized);

    std::vector<std::vector<unsigned char>> pushes;
    std::string error;
    const bool ok = VoidCoinReadCanonicalP2QRPushes(
        script_sig, pushes, &error, VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);

    // Rejected -> AcceptSingleTransaction returns TX_NOT_STANDARD.
    BOOST_CHECK(!ok);
    BOOST_CHECK(error.find("too-many-pushes") != std::string::npos);

    // Bounded: the decoder bailed at the limit instead of allocating one vector
    // per input push. This is what caps the transient memory. Without the bound
    // this vector would hold ~5,000,000 entries.
    BOOST_CHECK_LE(pushes.size(), VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES + 1);
}

// Exactly at the bound is still accepted (structure is unchanged for legitimate
// envelopes); exactly one over the bound is the first rejection.
BOOST_AUTO_TEST_CASE(bound_boundary_accept_then_reject)
{
    {
        const CScript at_bound =
            ManyCanonicalSingleBytePushes(VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);
        std::vector<std::vector<unsigned char>> pushes;
        std::string error;
        const bool ok = VoidCoinReadCanonicalP2QRPushes(
            at_bound, pushes, &error, VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);
        BOOST_CHECK(ok);
        BOOST_CHECK_EQUAL(pushes.size(), VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);
    }
    {
        const CScript over_bound =
            ManyCanonicalSingleBytePushes(VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES + 1);
        std::vector<std::vector<unsigned char>> pushes;
        std::string error;
        const bool ok = VoidCoinReadCanonicalP2QRPushes(
            over_bound, pushes, &error, VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);
        BOOST_CHECK(!ok);
        BOOST_CHECK(error.find("too-many-pushes") != std::string::npos);
        BOOST_CHECK_LE(pushes.size(), VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES + 1);
    }
}

// Positive control: a well-formed two-push envelope decodes fine and is not
// perturbed by the bound. Guards against the fix over-rejecting valid spends.
BOOST_AUTO_TEST_CASE(well_formed_two_push_envelope_accepted)
{
    std::vector<unsigned char> a(VOIDCOIN_P2QR_SIGNATURE_SIZE, 0x11);
    std::vector<unsigned char> b(VOIDCOIN_P2QR_PUBKEY_SIZE, 0x22);
    CScript script_sig;
    script_sig << a << b;

    std::vector<std::vector<unsigned char>> pushes;
    std::string error;
    const bool ok = VoidCoinReadCanonicalP2QRPushes(
        script_sig, pushes, &error, VOIDCOIN_P2QR_MULTISIG_P2SH_MAX_PUSHES);

    BOOST_CHECK(ok);
    BOOST_REQUIRE_EQUAL(pushes.size(), 2u);
    BOOST_CHECK(pushes[0] == a);
    BOOST_CHECK(pushes[1] == b);
}

BOOST_AUTO_TEST_SUITE_END()
