// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Tests for the VCIP-3 rebuild of the P2QR time-lock output type. The old VCIP-1
// vault/timelock feature was DISABLED (fundable-but-unspendable, no spend-
// authorization path). VCIP-3 rebuilds it as a correct, spendable, versioned
// output:
//   OP_QuantumQuark(0x50) 0x20 <32-byte program> 0x0a
//     <10-byte descriptor = version(1) || lock_type(1) || lock_value(uint64 LE)>
// These tests lock in the re-enabled address/script/relay paths (the ML-DSA-87
// spend authorization is covered by voidcoin_timelock_spend_tests.cpp).

#include <addresstype.h>
#include <key_io.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/voidcoin_p2qr.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <optional>
#include <string>
#include <variant>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(voidcoin_timelock_enabled_tests, BasicTestingSetup)

//! Deterministic 32-byte P2QR program placeholder.
static uint256 SampleProgram()
{
    uint256 p;
    for (size_t i = 0; i < p.size(); ++i) {
        p.begin()[i] = static_cast<unsigned char>(0x11 + i);
    }
    return p;
}

//! Build a well-formed VOIDCOIN_P2QR_TIMELOCK scriptPubKey (VCIP-3 versioned form).
static CScript MakeWellFormedTimelockScript(uint8_t lock_type, uint64_t lock_value)
{
    VoidCoinP2QRTimeLock lock;
    lock.version = VOIDCOIN_P2QR_TIMELOCK_VERSION;
    lock.lock_type = lock_type;
    lock.lock_value = lock_value;
    return VoidCoinMakeP2QRTimeLockScriptPubKey(SampleProgram(), lock);
}

// The wallet/global script builder must now BUILD the 45-byte versioned time-lock
// scriptPubKey from a destination (the VCIP-1 "return empty script" gate is gone).
BOOST_AUTO_TEST_CASE(timelock_scriptpubkey_is_built)
{
    const VoidCoinP2QRTimeLockDestination tl(
        SampleProgram(), VOIDCOIN_P2QR_TIMELOCK_VERSION,
        VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 10000);
    const CScript spk = GetScriptForDestination(tl);
    BOOST_CHECK_EQUAL(spk.size(), VOIDCOIN_P2QR_TIMELOCK_SCRIPT_SIZE);

    // It must match the canonical Stage-1 builder byte-for-byte.
    const CScript expected = MakeWellFormedTimelockScript(VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 10000);
    BOOST_CHECK(spk == expected);

    // And it must solve back to a time-lock output.
    std::vector<std::vector<unsigned char>> solutions;
    BOOST_CHECK(Solver(spk, solutions) == TxoutType::VOIDCOIN_P2QR_TIMELOCK);
}

// A supported time-lock output (version 1, known lock_type) is now RELAY-STANDARD
// so a funding transaction to it is accepted into the mempool.
BOOST_AUTO_TEST_CASE(timelock_supported_output_is_standard)
{
    for (uint8_t lock_type : {VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP}) {
        const CScript spk = MakeWellFormedTimelockScript(lock_type, 1893456000);

        std::vector<std::vector<unsigned char>> solutions;
        BOOST_REQUIRE(Solver(spk, solutions) == TxoutType::VOIDCOIN_P2QR_TIMELOCK);

        TxoutType which;
        BOOST_CHECK_MESSAGE(IsStandard(spk, std::nullopt, which),
            "supported time-lock output should be relay-standard");
        BOOST_CHECK(which == TxoutType::VOIDCOIN_P2QR_TIMELOCK);
    }
}

// An unsupported descriptor (bad version, or a reserved/unknown lock_type) stays
// NON-standard: no wallet path may hand out a fundable-but-unspendable address.
BOOST_AUTO_TEST_CASE(timelock_unsupported_output_is_nonstandard)
{
    // Reserved relative-height lock_type 0x02: parses structurally but is not a
    // currently-spendable combination.
    {
        VoidCoinP2QRTimeLock lock;
        lock.version = VOIDCOIN_P2QR_TIMELOCK_VERSION;
        lock.lock_type = VOIDCOIN_P2QR_TIMELOCK_TYPE_RESERVED_REL_HEIGHT;
        lock.lock_value = 100;
        const CScript spk = VoidCoinMakeP2QRTimeLockScriptPubKey(SampleProgram(), lock);

        TxoutType which;
        BOOST_CHECK(!IsStandard(spk, std::nullopt, which));
        BOOST_CHECK(which == TxoutType::VOIDCOIN_P2QR_TIMELOCK);
    }

    // Unknown version 0x02.
    {
        VoidCoinP2QRTimeLock lock;
        lock.version = 0x02;
        lock.lock_type = VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT;
        lock.lock_value = 100;
        const CScript spk = VoidCoinMakeP2QRTimeLockScriptPubKey(SampleProgram(), lock);

        TxoutType which;
        BOOST_CHECK(!IsStandard(spk, std::nullopt, which));
    }
}

// A vqt (time-lock) address must round-trip: EncodeDestination -> DecodeDestination
// returns the same program + descriptor, and the destination is valid/fundable.
BOOST_AUTO_TEST_CASE(timelock_address_roundtrips)
{
    const VoidCoinP2QRTimeLockDestination tl(
        SampleProgram(), VOIDCOIN_P2QR_TIMELOCK_VERSION,
        VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, 1893456000ULL);
    const std::string addr = EncodeDestination(tl);
    BOOST_REQUIRE(!addr.empty());

    std::string error;
    const CTxDestination decoded = DecodeDestination(addr, error);
    BOOST_CHECK_MESSAGE(IsValidDestination(decoded), "vqt address must decode to a valid destination: " + error);
    BOOST_REQUIRE(std::holds_alternative<VoidCoinP2QRTimeLockDestination>(decoded));

    const auto& got = std::get<VoidCoinP2QRTimeLockDestination>(decoded);
    BOOST_CHECK(got.program == tl.program);
    BOOST_CHECK_EQUAL((int)got.version, (int)tl.version);
    BOOST_CHECK_EQUAL((int)got.lock_type, (int)tl.lock_type);
    BOOST_CHECK_EQUAL(got.lock_value, tl.lock_value);

    // ExtractDestination on the built scriptPubKey yields the same destination.
    const CScript spk = GetScriptForDestination(tl);
    CTxDestination extracted;
    BOOST_CHECK(ExtractDestination(spk, extracted));
    BOOST_CHECK(extracted == CTxDestination{tl});
}

BOOST_AUTO_TEST_SUITE_END()
