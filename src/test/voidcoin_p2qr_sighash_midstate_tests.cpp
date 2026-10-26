// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// Regression guard for the P2QR sighash O(N)->O(N^2) DoS.
//
// The whole-transaction sighash subhashes (preimage fields 6..10) are
// precomputed ONCE per transaction into a P2QRSighashMidstate and reused for
// every input. That precompute is BYTE-IDENTICAL to the naive per-input
// recompute (VCIP-2 / BIP-143 precedent), so it is invisible to any digest
// comparison, any "tip hash matches" reindex, and the standard test suite. A
// future refactor could therefore silently reintroduce the quadratic per-input
// recompute -- or re-add a nullptr/defaulted "fallback" midstate -- and every
// existing test would still be green.
//
// This file is the tripwire that such a regression must trip. It proves the
// midstate is a MANDATORY, tx-bound input to the consensus path, and that a
// missing or foreign midstate FAILS LOUDLY -- compile error, thrown exception,
// or hard consensus reject -- and never silently degrades to O(N^2).
//
// The two HIGH findings this locks down:
//   HIGH-1: the O(N) precompute must be on the consensus path.
//   HIGH-2: there must be NO defaulted/optional midstate with a per-input
//           recompute fallback, or tests could pass with the optimization off.

#include <consensus/voidcoinp2qr.h>

#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace vp = consensus::voidcoinp2qr;

namespace {

// A midstate that is bound to `tx` and populated -- the only kind the consensus
// path will accept. Used as the positive control against every negative case.
vp::P2QRSighashMidstate BuiltFor(const CTransaction& tx,
                                 const std::vector<CTxOut>& spent_outputs)
{
    return vp::BuildSighashMidstate(tx, spent_outputs);
}

// Minimal single-input transaction plus a vin-aligned spent-outputs vector.
// The scriptPubKey type of the spent output is caller-controlled so each test
// can steer which post-midstate check it lands on.
struct OneInputFixture {
    CMutableTransaction mtx;
    std::vector<CTxOut> spent_outputs;

    explicit OneInputFixture(const CScript& spent_script, uint32_t locktime = 0)
    {
        mtx.version = 2;
        mtx.nLockTime = locktime;
        CTxIn in;
        in.prevout = COutPoint(Txid::FromUint256(uint256::ONE), 0);
        in.nSequence = CTxIn::SEQUENCE_FINAL;
        mtx.vin.push_back(in);

        CTxOut out;
        out.nValue = 1000;
        out.scriptPubKey = spent_script;
        mtx.vout.push_back(out);

        spent_outputs.push_back(out);
    }

    CTransaction tx() const { return CTransaction(mtx); }
    const CTxOut& spent() const { return spent_outputs[0]; }
};

// The exact hard-reject strings the consensus entry points emit when the
// midstate is absent or not bound to the transaction under validation.
const std::string kCheckSpendMidstateError =
    "VOIDCOIN_P2QR sighash midstate is missing or not bound to this transaction";
const std::string kP2SHMidstateError =
    "VOIDCOIN_P2QR P2SH sighash midstate is missing or not bound to this transaction";

// Generic-lambda call wrappers so the "is this callable?" guards below use
// std::is_invocable_v (proper SFINAE via the trailing decltype) instead of a
// bare requires-expression. A requires-expression on an ill-formed call to a
// non-template function can hard-error on GCC rather than yield false, which
// would break this very tripwire; is_invocable_v is robust across compilers.
inline constexpr auto kCallCheckSpend = [](auto&&... a)
    -> decltype(vp::CheckSpend(std::forward<decltype(a)>(a)...)) {
    return vp::CheckSpend(std::forward<decltype(a)>(a)...);
};
inline constexpr auto kCallCheckSpendP2SHWrapped = [](auto&&... a)
    -> decltype(vp::CheckSpendP2SHWrapped(std::forward<decltype(a)>(a)...)) {
    return vp::CheckSpendP2SHWrapped(std::forward<decltype(a)>(a)...);
};
inline constexpr auto kCallSignatureHash = [](auto&&... a)
    -> decltype(vp::SignatureHash(std::forward<decltype(a)>(a)...)) {
    return vp::SignatureHash(std::forward<decltype(a)>(a)...);
};
inline constexpr auto kCallSignatureHashP2SHWrapped = [](auto&&... a)
    -> decltype(vp::SignatureHashP2SHWrapped(std::forward<decltype(a)>(a)...)) {
    return vp::SignatureHashP2SHWrapped(std::forward<decltype(a)>(a)...);
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_sighash_midstate_tests, BasicTestingSetup)

// ---------------------------------------------------------------------------
// HIGH-2, compile-time: the midstate parameter is NON-DEFAULTED. There is no
// overload of any consensus/signing entry point that omits it. If someone
// reintroduces a defaulted/optional midstate (the fallback that silently
// recomputes per input), these calls become well-formed and the build fails
// here. This is the "compile error" arm of "fail loudly", checked at compile
// time so it cannot be skipped at runtime.
// ---------------------------------------------------------------------------

// Callable WITHOUT a midstate (5/4 args) -> must be ill-formed.
static_assert(!std::is_invocable_v<decltype(kCallCheckSpend),
                  const CTransaction&, uint32_t, const CTxOut&,
                  const std::vector<CTxOut>&, std::string&>,
    "REGRESSION: CheckSpend is callable without a midstate -- the mandatory "
    "precompute has a fallback/default again (HIGH-2). O(N^2) DoS can return.");

static_assert(!std::is_invocable_v<decltype(kCallCheckSpendP2SHWrapped),
                  const CTransaction&, uint32_t, const CTxOut&,
                  const std::vector<CTxOut>&, std::string&>,
    "REGRESSION: CheckSpendP2SHWrapped is callable without a midstate (HIGH-2).");

static_assert(!std::is_invocable_v<decltype(kCallSignatureHash),
                  const CTransaction&, uint32_t, const CTxOut&,
                  const std::vector<CTxOut>&>,
    "REGRESSION: SignatureHash is callable without a midstate (HIGH-2).");

static_assert(!std::is_invocable_v<decltype(kCallSignatureHashP2SHWrapped),
                  const CTransaction&, uint32_t, const CTxOut&,
                  const std::vector<CTxOut>&>,
    "REGRESSION: SignatureHashP2SHWrapped is callable without a midstate (HIGH-2).");

// Positive control: WITH a midstate the same calls ARE well-formed. Without
// this, the negative static_asserts above could pass for an unrelated reason
// (renamed function, changed arg type) while giving false confidence.
static_assert(requires(const CTransaction& t, uint32_t i, const CTxOut& o,
                       const std::vector<CTxOut>& os,
                       const vp::P2QRSighashMidstate& m, std::string& e) {
    vp::CheckSpend(t, i, o, os, m, e);
}, "P2QR CheckSpend must be callable WITH a midstate (detector sanity).");

static_assert(requires(const CTransaction& t, uint32_t i, const CTxOut& o,
                       const std::vector<CTxOut>& os,
                       const vp::P2QRSighashMidstate& m) {
    vp::SignatureHash(t, i, o, os, m);
}, "P2QR SignatureHash must be callable WITH a midstate (detector sanity).");

// The struct's readiness flag must default to false, so a freshly declared
// (unbuilt) midstate is rejected rather than silently trusted.
BOOST_AUTO_TEST_CASE(default_midstate_is_not_ready)
{
    vp::P2QRSighashMidstate midstate;
    BOOST_CHECK(!midstate.m_ready);
}

// ---------------------------------------------------------------------------
// HIGH-1 / HIGH-2, runtime consensus path: CheckSpend hard-rejects an unbuilt
// midstate, and the SAME transaction with a properly bound midstate gets PAST
// the midstate gate (failing later, for a different reason). The differential
// is the whole point: if a fallback were reintroduced, the unbuilt case would
// stop producing the midstate error and fall through to the later check, and
// this test would fail -- which is exactly the alarm we want.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(checkspend_rejects_unbuilt_midstate)
{
    // Non-P2QR spent script: with a valid midstate the call proceeds past the
    // midstate gate and fails at the later "non-P2QR output" check.
    OneInputFixture f{CScript()};
    const CTransaction tx = f.tx();

    // Unbuilt (default) midstate -> loud hard reject at the midstate gate.
    {
        vp::P2QRSighashMidstate unbuilt; // m_ready == false
        std::string error;
        const bool ok = vp::CheckSpend(tx, 0, f.spent(), f.spent_outputs, unbuilt, error);
        BOOST_CHECK(!ok);
        BOOST_CHECK_EQUAL(error, kCheckSpendMidstateError);
    }

    // Bound midstate -> passes the midstate gate; different (later) rejection.
    // Proves the rejection above is specifically the midstate guard, not an
    // incidental property of the transaction.
    {
        const vp::P2QRSighashMidstate bound = BuiltFor(tx, f.spent_outputs);
        std::string error;
        const bool ok = vp::CheckSpend(tx, 0, f.spent(), f.spent_outputs, bound, error);
        BOOST_CHECK(!ok);
        BOOST_CHECK(error != kCheckSpendMidstateError);
        BOOST_CHECK(!error.empty());
    }
}

// A midstate built for a DIFFERENT transaction (m_ready == true, wrong m_txid)
// must be rejected. Silently accepting it would sign/validate against another
// transaction's whole-tx subhashes -- a chain split, not a slow path.
BOOST_AUTO_TEST_CASE(checkspend_rejects_foreign_midstate)
{
    OneInputFixture target{CScript()};
    OneInputFixture other{CScript(), /*locktime=*/0x11223344}; // distinct txid

    const CTransaction tx = target.tx();
    const CTransaction tx_other = other.tx();
    BOOST_REQUIRE(tx.GetHash() != tx_other.GetHash());

    const vp::P2QRSighashMidstate foreign =
        BuiltFor(tx_other, other.spent_outputs); // ready, but bound to tx_other
    BOOST_REQUIRE(foreign.m_ready);

    std::string error;
    const bool ok = vp::CheckSpend(tx, 0, target.spent(), target.spent_outputs, foreign, error);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(error, kCheckSpendMidstateError);
}

// Same guarantees on the P2SH-wrapped consensus entry point.
BOOST_AUTO_TEST_CASE(checkspend_p2sh_rejects_unbuilt_and_foreign_midstate)
{
    OneInputFixture f{CScript()};
    const CTransaction tx = f.tx();

    // Unbuilt.
    {
        vp::P2QRSighashMidstate unbuilt;
        std::string error;
        const bool ok = vp::CheckSpendP2SHWrapped(tx, 0, f.spent(), f.spent_outputs, unbuilt, error);
        BOOST_CHECK(!ok);
        BOOST_CHECK_EQUAL(error, kP2SHMidstateError);
    }

    // Foreign (built for another tx).
    {
        OneInputFixture other{CScript(), 0x55667788};
        const CTransaction tx_other = other.tx();
        BOOST_REQUIRE(tx.GetHash() != tx_other.GetHash());
        const vp::P2QRSighashMidstate foreign = BuiltFor(tx_other, other.spent_outputs);
        std::string error;
        const bool ok = vp::CheckSpendP2SHWrapped(tx, 0, f.spent(), f.spent_outputs, foreign, error);
        BOOST_CHECK(!ok);
        BOOST_CHECK_EQUAL(error, kP2SHMidstateError);
    }
}

// ---------------------------------------------------------------------------
// The public SignatureHash wrappers are header-exposed and enforce their
// preconditions with hard throws (not NDEBUG-erased asserts), so misuse fails
// loudly even in release builds. Reaching the midstate check requires a
// well-typed spent output (native P2QR here), isolating the midstate throw.
// ---------------------------------------------------------------------------
BOOST_AUTO_TEST_CASE(signaturehash_throws_on_unbuilt_or_foreign_midstate)
{
    uint256 program;
    program.SetNull();
    const CScript p2qr_spk = vp::MakeRedeemScript(program); // native P2QR output

    OneInputFixture f{p2qr_spk};
    const CTransaction tx = f.tx();

    // Unbuilt midstate -> throw.
    {
        vp::P2QRSighashMidstate unbuilt;
        BOOST_CHECK_THROW(
            vp::SignatureHash(tx, 0, f.spent(), f.spent_outputs, unbuilt),
            std::invalid_argument);
    }

    // Foreign midstate -> throw.
    {
        OneInputFixture other{p2qr_spk, 0x0abcdef0};
        const CTransaction tx_other = other.tx();
        BOOST_REQUIRE(tx.GetHash() != tx_other.GetHash());
        const vp::P2QRSighashMidstate foreign = BuiltFor(tx_other, other.spent_outputs);
        BOOST_CHECK_THROW(
            vp::SignatureHash(tx, 0, f.spent(), f.spent_outputs, foreign),
            std::invalid_argument);
    }

    // Positive control: a correctly bound midstate does NOT throw.
    {
        const vp::P2QRSighashMidstate bound = BuiltFor(tx, f.spent_outputs);
        BOOST_CHECK_NO_THROW(
            (void)vp::SignatureHash(tx, 0, f.spent(), f.spent_outputs, bound));
    }
}

BOOST_AUTO_TEST_CASE(signaturehash_p2sh_throws_on_unbuilt_or_foreign_midstate)
{
    uint256 program;
    program.SetNull();
    const CScript p2sh_spk = vp::MakeP2SHScriptPubKey(program); // P2SH carrier

    OneInputFixture f{p2sh_spk};
    const CTransaction tx = f.tx();

    // Unbuilt.
    {
        vp::P2QRSighashMidstate unbuilt;
        BOOST_CHECK_THROW(
            vp::SignatureHashP2SHWrapped(tx, 0, f.spent(), f.spent_outputs, unbuilt),
            std::invalid_argument);
    }

    // Foreign.
    {
        OneInputFixture other{p2sh_spk, 0x13572468};
        const CTransaction tx_other = other.tx();
        BOOST_REQUIRE(tx.GetHash() != tx_other.GetHash());
        const vp::P2QRSighashMidstate foreign = BuiltFor(tx_other, other.spent_outputs);
        BOOST_CHECK_THROW(
            vp::SignatureHashP2SHWrapped(tx, 0, f.spent(), f.spent_outputs, foreign),
            std::invalid_argument);
    }

    // Positive control.
    {
        const vp::P2QRSighashMidstate bound = BuiltFor(tx, f.spent_outputs);
        BOOST_CHECK_NO_THROW(
            (void)vp::SignatureHashP2SHWrapped(tx, 0, f.spent(), f.spent_outputs, bound));
    }
}

// The builder itself must reject a spent-outputs vector that is not vin-aligned
// with a hard throw. A mis-sized vector would otherwise produce a midstate that
// hashes the wrong set of spent amounts/scripts -- a silently wrong digest.
BOOST_AUTO_TEST_CASE(build_midstate_rejects_misaligned_spent_outputs)
{
    OneInputFixture f{CScript()};
    const CTransaction tx = f.tx();

    std::vector<CTxOut> too_many = f.spent_outputs;
    too_many.push_back(f.spent()); // size 2 vs 1 input

    BOOST_CHECK_THROW(vp::BuildSighashMidstate(tx, too_many), std::invalid_argument);
    BOOST_CHECK_THROW(vp::BuildSighashMidstate(tx, std::vector<CTxOut>{}), std::invalid_argument);

    // Correctly aligned -> builds a ready, tx-bound midstate.
    const vp::P2QRSighashMidstate ok = vp::BuildSighashMidstate(tx, f.spent_outputs);
    BOOST_CHECK(ok.m_ready);
    BOOST_CHECK(ok.m_txid == tx.GetHash());
}

BOOST_AUTO_TEST_SUITE_END()
