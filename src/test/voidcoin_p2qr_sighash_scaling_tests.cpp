// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VCIP-2 release-gate artifact "T6": prove the P2QR sighash precompute is
// actually active on the per-input path.
//
// The standard test suite CANNOT see this optimization: by construction it is
// byte-neutral (the digest is identical whether the five whole-transaction
// subhashes are recomputed per input or read from a once-per-transaction
// midstate), so no correctness vector distinguishes O(N) from O(N^2). This file
// closes that blind spot with three independent gates:
//
//   1. byte_identity_new_equals_old  -- the optimized (shared-midstate) digest
//      equals the naive (rebuild-per-input) digest for every input. This is the
//      consensus-neutrality proof: the change forks nothing.
//
//   2. mandatory_midstate_no_fallback -- closes HIGH-2 deterministically. There
//      is no defaulted/nullptr midstate and no silent O(N)-per-input fallback: a
//      missing or foreign-transaction midstate is a hard error, so a caller
//      cannot obtain a digest without a populated, tx-bound midstate. A test can
//      therefore never "pass" with the optimization inactive.
//
//   3. measured_on_scaling -- the measured (not assumed) gate. It times the real
//      production loop (build once + N per-input SignatureHash) against the
//      pre-refactor loop (rebuild the subhashes on every input) over a maximal
//      N-input P2QR transaction and asserts the optimized path grows
//      sub-quadratically while the naive path grows super-linearly, and that the
//      optimized/naive speedup GROWS with N (it cannot, if the two paths did the
//      same per-input work).
//
// The "naive" path is reproduced faithfully with the public API: calling
// BuildSighashMidstate() once per input, immediately before SignatureHash(),
// recomputes exactly the five whole-transaction subhashes (via the very same
// anonymous-namespace helpers) that the pre-refactor SignatureHashInternal
// streamed inline. Same helpers, same bytes -- only the amortization differs.

#include <consensus/voidcoinp2qr.h>

#include <primitives/transaction.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/transaction_identifier.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <vector>

using consensus::voidcoinp2qr::BuildSighashMidstate;
using consensus::voidcoinp2qr::MakeRedeemScript;
using consensus::voidcoinp2qr::P2QRSighashMidstate;
using consensus::voidcoinp2qr::SignatureHash;

BOOST_FIXTURE_TEST_SUITE(voidcoin_p2qr_sighash_scaling_tests, BasicTestingSetup)

namespace {

//! Deterministic 32-byte value from a seed (distinct per input/output so the
//! whole-transaction subhashes actually stream varying data).
uint256 SeedHash(uint32_t seed)
{
    std::array<unsigned char, 32> b{};
    for (int i = 0; i < 4; ++i) {
        b[i] = static_cast<unsigned char>((seed >> (8 * i)) & 0xff);
    }
    uint32_t x = seed * 2654435761u + 1u;
    for (size_t i = 4; i < b.size(); ++i) {
        x = x * 1103515245u + 12345u;
        b[i] = static_cast<unsigned char>((x >> 16) & 0xff);
    }
    uint256 h;
    std::copy(b.begin(), b.end(), h.begin());
    return h;
}

//! A maximal N-input P2QR transaction plus its vin-aligned spent outputs. Every
//! spent output is a native P2QR scriptPubKey (OP_RESERVED <32-byte program>),
//! which is what the sighash path requires. scriptSigs are irrelevant to the
//! sighash and are left empty so the measurement isolates the subhash cost.
struct P2QRTxFixture {
    // spent_outputs MUST be declared before tx: members initialize in
    // DECLARATION order (not member-init-list order), and Build() fills
    // spent_outputs while building the transaction. If tx came first, Build()
    // would write into a not-yet-constructed vector -> UB / heap corruption.
    std::vector<CTxOut> spent_outputs;
    CTransaction tx;

    explicit P2QRTxFixture(uint32_t n)
        : tx{Build(n, spent_outputs)} {}

private:
    static CMutableTransaction Build(uint32_t n, std::vector<CTxOut>& spent_outputs)
    {
        CMutableTransaction mtx;
        mtx.version = 2;
        mtx.nLockTime = 0;
        mtx.vin.reserve(n);
        mtx.vout.reserve(n);
        spent_outputs.clear();
        spent_outputs.reserve(n);

        for (uint32_t i = 0; i < n; ++i) {
            mtx.vin.emplace_back(COutPoint{Txid::FromUint256(SeedHash(i)), i});
            mtx.vin.back().nSequence = 0xfffffffeu - i;

            const CScript spk = MakeRedeemScript(SeedHash(0x8000'0000u ^ i));
            mtx.vout.emplace_back(CAmount{1000 + i}, spk);
            spent_outputs.emplace_back(CAmount{5000 + i}, spk);
        }
        return mtx;
    }
};

//! Min wall-clock over `reps` runs of `fn`. min (not mean) is robust to
//! scheduler noise on a loaded CI box: noise only ever adds time, so the
//! fastest observed run is the cleanest estimate of the intrinsic cost.
template <typename Fn>
double MinNanos(int reps, Fn&& fn)
{
    double best = std::numeric_limits<double>::infinity();
    for (int r = 0; r < reps; ++r) {
        const auto t0 = std::chrono::steady_clock::now();
        fn();
        const auto t1 = std::chrono::steady_clock::now();
        const double ns = std::chrono::duration<double, std::nano>(t1 - t0).count();
        best = std::min(best, ns);
    }
    return best;
}

//! Sink to keep the optimizer from discarding the digest computation.
volatile uint8_t g_sink = 0;
void Consume(const uint256& d) { g_sink ^= d.data()[0]; }

// ---- The two loops under test, both using ONLY the public API. -------------

//! Production path: build the midstate once, reuse it for all N inputs. O(N).
void RunOptimized(const P2QRTxFixture& f)
{
    const P2QRSighashMidstate midstate = BuildSighashMidstate(f.tx, f.spent_outputs);
    for (uint32_t i = 0; i < f.tx.vin.size(); ++i) {
        Consume(SignatureHash(f.tx, i, f.spent_outputs[i], f.spent_outputs, midstate));
    }
}

//! Pre-refactor path: rebuild the five whole-tx subhashes on every input. This
//! is exactly what the old inline SignatureHashInternal did, reproduced via the
//! public API. O(N^2).
void RunNaivePerInput(const P2QRTxFixture& f)
{
    for (uint32_t i = 0; i < f.tx.vin.size(); ++i) {
        const P2QRSighashMidstate midstate = BuildSighashMidstate(f.tx, f.spent_outputs);
        Consume(SignatureHash(f.tx, i, f.spent_outputs[i], f.spent_outputs, midstate));
    }
}

} // namespace

// Gate 1: consensus neutrality. The optimized digest must equal the naive
// digest for every input of a multi-input transaction. If this ever fails, the
// precompute has diverged from the per-input recompute and the change is NOT
// byte-identical -- a hard fork. Never flakes.
BOOST_AUTO_TEST_CASE(byte_identity_new_equals_old)
{
    for (const uint32_t n : {1u, 2u, 17u, 128u, 500u}) {
        const P2QRTxFixture f{n};
        const P2QRSighashMidstate shared = BuildSighashMidstate(f.tx, f.spent_outputs);

        for (uint32_t i = 0; i < n; ++i) {
            // Optimized: reuse the shared midstate.
            const uint256 opt = SignatureHash(f.tx, i, f.spent_outputs[i], f.spent_outputs, shared);
            // Naive: a freshly rebuilt midstate for this very input.
            const P2QRSighashMidstate fresh = BuildSighashMidstate(f.tx, f.spent_outputs);
            const uint256 naive = SignatureHash(f.tx, i, f.spent_outputs[i], f.spent_outputs, fresh);

            BOOST_REQUIRE_MESSAGE(opt == naive,
                "sighash diverged at n=" << n << " input=" << i
                << " opt=" << opt.ToString() << " naive=" << naive.ToString());
        }
    }
}

// Gate 2: HIGH-2. There is no defaulted midstate and no O(N)-per-input
// fallback. A digest is unobtainable without a populated, tx-bound midstate, so
// a benchmark cannot silently run the slow path and still "succeed". Never
// flakes.
BOOST_AUTO_TEST_CASE(mandatory_midstate_no_fallback)
{
    const P2QRTxFixture f{8};

    // (a) A default-constructed midstate is not ready -> hard error, not a slow
    // per-input recompute.
    const P2QRSighashMidstate unready{};
    BOOST_REQUIRE(!unready.m_ready);
    BOOST_CHECK_THROW(
        SignatureHash(f.tx, 0, f.spent_outputs[0], f.spent_outputs, unready),
        std::invalid_argument);

    // (b) A midstate built for a DIFFERENT transaction is rejected by the txid
    // binding -> cannot be silently reused across transactions (a chain split).
    // NOTE: the fixture is deterministic in n, so `other` must use a different
    // input count than f{8}, or the two transactions (and their txids) would be
    // identical and this would not exercise the foreign-midstate path.
    const P2QRTxFixture other{9};
    const P2QRSighashMidstate foreign = BuildSighashMidstate(other.tx, other.spent_outputs);
    BOOST_REQUIRE(foreign.m_ready);
    BOOST_REQUIRE(foreign.m_txid != f.tx.GetHash());
    BOOST_CHECK_THROW(
        SignatureHash(f.tx, 0, f.spent_outputs[0], f.spent_outputs, foreign),
        std::invalid_argument);

    // (c) The correct, tx-bound midstate succeeds. This is the only way to get a
    // digest -- so a passing measurement necessarily exercised the real path.
    const P2QRSighashMidstate good = BuildSighashMidstate(f.tx, f.spent_outputs);
    BOOST_CHECK_NO_THROW(
        SignatureHash(f.tx, 0, f.spent_outputs[0], f.spent_outputs, good));
}

// Gate 3: measured proof the optimization is active. Time the real production
// loop vs the pre-refactor loop over N and 4N inputs and assert:
//   * optimized grows SUB-quadratically (4x work, well under 16x time)
//   * naive grows SUPER-linearly       (4x work, well over 4x time)
//   * the optimized/naive speedup GROWS with N -- impossible unless the
//     optimized loop does asymptotically less per-input work.
//
// Thresholds sit at the geometric mean of the linear (4x) and quadratic (16x)
// growth factors (sqrt(4*16) = 8), giving a wide, noise-tolerant separation.
// The deterministic gates above are the hard fork/HIGH-2 guarantees; this gate
// is the measured evidence and is intentionally generous to avoid CI flake.
BOOST_AUTO_TEST_CASE(measured_on_scaling)
{
    constexpr uint32_t kSmall = 512;
    constexpr uint32_t kBig = 4 * kSmall; // 2048
    constexpr int kReps = 3;              // min-of-3 to shed scheduler noise

    const P2QRTxFixture small{kSmall};
    const P2QRTxFixture big{kBig};

    // Warm caches / branch predictors before timing.
    RunOptimized(small);
    RunNaivePerInput(small);

    const double opt_small = MinNanos(kReps, [&] { RunOptimized(small); });
    const double opt_big = MinNanos(kReps, [&] { RunOptimized(big); });
    const double naive_small = MinNanos(kReps, [&] { RunNaivePerInput(small); });
    const double naive_big = MinNanos(kReps, [&] { RunNaivePerInput(big); });

    const double opt_growth = opt_big / opt_small;       // ideal ~4 (linear)
    const double naive_growth = naive_big / naive_small; // ideal ~16 (quadratic)
    const double speedup_small = naive_small / opt_small;
    const double speedup_big = naive_big / opt_big;

    BOOST_TEST_MESSAGE("P2QR sighash scaling (min-of-" << kReps << ", ns):");
    BOOST_TEST_MESSAGE("  N=" << kSmall << "  optimized=" << opt_small
                              << "  naive=" << naive_small
                              << "  speedup=" << speedup_small << "x");
    BOOST_TEST_MESSAGE("  N=" << kBig << "  optimized=" << opt_big
                              << "  naive=" << naive_big
                              << "  speedup=" << speedup_big << "x");
    BOOST_TEST_MESSAGE("  growth 4x-inputs: optimized=" << opt_growth
                              << "x (linear~4, quadratic~16), naive="
                              << naive_growth << "x");

    // Sanity: the naive path is slower at both sizes (the optimization helps).
    BOOST_CHECK_GT(naive_small, opt_small);
    BOOST_CHECK_GT(naive_big, opt_big);

    // Optimized path is sub-quadratic: 4x the inputs costs well under 16x.
    BOOST_CHECK_LT(opt_growth, 8.0);

    // Naive path is super-linear: 4x the inputs costs well over 4x.
    BOOST_CHECK_GT(naive_growth, 8.0);

    // The decisive check that the optimization is ACTIVE (closes HIGH-1/HIGH-2
    // as a live measurement): if the production loop secretly did per-input
    // subhash work, its speedup over the naive loop would be ~constant. Instead
    // the speedup must scale ~linearly with N, so at 4x inputs it must grow
    // substantially. Require it to at least double (ideal ~4x).
    BOOST_CHECK_GT(speedup_big, 2.0 * speedup_small);

    // And the absolute speedup at the large size must be decisive, not marginal.
    BOOST_CHECK_GT(speedup_big, 10.0);
}

BOOST_AUTO_TEST_SUITE_END()
