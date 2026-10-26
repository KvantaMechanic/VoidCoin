// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// VCIP-3 (VC-13): tests for the 231,000,000 VOID hard supply cap.
//
// These exercise the single source of truth ApplyVoidSupplyCap() /
// GetBlockSubsidyWithBounty() and the CBlockIndex::nChainSupply issuance
// accumulator recurrence used by node/blockstorage.cpp, node/miner.cpp and
// validation.cpp::ConnectBlock. The scenarios build an in-memory regtest-style
// chain with a *tiny* synthetic cap and mine PAST it, asserting:
//   * pre-activation emission is byte-identical to the legacy schedule (the cap
//     is ignored, even when cumulative issuance already exceeds it);
//   * at/after activation cumulative issuance clamps EXACTLY at the cap and the
//     tail/bounty are neutralized (subsidy 0) once the cap is reached;
//   * a coinbase paying more than the clamped subsidy would be rejected
//     (bad-cb-amount), i.e. the clamped value is strictly below the uncapped
//     schedule at the binding block; and
//   * the miner path and the validator path derive the identical subsidy.

#include <chain.h>
#include <consensus/amount.h>
#include <consensus/params.h>
#include <uint256.h>
#include <validation.h>

#include <test/util/setup_common.h>

#include <array>
#include <cstdint>
#include <deque>
#include <limits>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(voidcoin_supply_cap_tests, BasicTestingSetup)

namespace {

// First-3-bytes-of-parent-hash bounty predicate (VOID_BOUNTY_THRESHOLD = 33554).
constexpr std::array<uint8_t, 3> HASH_NO_BOUNTY{0xFF, 0xFF, 0xFF}; // >> threshold
constexpr std::array<uint8_t, 3> HASH_BOUNTY{0x00, 0x00, 0x00};    // < threshold

uint256 HashWithPrefix(const std::array<uint8_t, 3>& prefix)
{
    std::array<unsigned char, 32> bytes;
    bytes.fill(0xAB);
    bytes[0] = prefix[0];
    bytes[1] = prefix[1];
    bytes[2] = prefix[2];
    return uint256(Span<const unsigned char>(bytes.data(), bytes.size()));
}

// A minimal in-memory chain that maintains CBlockIndex::nChainSupply with the
// EXACT recurrence used in node/blockstorage.cpp, so we test the real clamp.
struct SimChain {
    const Consensus::Params& params;
    std::deque<uint256> hashes;      // stable storage for phashBlock
    std::deque<CBlockIndex> indices; // stable storage for pprev pointers
    std::vector<CAmount> subsidy;    // subsidy minted at each height (index == height)

    explicit SimChain(const Consensus::Params& p) : params{p}
    {
        // Genesis (height 0): mints nothing, nChainSupply == 0 (blockstorage sets
        // the pprev==nullptr case to 0 without consulting GetBlockSubsidyWithBounty).
        hashes.push_back(HashWithPrefix(HASH_NO_BOUNTY));
        indices.emplace_back();
        CBlockIndex& g = indices.back();
        g.nHeight = 0;
        g.pprev = nullptr;
        g.phashBlock = &hashes.back();
        g.nChainSupply = 0;
        subsidy.push_back(0);
    }

    // Append one block at the next height. `own_prefix` sets THIS block's hash,
    // which governs whether the *next* block is a Void Collapse Bounty block.
    CAmount Mine(const std::array<uint8_t, 3>& own_prefix)
    {
        CBlockIndex& prev = indices.back();
        hashes.push_back(HashWithPrefix(own_prefix));
        indices.emplace_back();
        CBlockIndex& idx = indices.back();
        idx.nHeight = prev.nHeight + 1;
        idx.pprev = &prev;
        idx.phashBlock = &hashes.back();

        // Validator/consensus limit == miner limit == accumulator increment.
        const CAmount s = GetBlockSubsidyWithBounty(&idx, params);
        idx.nChainSupply = prev.nChainSupply + s; // blockstorage.cpp recurrence
        subsidy.push_back(s);
        return s;
    }

    const CBlockIndex& Tip() const { return indices.back(); }
    CAmount Supply() const { return indices.back().nChainSupply; }
};

// Base value-initialized params; only the fields the subsidy math reads are set.
Consensus::Params MakeParams(int halving_interval, bool min_difficulty,
                             int vcip3_height, CAmount cap)
{
    Consensus::Params p{};
    p.nSubsidyHalvingInterval = halving_interval;
    p.fPowAllowMinDifficultyBlocks = min_difficulty;
    p.nVCIP3ActivationHeight = vcip3_height;
    p.nVoidSupplyCap = cap;
    return p;
}

} // namespace

// ApplyVoidSupplyCap is the whole rule in one place: prove the boundary algebra.
BOOST_AUTO_TEST_CASE(apply_void_supply_cap_algebra)
{
    Consensus::Params p = MakeParams(/*halving*/1'000'000, /*mindiff*/true,
                                     /*vcip3*/100, /*cap*/1000 * COIN);

    // Pre-activation: identity, regardless of how far over the cap we already are.
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(50 * COIN, 999 * COIN, /*h*/99, p), 50 * COIN);
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(200 * COIN, 5000 * COIN, /*h*/0, p), 200 * COIN);

    // At/after activation: min(scheduled, headroom), headroom floored at 0.
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(50 * COIN, 900 * COIN, 100, p), 50 * COIN);  // headroom 100
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(50 * COIN, 970 * COIN, 100, p), 30 * COIN);  // headroom 30 binds
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(50 * COIN, 1000 * COIN, 100, p), 0);         // exactly full
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(200 * COIN, 1000 * COIN, 100, p), 0);        // bounty, no headroom
    BOOST_CHECK_EQUAL(ApplyVoidSupplyCap(50 * COIN, 1234 * COIN, 100, p), 0);         // already over -> 0
}

// Mine past a tiny cap that is crossed AFTER activation: cumulative issuance must
// land EXACTLY on the cap and stay there; the crossing block is clamped below the
// uncapped schedule (so overpaying it is bad-cb-amount).
BOOST_AUTO_TEST_CASE(cumulative_issuance_clamps_exactly_at_cap)
{
    const CAmount cap = 325 * COIN;
    // Active from height 1, base subsidy 50 (no halvings in range), no bounty.
    Consensus::Params p = MakeParams(1'000'000, /*mindiff*/true, /*vcip3*/1, cap);
    SimChain chain(p);

    // Full schedule: 50,50,50,50,50,50 -> cum 50,100,150,200,250,300 (all <= cap).
    for (int h = 1; h <= 6; ++h) {
        BOOST_CHECK_EQUAL(chain.Mine(HASH_NO_BOUNTY), 50 * COIN);
    }
    BOOST_CHECK_EQUAL(chain.Supply(), 300 * COIN);

    // Crossing block (height 7): scheduled 50 but only 25 of headroom remains.
    const CAmount uncapped = GetBlockSubsidy(7, p); // 50 * COIN
    const CAmount at_cross = chain.Mine(HASH_NO_BOUNTY);
    BOOST_CHECK_EQUAL(at_cross, 25 * COIN);
    BOOST_CHECK_LT(at_cross, uncapped);      // clamped below schedule ...
    BOOST_CHECK_EQUAL(chain.Supply(), cap);  // ... landing EXACTLY on the cap.

    // A coinbase paying the uncapped schedule here (fees==0) would be rejected:
    // ConnectBlock's limit is nFees + at_cross, and uncapped > at_cross.
    BOOST_CHECK_GT(uncapped, at_cross);

    // Every subsequent block mints 0 (tail/emission neutralized), supply frozen.
    for (int h = 8; h <= 15; ++h) {
        BOOST_CHECK_EQUAL(chain.Mine(HASH_NO_BOUNTY), 0);
        BOOST_CHECK_EQUAL(chain.Supply(), cap);
    }

    // Invariant: cumulative issuance is monotonic and never exceeds the cap.
    CAmount running = 0;
    for (size_t h = 0; h < chain.subsidy.size(); ++h) {
        running += chain.subsidy[h];
        BOOST_CHECK_LE(running, cap);
        BOOST_CHECK_EQUAL(running, chain.indices[h].nChainSupply);
    }
}

// The activation gate: BEFORE the fork height, emission is byte-identical to the
// legacy schedule EVEN WHEN cumulative issuance already exceeds the tiny cap.
// AFTER the fork height, emission halts (it cannot claw back the pre-fork
// overshoot, but it mints nothing more).
BOOST_AUTO_TEST_CASE(pre_activation_emission_unchanged)
{
    const CAmount cap = 125 * COIN; // deliberately smaller than pre-activation supply
    Consensus::Params p = MakeParams(1'000'000, /*mindiff*/true, /*vcip3*/5, cap);
    SimChain chain(p);

    // Reference schedule with the cap feature entirely OFF (never activates).
    Consensus::Params p_off = MakeParams(1'000'000, true,
                                         std::numeric_limits<int>::max(), cap);

    // Heights 1..4 are pre-activation: full 50/block, cap ignored, even though
    // cumulative (150, 200) blows past cap==125.
    for (int h = 1; h <= 4; ++h) {
        const CAmount minted = chain.Mine(HASH_NO_BOUNTY);
        BOOST_CHECK_EQUAL(minted, 50 * COIN);
        BOOST_CHECK_EQUAL(minted, GetBlockSubsidy(h, p_off)); // byte-identical to no-fork
    }
    BOOST_CHECK_EQUAL(chain.Supply(), 200 * COIN); // > cap, but pre-fork so allowed

    // Height 5 onward is post-activation: already over the cap -> mint nothing.
    for (int h = 5; h <= 9; ++h) {
        BOOST_CHECK_EQUAL(chain.Mine(HASH_NO_BOUNTY), 0);
    }
    BOOST_CHECK_EQUAL(chain.Supply(), 200 * COIN); // frozen, not reduced
}

// The Void Collapse Bounty is kept as a feature but is equally subject to the cap.
BOOST_AUTO_TEST_CASE(void_collapse_bounty_is_capped)
{
    const CAmount cap = 600 * COIN;
    // min-difficulty => bounty eligible from height 10; VCIP-3 active from height 1.
    Consensus::Params p = MakeParams(1'000'000, /*mindiff*/true, /*vcip3*/1, cap);
    SimChain chain(p);

    // Heights 1..9: base 50 each (no bounty), cum 450 at height 9. Set height 10's
    // hash to the bounty prefix so height 11 qualifies as a bounty block.
    for (int h = 1; h <= 9; ++h) {
        BOOST_CHECK_EQUAL(chain.Mine(HASH_NO_BOUNTY), 50 * COIN);
    }
    BOOST_CHECK_EQUAL(chain.Mine(HASH_BOUNTY), 50 * COIN); // height 10, itself non-bounty
    BOOST_CHECK_EQUAL(chain.Supply(), 500 * COIN);

    // Height 11 qualifies for the 200 VOID bounty, but only 100 of headroom is
    // left (600 - 500). The bounty is clamped to 100, NOT paid in full.
    const CAmount minted = chain.Mine(HASH_NO_BOUNTY);
    BOOST_CHECK_EQUAL(minted, 100 * COIN);
    BOOST_CHECK_LT(minted, 200 * COIN);       // bounty clamped
    BOOST_CHECK_EQUAL(chain.Supply(), cap);   // exact cap

    // Height 12 is also bounty-eligible height-wise but headroom is 0 -> mints 0.
    BOOST_CHECK_EQUAL(chain.Mine(HASH_NO_BOUNTY), 0);
    BOOST_CHECK_EQUAL(chain.Supply(), cap);
}

// Miner path (transient index built from height+parent, as node/miner.cpp does)
// derives the identical subsidy to the validator path (the real chain index),
// at every height including across the cap boundary.
BOOST_AUTO_TEST_CASE(miner_and_validator_paths_agree)
{
    const CAmount cap = 325 * COIN;
    Consensus::Params p = MakeParams(1'000'000, /*mindiff*/true, /*vcip3*/1, cap);
    SimChain chain(p);

    for (int h = 1; h <= 12; ++h) {
        const CBlockIndex& prev = chain.Tip();

        // Miner-style: transient index for the block being assembled.
        CBlockIndex miner_index;
        miner_index.nHeight = prev.nHeight + 1;
        miner_index.pprev = const_cast<CBlockIndex*>(&prev);
        const CAmount miner_subsidy = GetBlockSubsidyWithBounty(&miner_index, p);

        // Validator-style: the value the chain actually accumulates.
        const CAmount validator_subsidy = chain.Mine(HASH_NO_BOUNTY);

        BOOST_CHECK_EQUAL(miner_subsidy, validator_subsidy);
    }
    BOOST_CHECK_EQUAL(chain.Supply(), cap);
}

BOOST_AUTO_TEST_SUITE_END()
