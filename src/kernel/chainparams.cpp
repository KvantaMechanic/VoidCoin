#include <cstdio>
// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <kernel/chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/params.h>
#include <hash.h>
#include <kernel/messagestartchars.h>
#include <logging.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <limits>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <type_traits>

using namespace util::hex_literals;

// Workaround MSVC bug triggering C7595 when calling consteval constructors in
// initializer lists.
// A fix may be on the way:
// https://developercommunity.visualstudio.com/t/consteval-conversion-function-fails/1579014
#if defined(_MSC_VER)
auto consteval_ctor(auto&& input) { return input; }
#else
#define consteval_ctor(input) (input)
#endif

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "VoidCoin Genesis - June 29 2026 - The Void Begins";

    const CScript genesisOutputScript = CScript()
        << OP_RESERVED
        << ParseHex("78630624d93a988e3f6e87924045f6bce335b8e9fe61fab0494f0d57c5e54191");

    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network on which people trade goods and services.
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        m_chain_type = ChainType::MAIN;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();

        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.script_flag_exceptions.clear();

        consensus.BIP34Height = 100;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 150;
        consensus.BIP66Height = 200;
        consensus.CSVHeight = 250;
        consensus.SegwitHeight = std::numeric_limits<int>::max();
        consensus.MinBIP9WarningHeight = 2500;

        consensus.nP2QRActivationHeight = 1;
        consensus.nP2QRTimelockActivationHeight = 10000;
        // VCIP-3 hard fork (231M supply cap + VC-14 ML-DSA-87 verification budget
        // + PA-06 raised multisig push caps). ANNOUNCED, COORDINATED FLAG DAY:
        // block 32000. Before this height every consensus rule is byte-identical to
        // today, so the already-mined chain validates unchanged; AT block 32000 the
        // new rules engage simultaneously on all upgraded nodes. EVERY node and
        // miner MUST run this (or a later) build before block 32000 or they split
        // off permanently at that height. (Set to 32000 on 2026-07-22, tip ~28731,
        // ~3269 blocks / ~2.3 days ahead at set time.)
        consensus.nVCIP3ActivationHeight = 32000;

        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60;
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;

        consensus.nRuleChangeActivationThreshold = 1916;
        consensus.nMinerConfirmationWindow = 2016;

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0;

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = std::numeric_limits<int>::max();

        // VC-12 / PA-02: nonzero anti-DoS work threshold + recent assumevalid
        // (node-policy IBD hardening only; NOT consensus). Every value below is
        // programmatically re-derivable from a single anchor height (currently
        // block 20000, comfortably below the tip) on a fully-synced node:
        //
        //   ANCHOR=20000
        //   H=$(voidcoin-cli getblockhash $ANCHOR)
        //   voidcoin-cli getblockheader $H | jq '.hash, .chainwork, .time'
        //   voidcoin-cli getchaintxstats $((ANCHOR-1)) $H | jq '.txcount, .txrate'
        //
        //     .hash      -> defaultAssumeValid AND checkpointData[ANCHOR]
        //     .chainwork -> nMinimumChainWork
        //     .time      -> chainTxData.nTime
        //     .txcount   -> chainTxData.tx_count
        //     .txrate    -> chainTxData.dTxRate
        //
        // INVARIANT (verified at the synced tip, not at construction): the anchor
        // height MUST be <= the honest chain tip, so nMinimumChainWork (the anchor
        // block's cumulative work) MUST be <= chainwork@tip. If nMinimumChainWork
        // ever exceeds chainwork@tip the node can never leave IBD. At the capture
        // tip (height 22349) chainwork@tip = ...f2f9877a11289e4e2c, and
        // nMinimumChainWork = ...edf98a8d14e3b7e431 < chainwork@tip. Re-verify this
        // relation whenever the anchor is advanced. The construction-time asserts
        // at the end of this constructor enforce the statically-checkable subset
        // (anchor hash == top checkpoint == assumevalid; chainTxData.nTime >=
        // genesis time).
        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000edf98a8d14e3b7e431"};
        consensus.defaultAssumeValid = uint256{"000000000000004b5060bbdf8d373179046a19fd2b5db912ac0827989e9df1de"}; // block 20000

        pchMessageStart[0] = 0xD3;
        pchMessageStart[1] = 0xAD;
        pchMessageStart[2] = 0xC0;
        pchMessageStart[3] = 0xDE;

        nDefaultPort = 7777;
        nPruneAfterHeight = 200000;
        m_assumed_blockchain_size = 10;
        m_assumed_chain_state_size = 10;

        genesis = CreateGenesisBlock(1782730000U, 1896980011U, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256{"00000000238e081320ba119856513b2c9dfb82ee6a917f178cfbb7ac0e4adeaa"});
        assert(genesis.hashMerkleRoot == uint256{"6a6a27112d0b4ba692f3f64452a4343b619fc99014a335104ac3eedbf6153bfb"});

        vSeeds.clear();
        vSeeds.emplace_back("seed1.voidcoin.crypto-eire.com.");
        vSeeds.emplace_back("seed.void-coin.net.");

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,70);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1,190);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "void";
        bech32_qr_hrp = "vqr";
        bech32_qrt_hrp = "vqt";

        vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_main), std::end(chainparams_seed_main));

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        // VC-12: eclipse/IBD hardening. Node-policy checkpoints only (block-hash
        // gate on the honest chain); NOT consensus rules. Hashes captured from a
        // fully-synced node at tip height 21092.
        checkpointData = {
            {
                {10000, uint256{"0000000000000089b22b204ba6881125b8e6f75528b021b36386c0ceb9c2ca80"}},
                {15000, uint256{"0000000000000069f686b3c5d1408489c3e4473181210240c2c1c2841c1606f4"}},
                {20000, uint256{"000000000000004b5060bbdf8d373179046a19fd2b5db912ac0827989e9df1de"}},
            }
        };

        m_assumeutxo_data = {};

       // PA-10: anchored at block 20000 (same block as defaultAssumeValid and the
       // top checkpoint). The prior values were inconsistent — .nTime (1781969661)
       // predated the genesis block time (1782730000), which is impossible and
       // corrupts GuessVerificationProgress during sync. These are the actual
       // block-20000 statistics (getblockheader.time / getchaintxstats.txcount /
       // .txrate); see the derivation recipe above.
       chainTxData = ChainTxData{
           .nTime    = 1784191776,
           .tx_count = 20212,
           .dTxRate  = 0.01418786246267876,
           };

       // PA-02 / PA-10: statically-checkable node-policy invariants. These run at
       // node startup (chainparams construction) so a bad hand-edit of the anchor
       // data fails closed instead of silently corrupting IBD. They are NOT
       // consensus rules — the block/tx history validates identically regardless.
       assert(!checkpointData.mapCheckpoints.empty());
       // assumevalid must be exactly the top checkpoint's block hash (single anchor).
       assert(consensus.defaultAssumeValid ==
              checkpointData.mapCheckpoints.rbegin()->second);
       // chainTxData is a snapshot of a real post-genesis block: its timestamp can
       // never predate genesis (this is the PA-10 regression guard).
       assert(chainTxData.nTime >= genesis.GetBlockTime());
       // Progress estimation assumes forward motion since the anchor.
       assert(chainTxData.dTxRate >= 0);
        }
};

/**
 * Testnet5: VoidCoin Public Testnet Supporting Development and Implementation of Quantum Resistant Signature Schemes
 */
class CTestNet5Params : public CChainParams {
public:
    CTestNet5Params() {
        m_chain_type = ChainType::TESTNET5;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.script_flag_exceptions.emplace( // BIP16 exception
            uint256{"0000000075a6fb48774590b99c93bcd2d358559949c3e338fcaaf4b4c1a01d94"}, SCRIPT_VERIFY_NONE);
        consensus.script_flag_exceptions.emplace( // Taproot exception
            uint256{"0000000075a6fb48774590b99c93bcd2d358559949c3e338fcaaf4b4c1a01d94"}, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS);
        consensus.BIP34Height = 200;
        consensus.BIP34Hash = uint256::ZERO;
        consensus.BIP65Height = 225;
        consensus.BIP66Height = 230;
        consensus.CSVHeight = 235;
        consensus.SegwitHeight = 240;
        consensus.nP2QRActivationHeight = 5;
        consensus.nP2QRTimelockActivationHeight = 10;
        // VCIP-3 hard fork activation (testnet). FAIL-SAFE DEFAULT: never-active
        // sentinel. Maintainer sets an announced testnet height when ready to
        // exercise the fork on public testnet (activation is tested on regtest via
        // the -vcip3activationheight knob first). Pre-activation consensus is unchanged.
        consensus.nVCIP3ActivationHeight = std::numeric_limits<int>::max(); // TODO(maintainer): set the testnet VCIP-3 activation height
        consensus.MinBIP9WarningHeight = 0;
        consensus.powLimit = uint256{"00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Deployment of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = 1778735194; // April 24th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = 18942120000; // August 11th, 2021
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 25; // Approximately November 12th, 2021

        consensus.nMinimumChainWork = uint256{"0000000000000000000000000000000000000000000000000000000000000001"};
        consensus.defaultAssumeValid = uint256{"0000000075a6fb48774590b99c93bcd2d358559949c3e338fcaaf4b4c1a01d94"}; // 0

        pchMessageStart[0] = 0x51; // Q
        pchMessageStart[1] = 0x52; // R
        pchMessageStart[2] = 0x54; // T
        pchMessageStart[3] = 0x35; // 5
        nDefaultPort = 58338;
        nPruneAfterHeight = 1000;
        m_assumed_blockchain_size = 1;
        m_assumed_chain_state_size = 1;

        genesis = CreateGenesisBlock(1782730000U, 1896980011U, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // assert disabled
        // assert disabled

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("seed.testnet5.voidcoin.ddns.net."); 
        

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tn";
        bech32_qr_hrp = "tnqr";
        bech32_qrt_hrp = "tnqt";

        

        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;

        checkpointData = {
            {
                {},
            }
        };

        m_assumeutxo_data = {
            {}
        };

        chainTxData = ChainTxData{
            .nTime    = 1778735194,
            .tx_count = 1,
            .dTxRate  = 0.0,
        };
    }
};





/**
 * Signet: test network with an additional consensus parameter (see BIP325).
 */
class SigNetParams : public CChainParams {
public:
    explicit SigNetParams(const SigNetOptions& options)
    {
        std::vector<uint8_t> bin;
        vFixedSeeds.clear();
        vSeeds.clear();

        if (!options.challenge) {
            bin = "512103ad5e0edad18cb1f0fc0d28a3d4f1f3e445640337489abb10404f2d1e086be430210359ef5021964fe22d6f8e05b2463c9540ce96883fe3b278760f048f5189f2e6c452ae"_hex_v_u8;
            vFixedSeeds = std::vector<uint8_t>(std::begin(chainparams_seed_signet), std::end(chainparams_seed_signet));
            vSeeds.emplace_back("seed.signet.voidcoin.ddns.net.");
            

            consensus.nMinimumChainWork = uint256{"000000000000000000000000000000000000000000000000000002b517f3d1a1"};
            consensus.defaultAssumeValid = uint256{"000000895a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a"}; // 237722
            m_assumed_blockchain_size = 9;
            m_assumed_chain_state_size = 1;
            chainTxData = ChainTxData{
                // Data from RPC: getchaintxstats 4096 000000895a110f46e59eb82bbc5bfb67fa314656009c295509c21b4999f5180a
                .nTime    = 1741019645,
                .tx_count = 16540736,
                .dTxRate  = 1.064918879911595,
            };
        } else {
            bin = *options.challenge;
            consensus.nMinimumChainWork = uint256{};
            consensus.defaultAssumeValid = uint256{};
            m_assumed_blockchain_size = 0;
            m_assumed_chain_state_size = 0;
            chainTxData = ChainTxData{
                0,
                0,
                0,
            };
            LogPrintf("Signet with challenge %s\n", HexStr(bin));
        }

        if (options.seeds) {
            vSeeds = *options.seeds;
        }

        m_chain_type = ChainType::SIGNET;
        consensus.signet_blocks = true;
        consensus.signet_challenge.assign(bin.begin(), bin.end());
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP34Height = 1;
        consensus.BIP34Hash = uint256{};
        consensus.BIP65Height = 1;
        consensus.BIP66Height = 1;
        consensus.CSVHeight = 1;
        consensus.SegwitHeight = 1;
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.enforce_BIP94 = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1815; // 90% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.MinBIP9WarningHeight = 0;
        consensus.nP2QRActivationHeight = std::numeric_limits<int>::max();
        // Signet has no P2QR activation, so the VCIP-3 ML-DSA budget is moot;
        // keep it never-active for consistency with nP2QRActivationHeight.
        consensus.nVCIP3ActivationHeight = std::numeric_limits<int>::max();
        consensus.powLimit = uint256{"00000377ae000000000000000000000000000000000000000000000000000000"};
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = Consensus::BIP9Deployment::NEVER_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        // Activation of Taproot (BIPs 340-342)
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        // message start is defined as the first 4 bytes of the sha256d of the block script
        HashWriter h{};
        h << consensus.signet_challenge;
        uint256 hash = h.GetHash();
        std::copy_n(hash.begin(), 4, pchMessageStart.begin());

        nDefaultPort = 38338;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1781049494, 8469369, 0x1e0377ae, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // assert disabled

        m_assumeutxo_data = {
            {
                .height = 160'000,
                .hash_serialized = AssumeutxoHash{uint256{"fe0a44309b74d6b5883d246cb419c6221bcccf0b308c9b59b7d70783dbdf928a"}},
                .m_chain_tx_count = 2289496,
                .blockhash = consteval_ctor(uint256{"0000003ca3c99aff040f2563c2ad8f8ec88bd0fd6b8f0895cfaf1ef90353a62c"}),
            }
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";
        bech32_qr_hrp = "tbqr";
        bech32_qrt_hrp = "tbqt";
        
        fDefaultConsistencyChecks = false;
        m_is_mockable_chain = false;
    }
};

/**
 * Regression test: intended for private networks only. Has minimal difficulty to ensure that
 * blocks can be found instantly.
 */
class CRegTestParams : public CChainParams
{
public:
    explicit CRegTestParams(const RegTestOptions& opts)
    {
        m_chain_type = ChainType::REGTEST;
        consensus.signet_blocks = false;
        consensus.signet_challenge.clear();
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP34Height = 1; // Always active unless overridden
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1;  // Always active unless overridden
        consensus.BIP66Height = 1;  // Always active unless overridden
        consensus.CSVHeight = 1;    // Always active unless overridden
        consensus.SegwitHeight = 0; // Always active unless overridden
        consensus.MinBIP9WarningHeight = 0;
        consensus.nP2QRActivationHeight = 0;
        consensus.nP2QRTimelockActivationHeight = 0;
        // VCIP-3 active from genesis on regtest (consistent with P2QR), so tests
        // can exercise the VC-14 ML-DSA verification budget. No honest regtest
        // block reaches MAX_BLOCK_MLDSA_VERIFICATIONS, so this changes nothing
        // for existing regtest block tests.
        consensus.nVCIP3ActivationHeight = 0;
        consensus.powLimit = uint256{"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
        consensus.nPowTargetTimespan = 24 * 60 * 60; // one day
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.enforce_BIP94 = opts.enforce_bip94;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)

        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].min_activation_height = 0; // No activation delay

        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].bit = 2;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].min_activation_height = 0; // No activation delay

        consensus.nMinimumChainWork = uint256{};
        consensus.defaultAssumeValid = uint256{};

        pchMessageStart[0] = 0xfb;
        pchMessageStart[1] = 0xbb;
        pchMessageStart[2] = 0xb6;
        pchMessageStart[3] = 0xdb;
        nDefaultPort = 18448;
        nPruneAfterHeight = opts.fastprune ? 100 : 1000;
        m_assumed_blockchain_size = 0;
        m_assumed_chain_state_size = 0;

        for (const auto& [dep, height] : opts.activation_heights) {
            switch (dep) {
            case Consensus::BuriedDeployment::DEPLOYMENT_SEGWIT:
                consensus.SegwitHeight = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_HEIGHTINCB:
                consensus.BIP34Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_DERSIG:
                consensus.BIP66Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CLTV:
                consensus.BIP65Height = int{height};
                break;
            case Consensus::BuriedDeployment::DEPLOYMENT_CSV:
                consensus.CSVHeight = int{height};
                break;
            }
        }

        for (const auto& [deployment_pos, version_bits_params] : opts.version_bits_parameters) {
            consensus.vDeployments[deployment_pos].nStartTime = version_bits_params.start_time;
            consensus.vDeployments[deployment_pos].nTimeout = version_bits_params.timeout;
            consensus.vDeployments[deployment_pos].min_activation_height = version_bits_params.min_activation_height;
        }

        // VCIP-3 (VC-13) supply-cap test overrides. Defaults leave regtest
        // byte-identical to before (cap = MAX_MONEY, activation kept at the value
        // set above); -vcip3supplycap / -vcip3activationheight let functional
        // tests mine past a tiny cap and probe the pre-/post-activation boundary.
        consensus.nVoidSupplyCap = opts.vcip3_supply_cap;
        if (opts.vcip3_activation_height >= 0) {
            consensus.nVCIP3ActivationHeight = opts.vcip3_activation_height;
        }

        genesis = CreateGenesisBlock(1781049388, 84, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();

        // assert disabled

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();
        vSeeds.emplace_back("dummySeed.invalid.");

        fDefaultConsistencyChecks = true;
        m_is_mockable_chain = true;

        checkpointData = {
            {
                {0, uint256{"47f56596a23f141a5135385a50c968bba4e074111cc9446680933921307d8b5a"}},
            }
        };

        m_assumeutxo_data = {
            {   // For use by unit tests
                .height = 110,
                .hash_serialized = AssumeutxoHash{uint256{"6657b736d4fe4db0cbc796789e812d5dba7f5c143764b1b6905612f1830609d1"}},
                .m_chain_tx_count = 111,
                .blockhash = consteval_ctor(uint256{"696e92821f65549c7ee134edceeeeaaa4105647a3c4fd9f298c0aec0ab50425c"}),
            },
            {
                // For use by fuzz target src/test/fuzz/utxo_snapshot.cpp
                .height = 200,
                .hash_serialized = AssumeutxoHash{uint256{"4f34d431c3e482f6b0d67b64609ece3964dc8d7976d02ac68dd7c9c1421738f2"}},
                .m_chain_tx_count = 201,
                .blockhash = consteval_ctor(uint256{"5e93653318f294fb5aa339d00bbf8cf1c3515488ad99412c37608b139ea63b27"}),
            },
            {
                // For use by test/functional/feature_assumeutxo.py
                .height = 299,
                .hash_serialized = AssumeutxoHash{uint256{"a4bf3407ccb2cc0145c49ebba8fa91199f8a3903daf0883875941497d2493c27"}},
                .m_chain_tx_count = 334,
                .blockhash = consteval_ctor(uint256{"3bb7ce5eba0be48939b7a521ac1ba9316afee2c7bada3a0cca24188e6d7d96c0"}),
            },
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
        bech32_qr_hrp = "bcrtqr";
        bech32_qrt_hrp = "bcrtqt";
    }
};

std::unique_ptr<const CChainParams> CChainParams::SigNet(const SigNetOptions& options)
{
    return std::make_unique<const SigNetParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::RegTest(const RegTestOptions& options)
{
    return std::make_unique<const CRegTestParams>(options);
}

std::unique_ptr<const CChainParams> CChainParams::Main()
{
    return std::make_unique<const CMainParams>();
}

std::unique_ptr<const CChainParams> CChainParams::TestNet5()
{
    return std::make_unique<const CTestNet5Params>();
}

std::vector<int> CChainParams::GetAvailableSnapshotHeights() const
{
    std::vector<int> heights;
    heights.reserve(m_assumeutxo_data.size());

    for (const auto& data : m_assumeutxo_data) {
        heights.emplace_back(data.height);
    }
    return heights;
}

std::optional<ChainType> GetNetworkForMagic(const MessageStartChars& message)
{
    const auto mainnet_msg = CChainParams::Main()->MessageStart();
    const auto testnet5_msg = CChainParams::TestNet5()->MessageStart();
    const auto regtest_msg = CChainParams::RegTest({})->MessageStart();
    const auto signet_msg = CChainParams::SigNet({})->MessageStart();

    if (std::ranges::equal(message, mainnet_msg)) {
        return ChainType::MAIN;
    } else if (std::ranges::equal(message, testnet5_msg)) {
        return ChainType::TESTNET5;
    } else if (std::ranges::equal(message, regtest_msg)) {
        return ChainType::REGTEST;
    } else if (std::ranges::equal(message, signet_msg)) {
        return ChainType::SIGNET;
    }
    return std::nullopt;
}
