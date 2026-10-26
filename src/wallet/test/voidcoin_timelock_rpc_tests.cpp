// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Wallet tests for the VCIP-3 rebuild of the P2QR time-lock feature. The old
// VCIP-1 vault/timelock feature was DISABLED (getnewtimelockaddress always
// errored; timelock keys were fresh-random and unrecoverable, VC-11). VCIP-3
// re-enables it correctly:
//   - the time-lock key is derived/persisted through the SAME native P2QR key
//     machinery, so it is wallet-recoverable and signable;
//   - IsMine recognizes a time-lock output whose committed program is ours;
//   - SignTransaction produces an ML-DSA-87 signature over the time-lock sighash
//     that the consensus CheckSpendTimeLock() path accepts (self-verified here).

#include <consensus/amount.h>
#include <key_io.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <script/voidcoin_p2qr.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <variant>

namespace wallet {

BOOST_FIXTURE_TEST_SUITE(voidcoin_timelock_rpc_tests, TestingSetup)

// End-to-end at the wallet layer: derive a time-lock destination, confirm the
// wallet owns the output, and sign a spend of it (SignTransaction self-verifies
// each input via CheckSpendTimeLock, exactly as consensus will).
BOOST_AUTO_TEST_CASE(timelock_derive_ismine_and_sign)
{
    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));

    VoidCoinP2QRTimeLockDestination tl;
    {
        LOCK(wallet->cs_wallet);
        auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
        BOOST_REQUIRE(spkm != nullptr);

        auto op_dest = spkm->GetNewTimeLockDestination(VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT, 100000);
        BOOST_REQUIRE(op_dest);
        const auto* got = std::get_if<VoidCoinP2QRTimeLockDestination>(&*op_dest);
        BOOST_REQUIRE(got != nullptr);
        tl = *got;

        BOOST_CHECK_EQUAL((int)tl.version, (int)VOIDCOIN_P2QR_TIMELOCK_VERSION);
        BOOST_CHECK_EQUAL((int)tl.lock_type, (int)VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT);
        BOOST_CHECK_EQUAL(tl.lock_value, 100000u);

        const CScript spk = GetScriptForDestination(tl);
        BOOST_CHECK_EQUAL(spk.size(), VOIDCOIN_P2QR_TIMELOCK_SCRIPT_SIZE);

        // The wallet owns/recognizes the time-lock output (its committed program
        // is the derived-and-persisted single-key P2QR program).
        BOOST_CHECK(spkm->IsMine(spk) == ISMINE_SPENDABLE);

        // Build a self-spend of the time-lock output and sign it. SignTransaction
        // routes it through the time-lock sighash + CheckSpendTimeLock self-check.
        CMutableTransaction mtx;
        mtx.vin.push_back(CTxIn{Txid::FromUint256(uint256::ONE), 0});
        mtx.vout.emplace_back(9 * COIN, spk);

        std::map<COutPoint, Coin> coins;
        coins[mtx.vin[0].prevout].out = CTxOut(10 * COIN, spk);

        std::map<int, bilingual_str> input_errors;
        BOOST_CHECK_MESSAGE(spkm->SignTransaction(mtx, coins, SIGHASH_ALL, input_errors),
            "SignTransaction must sign+self-verify a wallet-owned time-lock input");

        // The signed input carries the native single-key envelope (<sig> <pubkey>),
        // with no P2SH redeemScript push.
        BOOST_CHECK(!mtx.vin[0].scriptSig.empty());
    }

    // The derived address round-trips through the address codec.
    const std::string addr = EncodeDestination(tl);
    BOOST_REQUIRE(!addr.empty());
    std::string error;
    const CTxDestination decoded = DecodeDestination(addr, error);
    BOOST_CHECK_MESSAGE(std::holds_alternative<VoidCoinP2QRTimeLockDestination>(decoded),
        "vqt address must decode to a time-lock destination: " + error);
    BOOST_CHECK(decoded == CTxDestination{tl});
}

// A time-lock derived with lock_type "time" (absolute MTP) carries the MTP type
// and value, and its output is likewise wallet-owned.
BOOST_AUTO_TEST_CASE(timelock_mtp_type_derives)
{
    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));

    LOCK(wallet->cs_wallet);
    auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
    BOOST_REQUIRE(spkm != nullptr);

    auto op_dest = spkm->GetNewTimeLockDestination(VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP, 1893456000ULL);
    BOOST_REQUIRE(op_dest);
    const auto* got = std::get_if<VoidCoinP2QRTimeLockDestination>(&*op_dest);
    BOOST_REQUIRE(got != nullptr);
    BOOST_CHECK_EQUAL((int)got->lock_type, (int)VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP);
    BOOST_CHECK_EQUAL(got->lock_value, 1893456000ULL);

    const CScript spk = GetScriptForDestination(*got);
    BOOST_CHECK(spkm->IsMine(spk) == ISMINE_SPENDABLE);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
