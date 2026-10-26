// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Regression test for BLOCKER-2: wallets that were encrypted by a build
// predating the VC-03 fix still carry their ML-DSA-87 P2QR seeds as *plaintext*
// VOIDCOIN_P2QR_KEY records on disk, because the native P2QR SPKM never took
// part in EncryptWallet (and EncryptWallet refuses to re-run once IsCrypted()).
// CWallet::Unlock must migrate those cleartext seeds to encrypted-at-rest
// (CRYPTED_VOIDCOIN_P2QR_KEY) records in place, the only moment the master key
// is available.

#include <wallet/wallet.h>

#include <addresstype.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/translation.h>
#include <wallet/pqkey.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/test/util.h>
#include <wallet/walletdb.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <memory>
#include <string>
#include <vector>

namespace wallet {

BOOST_AUTO_TEST_SUITE(voidcoin_p2qr_migration_tests)

// Walk the raw DB records and report whether any record of the given DB type
// exists. Mirrors the helper in voidcoin_p2qr_encryption_tests.cpp / walletload.
static bool HasAnyRecordOfType(WalletDatabase& db, const std::string& key)
{
    std::unique_ptr<DatabaseBatch> batch = db.MakeBatch(false);
    BOOST_CHECK(batch);
    std::unique_ptr<DatabaseCursor> cursor = batch->GetNewCursor();
    BOOST_CHECK(cursor);
    while (true) {
        DataStream ssKey{};
        DataStream ssValue{};
        DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
        assert(status != DatabaseCursor::Status::FAIL);
        if (status == DatabaseCursor::Status::DONE) break;
        std::string type;
        ssKey >> type;
        if (type == key) return true;
    }
    return false;
}

// Copy every record whose DB key begins with `type` out of `src`.
static MockableData FilterRecordsOfType(const MockableData& src, const std::string& type)
{
    MockableData out;
    for (const auto& [k, v] : src) {
        DataStream ssKey{k};
        std::string t;
        ssKey >> t;
        if (t == type) out.emplace(k, v);
    }
    return out;
}

// Drop every record whose DB key begins with `type` from `data`.
static void EraseRecordsOfType(MockableData& data, const std::string& type)
{
    for (auto it = data.begin(); it != data.end();) {
        DataStream ssKey{it->first};
        std::string t;
        ssKey >> t;
        if (t == type) {
            it = data.erase(it);
        } else {
            ++it;
        }
    }
}

// Build a self-spend of a native P2QR output and ask the P2QR SPKM to sign it.
// Returns whether SignTransaction succeeded (it also self-verifies each input).
static bool TrySignP2QRSpend(VoidCoinP2QRScriptPubKeyMan& spkm, const VoidCoinP2QRDestination& dest)
{
    const CScript spk = GetScriptForDestination(dest);

    CMutableTransaction mtx;
    mtx.vin.push_back(CTxIn{Txid::FromUint256(uint256::ONE), 0});
    mtx.vout.emplace_back(9 * COIN, spk);

    std::map<COutPoint, Coin> coins;
    coins[mtx.vin[0].prevout].out = CTxOut(10 * COIN, spk);

    std::map<int, bilingual_str> input_errors;
    return spkm.SignTransaction(mtx, coins, SIGHASH_ALL, input_errors);
}

// Reconstruct the exact on-disk artifact of a pre-VC-03 build: an *encrypted*
// wallet (master key present) whose P2QR seed is still a *plaintext*
// VOIDCOIN_P2QR_KEY record, with no CRYPTED_VOIDCOIN_P2QR_KEY counterpart.
BOOST_FIXTURE_TEST_CASE(p2qr_plaintext_seed_migrated_on_unlock, TestingSetup)
{
    const SecureString passphrase{"migrate horse battery staple"};

    MockableData plaintext_p2qr;   // the cleartext P2QR record(s) captured pre-encryption
    MockableData buggy_records;    // encrypted wallet + plaintext P2QR record (no crypted)
    VoidCoinP2QRDestination dest;

    {
        std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));
        {
            LOCK(wallet->cs_wallet);
            auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
            BOOST_REQUIRE(spkm != nullptr);
            auto op_dest = spkm->GetNewDestination(OutputType::BECH32M /* ignored by QR SPKM */);
            BOOST_REQUIRE(op_dest);
            dest = std::get<VoidCoinP2QRDestination>(*op_dest);
        }

        // Snapshot the plaintext seed record while the wallet is still unencrypted.
        plaintext_p2qr = FilterRecordsOfType(GetMockableDatabase(*wallet).m_records, DBKeys::VOIDCOIN_P2QR_KEY);
        BOOST_REQUIRE(!plaintext_p2qr.empty());

        // Encrypt (the fixed path migrates the seed to a crypted record), then
        // *downgrade* to the buggy shape: strip the crypted P2QR record and
        // re-inject the plaintext one. The master-key records still match
        // `passphrase`, so this is a faithful pre-VC-03 wallet.
        BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
        wallet->Flush();
        buggy_records = GetMockableDatabase(*wallet).m_records;
    }
    EraseRecordsOfType(buggy_records, DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY);
    for (const auto& [k, v] : plaintext_p2qr) buggy_records[k] = v;

    // Load the victim wallet from the reconstructed buggy state.
    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase(buggy_records)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());

    // Pre-condition: cleartext seed on disk, no crypted record.
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));

    auto* spkm = WITH_LOCK(wallet->cs_wallet, return wallet->GetVoidCoinP2QRScriptPubKeyMan());
    BOOST_REQUIRE(spkm != nullptr);

    // The address is owned (public half resident) even while locked, but the
    // seed guard blocks signing until the wallet is genuinely unlocked.
    BOOST_CHECK(spkm->IsMine(GetScriptForDestination(dest)) == ISMINE_SPENDABLE);
    {
        CPQKey key_locked;
        BOOST_CHECK(!spkm->GetKey(dest, key_locked));
        BOOST_CHECK(!TrySignP2QRSpend(*spkm, dest));
    }

    // A wrong passphrase must not unlock and must not migrate anything.
    BOOST_CHECK(!wallet->Unlock(SecureString{"wrong passphrase"}));
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));

    // The correct passphrase (the walletpassphrase path) unlocks and migrates.
    BOOST_CHECK(wallet->Unlock(passphrase));
    BOOST_CHECK(!wallet->IsLocked());

    // Post-condition: plaintext record is gone; a crypted record replaced it.
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));

    // Signing works after migration.
    {
        CPQKey key_unlocked;
        BOOST_CHECK(spkm->GetKey(dest, key_unlocked));
        BOOST_CHECK(key_unlocked.GetDestination() == dest);
        BOOST_CHECK(TrySignP2QRSpend(*spkm, dest));
    }

    // Re-lock: signing fails again; the secret is only in the crypted record now.
    BOOST_CHECK(wallet->Lock());
    BOOST_CHECK(wallet->IsLocked());
    {
        CPQKey key_relocked;
        BOOST_CHECK(!spkm->GetKey(dest, key_relocked));
        BOOST_CHECK(!TrySignP2QRSpend(*spkm, dest));
    }

    // Unlocking again is an idempotent no-op (nothing left to migrate) and
    // signing still works.
    BOOST_CHECK(wallet->Unlock(passphrase));
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(TrySignP2QRSpend(*spkm, dest));

    // Durability: the migration must survive a full close/reopen of the DB.
    MockableData migrated_records = GetMockableDatabase(*wallet).m_records;
    std::shared_ptr<CWallet> reloaded(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase(migrated_records)));
    BOOST_CHECK_EQUAL(reloaded->LoadWallet(), DBErrors::LOAD_OK);
    BOOST_CHECK(reloaded->IsCrypted());
    BOOST_CHECK(!HasAnyRecordOfType(reloaded->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(HasAnyRecordOfType(reloaded->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));

    auto* rspkm = WITH_LOCK(reloaded->cs_wallet, return reloaded->GetVoidCoinP2QRScriptPubKeyMan());
    BOOST_REQUIRE(rspkm != nullptr);
    BOOST_CHECK(rspkm->IsMine(GetScriptForDestination(dest)) == ISMINE_SPENDABLE);
    BOOST_CHECK(reloaded->Unlock(passphrase));
    {
        CPQKey key_reloaded;
        BOOST_CHECK(rspkm->GetKey(dest, key_reloaded));
        BOOST_CHECK(key_reloaded.GetDestination() == dest);
        BOOST_CHECK(TrySignP2QRSpend(*rspkm, dest));
    }
}

// VC-03 residual: migrating the plaintext seed must not only erase the
// VOIDCOIN_P2QR_KEY row but also Rewrite() the whole database file, so the
// cleartext ML-DSA-87 seed cannot linger in BDB slack space. On a real BDB
// backend the slack is unobservable from the record set; here we assert the
// migration triggered a database Rewrite() (observed via MockableDatabase's
// rewrite counter) exactly on the unlock that migrated, and that no plaintext
// row survives afterwards — while a wrong passphrase and an already-migrated
// (no-op) unlock trigger no Rewrite().
BOOST_FIXTURE_TEST_CASE(p2qr_migration_rewrites_db_and_leaves_no_plaintext_row, TestingSetup)
{
    const SecureString passphrase{"migrate horse battery staple"};

    MockableData plaintext_p2qr;
    MockableData buggy_records;

    {
        std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));
        {
            LOCK(wallet->cs_wallet);
            auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
            BOOST_REQUIRE(spkm != nullptr);
            BOOST_REQUIRE(spkm->GetNewDestination(OutputType::BECH32M));
        }
        plaintext_p2qr = FilterRecordsOfType(GetMockableDatabase(*wallet).m_records, DBKeys::VOIDCOIN_P2QR_KEY);
        BOOST_REQUIRE(!plaintext_p2qr.empty());
        BOOST_REQUIRE(wallet->EncryptWallet(passphrase));
        wallet->Flush();
        buggy_records = GetMockableDatabase(*wallet).m_records;
    }
    EraseRecordsOfType(buggy_records, DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY);
    for (const auto& [k, v] : plaintext_p2qr) buggy_records[k] = v;

    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase(buggy_records)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));

    MockableDatabase& mock_db = GetMockableDatabase(*wallet);

    // A wrong passphrase migrates nothing and must not Rewrite() the DB.
    const int rewrites_before = mock_db.m_rewrite_count;
    BOOST_CHECK(!wallet->Unlock(SecureString{"wrong passphrase"}));
    BOOST_CHECK_EQUAL(mock_db.m_rewrite_count, rewrites_before);
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));

    // The correct passphrase migrates: the plaintext row is gone, a crypted row
    // replaces it, and the DB was Rewrite()n to purge cleartext slack.
    BOOST_CHECK(wallet->Unlock(passphrase));
    BOOST_CHECK_GT(mock_db.m_rewrite_count, rewrites_before);
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));

    // A second unlock has nothing to migrate: idempotent no-op, no further Rewrite().
    const int rewrites_after_migrate = mock_db.m_rewrite_count;
    BOOST_CHECK(wallet->Lock());
    BOOST_CHECK(wallet->Unlock(passphrase));
    BOOST_CHECK_EQUAL(mock_db.m_rewrite_count, rewrites_after_migrate);
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
