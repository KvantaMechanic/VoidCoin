// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

// Regression tests for VC-03: P2QR / ML-DSA-87 wallet seeds must participate in
// wallet encryption (encrypted at rest, only signable while unlocked).

#include <wallet/wallet.h>

#include <addresstype.h>
#include <coins.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <script/solver.h>
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
#include <vector>

namespace wallet {

BOOST_AUTO_TEST_SUITE(voidcoin_p2qr_encryption_tests)

// Walk the raw DB records and report whether any record of the given DB type
// exists. Mirrors the helper in walletload_tests.cpp.
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

// Count raw DB records of a given type. Lets us assert that a *new* key added to
// an already-encrypted wallet lands as an additional crypted record and never a
// plaintext one.
static size_t CountRecordsOfType(WalletDatabase& db, const std::string& key)
{
    std::unique_ptr<DatabaseBatch> batch = db.MakeBatch(false);
    BOOST_CHECK(batch);
    std::unique_ptr<DatabaseCursor> cursor = batch->GetNewCursor();
    BOOST_CHECK(cursor);
    size_t count = 0;
    while (true) {
        DataStream ssKey{};
        DataStream ssValue{};
        DatabaseCursor::Status status = cursor->Next(ssKey, ssValue);
        assert(status != DatabaseCursor::Status::FAIL);
        if (status == DatabaseCursor::Status::DONE) break;
        std::string type;
        ssKey >> type;
        if (type == key) ++count;
    }
    return count;
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

BOOST_FIXTURE_TEST_CASE(p2qr_seed_encrypted_and_locked_signing, TestingSetup)
{
    const SecureString passphrase{"correct horse battery staple"};

    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));

    VoidCoinP2QRDestination dest;
    {
        LOCK(wallet->cs_wallet);
        auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
        BOOST_REQUIRE(spkm != nullptr);

        auto op_dest = spkm->GetNewDestination(OutputType::BECH32M /* ignored by QR SPKM */);
        BOOST_REQUIRE(op_dest);
        dest = std::get<VoidCoinP2QRDestination>(*op_dest);

        // Before encryption: plaintext seed record on disk, no crypted record,
        // and signing works (the wallet is not encrypted, so never "locked").
        BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
        BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));
        BOOST_CHECK(!wallet->IsCrypted());
        BOOST_CHECK(!wallet->IsLocked());

        CPQKey key_before;
        BOOST_CHECK(spkm->GetKey(dest, key_before));
        BOOST_CHECK(TrySignP2QRSpend(*spkm, dest));
    }

    // Encrypt in place. This must migrate the plaintext seed to a crypted record.
    BOOST_CHECK(wallet->EncryptWallet(passphrase));
    wallet->Flush();

    auto* spkm = WITH_LOCK(wallet->cs_wallet, return wallet->GetVoidCoinP2QRScriptPubKeyMan());
    BOOST_REQUIRE(spkm != nullptr);

    // On-disk: the plaintext seed record is gone; a crypted record took its place.
    BOOST_CHECK(!HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY));
    BOOST_CHECK(HasAnyRecordOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));

    // The wallet is now encrypted and (per EncryptWallet) locked.
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());

    // While locked, the private key is unavailable and signing must fail.
    {
        CPQKey key_locked;
        BOOST_CHECK(!spkm->GetKey(dest, key_locked));
        std::vector<unsigned char> seed_locked;
        BOOST_CHECK(!spkm->ExportSeed(dest, seed_locked));
        BOOST_CHECK(!TrySignP2QRSpend(*spkm, dest));
    }

    // A wrong passphrase must not unlock.
    BOOST_CHECK(!wallet->Unlock(SecureString{"wrong passphrase"}));
    BOOST_CHECK(wallet->IsLocked());

    // Correct passphrase: unlock and signing works again.
    BOOST_CHECK(wallet->Unlock(passphrase));
    BOOST_CHECK(!wallet->IsLocked());
    {
        CPQKey key_unlocked;
        BOOST_CHECK(spkm->GetKey(dest, key_unlocked));
        BOOST_CHECK(key_unlocked.GetDestination() == dest);
        BOOST_CHECK(TrySignP2QRSpend(*spkm, dest));
    }

    // Re-lock: signing must fail once more.
    BOOST_CHECK(wallet->Lock());
    BOOST_CHECK(wallet->IsLocked());
    {
        CPQKey key_relocked;
        BOOST_CHECK(!spkm->GetKey(dest, key_relocked));
        BOOST_CHECK(!TrySignP2QRSpend(*spkm, dest));
    }
}

// Backward-compat: a wallet that already holds an encrypted P2QR record on disk
// must load, expose the address while locked, and sign after unlock.
BOOST_FIXTURE_TEST_CASE(p2qr_crypted_record_roundtrips_on_reload, TestingSetup)
{
    const SecureString passphrase{"another correct passphrase"};

    // Capture the on-disk records of an encrypted wallet holding one P2QR key.
    MockableData records;
    VoidCoinP2QRDestination dest;
    {
        std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));
        {
            LOCK(wallet->cs_wallet);
            auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
            auto op_dest = spkm->GetNewDestination(OutputType::BECH32M);
            BOOST_REQUIRE(op_dest);
            dest = std::get<VoidCoinP2QRDestination>(*op_dest);
        }
        BOOST_CHECK(wallet->EncryptWallet(passphrase));
        wallet->Flush();
        records = GetMockableDatabase(*wallet).m_records;
    }

    // The persisted state is a crypted record with no plaintext seed.
    {
        auto probe_db = CreateMockableWalletDatabase(records);
        BOOST_CHECK(HasAnyRecordOfType(*probe_db, DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY));
        BOOST_CHECK(!HasAnyRecordOfType(*probe_db, DBKeys::VOIDCOIN_P2QR_KEY));
    }

    // Reload a fresh wallet from those records.
    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase(records)));
    BOOST_CHECK_EQUAL(wallet->LoadWallet(), DBErrors::LOAD_OK);
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());

    auto* spkm = WITH_LOCK(wallet->cs_wallet, return wallet->GetVoidCoinP2QRScriptPubKeyMan());
    BOOST_REQUIRE(spkm != nullptr);

    // Address ownership works while locked (public half is resident)...
    BOOST_CHECK(spkm->IsMine(GetScriptForDestination(dest)) == ISMINE_SPENDABLE);
    // ...but the secret is not, so signing fails until unlocked.
    {
        CPQKey key_locked;
        BOOST_CHECK(!spkm->GetKey(dest, key_locked));
        BOOST_CHECK(!TrySignP2QRSpend(*spkm, dest));
    }

    BOOST_CHECK(wallet->Unlock(passphrase));
    {
        CPQKey key_unlocked;
        BOOST_CHECK(spkm->GetKey(dest, key_unlocked));
        BOOST_CHECK(key_unlocked.GetDestination() == dest);
        BOOST_CHECK(TrySignP2QRSpend(*spkm, dest));
    }
}

// VC-03 / BLOCKER-1 regression: keys generated AFTER encryptwallet must be
// written encrypted (never a plaintext VOIDCOIN_P2QR_KEY record), and new-key
// generation must fail while the wallet is locked.
BOOST_FIXTURE_TEST_CASE(p2qr_new_key_after_encrypt_is_crypted_only, TestingSetup)
{
    const SecureString passphrase{"correct horse battery staple"};

    std::shared_ptr<CWallet> wallet(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase()));

    // One key before encryption.
    VoidCoinP2QRDestination dest_before;
    {
        LOCK(wallet->cs_wallet);
        auto* spkm = wallet->GetOrCreateVoidCoinP2QRScriptPubKeyMan();
        BOOST_REQUIRE(spkm != nullptr);
        auto op = spkm->GetNewDestination(OutputType::BECH32M);
        BOOST_REQUIRE(op);
        dest_before = std::get<VoidCoinP2QRDestination>(*op);
    }

    BOOST_CHECK(wallet->EncryptWallet(passphrase));
    wallet->Flush();

    auto* spkm = WITH_LOCK(wallet->cs_wallet, return wallet->GetVoidCoinP2QRScriptPubKeyMan());
    BOOST_REQUIRE(spkm != nullptr);

    // After encryption: one crypted record, zero plaintext records, wallet locked.
    BOOST_CHECK(wallet->IsCrypted());
    BOOST_CHECK(wallet->IsLocked());
    BOOST_CHECK_EQUAL(CountRecordsOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY), 1U);

    // (1) While LOCKED, generating/importing a new P2QR key must fail closed and
    // write nothing to disk.
    {
        auto op = WITH_LOCK(wallet->cs_wallet, return spkm->GetNewDestination(OutputType::BECH32M));
        BOOST_CHECK(!op);
        VoidCoinP2QRDestination imp_dest;
        const std::vector<unsigned char> seed(MLDSA87_SEED_SIZE, 0x11);
        BOOST_CHECK(!spkm->ImportSeed(seed, imp_dest));
    }
    wallet->Flush();
    BOOST_CHECK_EQUAL(CountRecordsOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY), 1U);

    // (2) Unlock, then generate a new key. It must be persisted encrypted only.
    BOOST_CHECK(wallet->Unlock(passphrase));
    BOOST_CHECK(!wallet->IsLocked());

    VoidCoinP2QRDestination dest_after;
    {
        auto op = WITH_LOCK(wallet->cs_wallet, return spkm->GetNewDestination(OutputType::BECH32M));
        BOOST_REQUIRE(op);
        dest_after = std::get<VoidCoinP2QRDestination>(*op);
    }
    BOOST_CHECK(!(dest_after == dest_before));
    wallet->Flush();

    // Core assertion: NO plaintext record was ever written; the new key is a
    // second crypted record.
    BOOST_CHECK_EQUAL(CountRecordsOfType(wallet->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(wallet->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY), 2U);

    // The freshly-generated key is usable while unlocked and gated once locked.
    {
        CPQKey k;
        BOOST_CHECK(spkm->GetKey(dest_after, k));
        BOOST_CHECK(k.GetDestination() == dest_after);
        BOOST_CHECK(TrySignP2QRSpend(*spkm, dest_after));
    }
    BOOST_CHECK(wallet->Lock());
    {
        CPQKey k;
        BOOST_CHECK(!spkm->GetKey(dest_after, k));
        BOOST_CHECK(!TrySignP2QRSpend(*spkm, dest_after));
    }

    // (3) Reload from disk: the post-encryption key survives as a crypted record,
    // is owned while locked, and is spendable after unlock.
    MockableData records = GetMockableDatabase(*wallet).m_records;
    std::shared_ptr<CWallet> reloaded(new CWallet(m_node.chain.get(), "", CreateMockableWalletDatabase(records)));
    BOOST_CHECK_EQUAL(reloaded->LoadWallet(), DBErrors::LOAD_OK);
    BOOST_CHECK(reloaded->IsCrypted());
    BOOST_CHECK(reloaded->IsLocked());

    auto* rspkm = WITH_LOCK(reloaded->cs_wallet, return reloaded->GetVoidCoinP2QRScriptPubKeyMan());
    BOOST_REQUIRE(rspkm != nullptr);
    BOOST_CHECK(rspkm->IsMine(GetScriptForDestination(dest_after)) == ISMINE_SPENDABLE);
    BOOST_CHECK_EQUAL(CountRecordsOfType(reloaded->GetDatabase(), DBKeys::VOIDCOIN_P2QR_KEY), 0U);
    BOOST_CHECK_EQUAL(CountRecordsOfType(reloaded->GetDatabase(), DBKeys::CRYPTED_VOIDCOIN_P2QR_KEY), 2U);

    BOOST_CHECK(reloaded->Unlock(passphrase));
    {
        CPQKey k;
        BOOST_CHECK(rspkm->GetKey(dest_after, k));
        BOOST_CHECK(k.GetDestination() == dest_after);
        BOOST_CHECK(TrySignP2QRSpend(*rspkm, dest_after));
    }
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
