#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VoidCoin VC-03 wallet min-version gate (wallet fix #7: the AddKey gap).

Post-quantum P2QR (ML-DSA-87) seeds are stored wallet-encrypted as
`cvoidcoinp2qrkey` records that a pre-VC-03 build cannot read. To make an
older build fail closed ("wallet too new") instead of silently hiding the
P2QR balance, the wallet min version must be raised to
FEATURE_VOIDCOIN_P2QR_CRYPT (700000) whenever such an encrypted record is
first written.

The review flagged that EncryptWallet only raised the version when the wallet
ALREADY held P2QR keys (its HaveCryptedKeys() guard). A wallet that was
encrypted with NO P2QR keys and then generated its FIRST P2QR address went
through VoidCoinP2QRScriptPubKeyMan::AddKey, which was previously un-gated.
The fix raises the min version inside AddKey's encrypted branch
(src/wallet/scriptpubkeyman.cpp: m_storage.SetMinVersion(FEATURE_VOIDCOIN_P2QR_CRYPT, &batch)).

WHY THIS TEST HAS TO SYNTHESIZE ITS PRECONDITION
------------------------------------------------
On this build FEATURE_LATEST == FEATURE_VOIDCOIN_P2QR_CRYPT == 700000, and
CWallet::Create bumps every newly-created spendable wallet to FEATURE_LATEST at
first run (the fFirstRun SetMinVersion(FEATURE_LATEST) fires before the blank
flag is applied). So a wallet created by THIS build already reports 700000 and
can never sit in the flagged "encrypted, P2QR-less, below 700000" state via
RPC alone -- the AddKey raise would be an unobservable no-op.

The only wallets that can be below 700000 are ones written by a pre-VC-03
build. This test reproduces that exact wallet by lowering the persisted
`minversion` record on disk to FEATURE_WALLETCRYPT (40000, scenario A) /
FEATURE_PRE_SPLIT_KEYPOOL (169900, scenario B) -- values an older build would
have -- while the wallet is unloaded, then reloading. The BEHAVIOR under test
(the min-version RAISE) is then driven entirely through real wallet RPCs
(getnewvoidcoinp2qraddress -> AddKey; encryptwallet -> EncryptWallet) and the
raise from below 700000 up to exactly 700000 is observed.
"""
import sqlite3
import struct

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import assert_equal
from test_framework.wallet_util import WalletUnlock

# src/wallet/walletutil.h
FEATURE_WALLETCRYPT = 40000
FEATURE_PRE_SPLIT_KEYPOOL = 169900
FEATURE_VOIDCOIN_P2QR_CRYPT = 700000

# key blob of the "minversion" wallet record: 1-byte length prefix (0x0a) + name
MINVERSION_KEY = b"\x0a" + b"minversion"


class VoidCoinWalletMinVersionTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def wallet_version(self, w):
        return w.getwalletinfo()["walletversion"]

    def force_persisted_minversion(self, node, name, version):
        """Simulate a pre-VC-03 wallet by rewriting the on-disk `minversion`
        record to `version` while the wallet is unloaded, then reloading. The
        value is a 4-byte little-endian int (as CWalletDB::WriteMinVersion
        serialises it). Returns the version the reloaded wallet reports."""
        node.unloadwallet(name)
        db_path = node.wallets_path / name / "wallet.dat"
        con = sqlite3.connect(db_path)
        try:
            new_val = struct.pack("<i", version)
            cur = con.execute(
                "UPDATE main SET value=? WHERE key=?", (new_val, MINVERSION_KEY))
            assert_equal(cur.rowcount, 1)  # exactly one minversion record edited
            con.commit()
        finally:
            con.close()
        node.loadwallet(name)
        return self.wallet_version(node.get_wallet_rpc(name))

    def run_test(self):
        node = self.nodes[0]
        passphrase = "voidcoin-p2qr-secret"
        self.scenario_a_addkey_gate(node, passphrase)
        self.scenario_b_encryptwallet_gate(node, passphrase)

    def scenario_a_addkey_gate(self, node, passphrase):
        self.log.info("Scenario A (fix #7): encrypted wallet with NO P2QR keys "
                      "sitting below 700000 -> first P2QR key via AddKey must "
                      "raise the min version to 700000")

        node.createwallet(wallet_name="gap", blank=True)
        w = node.get_wallet_rpc("gap")

        # Encrypt while the wallet holds NO P2QR keys. This is precisely the
        # path where EncryptWallet's HaveCryptedKeys() guard is false and does
        # NOT raise the VC-03 version.
        w.encryptwallet(passphrase)

        # Put the wallet in the exact state the review flagged: encrypted, no
        # P2QR keys, min version BELOW the P2QR feature (as a pre-VC-03 build
        # would leave it). A native VC-03 wallet cannot reach this via RPC
        # because it is pinned at FEATURE_LATEST == 700000 from creation.
        v_pre = self.force_persisted_minversion(node, "gap", FEATURE_WALLETCRYPT)
        w = node.get_wallet_rpc("gap")
        self.log.info("encrypted, P2QR-less wallet forced to version = %d", v_pre)
        assert_equal(v_pre, FEATURE_WALLETCRYPT)
        assert v_pre < FEATURE_VOIDCOIN_P2QR_CRYPT

        # Generate the FIRST P2QR address. getnewvoidcoinp2qraddress routes
        # through VoidCoinP2QRScriptPubKeyMan::AddKey, whose encrypted branch
        # writes a crypted seed record AND (fix #7) raises the min version.
        with WalletUnlock(w, passphrase):
            addr = w.getnewvoidcoinp2qraddress()
        # A non-empty native P2QR address means a key was generated. We do NOT
        # call getaddressinfo/validateaddress to re-confirm the type: on this
        # build both throw "Internal bug detected" for native P2QR addresses
        # (DescribeAddress pushes an undocumented `mining_address` key). The
        # version raise below is the definitive proof anyway -- ONLY the P2QR
        # crypted-key AddKey branch raises the wallet to exactly 700000.
        assert isinstance(addr, str) and addr, "no P2QR address returned"

        v_after = self.wallet_version(w)
        self.log.info("after first P2QR key via AddKey, version = %d", v_after)
        assert_equal(v_after, FEATURE_VOIDCOIN_P2QR_CRYPT)

        # The raise must be persisted, not just in-memory.
        node.unloadwallet("gap")
        node.loadwallet("gap")
        assert_equal(self.wallet_version(node.get_wallet_rpc("gap")),
                     FEATURE_VOIDCOIN_P2QR_CRYPT)
        self.log.info("raised min version persisted across unload/reload")

    def scenario_b_encryptwallet_gate(self, node, passphrase):
        self.log.info("Scenario B: unencrypted wallet already holding a P2QR "
                      "key, sitting below 700000 -> encryptwallet must raise "
                      "the min version to 700000")

        node.createwallet(wallet_name="pre", blank=True)
        w = node.get_wallet_rpc("pre")

        # Unencrypted P2QR generation stores a PLAINTEXT seed; AddKey's
        # unencrypted branch does NOT raise the version (a pre-VC-03 build can
        # read a plaintext voidcoinp2qrkey record).
        addr = w.getnewvoidcoinp2qraddress()
        assert isinstance(addr, str) and addr, "no P2QR address returned"

        # Force the below-feature baseline a pre-VC-03 build would leave on an
        # unencrypted wallet, then confirm it still loads (plaintext records are
        # readable at this version).
        v_pre = self.force_persisted_minversion(node, "pre", FEATURE_PRE_SPLIT_KEYPOOL)
        w = node.get_wallet_rpc("pre")
        self.log.info("unencrypted wallet holding a P2QR key forced to version = %d", v_pre)
        assert_equal(v_pre, FEATURE_PRE_SPLIT_KEYPOOL)
        assert v_pre < FEATURE_VOIDCOIN_P2QR_CRYPT

        # Encrypting migrates the plaintext seed into a crypted cvoidcoinp2qrkey
        # record; EncryptWallet's HaveCryptedKeys() guard must now raise the
        # version.
        w.encryptwallet(passphrase)
        v_after = self.wallet_version(w)
        self.log.info("after encryptwallet migrated the P2QR seed, version = %d", v_after)
        assert_equal(v_after, FEATURE_VOIDCOIN_P2QR_CRYPT)


if __name__ == "__main__":
    VoidCoinWalletMinVersionTest(__file__).main()
