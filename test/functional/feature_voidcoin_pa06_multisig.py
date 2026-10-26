#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""PA-06 / VCIP-3: a validly-funded P2QR multisig must be SPENDABLE.

PA-06 background (see src/script/voidcoin_p2qr.h and the C++ regression suite
src/test/voidcoin_p2qr_pa06_pushcap_tests.cpp): the newer signer-program P2QR
multisig spend envelope is 3m + n + 2 pushes, but the *legacy* spend-side push
cap was sized for the older 2m + n + 2 pubkey envelope. A signer-program
multisig whose spend needs more than the legacy cap funds fine yet can never be
spent -- its scriptSig is rejected as "too-many-pushes" before any signature
check, so the coins are permanently stranded. The fix raises the spend-side
push cap at the VCIP-3 activation height; before activation the legacy cap
stays byte-for-byte in force.

This functional test drives the fix through the real wallet/node RPC path on
regtest. The node builds, signs and validates the P2QR multisig spend
(createp2qrmultisig + fund + sendtoaddress), rather than hand-constructing
ML-DSA txs. The multisig lives in its OWN wallet holding exactly one UTXO (the
funding output), so a confirmed sweep of that wallet PROVES the multisig itself
was spent -- not some other UTXO.

  * node0 (-vcip3activationheight=1, VCIP-3 ACTIVE): a wallet-owned 2-of-3 P2QR
    multisig is created, funded with a real on-chain output, and then SPENT.
    The spend is accepted into the mempool and confirmed in a block -> a
    validly-funded multisig is spendable once VCIP-3 is active.

  * node1 (-vcip3activationheight=1_000_000, VCIP-3 INACTIVE): the same normal
    2-of-3 multisig funds and spends under the LEGACY push cap, confirming the
    pre-fork cap is in force and still admits normal multisigs (their small
    3m + n + 2 = 11-push envelope sits well within the legacy cap).

Size limitation (documented, not faked): stranding a multisig pre-fork requires
a spend envelope of 3m + n + 2 > 3074 (the legacy cap) pushes, e.g. the
700-of-1000 policy in the C++ suite (3102 pushes). Built through RPC that spend
carries ~700 ML-DSA-87 signatures (~4627 B each) plus ~700 pubkeys (~2592 B) and
1000 programs -- a multi-megabyte scriptSig that exceeds the block size limit and
cannot be mined on regtest. The pre-fork-unspendable / post-fork-spendable
contract at that extreme is therefore verified at the consensus entry point
(consensus::voidcoinp2qr::CheckSpend) by the C++ regression suite named above;
this test verifies the end-to-end RPC spendability of a normal multisig under
both activation regimes.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)

# Legacy spend-side push cap = 2*MAX_SIGNATURES + MAX_KEYS + 2 = 2*1024+1024+2.
LEGACY_PUSH_CAP = 2 * 1024 + 1024 + 2  # 3074


class VoidCoinPa06MultisigTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        self.extra_args = [
            # node0: VCIP-3 active from block 1
            ["-vcip3activationheight=1", "-txindex"],
            # node1: VCIP-3 never activates on this regtest chain
            ["-vcip3activationheight=1000000", "-txindex"],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Independent regimes; do NOT connect the two nodes.
        self.setup_nodes()

    def init_wallet(self, *, node):
        # VoidCoin refuses legacy/bech32 addresses, so the framework's default
        # importprivkey(deterministic legacy coinbase key) path is unusable.
        # Create a plain "miner" descriptor wallet; keys come from P2QR RPCs.
        self.nodes[node].createwallet(wallet_name="miner",
                                      descriptors=self.options.descriptors,
                                      load_on_startup=True)

    def mine_to_miner(self, node, miner, n):
        addr = miner.getnewvoidcoinp2qrminingaddress()["address"]
        self.generatetoaddress(node, n, addr, sync_fun=self.no_op)

    def run_multisig_fund_and_spend(self, node, label):
        miner = node.get_wallet_rpc("miner")

        # Mature a coinbase so the miner wallet has spendable VOID (100-conf
        # maturity: 130 blocks -> 30 mature coinbases).
        self.mine_to_miner(node, miner, 130)
        assert_greater_than(miner.getbalance(), Decimal("100"))
        assert_greater_than(node.getblockcount(), 1)

        # --- the multisig lives in its OWN wallet (sole UTXO == the spend) -----
        node.createwallet(wallet_name="msig_" + label,
                          descriptors=self.options.descriptors)
        msig_w = node.get_wallet_rpc("msig_" + label)

        signers = [msig_w.getnewvoidcoinp2qraddress() for _ in range(3)]
        msig = msig_w.createp2qrmultisig(2, signers)
        msig_addr = msig["address"]
        assert_equal(msig["required"], 2)
        assert_equal(msig["total"], 3)

        # Signer-program 2-of-3 spend envelope is 3m + n + 2 = 11 pushes,
        # comfortably inside BOTH the legacy and the raised push caps.
        assert_greater_than(LEGACY_PUSH_CAP, 3 * 2 + 3 + 2)

        # --- fund the multisig with a real on-chain output --------------------
        fund_amount = Decimal("25")
        fund_txid = miner.sendtoaddress(msig_addr, fund_amount)
        self.mine_to_miner(node, miner, 1)  # confirm the funding

        utxos = msig_w.listunspent(1, 9999, [msig_addr])
        assert_equal(len(utxos), 1)               # the multisig wallet's SOLE UTXO
        u = utxos[0]
        assert_equal(u["txid"], fund_txid)
        assert_equal(u["address"], msig_addr)
        assert_equal(Decimal(str(u["amount"])), fund_amount)
        assert_equal(Decimal(str(msig_w.getbalance())), fund_amount)
        self.log.info("[%s] funded multisig %s with %s VOID at %s:%d",
                      label, msig_addr, fund_amount, u["txid"], u["vout"])

        # --- SPEND the multisig ------------------------------------------------
        # The msig wallet holds only this one UTXO, so sweeping it (fee taken
        # from the amount) provably spends the multisig itself. The node signs
        # the 2-of-3 ML-DSA-87 P2QR scriptSig via its wallet-native spend path.
        dest = miner.getnewvoidcoinp2qraddress()
        spend_txid = msig_w.sendtoaddress(address=dest, amount=fund_amount,
                                          subtractfeefromamount=True)

        # It must be a valid, mempool-accepted spend of that exact input.
        entry = node.getmempoolentry(spend_txid)
        assert_greater_than(entry["vsize"], 0)
        raw = node.getrawtransaction(spend_txid, True)
        spent_inputs = {(vin["txid"], vin["vout"]) for vin in raw["vin"]}
        assert_equal(spent_inputs, {(u["txid"], u["vout"])})

        # Confirm it and prove spendability end-to-end.
        self.mine_to_miner(node, miner, 1)
        spent = node.getrawtransaction(spend_txid, True)
        assert_greater_than(spent["confirmations"], 0)

        # The funding multisig UTXO is now consumed.
        assert_equal(node.gettxout(u["txid"], u["vout"]), None)
        assert_equal(Decimal(str(msig_w.getbalance())), Decimal("0"))

        # The swept funds landed in the miner wallet (recovered from multisig).
        recovered = miner.listunspent(1, 9999, [dest])
        assert_equal(len(recovered), 1)
        assert_greater_than(fund_amount, Decimal(str(recovered[0]["amount"])))  # minus fee
        self.log.info("[%s] multisig SPENT in %s (recovered %s VOID)",
                      label, spend_txid, recovered[0]["amount"])
        node.unloadwallet("msig_" + label)

    def run_test(self):
        # VCIP-3 active regime: raised push cap -> multisig spendable.
        self.log.info("node0: VCIP-3 ACTIVE (activationheight=1)")
        assert_equal(self.nodes[0].getblockchaininfo()["blocks"], 0)
        self.run_multisig_fund_and_spend(self.nodes[0], "VCIP3active")

        # Legacy regime: pre-activation cap in force, normal multisig still spends.
        self.log.info("node1: VCIP-3 INACTIVE (activationheight=1000000)")
        self.run_multisig_fund_and_spend(self.nodes[1], "legacycap")
        assert_greater_than(1000000, self.nodes[1].getblockcount())  # never activated


if __name__ == "__main__":
    VoidCoinPa06MultisigTest(__file__).main()
