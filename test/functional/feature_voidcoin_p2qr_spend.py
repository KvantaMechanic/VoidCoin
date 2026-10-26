#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end exercise of the O(N) VoidCoin P2QR sighash on a running regtest chain.

VoidCoin replaces ECDSA with ML-DSA-87 P2QR outputs. The consensus sighash was
rewritten to build a single per-transaction midstate (HashPrevouts / HashSequences
/ HashOutputs / HashSpentAmounts / HashSpentScripts) that every input reuses, so a
transaction with N P2QR inputs is validated in O(N) instead of O(N^2). This test
proves that rewrite works against a live node, not just against static unit vectors,
by having the wallet build, sign, broadcast and confirm real P2QR spends:

  * Phase 1 (single-sig P2QR spend): mine to a P2QR mining address to get spendable
    coins, fund a native P2QR address, then spend it. Assert the spend enters the
    mempool, confirms in a block, and both wallets' balances update by exactly the
    transferred amount (and the fee).

  * Phase 2 (multi-input P2QR spend -- the O(N) midstate case): fund a fresh wallet
    with several separate native P2QR UTXOs, then spend an amount large enough to
    force coin selection to combine multiple of them into ONE transaction. Assert the
    resulting tx really has >= 2 inputs, that every input's prevout is a native
    `voidcoin_p2qr` output, and that it enters the mempool and confirms -- i.e. the
    shared per-tx midstate produced a valid sighash for every input.

To keep balance assertions immune to coinbase maturation, ALL coinbases live in a
dedicated `bank` wallet (which mines and receives every confirming block); the
spending/receiving wallets under test are funded only with ordinary, already-mature
native P2QR UTXOs. Everything is driven through wallet/node RPCs; the node builds and
signs the P2QR transactions itself. No transactions are hand-constructed.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
    assert_raises_rpc_error,
)

P2QR_OUTPUT_TYPES = ("voidcoin_p2qr", "scripthash")  # native, or wrapped-P2QR P2SH


class VoidCoinP2QRSpendTest(VoidCoinTestFramework):
    def add_options(self, parser):
        # Enable the wallet subsystem (so the node does NOT get -disablewallet) but
        # WITHOUT setting _requires_wallet, so the framework won't auto-create a
        # default wallet and importprivkey a legacy coinbase key (which VoidCoin's
        # P2QR-only wallet path does not use). We create P2QR wallets ourselves.
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # -txindex so we can look up any confirmed parent tx to verify each spent
        # input was a native P2QR output. -fallbackfee so the wallet can attach a
        # fee on regtest (no fee-estimation data). P2QR txs are large but the fee
        # is charged on the P2QR-adjusted virtual size, so this stays cheap.
        self.extra_args = [["-txindex=1", "-fallbackfee=0.0002"]]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.test_framework import SkipTest
            raise SkipTest("wallet has not been compiled.")

    def spk_type(self, txid, vout):
        """scriptPubKey 'type' string of a given output (needs -txindex)."""
        rawtx = self.nodes[0].getrawtransaction(txid, True)
        return rawtx["vout"][vout]["scriptPubKey"]["type"]

    def run_test(self):
        node = self.nodes[0]

        # bank owns every coinbase and receives every confirming block, so the
        # wallets under test never hold (maturing) coinbases and their balances are
        # exact. bob/dave are payees; alice/carol are the P2QR spenders.
        for name in ("bank", "alice", "bob", "carol", "dave"):
            node.createwallet(wallet_name=name)
        self.bank = node.get_wallet_rpc("bank")

        # A P2QR mining address: BTC-style P2SH wrapper whose redeemScript is a
        # native VoidCoin P2QR program. Coinbase output-type policy accepts it and
        # the wallet can spend it through the P2QR path.
        self.sink = self.bank.getnewvoidcoinp2qrminingaddress()["address"]
        self.log.info("P2QR mining address (wrapped P2SH): %s", self.sink)

        # Mine 130 blocks to it. With regtest's 50 VOID base subsidy (halving every
        # 150), heights 1..30 mature (>100 confs) -> ~1500 VOID spendable in bank.
        self.confirm(130)
        assert_equal(node.getblockcount(), 130)
        assert_greater_than(self.bank.getbalance(), Decimal("1000"))

        self.phase1_single_sig_spend(node)
        self.phase2_multi_input_spend(node)

    def confirm(self, n=1):
        """Mine n blocks (all coinbases go to the bank sink) and return hashes."""
        return self.generatetoaddress(self.nodes[0], n, self.sink, sync_fun=self.no_op)

    def fund(self, dest_wallet, amounts):
        """From bank, create one native-P2QR UTXO per value in `amounts`, confirmed."""
        addr = dest_wallet.getnewvoidcoinp2qraddress()
        for value in amounts:
            self.bank.sendtoaddress(addr, value)
        self.confirm(1)
        return addr

    # --------------------------------------------------------------------- #
    def phase1_single_sig_spend(self, node):
        self.log.info("Phase 1: single-sig P2QR spend enters mempool and confirms")
        alice = node.get_wallet_rpc("alice")
        bob = node.get_wallet_rpc("bob")

        # Fund alice with a single, clean native-P2QR UTXO of 200 VOID.
        self.fund(alice, [Decimal("200")])
        assert_equal(alice.getbalance(), Decimal("200"))
        assert_equal(len(alice.listunspent()), 1)

        # Native P2QR (ML-DSA-87) inputs cannot be carried in a BIP-174 PSBT. The
        # PSBT spend paths must fail with the clear, specific "not supported in
        # PSBT" error (RPC_INVALID_PARAMETER, -8) that points at the working spend
        # paths, NOT the generic "Signer does not support PSBT". Direct-sign
        # (sendtoaddress, below) is the supported path and must still work.
        psbt_dest = bob.getnewvoidcoinp2qraddress()
        assert_raises_rpc_error(-8, "not supported in PSBT",
                                alice.walletcreatefundedpsbt, [], {psbt_dest: 1})
        assert_raises_rpc_error(-8, "not supported in PSBT",
                                alice.send, {psbt_dest: 1})

        bob_addr = bob.getnewvoidcoinp2qraddress()
        amount = Decimal("100")
        txid = alice.sendtoaddress(bob_addr, amount)

        # The wallet built & signed a real P2QR spend and it is now in the mempool.
        assert txid in node.getrawmempool(), "spend tx did not enter the mempool"
        entry = alice.gettransaction(txid)
        assert_equal(entry["confirmations"], 0)
        fee = -entry["fee"]  # gettransaction reports fee as a negative number
        assert_greater_than(fee, Decimal("0"))

        decoded = node.getrawtransaction(txid, True)
        # Single native-P2QR input -> the P2QR sighash ran over exactly one input.
        assert_equal(len(decoded["vin"]), 1)
        in0 = decoded["vin"][0]
        assert_equal(self.spk_type(in0["txid"], in0["vout"]), "voidcoin_p2qr")
        # The payment output to bob is a native P2QR output; the change is a P2QR form.
        pay_out = [o for o in decoded["vout"]
                   if o["scriptPubKey"].get("address") == bob_addr]
        assert_equal(len(pay_out), 1)
        assert_equal(pay_out[0]["scriptPubKey"]["type"], "voidcoin_p2qr")
        assert_equal(pay_out[0]["value"], amount)
        for o in decoded["vout"]:
            assert o["scriptPubKey"]["type"] in P2QR_OUTPUT_TYPES, \
                "wallet produced a non-P2QR output: %s" % o["scriptPubKey"]["type"]

        # Confirm it.
        blockhash = self.confirm(1)[0]
        assert txid in node.getblock(blockhash)["tx"], "spend not included in block"
        assert_equal(alice.gettransaction(txid)["confirmations"], 1)
        assert txid not in node.getrawmempool()

        # Balances updated: bob got exactly `amount`; alice dropped by amount+fee.
        assert_equal(bob.getbalance(), amount)
        assert_equal(alice.getbalance(), Decimal("200") - amount - fee)
        self.log.info("Phase 1 OK: bob=%s VOID, alice=%s VOID, fee=%s VOID",
                      bob.getbalance(), alice.getbalance(), fee)

    # --------------------------------------------------------------------- #
    def phase2_multi_input_spend(self, node):
        self.log.info("Phase 2: multi-input P2QR spend (shared O(N) midstate)")
        carol = node.get_wallet_rpc("carol")
        dave = node.get_wallet_rpc("dave")

        # Give carol five SEPARATE native P2QR UTXOs of 20 VOID each (one address,
        # five confirmed payments), so a large spend must combine several of them.
        piece = Decimal("20")
        n_pieces = 5
        self.fund(carol, [piece] * n_pieces)
        assert_equal(carol.getbalance(), piece * n_pieces)
        assert_equal(len(carol.listunspent()), n_pieces)

        # Spend 90 VOID -> must combine >= 5 of the 20-VOID UTXOs into one tx.
        dave_addr = dave.getnewvoidcoinp2qraddress()
        send_amount = Decimal("90")
        txid = carol.sendtoaddress(dave_addr, send_amount)

        assert txid in node.getrawmempool(), "multi-input spend not in mempool"
        decoded = node.getrawtransaction(txid, True)

        # This is the case the midstate optimizes: many P2QR inputs in one tx.
        assert_greater_than_or_equal(len(decoded["vin"]), 2)
        self.log.info("Multi-input spend has %d inputs", len(decoded["vin"]))
        for vin in decoded["vin"]:
            assert_equal(self.spk_type(vin["txid"], vin["vout"]), "voidcoin_p2qr")

        fee = -carol.gettransaction(txid)["fee"]

        # Confirm: the block-validation path recomputes the shared midstate once and
        # verifies every P2QR input against it. If any input's sighash were wrong the
        # block would be rejected and this tx would never confirm.
        blockhash = self.confirm(1)[0]
        assert txid in node.getblock(blockhash)["tx"], "multi-input spend not mined"
        assert_equal(carol.gettransaction(txid)["confirmations"], 1)
        assert txid not in node.getrawmempool()

        # Balances updated across the multi-input spend.
        assert_equal(dave.getbalance(), send_amount)
        assert_equal(carol.getbalance(), piece * n_pieces - send_amount - fee)
        self.log.info("Phase 2 OK: dave=%s VOID over a %d-input P2QR tx, carol=%s VOID, fee=%s VOID",
                      dave.getbalance(), len(decoded["vin"]), carol.getbalance(), fee)


if __name__ == "__main__":
    VoidCoinP2QRSpendTest(__file__).main()
