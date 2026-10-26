#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VCIP-3 P2QR time-lock: reorg mempool eviction of a now-premature spend.

Regression guard for the reorg mempool-eviction fix.

A time-lock spend that is valid at the current tip (its absolute-height lock has
matured, spend_height = tip+1 >= lock_value) can become PREMATURE again if a reorg
lowers the tip below the lock's maturity. Before the fix, such a spend survived in
the mempool after the reorg; with -checkmempool the subsequent mempool.check() ran
CheckTxInputs against the new tip, found the spend now consensus-invalid, and tripped
its assert -- crashing the node.

The fix extends Chainstate::MaybeUpdateMempoolForReorg's eviction filter
(filter_final_and_mature) to re-run the VCIP-3 time-lock gate against the NEW tip
(next-block height tip+1, and BIP113 MTP) and evict any spend whose lock is no longer
met -- kept in lockstep with Consensus::CheckTxInputs, so mempool.check() stays
consistent and never asserts.

This test, with -checkmempool=1 so mempool.check() runs on every block-connect and
reorg, proves the eviction end to end:

  1. Fund a height-locked (lock_value = L) time-lock output, confirmed deep.
  2. Mine the tip to exactly L-1, so a spend (spend_height = tip+1 = L >= L) is valid;
     broadcast a hand-built ML-DSA-87 spend and confirm it enters the mempool.
  3. invalidateblock the tip -> tip drops to L-2 -> the spend is now premature
     (spend_height = L-1 < L). Assert it was evicted from the mempool and the node is
     still alive and consistent (no mempool.check() assert crash).
  4. reconsiderblock restores the tip to L-1, and the spend is re-accepted -- proving
     the eviction was purely maturity-driven, not corruption.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import assert_equal, assert_greater_than


class VoidCoinTimeLockReorgTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # VCIP-3 active from height 1 (so time-lock outputs are creatable), and
        # -checkmempool=1 so mempool.check() runs on every block/reorg -- this is
        # what would assert/crash if the eviction fix regressed.
        self.extra_args = [[
            "-txindex=1",
            "-fallbackfee=0.0002",
            "-checkmempool=1",
            "-vcip3activationheight=1",
        ]]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.test_framework import SkipTest
            raise SkipTest("wallet has not been compiled.")

    def confirm(self, n=1):
        """Mine n blocks to the bank sink (keeps coinbases out of the vault wallet)."""
        return self.generatetoaddress(self.nodes[0], n, self.sink, sync_fun=self.no_op)

    def run_test(self):
        node = self.nodes[0]
        for name in ("bank", "vault", "payee"):
            node.createwallet(wallet_name=name)
        self.bank = node.get_wallet_rpc("bank")
        vault = node.get_wallet_rpc("vault")
        payee = node.get_wallet_rpc("payee")

        # All coinbases live in the bank sink so the vault balance stays exact.
        self.sink = self.bank.getnewvoidcoinp2qrminingaddress()["address"]
        self.confirm(130)
        assert_greater_than(self.bank.getbalance(), Decimal("1000"))

        # --- Choose a maturity height L far enough ahead that funding confirms deep. ---
        tip = node.getblockcount()
        L = tip + 15
        res = vault.getnewtimelockaddress("height", L, "reorg vault")
        vqt_addr = res["address"]
        assert_equal(res["lock_type"], "height")
        assert_equal(res["lock_value"], L)
        assert_equal(res["timelock_version"], 1)

        # --- Fund the time-lock output and confirm it DEEP (well below L-1), so the
        #     one-block reorg later does not disconnect the funding tx. ---
        amount = Decimal("50")
        fund_txid = self.bank.sendtoaddress(vqt_addr, amount)
        assert fund_txid in node.getrawmempool()
        self.confirm(1)
        fund_height = node.getblockcount()
        decoded = node.getrawtransaction(fund_txid, True)
        tl_vout = next(o["n"] for o in decoded["vout"]
                       if o["scriptPubKey"].get("address") == vqt_addr)
        assert_equal(decoded["vout"][tl_vout]["scriptPubKey"]["type"],
                     "voidcoin_p2qr_timelock")
        assert_equal(vault.getbalance(), amount)
        assert_greater_than(L - 1, fund_height + 5)  # funding is many blocks below L-1
        self.log.info("time-lock output funded at height %d, matures at L=%d",
                      fund_height, L)

        # --- Mine to exactly L-1 so a spend (spend_height = tip+1 = L) is valid. ---
        self.confirm((L - 1) - node.getblockcount())
        assert_equal(node.getblockcount(), L - 1)

        # --- Build + sign the time-lock spend by hand (P2QR inputs are not
        #     PSBT-carriable), broadcast it, and confirm it is accepted at tip L-1. ---
        payee_addr = payee.getnewvoidcoinp2qraddress()
        change_addr = vault.getnewvoidcoinp2qraddress()
        raw = node.createrawtransaction(
            [{"txid": fund_txid, "vout": tl_vout}],
            [{payee_addr: Decimal("10")}, {change_addr: amount - Decimal("10.01")}])
        signed = vault.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        spend_txid = node.sendrawtransaction(signed["hex"])
        assert spend_txid in node.getrawmempool(), \
            "matured time-lock spend must be accepted at tip L-1"
        self.log.info("time-lock spend %s accepted into mempool at tip %d",
                      spend_txid, node.getblockcount())

        # --- REORG: invalidate the tip so it drops to L-2; the spend
        #     (spend_height = L-1 < L) is now premature and must be evicted. ---
        invalidated = node.getbestblockhash()
        node.invalidateblock(invalidated)
        assert_equal(node.getblockcount(), L - 2)
        assert spend_txid not in node.getrawmempool(), \
            "a now-premature time-lock spend must be evicted from the mempool after reorg"
        self.log.info("reorg to tip %d evicted the now-premature spend", node.getblockcount())

        # --- Node is still alive and consistent: no mempool.check() assert crash.
        #     Read-only mempool + mining calls must still work. ---
        assert_equal(node.getblockcount(), L - 2)
        node.getmempoolinfo()
        tmpl = node.getblocktemplate({"rules": []})
        assert_equal(tmpl["height"], L - 1)
        # The funding tx survived the reorg (it was confirmed deep).
        assert_equal(node.getrawtransaction(fund_txid, True)["confirmations"] >= 1, True)
        self.log.info("node consistent after reorg (getmempoolinfo/getblocktemplate OK)")

        # --- reconsiderblock restores tip to L-1; the spend is re-acceptable,
        #     proving eviction was purely maturity-driven. ---
        node.reconsiderblock(invalidated)
        assert_equal(node.getblockcount(), L - 1)
        readmit_txid = node.sendrawtransaction(signed["hex"])
        assert_equal(readmit_txid, spend_txid)
        assert spend_txid in node.getrawmempool(), \
            "the spend must be re-acceptable once the tip is restored to L-1"
        self.log.info("tip restored to %d; spend re-accepted -- eviction was "
                      "maturity-driven only", node.getblockcount())


if __name__ == "__main__":
    VoidCoinTimeLockReorgTest(__file__).main()
