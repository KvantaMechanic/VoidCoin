#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VCIP-3 (VC-13): end-to-end test of the 231,000,000 VOID hard supply cap.

Runs a regtest chain with a *tiny* synthetic cap (via -vcip3supplycap) and a
chosen activation height (via -vcip3activationheight), then MINES PAST the cap
and asserts:

  * Phase A (post-activation, cap crossed after activation): cumulative issuance
    (gettxoutsetinfo total_amount) is monotonic, never exceeds the cap, and
    clamps EXACTLY at the cap; every block after the cap mints 0.
  * Phase B (activation gate): before the activation height, per-block emission
    is the full legacy schedule (base 50 VOID or the 200 VOID Void Collapse
    Bounty) EVEN WHEN cumulative issuance already exceeds the tiny cap; from the
    activation height on, emission is clamped (0 here, since already over cap).
  * Phase C (consensus rejection): a coinbase that pays more than the clamped
    subsidy post-activation is invalid (bad-cb-amount).

The per-block assertions key off cumulative deltas, so they are robust to the
(random, ~1/500) Void Collapse Bounty blocks that regtest may produce. Coinbases
pay to a P2SH(OP_TRUE) output, which VoidCoin's coinbase output-type policy
accepts (native P2QR or wrapped P2SH only).
"""
from decimal import Decimal

from test_framework.address import script_to_p2sh
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import COIN
from test_framework.script import CScript, OP_TRUE
from test_framework.script_util import script_to_p2sh_script
from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import assert_equal

BASE = Decimal("50")      # base subsidy, VOID
BOUNTY = Decimal("200")   # Void Collapse Bounty, VOID

REDEEM = CScript([OP_TRUE])
P2SH_ADDR = script_to_p2sh(REDEEM)          # base58 P2SH address for mining
P2SH_SPK = script_to_p2sh_script(REDEEM)    # the corresponding scriptPubKey


class Vcip3SupplyCapTest(VoidCoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # node0: cap crossed AFTER activation (exact-cap + overpay reject).
        # node1: activation deferred so we can observe the pre-activation gate.
        self.cap0 = Decimal("1000")   # VOID
        self.cap1 = Decimal("1000")   # VOID
        # Keep the whole test inside the first halving window (regtest halves the
        # subsidy every 150 blocks) so the pre-activation schedule is a clean
        # 50 VOID (or the 200 VOID bounty) and the arithmetic stays exact.
        self.activation1 = 140
        self.extra_args = [
            ["-vcip3activationheight=1",
             "-vcip3supplycap=%d" % int(self.cap0 * COIN)],
            ["-vcip3activationheight=%d" % self.activation1,
             "-vcip3supplycap=%d" % int(self.cap1 * COIN)],
        ]

    def setup_network(self):
        # Start both nodes but DO NOT connect them: node0 and node1 run
        # different cap/activation regimes on independent chains.
        self.setup_nodes()

    def mine(self, node):
        self.generatetoaddress(node, 1, P2SH_ADDR, sync_fun=self.no_op)

    def total_issued(self, node):
        # UTXO-set total == cumulative coinbase issuance (no spends, fees == 0;
        # the genesis coinbase is excluded from the UTXO set).
        return node.gettxoutsetinfo()["total_amount"]

    def run_test(self):
        self.phase_a_exact_cap()
        self.phase_b_activation_gate()
        self.phase_c_overpay_rejected()

    def phase_a_exact_cap(self):
        node = self.nodes[0]
        self.log.info("Phase A: cumulative issuance clamps exactly at the cap")

        prev = Decimal("0")
        reached_cap = False
        # 1000 VOID cap / 50 per block => ~20 blocks to the cap; mine well past.
        for _ in range(60):
            self.mine(node)
            total = self.total_issued(node)
            delta = total - prev
            # Never exceed the cap.
            assert total <= self.cap0, f"issuance {total} exceeded cap {self.cap0}"
            assert delta >= 0
            # Every block *strictly after* the cap is reached mints exactly 0
            # (tail/bounty neutralized). Check with the PRIOR reached_cap so the
            # crossing block itself (which may mint a partial subsidy) is exempt.
            if reached_cap:
                assert_equal(delta, Decimal("0"))
            if total == self.cap0:
                reached_cap = True
            prev = total

        assert reached_cap, "cap was never reached"
        assert_equal(self.total_issued(node), self.cap0)

    def phase_b_activation_gate(self):
        node = self.nodes[1]
        self.log.info("Phase B: pre-activation emission ignores the cap; "
                      "post-activation it clamps")

        prev = Decimal("0")
        pre_over_cap = False
        for _ in range(self.activation1 + 5):
            height = node.getblockcount() + 1
            self.mine(node)
            total = self.total_issued(node)
            delta = total - prev
            if height < self.activation1:
                # Full legacy schedule: base or bounty, NEVER a partial clamp,
                # even after cumulative has blown past the tiny cap.
                assert delta in (BASE, BOUNTY), \
                    f"pre-activation block {height} minted {delta}, not schedule"
                if total > self.cap1:
                    pre_over_cap = True
            else:
                # At/after activation and already over cap => mint nothing.
                assert_equal(delta, Decimal("0"))
            prev = total

        assert pre_over_cap, "cumulative never exceeded cap pre-activation"

    def phase_c_overpay_rejected(self):
        node = self.nodes[0]
        self.log.info("Phase C: an over-paying coinbase is bad-cb-amount")

        # node0 is past its cap, so the allowed subsidy is 0. Build a block whose
        # coinbase pays 1 VOID (to a P2SH output so it passes the output-type
        # policy) and submit it: consensus must reject it on the AMOUNT.
        tip = node.getbestblockhash()
        tmpl = node.getblocktemplate({"rules": []})
        height = tmpl["height"]
        # nValue != 50 => create_coinbase uses the literal value with no halving.
        coinbase = create_coinbase(height, script_pubkey=P2SH_SPK, nValue=1)
        block = create_block(int(tip, 16), coinbase, tmpl=tmpl)
        block.solve()

        result = node.submitblock(block.serialize().hex())
        assert_equal(result, "bad-cb-amount")
        assert_equal(node.getbestblockhash(), tip)  # tip did not advance
        # And the honestly-mined next block (subsidy 0) is accepted, staying at cap.
        self.mine(node)
        assert_equal(self.total_issued(node), self.cap0)


if __name__ == "__main__":
    Vcip3SupplyCapTest(__file__).main()
