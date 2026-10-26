#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VCIP-3 (VC-13): activation sentinel (fix #1) + activation atomicity.

Exercises the flag-day gate for the VCIP-3 supply-cap consensus rule, reusing the
two regtest knobs from feature_vcip3_supply_cap.py:

  * -vcip3supplycap=<sat>    : a *tiny* synthetic 231M-VOID hard cap so the clamp
                               is observable in a handful of blocks.
  * -vcip3activationheight=H : the flag-day the VCIP-3 rules turn on.

IMPORTANT regtest fact (verified against src/kernel/chainparams.cpp):
  On REGTEST, nVCIP3ActivationHeight DEFAULTS TO 0 (VCIP-3 active from genesis,
  "consistent with P2QR" -- CRegTestParams line ~495), NOT the INT_MAX sentinel.
  The INT_MAX sentinel (fix #1) is the compiled-in default for MAINNET / TESTNET /
  SIGNET (chainparams.cpp lines ~118 / ~270 / ~418, each flagged with a
  "TODO: set the announced VCIP-3 activation height" so no real network ever
  fail-opens at genesis). Therefore the sentinel is validated on regtest by
  DRIVING that exact INT_MAX value through -vcip3activationheight, not by omitting
  the knob (omitting it selects the regtest default 0, which DOES engage).

Three independent regtest chains (unconnected nodes):

  CHECK A  -- SENTINEL INERT (fix #1). node0 sets -vcip3activationheight=INT_MAX
    (2147483647, the very value the non-regtest params default to) plus the tiny
    cap. We mine far past the height at which the tiny cap would clamp and confirm
    the fork never engages: every block keeps minting the full legacy schedule and
    cumulative issuance blows well past the tiny cap.

  CHECK A' -- SENTINEL IS LOAD-BEARING (contrast). node1 sets the SAME tiny cap but
    OMITS the activation knob, selecting the regtest default (activation height 0).
    The identical cap now DOES clamp: cumulative issuance stops exactly at the cap
    and later blocks mint 0. Same cap, only the activation height differs, and the
    behavior flips inert -> engaged -- i.e. the sentinel is what holds the fork off.

  CHECK B  -- ATOMIC OFF-BY-ONE BOUNDARY. node2 sets the tiny cap AND a finite
    activation height H. Before H the rule is byte-identical to base (full legacy
    schedule despite the tiny cap); at H it engages exactly. The boundary is nailed
    through the CONSENSUS validator: the SAME hand-built coinbase (full legacy
    50 VOID) is ACCEPTED at H-1 but REJECTED (bad-cb-amount) at H, and honest
    mining at/after H mints exactly 0.

Coinbases pay to a P2SH(OP_TRUE) output, which VoidCoin's coinbase output-type
policy accepts (native P2QR or wrapped P2SH only), mirroring the sibling test.
"""
from decimal import Decimal

from test_framework.address import script_to_p2sh
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import COIN
from test_framework.script import CScript, OP_TRUE
from test_framework.script_util import script_to_p2sh_script
from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

BASE = Decimal("50")      # base subsidy, VOID
BOUNTY = Decimal("200")   # Void Collapse Bounty, VOID
INT_MAX = 2147483647      # the fix-#1 sentinel value (std::numeric_limits<int>::max())

REDEEM = CScript([OP_TRUE])
P2SH_ADDR = script_to_p2sh(REDEEM)          # base58 P2SH address for mining
P2SH_SPK = script_to_p2sh_script(REDEEM)    # the corresponding scriptPubKey


class VoidCoinActivationTest(VoidCoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        # Tiny synthetic cap so it is crossed in ~20 blocks (1000 / 50).
        self.cap = Decimal("1000")   # VOID
        # Activation flag-day for CHECK B. Kept inside the first halving window
        # (regtest halves every 150 blocks) so the pre-fork schedule is a clean
        # 50 VOID (or the 200 VOID bounty) and the arithmetic is exact.
        self.H = 130
        cap_sat = int(self.cap * COIN)
        self.extra_args = [
            # CHECK A: drive the INT_MAX sentinel -> VCIP-3 inert.
            ["-vcip3activationheight=%d" % INT_MAX, "-vcip3supplycap=%d" % cap_sat],
            # CHECK A': omit the knob -> regtest default activation 0 -> engages.
            ["-vcip3supplycap=%d" % cap_sat],
            # CHECK B: finite activation height H.
            ["-vcip3activationheight=%d" % self.H, "-vcip3supplycap=%d" % cap_sat],
        ]

    def setup_network(self):
        # Independent regimes on independent chains: start but do not connect.
        self.setup_nodes()

    def mine(self, node):
        self.generatetoaddress(node, 1, P2SH_ADDR, sync_fun=self.no_op)

    def total_issued(self, node):
        # UTXO-set total == cumulative coinbase issuance (no spends, fees == 0;
        # the genesis coinbase is excluded from the UTXO set).
        return node.gettxoutsetinfo()["total_amount"]

    def run_test(self):
        self.check_a_sentinel_inert()
        self.check_a_contrast_engages()
        self.check_b_activation_atomic()

    def check_a_sentinel_inert(self):
        node = self.nodes[0]
        self.log.info("CHECK A: INT_MAX sentinel -> VCIP-3 never engages, the tiny "
                      "cap does not clamp emission")

        prev = Decimal("0")
        crossed_cap = False
        # 1000 VOID cap / 50 per block => the cap height would be ~20. Mine WAY
        # past it; if the fork engaged at any height <= 50 the cap would clamp.
        N = 50
        for _ in range(N):
            self.mine(node)
            total = self.total_issued(node)
            delta = total - prev
            # Sentinel => every block mints the full legacy schedule, NEVER a
            # partial cap clamp, no matter how far past the tiny cap.
            assert delta in (BASE, BOUNTY), \
                f"sentinel: block minted {delta}, not the legacy schedule"
            if total > self.cap:
                crossed_cap = True
            prev = total

        assert crossed_cap, "cumulative issuance never exceeded the tiny cap"
        final = self.total_issued(node)
        # Cumulative issuance sits far above the tiny cap: the fork is inert.
        assert_greater_than(final, self.cap * 2)  # >= 2500 VOID vs 1000 cap
        self.log.info("  sentinel OK: issued %s VOID vs tiny cap %s VOID, "
                      "cap never engaged" % (final, self.cap))

    def check_a_contrast_engages(self):
        node = self.nodes[1]
        self.log.info("CHECK A': same tiny cap, regtest-default activation (0) -> "
                      "the cap DOES clamp (sentinel is load-bearing)")

        prev = Decimal("0")
        reached_cap = False
        saw_zero_after_cap = False
        # Mine well past the ~20-block cap height.
        for _ in range(30):
            self.mine(node)
            total = self.total_issued(node)
            delta = total - prev
            # With the fork active from genesis the cap is enforced from block 1.
            assert total <= self.cap, f"issuance {total} exceeded cap {self.cap}"
            assert delta >= 0
            if reached_cap:
                # Every block strictly after the cap is reached mints 0.
                assert_equal(delta, Decimal("0"))
                saw_zero_after_cap = True
            if total == self.cap:
                reached_cap = True
            prev = total

        assert reached_cap, "cap was never reached under the regtest default"
        assert saw_zero_after_cap, "no post-cap block minted 0"
        assert_equal(self.total_issued(node), self.cap)
        self.log.info("  contrast OK: identical cap clamps exactly at %s VOID when "
                      "the sentinel is absent" % self.cap)

    def check_b_activation_atomic(self):
        node = self.nodes[2]
        self.log.info("CHECK B: activation at H=%d is byte-identical to base before "
                      "H and engages exactly AT H" % self.H)

        # --- Pre-activation: mine up to and including H-2. Every block mints the
        #     full legacy schedule; the tiny cap is inert even once cumulative
        #     issuance has blown past it. This is the "== legacy before H" leg.
        prev = Decimal("0")
        over_cap_pre = False
        while node.getblockcount() < self.H - 2:
            height = node.getblockcount() + 1
            self.mine(node)
            total = self.total_issued(node)
            delta = total - prev
            assert height < self.H
            assert delta in (BASE, BOUNTY), \
                f"pre-activation block {height} minted {delta}, not legacy schedule"
            if total > self.cap:
                over_cap_pre = True
            prev = total

        assert_equal(node.getblockcount(), self.H - 2)
        assert over_cap_pre, "cumulative never exceeded cap before activation"
        pre_total = prev  # cumulative issuance at H-2, already >> cap

        # --- Off-by-one boundary via the CONSENSUS validator. The SAME coinbase
        #     (full legacy 50 VOID) is legal at H-1 and illegal at H.

        # H-1 (pre-activation): a coinbase paying the full legacy 50 VOID is
        # ACCEPTED, because before H the cap clamp is a no-op.
        tip = node.getbestblockhash()
        tmpl = node.getblocktemplate({"rules": []})
        assert_equal(tmpl["height"], self.H - 1)
        cb_hm1 = create_coinbase(self.H - 1, script_pubkey=P2SH_SPK, nValue=50)
        blk_hm1 = create_block(int(tip, 16), cb_hm1, tmpl=tmpl)
        blk_hm1.solve()
        res = node.submitblock(blk_hm1.serialize().hex())
        assert res is None, f"H-1 full-subsidy coinbase unexpectedly rejected: {res}"
        assert_equal(node.getblockcount(), self.H - 1)
        assert_equal(node.getbestblockhash(), "%064x" % blk_hm1.sha256)
        # That block minted the full 50 VOID (cap inert pre-activation).
        assert_equal(self.total_issued(node) - pre_total, BASE)
        self.log.info("  H-1 (pre-fork): full 50 VOID coinbase ACCEPTED")

        # H (activation): the IDENTICAL 50-VOID coinbase is now an overpay because
        # cumulative issuance is over the cap => allowed subsidy is 0. Consensus
        # must reject it on the amount, and the tip must not advance.
        tip = node.getbestblockhash()
        tmpl = node.getblocktemplate({"rules": []})
        assert_equal(tmpl["height"], self.H)
        cb_h = create_coinbase(self.H, script_pubkey=P2SH_SPK, nValue=50)
        blk_h = create_block(int(tip, 16), cb_h, tmpl=tmpl)
        blk_h.solve()
        res = node.submitblock(blk_h.serialize().hex())
        assert_equal(res, "bad-cb-amount")
        assert_equal(node.getbestblockhash(), tip)          # tip did not advance
        assert_equal(node.getblockcount(), self.H - 1)
        self.log.info("  H   (fork on): identical 50 VOID coinbase REJECTED "
                      "(bad-cb-amount) -> validator flips atomically at H")

        # The honestly-mined activation block (allowed subsidy 0) is accepted and
        # mints exactly 0: emission engine agrees with the validator at H.
        before = self.total_issued(node)
        self.mine(node)
        assert_equal(node.getblockcount(), self.H)
        assert_equal(self.total_issued(node) - before, Decimal("0"))

        # And it stays clamped for subsequent blocks post-activation.
        prev = self.total_issued(node)
        for _ in range(5):
            self.mine(node)
            total = self.total_issued(node)
            assert_equal(total - prev, Decimal("0"))
            prev = total
        self.log.info("  post-fork blocks mint exactly 0 (cap holds)")


if __name__ == "__main__":
    VoidCoinActivationTest(__file__).main()
