#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VCIP-3 P2QR time-lock: the coinbase pre-activation output-creation gate.

Regression guard for the pre-activation COINBASE consensus-split fix.

The 45-byte VCIP-3 time-lock output shape

    OP_RESERVED(0x50) <program[32]> <lock_descriptor[10]>   (45 bytes)

is permitted by VoidCoin's *context-free* output rule (IsVoidCoinAllowedOutputScript
in consensus/tx_check.cpp), so it is not rejected as bad-txns-forbidden-output. For
ordinary transactions, whether such an output may be CREATED before the VCIP-3
activation height is gated inside Consensus::CheckTxInputs -- but the coinbase never
passes through CheckTxInputs (it has no prevouts), so that height gate did not apply
to it. A pre-activation coinbase carrying a time-lock output was therefore ACCEPTED
by an upgraded node while a base (pre-fork) node rejects the shape outright as
bad-txns-forbidden-output -- a single miner could thus partition upgraded from base
nodes during rollout (a consensus split).

The fix adds a coinbase branch to ConnectBlock that, for block height <
nVCIP3ActivationHeight, rejects any coinbase output whose scriptPubKey is a time-lock
shape with reason "bad-txns-timelock-output-premature". Post-activation a coinbase
MAY carry a time-lock output (accepted). This test drives that height boundary end to
end against a live regtest node:

  * NEGATIVE (pre-activation): a coinbase whose sole output is a time-lock output,
    paying the correct subsidy and otherwise valid, is rejected on the time-lock
    reason and the tip does not advance.
  * SANITY: an honest P2QR coinbase at the SAME height is accepted -- proving the
    rejection was specifically the time-lock output, not a malformed block.
  * POSITIVE (post-activation): the same time-lock-output coinbase is accepted and
    the tip advances -- proving the gate is a clean height boundary, not a
    permanent ban.
"""
from test_framework.blocktools import create_block, create_coinbase
from test_framework.script import CScript
from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import assert_equal, assert_greater_than

ACTIVATION = 130  # VCIP-3 activation height (override), comfortably above the start


def make_timelock_spk(lock_type, lock_value, program=None):
    """Build the raw 45-byte VCIP-3 P2QR time-lock scriptPubKey.

    The coinbase creation gate keys off the output SHAPE (via IsTimeLockOutput),
    not ownership, so `program` may be any 32 bytes for this test.
    """
    if program is None:
        program = bytes([0x11]) * 32
    assert len(program) == 32
    # descriptor = version(0x01) || lock_type(1) || lock_value(uint64 LE, 8) = 10 bytes
    descriptor = bytes([0x01, lock_type]) + lock_value.to_bytes(8, "little")
    assert len(descriptor) == 10
    # 0x50 = OP_RESERVED; 0x20 pushes the 32-byte program; 0x0a pushes the 10-byte
    # descriptor. 2 + 32 + 1 + 10 = 45 bytes.
    spk = bytes([0x50, 0x20]) + program + bytes([0x0a]) + descriptor
    assert len(spk) == 45
    return spk


class VoidCoinTimeLockCoinbaseTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "-txindex=1",
            "-fallbackfee=0.0002",
            "-vcip3activationheight=%d" % ACTIVATION,
        ]]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.test_framework import SkipTest
            raise SkipTest("wallet has not been compiled.")

    def mine_to(self, node, height):
        """Mine (honest P2QR coinbases) to the bank sink until tip == height."""
        while node.getblockcount() < height:
            self.generatetoaddress(node, 1, self.sink, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), height)

    def submit_timelock_coinbase(self, node):
        """Build+solve a block on the current tip whose sole coinbase output is a
        45-byte time-lock output paying the correct subsidy, submit it, and return
        submitblock's result (reject reason string, or None on accept)."""
        tip = node.getbestblockhash()
        tmpl = node.getblocktemplate({"rules": []})
        height = tmpl["height"]
        # Height lock; the value is irrelevant to the creation gate (shape-only).
        timelock_spk = make_timelock_spk(lock_type=0, lock_value=height + 1000)
        # Default nValue=50 => create_coinbase computes the correct halving-adjusted
        # subsidy, so the ONLY thing wrong pre-activation is the time-lock output.
        coinbase = create_coinbase(height, script_pubkey=CScript(timelock_spk))
        block = create_block(int(tip, 16), coinbase, tmpl=tmpl)
        block.solve()
        return node.submitblock(block.serialize().hex())

    def run_test(self):
        node = self.nodes[0]
        node.createwallet(wallet_name="miner")
        miner = node.get_wallet_rpc("miner")
        # A native-P2QR mining address gives honest, policy-valid coinbases.
        self.sink = miner.getnewvoidcoinp2qrminingaddress()["address"]

        # --- Mine to a height well below the activation height. ---
        self.mine_to(node, ACTIVATION - 10)
        assert_greater_than(ACTIVATION, node.getblockcount() + 1)  # still pre-activation

        # --- NEGATIVE: pre-activation coinbase time-lock output is rejected. ---
        self.log.info("NEGATIVE: pre-activation coinbase time-lock output is rejected")
        pre_tip = node.getbestblockhash()
        pre_height = node.getblockcount()
        res = self.submit_timelock_coinbase(node)
        assert_equal(res, "bad-txns-timelock-output-premature")
        # The rejected block must not have advanced the tip.
        assert_equal(node.getbestblockhash(), pre_tip)
        assert_equal(node.getblockcount(), pre_height)
        self.log.info("  pre-activation coinbase time-lock output rejected: %s", res)

        # --- SANITY: an honest P2QR coinbase at the SAME height is accepted. ---
        self.log.info("SANITY: an honest P2QR coinbase at the same height is accepted")
        self.generatetoaddress(node, 1, self.sink, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), pre_height + 1)
        assert node.getbestblockhash() != pre_tip
        self.log.info("  honest coinbase accepted at height %d (rejection was "
                      "specifically the time-lock output)", pre_height + 1)

        # --- POSITIVE: post-activation, the SAME coinbase shape is accepted. ---
        self.mine_to(node, ACTIVATION)
        assert_equal(node.getblockcount(), ACTIVATION)
        self.log.info("POSITIVE: post-activation coinbase time-lock output is accepted")
        act_tip = node.getbestblockhash()
        # The next block's height (tip+1) is >= ACTIVATION, i.e. post-activation.
        assert_greater_than(node.getblockcount() + 1, ACTIVATION - 1)
        res = self.submit_timelock_coinbase(node)
        assert res is None, \
            "post-activation coinbase time-lock output unexpectedly rejected: %s" % res
        assert node.getbestblockhash() != act_tip           # tip advanced
        assert_equal(node.getblockcount(), ACTIVATION + 1)
        self.log.info("  post-activation coinbase time-lock output accepted; "
                      "tip advanced to height %d", node.getblockcount())


if __name__ == "__main__":
    VoidCoinTimeLockCoinbaseTest(__file__).main()
