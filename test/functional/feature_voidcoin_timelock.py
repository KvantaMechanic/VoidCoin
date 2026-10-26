#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VCIP-3 P2QR time-lock: end-to-end lifecycle on a live regtest chain, driven
through the P2QR wallet/node RPCs with a chosen -vcip3activationheight.

The old VCIP-1 timelock output led with OP_RESERVED but had NO spend path, so
coins sent to it froze forever. VCIP-3 rebuilds it as a versioned, SPENDABLE
output gated on the hard fork:

    OP_QuantumQuark <program[32]> <lock_descriptor[10]>
    lock_descriptor = version(1) || lock_type(1) || lock_value(uint64 LE, 8)

`program` is the SAME single-key P2QR commitment used by native P2QR, so the
spend is a direct extension of native-P2QR CheckSpend, gated on VCIP-3 AND on the
lock (absolute height / absolute median-time-past) having matured.

Unlike feature_voidcoin_timelock_spend.py (which activates VCIP-3 at genesis),
this test drives the activation GATE explicitly via -vcip3activationheight and
covers BOTH lock types:

  * Phase 0 (pre-activation): before the activation height, CREATING a time-lock
    output is refused by consensus (bad-txns-timelock-output-premature), so the
    type is dormant/unfundable -- byte-for-byte the disabled behavior.
  * Phase 1 (absolute height lock): post-activation, fund a height-locked vqt
    address; a spend before the unlock height is rejected
    ("bad-txns-timelock-not-met"); at/after it the wallet's ML-DSA-87 spend
    enters the mempool, confirms, and balances update exactly.
  * Phase 2 (absolute MTP lock): same lifecycle for a time ("median-time-past")
    lock -- rejected while tip MTP < unlock time, accepted once the chain's MTP
    is advanced past it.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_raises_rpc_error,
)

ACTIVATION = 130  # VCIP-3 activation height (override)


class VoidCoinTimeLockTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [[
            "-txindex=1",
            "-fallbackfee=0.0002",
            "-rpcdoccheck=1",
            "-vcip3activationheight=%d" % ACTIVATION,
        ]]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.test_framework import SkipTest
            raise SkipTest("wallet has not been compiled.")

    def confirm(self, n=1):
        """Mine n blocks to the bank sink (keeps all coinbases out of test wallets)."""
        return self.generatetoaddress(self.nodes[0], n, self.sink, sync_fun=self.no_op)

    def run_test(self):
        node = self.nodes[0]
        for name in ("bank", "vaulth", "vaultt", "payeeh", "payeet"):
            node.createwallet(wallet_name=name)
        self.bank = node.get_wallet_rpc("bank")

        # All coinbases live in the bank sink so the tested wallets' balances stay
        # exact. A P2QR (wrapped-P2SH) mining address is accepted by coinbase policy.
        self.sink = self.bank.getnewvoidcoinp2qrminingaddress()["address"]

        # Mine to just below the activation height: mature coins in the bank, but
        # still PRE-activation (mempool spend height = tip+1 < ACTIVATION).
        self.confirm(ACTIVATION - 5)
        assert_greater_than(ACTIVATION, node.getblockcount() + 1)
        assert_greater_than(self.bank.getbalance(), Decimal("500"))

        self.phase0_pre_activation_creation_refused(node)

        # Advance to the activation height. Now time-lock outputs may be created
        # and (once their lock matures) spent.
        while node.getblockcount() < ACTIVATION:
            self.confirm(1)
        assert_equal(node.getblockcount(), ACTIVATION)

        self.phase1_absolute_height_lock(node)
        self.phase2_absolute_mtp_lock(node)

    # ------------------------------------------------------------------ #
    def phase0_pre_activation_creation_refused(self, node):
        self.log.info("Phase 0: pre-activation, time-lock output creation is refused")
        vault = node.get_wallet_rpc("vaulth")

        unlock_height = node.getblockcount() + 50
        res = vault.getnewtimelockaddress("height", unlock_height, "premature vault")
        vqt_addr = res["address"]
        assert_equal(res["timelock_version"], 1)

        # The wallet still builds/signs/commits the funding tx locally, but the
        # node's consensus rules refuse to CREATE a time-lock output before the
        # VCIP-3 activation height, so it never relays.
        txid = self.bank.sendtoaddress(vqt_addr, Decimal("50"))
        assert txid not in node.getrawmempool(), \
            "a pre-activation time-lock funding tx must not relay"
        fund_hex = self.bank.gettransaction(txid)["hex"]
        res = node.testmempoolaccept([fund_hex])[0]
        assert_equal(res["allowed"], False)
        assert "bad-txns-timelock-output-premature" in res["reject-reason"], res["reject-reason"]
        self.log.info("pre-activation creation correctly refused: %s", res["reject-reason"])
        # Free the locked inputs for the real post-activation phases.
        self.bank.abandontransaction(txid)

    # ------------------------------------------------------------------ #
    def phase1_absolute_height_lock(self, node):
        self.log.info("Phase 1: absolute-height lock -- fund, reject premature, spend at maturity")
        vault = node.get_wallet_rpc("vaulth")
        payee = node.get_wallet_rpc("payeeh")

        tip = node.getblockcount()
        unlock_height = tip + 6
        res = vault.getnewtimelockaddress("height", unlock_height, "height vault")
        vqt_addr = res["address"]
        assert_equal(res["lock_type"], "height")
        assert_equal(res["lock_value"], unlock_height)
        assert_equal(res["timelock_version"], 1)

        # RPC descriptions expose the lock.
        va = node.validateaddress(vqt_addr)
        assert_equal(va["isvalid"], True)
        assert_equal(va["isvoidcoinp2qrtimelock"], True)
        assert_equal(va["lock_value"], unlock_height)
        ai = vault.getaddressinfo(vqt_addr)
        assert_equal(ai["ismine"], True)
        assert_equal(ai["istimelocked"], True)
        assert_equal(ai["lock_type_name"], "height")

        # Fund it; the funding tx is standard and confirms.
        amount = Decimal("50")
        fund_txid = self.bank.sendtoaddress(vqt_addr, amount)
        assert fund_txid in node.getrawmempool(), "post-activation funding tx must relay"
        decoded = node.getrawtransaction(fund_txid, True)
        tl_out = [o for o in decoded["vout"]
                  if o["scriptPubKey"].get("address") == vqt_addr]
        assert_equal(len(tl_out), 1)
        assert_equal(tl_out[0]["scriptPubKey"]["type"], "voidcoin_p2qr_timelock")
        self.confirm(1)
        assert_equal(vault.getbalance(), amount)

        # Spending before the unlock height is rejected by consensus. The wallet
        # will NOT auto-select a not-yet-matured time-lock coin (VCIP-3 excludes it
        # from coin selection, exactly like an immature coinbase), so a plain
        # sendtoaddress here fails with "Insufficient funds" rather than building a
        # doomed transaction.
        payee_addr = payee.getnewvoidcoinp2qraddress()
        assert_greater_than(unlock_height, node.getblockcount() + 1)
        assert_raises_rpc_error(-6, "Insufficient funds",
                                vault.sendtoaddress, payee_addr, Decimal("10"))
        # Force the immature coin in via a hand-built raw spend, signed directly by
        # the wallet's ML-DSA-87 signer (the non-PSBT path -- P2QR inputs are not
        # PSBT-carriable), to prove the CONSENSUS gate independently rejects the
        # premature spend at the mempool layer.
        tl_vout = next(o["n"] for o in decoded["vout"]
                       if o["scriptPubKey"].get("address") == vqt_addr)
        change_addr = vault.getnewvoidcoinp2qraddress()
        raw = node.createrawtransaction(
            [{"txid": fund_txid, "vout": tl_vout}],
            [{payee_addr: Decimal("10")}, {change_addr: amount - Decimal("10.01")}])
        signed = vault.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        res = node.testmempoolaccept([signed["hex"]])[0]
        assert_equal(res["allowed"], False)
        assert "bad-txns-timelock-not-met" in res["reject-reason"], res["reject-reason"]
        self.log.info("premature height-lock spend rejected: %s", res["reject-reason"])

        # Mine to the unlock height, then spend for real.
        while node.getblockcount() < unlock_height - 1:
            self.confirm(1)
        assert_equal(node.getblockcount(), unlock_height - 1)

        send_amount = Decimal("10")
        spend_txid = vault.sendtoaddress(payee_addr, send_amount)
        assert spend_txid in node.getrawmempool(), "matured height-lock spend not accepted"
        spent = node.getrawtransaction(spend_txid, True)
        in0 = spent["vin"][0]
        prev = node.getrawtransaction(in0["txid"], True)
        assert_equal(prev["vout"][in0["vout"]]["scriptPubKey"]["type"], "voidcoin_p2qr_timelock")

        fee = -vault.gettransaction(spend_txid)["fee"]
        blockhash = self.confirm(1)[0]
        assert spend_txid in node.getblock(blockhash)["tx"], "spend not mined"
        assert_equal(vault.gettransaction(spend_txid)["confirmations"], 1)
        assert spend_txid not in node.getrawmempool()

        assert_equal(payee.getbalance(), send_amount)
        assert_equal(vault.getbalance(), amount - send_amount - fee)
        self.log.info("Phase 1 OK: payee=%s vault=%s fee=%s",
                      payee.getbalance(), vault.getbalance(), fee)

    # ------------------------------------------------------------------ #
    def phase2_absolute_mtp_lock(self, node):
        self.log.info("Phase 2: absolute-MTP lock -- fund, reject premature, spend past MTP")
        vault = node.get_wallet_rpc("vaultt")
        payee = node.get_wallet_rpc("payeet")

        tip_mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        unlock_time = tip_mtp + 3600  # one hour ahead of the chain's current MTP
        res = vault.getnewtimelockaddress("time", unlock_time, "time vault")
        vqt_addr = res["address"]
        assert_equal(res["lock_type"], "time")
        assert_equal(res["lock_value"], unlock_time)
        assert_equal(res["timelock_version"], 1)

        ai = vault.getaddressinfo(vqt_addr)
        assert_equal(ai["istimelocked"], True)
        assert_equal(ai["lock_type_name"], "time")
        assert_equal(ai["lock_value"], unlock_time)

        # Fund + confirm (block times are near real time, so MTP stays < unlock).
        amount = Decimal("50")
        fund_txid = self.bank.sendtoaddress(vqt_addr, amount)
        assert fund_txid in node.getrawmempool()
        decoded = node.getrawtransaction(fund_txid, True)
        tl_out = [o for o in decoded["vout"]
                  if o["scriptPubKey"].get("address") == vqt_addr]
        assert_equal(tl_out[0]["scriptPubKey"]["type"], "voidcoin_p2qr_timelock")
        self.confirm(1)
        assert_equal(vault.getbalance(), amount)

        # Spending before the chain's MTP reaches unlock_time is rejected. As in
        # phase 1, the wallet will not auto-select the not-yet-matured coin, so force
        # it in via manual input selection to exercise the consensus MTP gate.
        payee_addr = payee.getnewvoidcoinp2qraddress()
        cur_mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        assert_greater_than(unlock_time, cur_mtp)
        assert_raises_rpc_error(-6, "Insufficient funds",
                                vault.sendtoaddress, payee_addr, Decimal("10"))
        tl_vout = next(o["n"] for o in decoded["vout"]
                       if o["scriptPubKey"].get("address") == vqt_addr)
        change_addr = vault.getnewvoidcoinp2qraddress()
        raw = node.createrawtransaction(
            [{"txid": fund_txid, "vout": tl_vout}],
            [{payee_addr: Decimal("10")}, {change_addr: amount - Decimal("10.01")}])
        signed = vault.signrawtransactionwithwallet(raw)
        assert_equal(signed["complete"], True)
        res = node.testmempoolaccept([signed["hex"]])[0]
        assert_equal(res["allowed"], False)
        assert "bad-txns-timelock-not-met" in res["reject-reason"], res["reject-reason"]
        self.log.info("premature MTP-lock spend rejected: %s", res["reject-reason"])

        # Advance the chain's median-time-past past the unlock time. Mining 11
        # blocks at a mocktime beyond unlock_time makes MTP (median of the last 11
        # block times) equal that mocktime, satisfying the lock.
        node.setmocktime(unlock_time + 100)
        self.confirm(11)
        new_mtp = node.getblockheader(node.getbestblockhash())["mediantime"]
        assert_greater_than(new_mtp, unlock_time - 1)  # new_mtp >= unlock_time

        send_amount = Decimal("10")
        spend_txid = vault.sendtoaddress(payee_addr, send_amount)
        assert spend_txid in node.getrawmempool(), "matured MTP-lock spend not accepted"
        spent = node.getrawtransaction(spend_txid, True)
        in0 = spent["vin"][0]
        prev = node.getrawtransaction(in0["txid"], True)
        assert_equal(prev["vout"][in0["vout"]]["scriptPubKey"]["type"], "voidcoin_p2qr_timelock")

        fee = -vault.gettransaction(spend_txid)["fee"]
        blockhash = self.confirm(1)[0]
        assert spend_txid in node.getblock(blockhash)["tx"], "MTP spend not mined"
        assert_equal(vault.gettransaction(spend_txid)["confirmations"], 1)
        assert spend_txid not in node.getrawmempool()

        assert_equal(payee.getbalance(), send_amount)
        assert_equal(vault.getbalance(), amount - send_amount - fee)
        self.log.info("Phase 2 OK: payee=%s vault=%s fee=%s (MTP now %d >= unlock %d)",
                      payee.getbalance(), vault.getbalance(), fee, new_mtp, unlock_time)


if __name__ == "__main__":
    VoidCoinTimeLockTest(__file__).main()
