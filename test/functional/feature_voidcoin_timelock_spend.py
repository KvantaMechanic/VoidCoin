#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""End-to-end exercise of the VCIP-3 P2QR time-lock output on a running regtest chain.

The old VCIP-1 vault/timelock feature was disabled: its outputs had no spend-
authorization path, so funds sent to a vqt address were permanently frozen. VCIP-3
rebuilds the type as a correct, spendable, versioned output:

    OP_QuantumQuark <program[32]> <lock_descriptor[10]>
    lock_descriptor = version(1) || lock_type(1) || lock_value(uint64 LE)

where `program` is the SAME single-key P2QR commitment used by native P2QR, so the
spend is a direct extension of native-P2QR CheckSpend, gated on the VCIP-3 fork and
on the lock (absolute height / MTP) having matured.

This test proves, against a live node driven only through wallet/node RPCs:

  * getnewtimelockaddress returns a versioned vqt address and validateaddress /
    getaddressinfo describe it (version / lock_type / lock_value);
  * a funding tx to the vqt address is relay-standard, confirms, and the receiving
    wallet sees the coin as its own spendable balance;
  * spending the time-lock coin BEFORE the lock matures is rejected by consensus
    ("bad-txns-timelock-not-met");
  * once the lock height is reached, the wallet builds/signs/broadcasts a valid
    ML-DSA-87 spend that enters the mempool and confirms, and balances update.

Regtest activates VCIP-3 from genesis, so the spend rule and output creation are
live throughout. -rpcdoccheck is forced on so the RPC schemas are validated too.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class VoidCoinTimeLockSpendTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.extra_args = [["-txindex=1", "-fallbackfee=0.0002", "-rpcdoccheck=1"]]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.test_framework import SkipTest
            raise SkipTest("wallet has not been compiled.")

    def confirm(self, n=1):
        return self.generatetoaddress(self.nodes[0], n, self.sink, sync_fun=self.no_op)

    def run_test(self):
        node = self.nodes[0]

        for name in ("bank", "vault", "payee"):
            node.createwallet(wallet_name=name)
        self.bank = node.get_wallet_rpc("bank")
        vault = node.get_wallet_rpc("vault")
        payee = node.get_wallet_rpc("payee")

        # P2QR mining sink; keep all coinbases here so tested balances stay exact.
        self.sink = self.bank.getnewvoidcoinp2qrminingaddress()["address"]
        self.confirm(130)
        assert_greater_than(self.bank.getbalance(), Decimal("1000"))

        # ---- Derive a height-locked vqt address, unlocking a few blocks ahead. ----
        tip = node.getblockcount()
        unlock_height = tip + 6
        res = vault.getnewtimelockaddress("height", unlock_height, "my vault")
        vqt_addr = res["address"]
        assert_equal(res["lock_type"], "height")
        assert_equal(res["lock_value"], unlock_height)
        assert_equal(res["timelock_version"], 1)
        self.log.info("time-lock (height=%d) address: %s", unlock_height, vqt_addr)

        # validateaddress / getaddressinfo describe the lock.
        va = node.validateaddress(vqt_addr)
        assert_equal(va["isvalid"], True)
        assert_equal(va["isvoidcoinp2qrtimelock"], True)
        assert_equal(va["lock_value"], unlock_height)
        ai = vault.getaddressinfo(vqt_addr)
        assert_equal(ai["ismine"], True)
        assert_equal(ai["istimelocked"], True)
        assert_equal(ai["lock_type_name"], "height")

        # ---- Fund it. The funding tx must be standard and confirm. ----
        amount = Decimal("50")
        fund_txid = self.bank.sendtoaddress(vqt_addr, amount)
        assert fund_txid in node.getrawmempool(), "funding tx not relayed (nonstandard?)"
        # The funded output is a native VOIDCOIN_P2QR_TIMELOCK output.
        decoded = node.getrawtransaction(fund_txid, True)
        tl_out = [o for o in decoded["vout"]
                  if o["scriptPubKey"].get("address") == vqt_addr]
        assert_equal(len(tl_out), 1)
        assert_equal(tl_out[0]["scriptPubKey"]["type"], "voidcoin_p2qr_timelock")
        self.confirm(1)
        assert_equal(vault.getbalance(), amount)
        assert_equal(len(vault.listunspent()), 1)

        # ---- Spending before the lock matures must be rejected by consensus. ----
        payee_addr = payee.getnewvoidcoinp2qraddress()
        # tip+1 (the spend height) is still < unlock_height here, so consensus must
        # reject a spend. The P2QR wallet signs the spend and commits it LOCALLY
        # even when the node's mempool refuses it (it returns a txid without
        # raising), so we assert the rejection via testmempoolaccept and confirm the
        # tx never relays, then abandon it to free the coin for the matured spend.
        assert_greater_than(unlock_height, node.getblockcount() + 1)
        premature_txid = vault.sendtoaddress(payee_addr, Decimal("10"))
        assert premature_txid not in node.getrawmempool(), \
            "a premature time-lock spend must not enter the mempool"
        premature_hex = vault.gettransaction(premature_txid)["hex"]
        res = node.testmempoolaccept([premature_hex])[0]
        assert_equal(res["allowed"], False)
        assert "bad-txns-timelock-not-met" in res["reject-reason"], res["reject-reason"]
        self.log.info("premature spend correctly rejected: %s", res["reject-reason"])
        vault.abandontransaction(premature_txid)

        # ---- Mine until the lock is satisfied, then spend for real. ----
        # Spendable once tip+1 >= unlock_height, i.e. tip >= unlock_height - 1.
        while node.getblockcount() < unlock_height - 1:
            self.confirm(1)
        assert_equal(node.getblockcount(), unlock_height - 1)

        send_amount = Decimal("10")
        spend_txid = vault.sendtoaddress(payee_addr, send_amount)
        assert spend_txid in node.getrawmempool(), "matured time-lock spend not accepted"

        spent = node.getrawtransaction(spend_txid, True)
        assert_equal(len(spent["vin"]), 1)
        in0 = spent["vin"][0]
        prev = node.getrawtransaction(in0["txid"], True)
        assert_equal(prev["vout"][in0["vout"]]["scriptPubKey"]["type"],
                     "voidcoin_p2qr_timelock")

        fee = -vault.gettransaction(spend_txid)["fee"]
        blockhash = self.confirm(1)[0]
        assert spend_txid in node.getblock(blockhash)["tx"], "spend not mined"
        assert_equal(vault.gettransaction(spend_txid)["confirmations"], 1)
        assert spend_txid not in node.getrawmempool()

        assert_equal(payee.getbalance(), send_amount)
        assert_equal(vault.getbalance(), amount - send_amount - fee)
        self.log.info("time-lock spend OK: payee=%s, vault=%s, fee=%s",
                      payee.getbalance(), vault.getbalance(), fee)


if __name__ == "__main__":
    VoidCoinTimeLockSpendTest(__file__).main()
