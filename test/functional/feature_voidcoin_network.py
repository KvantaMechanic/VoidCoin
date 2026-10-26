#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Multi-node regtest exercise of the whole VoidCoin network, end to end.

VoidCoin replaces ECDSA with ML-DSA-87 P2QR outputs and forbids legacy / bech32 /
taproot addresses at the wallet and coinbase-policy layers, so a network test can
only use native P2QR addresses (getnewvoidcoinp2qr[mining]address). This test spins
up THREE nodes in the framework's default chain topology and drives the real network
paths a coin needs to be usable, asserting a concrete outcome at every step:

  Phase 1  BLOCK PROPAGATION / SYNC
      node0 mines P2QR coinbase blocks; assert all three nodes converge to the same
      best block hash and height via sync_all()/sync_blocks().

  Phase 2  MEMPOOL PROPAGATION
      node0's wallet builds and broadcasts a real P2QR spend that pays a wallet on
      node1; assert the txid appears in ALL three nodes' getrawmempool (sync_mempools),
      then mine it and assert it confirms network-wide and the payee's balance updates.

  Phase 3  REORG CONVERGENCE  (the key one)
      Split the network (disconnect_nodes) into {node0,node1} and {node2}. On the
      isolated node2, broadcast a P2QR spend and mine it into ONE short-chain block.
      On the {node0,node1} side mine a strictly LONGER chain that does NOT contain that
      tx. Reconnect (connect_nodes) and assert all three nodes converge on the longer
      chain (identical best hash / height), the short-chain block is orphaned
      (confirmations == -1), and the orphaned transaction returns to the mempool
      network-wide and then re-confirms cleanly -- no persistent split.

  Phase 4  P2P v2 TRANSPORT (BIP324; VoidCoin's VC-07/VC-15 fragment-reassembly path)
      Every node runs with -v2transport=1, so all of the above block/tx propagation
      travels over the v2 encrypted transport. We assert getpeerinfo reports
      transport_protocol_type == "v2" on every inter-node link (including the link
      re-established after the reorg), proving the fragment path carries a real network.

  Phase 5  CHAINSTATE / UTXO AGREEMENT
      After the mixed mine/spend/reorg/re-sync sequence, assert every node agrees on
      getbestblockhash AND on gettxoutsetinfo hash_serialized_3 -- i.e. identical
      chainstate and UTXO set, not merely the same tip height.

All coinbases live in node0's `bank` wallet so payee balances stay exact regardless of
coinbase maturity. Everything is driven through wallet/node RPCs; the nodes build and
sign every P2QR transaction themselves. No transactions are hand-constructed.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
)


class VoidCoinNetworkTest(VoidCoinTestFramework):
    def add_options(self, parser):
        # Enable the wallet subsystem (so nodes do NOT get -disablewallet) but WITHOUT
        # setting _requires_wallet, so the framework won't auto-create a default wallet
        # and importprivkey a legacy coinbase key (which VoidCoin's P2QR-only wallet
        # path does not use). We create P2QR wallets ourselves.
        self.add_wallet_options(parser)

    def set_test_params(self):
        # The shared framework cache mines legacy/taproot coinbases that VoidCoin
        # forbids, so cache-based setup fails -- clean chain bypasses it.
        self.setup_clean_chain = True
        self.num_nodes = 3
        # Whitelist the loopback links so tx relay / mempool sync is prompt.
        self.noban_tx_relay = True
        # Run the ENTIRE network over the BIP324 v2 encrypted transport, so every block
        # and transaction below exercises VoidCoin's v2 fragment-reassembly code path.
        # -txindex so we can classify any spent output as native P2QR; -fallbackfee so
        # the wallet can attach a fee on regtest (no fee-estimation data).
        common = ["-v2transport=1", "-txindex=1", "-fallbackfee=0.0002"]
        self.extra_args = [list(common) for _ in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        if not self.is_wallet_compiled():
            from test_framework.test_framework import SkipTest
            raise SkipTest("wallet has not been compiled.")

    # ------------------------------------------------------------------ helpers
    def spk_type(self, node, txid, vout):
        """scriptPubKey 'type' of an output (needs -txindex)."""
        return node.getrawtransaction(txid, True)["vout"][vout]["scriptPubKey"]["type"]

    def assert_all_links_v2(self, context):
        """Every peer link on every node must be the BIP324 v2 encrypted transport."""
        for i, node in enumerate(self.nodes):
            peers = node.getpeerinfo()
            assert len(peers) >= 1, "node%d has no peers (%s)" % (i, context)
            for p in peers:
                self.wait_until(lambda p=p, node=node:
                                self._peer_transport(node, p["id"]) == "v2")
        self.log.info("v2 transport OK (%s): all inter-node links report transport_protocol_type=v2", context)

    @staticmethod
    def _peer_transport(node, peer_id):
        for p in node.getpeerinfo():
            if p["id"] == peer_id:
                return p.get("transport_protocol_type")
        return None

    def assert_converged(self, nodes=None, context=""):
        """All given nodes share one best hash + height; return (hash, height)."""
        nodes = nodes or self.nodes
        hashes = [n.getbestblockhash() for n in nodes]
        heights = [n.getblockcount() for n in nodes]
        assert_equal(len(set(hashes)), 1)
        assert_equal(len(set(heights)), 1)
        self.log.info("converged (%s): height=%d hash=%s", context, heights[0], hashes[0][:16])
        return hashes[0], heights[0]

    # ------------------------------------------------------------------ test
    def run_test(self):
        node0, node1, node2 = self.nodes

        # Dedicated wallets: node0 mines & funds everything; node1 receives the mempool
        # payment; node2 does the reorg-orphaned self-spend.
        node0.createwallet(wallet_name="bank")
        node0.createwallet(wallet_name="spender")
        node1.createwallet(wallet_name="recv")
        node2.createwallet(wallet_name="n2")
        self.bank = node0.get_wallet_rpc("bank")
        self.spender = node0.get_wallet_rpc("spender")
        self.recv = node1.get_wallet_rpc("recv")
        self.n2 = node2.get_wallet_rpc("n2")

        # P2QR mining addresses (P2SH-wrapped native P2QR programs the coinbase policy
        # accepts and the wallet can spend). A node may mine to any address, but node0
        # keeps every coinbase in its own bank so payee balances stay exact.
        self.bank_mining = self.bank.getnewvoidcoinp2qrminingaddress()["address"]
        self.n2_mining = self.n2.getnewvoidcoinp2qrminingaddress()["address"]
        self.log.info("bank P2QR mining addr: %s", self.bank_mining)

        # The framework already connected node0<-node1<-node2 and both nodes advertise
        # v2, so the whole run travels over BIP324. Assert that up front.
        self.assert_all_links_v2("initial topology")

        self.phase1_block_propagation()
        self.phase2_mempool_propagation()
        self.phase3_reorg_convergence()
        self.phase5_chainstate_agreement()

    # ------------------------------------------------------------------ Phase 1
    def phase1_block_propagation(self):
        self.log.info("Phase 1: P2QR block propagation / network sync across 3 nodes")
        node0 = self.nodes[0]
        assert_equal(node0.getblockcount(), 0)

        # Mine 130 P2QR coinbase blocks on node0 and let the framework sync all three.
        # With regtest's 50 VOID subsidy (halving every 150), heights 1..~30 mature to
        # >100 confs -> ~1500 VOID spendable in bank.
        self.generatetoaddress(node0, 130, self.bank_mining)  # sync_fun defaults to sync_all
        _, height = self.assert_converged(context="after mining 130")
        assert_equal(height, 130)
        assert_greater_than(self.bank.getbalance(), Decimal("1000"))

        # Extra proof of P2P block propagation: mine a single block and confirm the tip
        # reaches node1 and node2 (not just node0) via sync_blocks().
        pre = node0.getbestblockhash()
        tip = self.generatetoaddress(node0, 1, self.bank_mining, sync_fun=self.sync_blocks)[0]
        assert tip != pre
        for i, n in enumerate(self.nodes):
            assert_equal(n.getbestblockhash(), tip)
        self.assert_converged(context="after +1 block")
        self.log.info("Phase 1 OK: 3 nodes share tip %s at height %d", tip[:16], node0.getblockcount())

    # ------------------------------------------------------------------ Phase 2
    def phase2_mempool_propagation(self):
        self.log.info("Phase 2: P2QR mempool propagation + network-wide confirmation")
        node0, node1, node2 = self.nodes

        # Give node0's `spender` wallet exactly ONE clean native-P2QR UTXO (bank's own
        # coinbase outputs are wrapped-P2QR P2SH, so spending from a dedicated single-
        # UTXO wallet guarantees the spend's input is a NATIVE voidcoin_p2qr output) and
        # confirm it network-wide.
        spend_src = self.spender.getnewvoidcoinp2qraddress()
        self.bank.sendtoaddress(spend_src, Decimal("200"))
        self.generatetoaddress(node0, 1, self.bank_mining)  # sync_all
        assert_equal(self.spender.getbalance(), Decimal("200"))
        assert_equal(len(self.spender.listunspent()), 1)

        # node1's wallet is the payee. Build a real P2QR spend on node0.
        payee = self.recv.getnewvoidcoinp2qraddress()
        amount = Decimal("100")
        txid = self.spender.sendtoaddress(payee, amount)
        assert txid in node0.getrawmempool(), "spend did not enter node0's mempool"

        # It really is a native P2QR spend: the single input is a native P2QR output and
        # every output is a P2QR form.
        decoded = node0.getrawtransaction(txid, True)
        assert_equal(len(decoded["vin"]), 1)
        in0 = decoded["vin"][0]
        assert_equal(self.spk_type(node0, in0["txid"], in0["vout"]), "voidcoin_p2qr")
        for o in decoded["vout"]:
            assert o["scriptPubKey"]["type"] in ("voidcoin_p2qr", "scripthash"), \
                "non-P2QR output: %s" % o["scriptPubKey"]["type"]

        # THE ASSERTION: the txid propagates to ALL three nodes' mempools over v2.
        self.sync_mempools()
        for i, n in enumerate(self.nodes):
            assert txid in n.getrawmempool(), "txid missing from node%d mempool" % i
        self.log.info("mempool propagation OK: %s present on all 3 nodes", txid[:16])

        # Mine it and assert it confirms network-wide and leaves every mempool.
        blockhash = self.generatetoaddress(node0, 1, self.bank_mining)[0]  # sync_all
        for i, n in enumerate(self.nodes):
            assert txid in n.getblock(blockhash)["tx"], "tx not in block on node%d" % i
            assert txid not in n.getrawmempool(), "tx still in node%d mempool" % i
        # The payee wallet on node1 saw the confirmed payment.
        assert_equal(self.recv.getbalance(), amount)
        self.assert_converged(context="after confirming the spend")
        self.log.info("Phase 2 OK: node1 payee balance=%s VOID; tx confirmed on all nodes", amount)

    # ------------------------------------------------------------------ Phase 3
    def phase3_reorg_convergence(self):
        self.log.info("Phase 3: network split -> competing chains -> reorg convergence")
        node0, node1, node2 = self.nodes

        # Pre-fund node2's wallet with a spendable native-P2QR UTXO while everyone is
        # still synced, so node2 can build a valid spend during the split. (Non-coinbase
        # output -> spendable at 1 confirmation.)
        n2_addr = self.n2.getnewvoidcoinp2qraddress()
        self.bank.sendtoaddress(n2_addr, Decimal("50"))
        self.generatetoaddress(node0, 1, self.bank_mining)  # sync_all
        assert_equal(self.n2.getbalance(), Decimal("50"))
        _, base_height = self.assert_converged(context="pre-split baseline")

        # --- SPLIT: {node0,node1} | {node2} -----------------------------------
        self.disconnect_nodes(1, 2)
        self.sync_blocks(self.nodes[:2])  # node2 is isolated -> only sync the pair
        assert_equal(len(node2.getpeerinfo()), 0)
        self.log.info("network split: group A={node0,node1}, group B={node2}")

        # --- Group B (loser): build a P2QR self-spend and mine ONE short block ---
        orphan_dest = self.n2.getnewvoidcoinp2qraddress()
        orphan_txid = self.n2.sendtoaddress(orphan_dest, Decimal("30"))
        assert orphan_txid in node2.getrawmempool()
        # Prove it's a native P2QR spend, then bury it in the short chain.
        assert any(self.spk_type(node2, vin["txid"], vin["vout"]) == "voidcoin_p2qr"
                   for vin in node2.getrawtransaction(orphan_txid, True)["vin"])
        short_hash = self.generatetoaddress(node2, 1, self.n2_mining, sync_fun=self.no_op)[0]
        assert orphan_txid in node2.getblock(short_hash)["tx"], "orphan tx not mined on short chain"
        assert_equal(node2.getblockcount(), base_height + 1)
        # Group A never saw the tx.
        assert orphan_txid not in node0.getrawmempool()
        assert orphan_txid not in node1.getrawmempool()
        self.log.info("group B mined SHORT chain: +1 block (height %d) incl. orphan tx %s",
                      node2.getblockcount(), orphan_txid[:16])

        # --- Group A (winner): mine a strictly LONGER chain WITHOUT that tx -----
        self.generatetoaddress(node0, 3, self.bank_mining,
                               sync_fun=lambda: self.sync_blocks(self.nodes[:2]))
        assert_equal(node0.getblockcount(), base_height + 3)
        long_hash = node0.getbestblockhash()
        assert long_hash != short_hash
        # Sanity: the two sides really disagree while split.
        assert node2.getbestblockhash() != long_hash
        self.log.info("group A mined LONG chain: +3 blocks (height %d)", node0.getblockcount())

        # --- RECONNECT and let the network resolve the fork --------------------
        self.connect_nodes(1, 2)
        self.sync_blocks()  # all three now peered again
        best_hash, best_height = self.assert_converged(context="after reorg")

        # Convergence outcome: everyone is on group A's LONGER chain.
        assert_equal(best_hash, long_hash)
        assert_equal(best_height, base_height + 3)
        # The short-chain block is orphaned on node2 (exists but off the active chain).
        assert_equal(node2.getblock(short_hash)["confirmations"], -1)
        self.log.info("reorg resolved: all nodes on longer chain; short block %s orphaned (conf=-1)",
                      short_hash[:16])

        # The reconnected node2<->node1 link is v2 again (fragment path after reconnect).
        self.assert_all_links_v2("after reorg reconnect")

        # The orphaned tx's inputs are unspent on the winning chain, so on reorg node2
        # resurrects it into its OWN mempool. This is the "returns to the mempool"
        # guarantee. NOTE: upstream Core (unchanged in VoidCoin) does NOT actively
        # re-relay a reorg-restored tx -- RelayTransaction only runs for txs received
        # live from a peer or freshly broadcast (net_processing ProcessValidTx);
        # MaybeUpdateMempoolForReorg re-adds via AcceptToMemoryPool without relaying, so
        # the tx re-propagates only via the slow wallet/unbroadcast rebroadcast timer
        # (10-15 min). Hence node2 has it back but node0/node1 legitimately do not yet.
        self.wait_until(lambda: orphan_txid in node2.getrawmempool(), timeout=30)
        assert orphan_txid not in node0.getrawmempool()
        assert orphan_txid not in node1.getrawmempool()
        self.log.info("orphaned tx %s resurrected into node2's own mempool "
                      "(reorg-restored txs are not auto-relayed by design)", orphan_txid[:16])

        # It is still a valid spend on the reunified chain, so a rebroadcast lets the
        # whole network re-accept it (drives the normal relay path deterministically,
        # instead of waiting on the multi-minute rebroadcast timer).
        raw = node2.getrawtransaction(orphan_txid)
        assert_equal(node0.sendrawtransaction(raw), orphan_txid)
        self.sync_mempools()
        for i, n in enumerate(self.nodes):
            assert orphan_txid in n.getrawmempool(), \
                "rebroadcast orphaned tx missing from node%d mempool" % i
        self.log.info("orphaned tx re-propagated to all 3 mempools after rebroadcast")

        # And it re-confirms cleanly on the reunified chain, network-wide.
        reconf_block = self.generatetoaddress(node0, 1, self.bank_mining)[0]  # sync_all
        for i, n in enumerate(self.nodes):
            assert orphan_txid in n.getblock(reconf_block)["tx"], "orphan tx not re-mined on node%d" % i
            assert orphan_txid not in n.getrawmempool()
        assert_equal(node2.getblock(short_hash)["confirmations"], -1)  # still orphaned
        # Self-spend preserved node2's value minus the fee.
        assert_greater_than(self.n2.getbalance(), Decimal("49"))
        assert_greater_than(Decimal("50"), self.n2.getbalance())
        self.assert_converged(context="after re-confirming orphaned tx")
        self.log.info("Phase 3 OK: no persistent split; orphaned tx re-confirmed; node2 balance=%s VOID",
                      self.n2.getbalance())

    # ------------------------------------------------------------------ Phase 5
    def phase5_chainstate_agreement(self):
        self.log.info("Phase 5: chainstate + UTXO-set agreement across all nodes")
        self.sync_all()
        best = {n.getbestblockhash() for n in self.nodes}
        assert_equal(len(best), 1)
        # Identical UTXO sets, not merely the same tip: compare the serialized hash.
        utxo_hashes = [n.gettxoutsetinfo("hash_serialized_3")["hash_serialized_3"] for n in self.nodes]
        assert_equal(len(set(utxo_hashes)), 1)
        heights = {n.getblockcount() for n in self.nodes}
        assert_equal(len(heights), 1)
        self.log.info("Phase 5 OK: all nodes agree at height %d, best=%s, utxo hash_serialized_3=%s",
                      heights.pop(), best.pop()[:16], utxo_hashes[0][:16])


if __name__ == "__main__":
    VoidCoinNetworkTest(__file__).main()
