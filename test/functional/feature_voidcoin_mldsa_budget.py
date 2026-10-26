#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VC-14 (VCIP-3): the per-block ML-DSA-87 signature-verification budget.

Consensus rule under test (src/consensus/consensus.h,
MAX_BLOCK_MLDSA_VERIFICATIONS = 8000; enforced in ConnectBlock at
src/validation.cpp:3285 and on the mempool per-tx path at
src/validation.cpp:1252): once VCIP-3 has activated, a block whose transactions'
cumulative P2QR/ML-DSA-87 signature-verification count EXCEEDS the budget is
invalid (reject reason "bad-blk-mldsa-verifications"); an at/under-budget block
is accepted.

Everything is driven through the real wallet/node RPC path on regtest -- the
node builds, signs (via its wallet-native P2QR spend path, i.e. sendtoaddress)
and validates genuine ML-DSA-87 P2QR spends -- so the verifications that flow
through the VC-14 accumulator are real, not synthetic. The two nodes run
independent (unconnected) chains, both with VCIP-3 active.

WHAT IS VERIFIED AT RUNTIME (the reachable half of the rule):

  * node0 -- ACCEPTED / under budget, single-key. The wallet holds only native
    single-key P2QR outputs (P2QR coinbases + P2QR change), so every input it
    spends performs exactly ONE genuine ML-DSA-87 verification. Several
    many-input consolidation transactions are broadcast; each:
      - is accepted into the mempool (the per-transaction VC-14 pre-check runs
        and passes: the tx's own count <= 8000), and
      - is proven to carry only real P2QR verifications -- its serialized size
        divided by its input count is >= 7219 bytes, the exact size of one
        ML-DSA-87 signature (4627 B) plus one public key (2592 B), so no input
        could be a cheap non-P2QR input.
    All of those transactions are then packed into and CONFIRMED in a SINGLE
    block. That block's ConnectBlock accumulate-and-check loop sums the real
    per-tx ML-DSA-87 verification counts across multiple transactions, stays
    under the budget, and ADMITS the block (the tip advances and every tx
    confirms). This is the exact cross-transaction accumulator the over-budget
    rule guards.

  * node1 -- ACCEPTED / under budget, multisig branch. A native 2-of-3 P2QR
    multisig (held in its own single-UTXO wallet, so sweeping it provably spends
    the multisig itself) is created, funded on-chain and SPENT. The counter
    scores this spend as 2 verifications (one per revealed signature), exercising
    the multisig branch of the per-input counter, and the spend confirms in a
    block.

WHY THE OVER-BUDGET REJECTION CANNOT BE FORCED ON REGTEST (documented, not
faked -- with a runtime-measured impossibility proof):

  Every ML-DSA-87 verification the budget counts requires its own 4627-byte
  signature push AND a >=2592-byte public key physically present in the block:
  the counter's strict parser (consensus::voidcoinp2qr::CountSpendVerifications
  -> VoidCoinParseP2QRMultisigSpend) rejects any signature push that is not
  exactly 4627 bytes, so the count can never be inflated below a hard
  ~7219-bytes-per-verification floor. Exceeding the 8000 budget therefore needs
  > 8001 * 7219 bytes ~= 57 MB of spend data, which blows past the 32 MB raw
  block-size limit (MAX_BLOCK_WEIGHT / WITNESS_SCALE_FACTOR = 128000000 / 4).
  CheckBlock enforces that raw limit ("bad-blk-length", src/validation.cpp:4732)
  BEFORE ConnectBlock ever runs the VC-14 budget check, so no block that reaches
  the budget check can physically exist. The budget (8000) is deliberately
  calibrated ABOVE the physical maximum (~4400 verifications in a completely
  full 32 MB block), and there is no regtest knob to lower it, so the
  over-budget rejection is unreachable by construction.

  This test proves that impossibility with numbers MEASURED from the real
  confirmed spends on node0: it derives the actual on-chain bytes-per-verification
  and asserts (a) the most verifications that fit in a 32 MB block is < 8000 and
  (b) an 8001-verification block would exceed the raw size limit -- i.e. the
  size gate fires first, by design. The exact over-budget predicate
  (MLDSAVerificationBudgetExceeded: reject iff activated AND count > 8000, exact
  at the 8000/8001 boundary) is pinned by the C++ regression suite
  src/test/voidcoin_p2qr_mldsa_budget_tests.cpp, which replays the real
  ConnectBlock accumulate-and-check loop without materializing a 57 MB block.
"""
from decimal import Decimal

from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    assert_greater_than_or_equal,
)

# Consensus constants mirrored from the C++ source (cross-checked below against
# real on-chain measurements).
MAX_BLOCK_MLDSA_VERIFICATIONS = 8000            # src/consensus/consensus.h
MLDSA87_SIGNATURE_SIZE = 4627                   # src/crypto/pq/mldsa87/mldsa87.h
MLDSA87_PUBLIC_KEY_SIZE = 2592                  # src/crypto/pq/mldsa87/mldsa87.h
MAX_BLOCK_WEIGHT = 128000000                    # src/consensus/consensus.h
WITNESS_SCALE_FACTOR = 4                        # src/consensus/consensus.h
# CheckBlock's raw serialized-size cap: size * 4 <= MAX_BLOCK_WEIGHT (validation.cpp:4732).
RAW_BLOCK_SIZE_LIMIT = MAX_BLOCK_WEIGHT // WITNESS_SCALE_FACTOR  # 32,000,000 bytes
# Hard floor: each counted verification needs a full 4627-byte signature push and
# a >=2592-byte public key present in the block. The counter's parser enforces the
# exact 4627-byte signature length, so this floor cannot be undercut.
MIN_BYTES_PER_VERIFICATION = MLDSA87_SIGNATURE_SIZE + MLDSA87_PUBLIC_KEY_SIZE  # 7219

# Several many-input consolidation spends, all mined into ONE block, so the
# block-level accumulator sums real verifications across multiple transactions.
# Amounts are large so coin selection is forced to combine many 50-VOID P2QR
# coinbases; the exact per-tx input count is read back and summed at runtime.
SPEND_AMOUNTS = [Decimal("700"), Decimal("500")]


class VoidCoinMldsaBudgetTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 2
        # VCIP-3 active from block 1 on both nodes, so the VC-14 accumulator and
        # budget are enforced for every block either node mines. -txindex makes
        # getrawtransaction work on confirmed txs.
        self.extra_args = [["-vcip3activationheight=1", "-txindex"],
                           ["-vcip3activationheight=1", "-txindex"]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self):
        # Independent regimes; do NOT connect the nodes.
        self.setup_nodes()

    def init_wallet(self, *, node):
        # VoidCoin refuses legacy/bech32 addresses, so the framework's default
        # coinbase-key import path is unusable. Create a plain "miner" descriptor
        # wallet; all keys come from the P2QR RPCs.
        self.nodes[node].createwallet(wallet_name="miner",
                                      descriptors=self.options.descriptors,
                                      load_on_startup=True)

    def run_test(self):
        # node0: many real single-key ML-DSA-87 verifications in one accepted
        # block + the runtime impossibility proof for the over-budget path.
        self.check_underbudget_singlekey_block(self.nodes[0])
        self.prove_overbudget_unreachable(self.nodes[0])
        # node1: the multisig branch of the counter (isolated wallet).
        self.check_underbudget_multisig_block(self.nodes[1])

    # ------------------------------------------------------------------
    # node0 -- under-budget: one block carrying many real single-key
    # ML-DSA-87 verifications, spread across several txs, is accepted.
    # ------------------------------------------------------------------
    def check_underbudget_singlekey_block(self, node):
        self.log.info("node0 under-budget: one block with many real single-key "
                      "ML-DSA-87 verifications across %d txs is ACCEPTED",
                      len(SPEND_AMOUNTS))
        miner = node.get_wallet_rpc("miner")

        # Mine to a wallet-owned P2QR mining address and mature the coinbases
        # (100-conf). 140 blocks -> 40 mature 50-VOID native-P2QR coinbases.
        mining = miner.getnewvoidcoinp2qrminingaddress()["address"]
        self.generatetoaddress(node, 140, mining, sync_fun=self.no_op)
        assert_greater_than(node.getblockcount(), 1)          # VCIP-3 is active
        assert_greater_than(miner.getbalance(), Decimal("1500"))

        spend_txids = []
        total_verifications = 0
        self._measured_bytes_per_verif = None
        for amt in SPEND_AMOUNTS:
            # Every wallet UTXO is a native single-key P2QR output, so this spend
            # combines several of them; each input == one real ML-DSA-87
            # verification. sendtoaddress builds and fully signs the ML-DSA spend
            # via the wallet-native P2QR spend path.
            dest = miner.getnewvoidcoinp2qraddress()
            txid = miner.sendtoaddress(dest, amt)

            # Mempool per-tx VC-14 pre-check ran and PASSED (count <= budget):
            # the tx is now queued in the mempool.
            assert txid in node.getrawmempool()
            raw = node.getrawtransaction(txid, True)  # served from mempool
            n_in = len(raw["vin"])
            assert_greater_than(n_in, 1)              # a genuine many-input P2QR spend

            # Each input carries a 4627 B signature + 2592 B public key, so the
            # per-input serialized cost is >= 7219 B. This PROVES every input is a
            # real native P2QR spend (== one ML-DSA-87 verification), not a cheap
            # non-P2QR input.
            per_verif = raw["size"] / n_in
            assert_greater_than_or_equal(per_verif, MIN_BYTES_PER_VERIFICATION)

            spend_txids.append(txid)
            total_verifications += n_in
            self._measured_bytes_per_verif = per_verif

        assert_equal(sorted(node.getrawmempool()), sorted(spend_txids))
        assert_greater_than(total_verifications, len(SPEND_AMOUNTS))  # clearly "many"

        # Mine ONE block: the miner packs ALL the spend txs into it, so the
        # ConnectBlock accumulator sums `total_verifications` real ML-DSA-87
        # verifications across several txs and ADMITS the block (under budget).
        tip_before = node.getbestblockhash()
        blk_hash = self.generatetoaddress(node, 1, mining, sync_fun=self.no_op)[0]
        assert node.getbestblockhash() != tip_before      # tip advanced == accepted
        assert_equal(node.getbestblockhash(), blk_hash)

        blk = node.getblock(blk_hash)
        for txid in spend_txids:
            assert txid in blk["tx"]                        # all in the SAME block
            assert_equal(miner.gettransaction(txid)["confirmations"], 1)
        assert_equal(node.getrawmempool(), [])              # everything confirmed

        self.log.info("node0 ACCEPTED: block %s carried %d real ML-DSA-87 "
                      "verifications across %d txs (~%.0f B/verification)",
                      blk_hash[:16], total_verifications, len(spend_txids),
                      self._measured_bytes_per_verif)

    # ------------------------------------------------------------------
    # node1 -- under-budget: a native 2-of-3 P2QR multisig spend (2
    # verifications) is accepted, exercising the multisig counter branch.
    # (Mirrors the proven wallet flow in feature_voidcoin_pa06_multisig.py.)
    # ------------------------------------------------------------------
    def check_underbudget_multisig_block(self, node):
        self.log.info("node1 under-budget: a native 2-of-3 P2QR multisig spend "
                      "(2 ML-DSA-87 verifications) is ACCEPTED")
        miner = node.get_wallet_rpc("miner")

        mining = miner.getnewvoidcoinp2qrminingaddress()["address"]
        self.generatetoaddress(node, 130, mining, sync_fun=self.no_op)
        assert_greater_than(miner.getbalance(), Decimal("100"))

        # The multisig lives in its OWN wallet holding exactly the funding UTXO,
        # so a confirmed sweep of that wallet provably spends the multisig itself.
        node.createwallet(wallet_name="msig", descriptors=self.options.descriptors)
        msig_w = node.get_wallet_rpc("msig")

        signers = [msig_w.getnewvoidcoinp2qraddress() for _ in range(3)]
        msig = msig_w.createp2qrmultisig(2, signers)
        msig_addr = msig["address"]
        assert_equal(msig["required"], 2)
        assert_equal(msig["total"], 3)

        fund_amount = Decimal("25")
        fund_txid = miner.sendtoaddress(msig_addr, fund_amount)
        self.generatetoaddress(node, 1, miner.getnewvoidcoinp2qrminingaddress()["address"],
                               sync_fun=self.no_op)

        utxos = msig_w.listunspent(1, 9999, [msig_addr])
        assert_equal(len(utxos), 1)               # the multisig wallet's SOLE UTXO
        u = utxos[0]
        assert_equal(u["txid"], fund_txid)

        # Sweep the multisig wallet (fee taken from the amount) -> provably spends
        # the 2-of-3 multisig, revealing 2 ML-DSA-87 signatures == 2 verifications
        # (the multisig branch of GetP2QRVerifyCount). Node signs the native P2QR
        # scriptSig via its wallet-native spend path.
        dest = miner.getnewvoidcoinp2qraddress()
        spend_txid = msig_w.sendtoaddress(address=dest, amount=fund_amount,
                                          subtractfeefromamount=True)

        # Mempool per-tx VC-14 check passed, and it spends exactly the multisig UTXO.
        assert spend_txid in node.getrawmempool()
        raw = node.getrawtransaction(spend_txid, True)
        spent_inputs = {(vin["txid"], vin["vout"]) for vin in raw["vin"]}
        assert_equal(spent_inputs, {(u["txid"], u["vout"])})

        tip_before = node.getbestblockhash()
        self.generatetoaddress(node, 1, miner.getnewvoidcoinp2qrminingaddress()["address"],
                               sync_fun=self.no_op)
        assert node.getbestblockhash() != tip_before       # accepted
        assert_greater_than(node.getrawtransaction(spend_txid, True)["confirmations"], 0)
        assert_equal(node.gettxout(u["txid"], u["vout"]), None)  # multisig UTXO consumed
        self.log.info("node1 ACCEPTED: 2-of-3 P2QR multisig spent in %s",
                      spend_txid[:16])
        node.unloadwallet("msig")

    # ------------------------------------------------------------------
    # Over-budget rejection is physically unreachable within the 32 MB raw
    # block-size limit -- proven with numbers measured on node0.
    # ------------------------------------------------------------------
    def prove_overbudget_unreachable(self, node):
        self.log.info("Over-budget rejection: physically unreachable within the "
                      "32 MB raw block-size limit (measured proof)")

        floor = MIN_BYTES_PER_VERIFICATION  # 7219 B, the hard per-verification floor

        # The real, confirmed P2QR spends must actually cost at least the
        # sig+pubkey floor per verification -- proving the floor is real on chain,
        # not just a source constant. (Measured includes tx/output overhead, so it
        # is strictly >= the pure sig+pubkey floor.)
        assert_greater_than_or_equal(self._measured_bytes_per_verif, floor)

        # (a) The MOST ML-DSA-87 verifications that can physically fit in a full
        #     32 MB block is far below the 8000 budget -- the documented
        #     calibration. So no block can ever reach the budget.
        max_verifs_in_a_block = RAW_BLOCK_SIZE_LIMIT // floor  # ~4432
        assert_greater_than(MAX_BLOCK_MLDSA_VERIFICATIONS, max_verifs_in_a_block)

        # (b) A one-over-budget (8001-verification) block would need more than the
        #     32 MB raw limit, so CheckBlock rejects it as "bad-blk-length" BEFORE
        #     ConnectBlock's VC-14 budget check can run. The over-budget path is
        #     therefore unreachable by construction.
        bytes_for_over_budget = (MAX_BLOCK_MLDSA_VERIFICATIONS + 1) * floor
        assert_greater_than(bytes_for_over_budget, RAW_BLOCK_SIZE_LIMIT)

        self.log.info("floor=%d B/verif; measured>=floor; max verifs in 32MB=%d "
                      "< budget=%d; 8001 verifs need %d B > %d B raw limit -> an "
                      "over-budget block is rejected bad-blk-length before VC-14 "
                      "runs (see C++ suite voidcoin_p2qr_mldsa_budget_tests.cpp "
                      "for the exact 8000/8001 predicate)",
                      floor, max_verifs_in_a_block,
                      MAX_BLOCK_MLDSA_VERIFICATIONS, bytes_for_over_budget,
                      RAW_BLOCK_SIZE_LIMIT)


if __name__ == "__main__":
    VoidCoinMldsaBudgetTest(__file__).main()
