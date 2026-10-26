#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Fix #6: coinstatsindex on-disk DB_VERSION gate (wipe-and-rebuild only on mismatch).

VCIP-2 changed the *meaning* of the per-height totals the coinstatsindex persists
(total_subsidy switched to GetBlockSubsidyWithBounty(), which mints 200 VOID on
Void Collapse Bounty blocks instead of the base 50). A database written by an
older binary carries the old semantics; silently extending it makes the
ReverseBlock() consistency Assert()s fire on a reorg across a bounty block.

The fix (src/index/coinstatsindex.cpp, CoinStatsIndex ctor) stamps an on-disk
format version (DB_VERSION 'V' == CURRENT_INDEX_VERSION 2) and, when it opens a
*populated* DB (DB_MUHASH present) whose on-disk version does NOT match, wipes and
rebuilds the index from genesis with the current semantics. A fresh build and a
normal restart (version already current) must NOT rebuild.

This test drives the real node:

  Phase 0  Build the coinstatsindex over a real regtest chain; a fresh build does
           not log a wipe.
  Phase 1  A normal restart does NOT wipe/rebuild; the muhash/stats are identical
           and the chain tip is untouched (stats-only, no consensus effect).
  Phase 2  Simulate the upgrade-with-stale-DB: with the node stopped, splice a
           leveldb write-batch into the coinstats DB's current write-ahead log that
           overrides DB_VERSION to 1 (an "old binary" value) at a high sequence
           number so it wins on recovery. On restart the gate detects the mismatch,
           logs the wipe, rebuilds from genesis, and the rebuilt index reproduces
           the EXACT same muhash/stats. The chain tip is unchanged across the wipe.
  Phase 3  After the rebuild the on-disk version is current again, so a further
           normal restart does NOT wipe.
  Phase 4  (best effort) If a real Void Collapse Bounty block exists on the chain,
           reorg across it (invalidate + reconsider) on the freshly rebuilt v2 DB
           and confirm ReverseBlock() does NOT abort (the node stays alive and the
           stats round-trip exactly).

Coinbases pay to P2SH(OP_TRUE), which VoidCoin's coinbase output-type policy
accepts, so no wallet / P2QR address is needed to mine.
"""
import struct

import crcmod

from test_framework.address import script_to_p2sh
from test_framework.script import CScript, OP_TRUE, OP_NOP
from test_framework.script_util import script_to_p2sh_script
from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import assert_equal

REDEEM = CScript([OP_TRUE])
P2SH_ADDR = script_to_p2sh(REDEEM)
P2SH_SPK = script_to_p2sh_script(REDEEM)

# A second, distinct P2SH mining address (different redeem => different coinbase
# => different block hash). Used to mine a competing branch after invalidateblock;
# without it the deterministic miner reproduces the exact invalidated block and
# the node rejects it as duplicate-invalid. The coinbase output-type policy
# accepts any wrapped P2SH.
REDEEM2 = CScript([OP_TRUE, OP_NOP])
P2SH_ADDR2 = script_to_p2sh(REDEEM2)

# Must mirror src/index/coinstatsindex.cpp.
DB_VERSION_KEY = bytes([0x56])          # 'V'
CURRENT_INDEX_VERSION = 2
STALE_VERSION = 1                       # "old binary" value the gate must reject

# Bounty predicate from GetBlockSubsidyWithBounty() (src/validation.cpp).
VOID_BOUNTY_THRESHOLD = 33554
BOUNTY_ACTIVATION_REGTEST = 10          # fPowAllowMinDifficultyBlocks branch
BOUNTY_REWARD = 200                     # VOID

LEVELDB_BLOCK_SIZE = 32768              # leveldb log block size
_crc32c = crcmod.predefined.mkPredefinedCrcFun("crc-32c")


def _mask_crc(crc):
    # leveldb crc32c::Mask
    return (((crc >> 15) | (crc << 17)) + 0xa282ead8) & 0xffffffff


def _put_varint32(n):
    out = bytearray()
    while True:
        b = n & 0x7f
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def _writebatch_single_put(seq, key, value):
    # WriteBatch rep: seq(fixed64 LE) + count(fixed32 LE) + [kTypeValue(1) key value]
    body = struct.pack("<QI", seq, 1)
    body += bytes([0x01])  # kTypeValue
    body += _put_varint32(len(key)) + key
    body += _put_varint32(len(value)) + value
    return body


def _leveldb_log_record(payload):
    rtype = 1  # kFullType
    crc = _mask_crc(_crc32c(bytes([rtype]) + payload))
    header = struct.pack("<IHB", crc, len(payload), rtype)
    return header + payload


def _bounty_value_from_parent_hash(parent_hash_hex):
    # uint256::begin() is the little-endian byte array; the RPC hash is the
    # big-endian display, so the first three internal bytes are the last three
    # hex bytes. bountyValue = b0<<16 | b1<<8 | b2 (see GetBlockSubsidyWithBounty).
    b0 = int(parent_hash_hex[62:64], 16)
    b1 = int(parent_hash_hex[60:62], 16)
    b2 = int(parent_hash_hex[58:60], 16)
    return (b0 << 16) | (b1 << 8) | b2


class CoinStatsIndexVersionTest(VoidCoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False
        # Enough blocks that a ~1/500 bounty block is very likely to materialize
        # for Phase 4, while the version-gate phases work at any height >= 10.
        self.chain_len = 2500
        self.extra_args = [["-coinstatsindex"]]

    # ---- helpers -------------------------------------------------------------
    def coinstats_db_dir(self, node):
        return node.chain_path / "indexes" / "coinstats" / "db"

    def wait_index_synced(self, node):
        self.wait_until(
            lambda: node.getindexinfo().get("coinstatsindex", {}).get("synced") is True,
            timeout=120,
        )

    def wait_index_at(self, node, height):
        def ready():
            info = node.getindexinfo().get("coinstatsindex", {})
            return info.get("synced") is True and info.get("best_block_height") == height
        self.wait_until(ready, timeout=120)

    def debug_offset(self, node):
        return node.debug_log_path.stat().st_size

    def debug_since(self, node, offset):
        with open(node.debug_log_path, "rb") as f:
            f.seek(offset)
            return f.read().decode("utf-8", errors="replace")

    def make_stale_db_version(self, node):
        """Splice a DB_VERSION=STALE_VERSION write into the coinstats DB log."""
        dbdir = self.coinstats_db_dir(node)
        logs = sorted(dbdir.glob("*.log"), key=lambda p: int(p.stem))
        assert logs, f"no leveldb .log file found in {dbdir}"
        logfile = logs[-1]

        seq = 1 << 40  # far above any real sequence -> wins on recovery
        value = struct.pack("<I", STALE_VERSION)  # uint32 LE, plaintext (obfuscate=off)
        payload = _writebatch_single_put(seq, DB_VERSION_KEY, value)
        record = _leveldb_log_record(payload)

        size = logfile.stat().st_size
        off_in_block = size % LEVELDB_BLOCK_SIZE
        assert off_in_block + len(record) <= LEVELDB_BLOCK_SIZE, (
            f"spliced record would cross a leveldb block boundary "
            f"(log size {size}); rerun after a fresh restart"
        )
        with open(logfile, "ab") as f:
            f.write(record)
        self.log.info(f"Spliced DB_VERSION={STALE_VERSION} into {logfile.name} "
                      f"(+{len(record)} bytes at offset {size})")

    def coinbase_amount(self, node, height):
        h = node.getblockhash(height)
        blk = node.getblock(h, 2)
        return sum(o["value"] for o in blk["tx"][0]["vout"])

    # ---- test ----------------------------------------------------------------
    def run_test(self):
        node = self.nodes[0]

        self.log.info(f"Phase 0: build coinstatsindex over {self.chain_len} blocks")
        block_hashes = self.generatetoaddress(node, self.chain_len, P2SH_ADDR,
                                              sync_fun=self.no_op)
        self.wait_index_synced(node)
        info = node.getindexinfo()["coinstatsindex"]
        assert_equal(info["synced"], True)
        assert_equal(info["best_block_height"], self.chain_len)

        base = node.gettxoutsetinfo("muhash")
        base_tip = node.getbestblockhash()
        base_height = node.getblockcount()
        assert_equal(base["height"], self.chain_len)
        # A brand-new index (DB_MUHASH absent at ctor time) must never wipe.
        assert "wiping and rebuilding" not in self.debug_since(node, 0), \
            "fresh index build unexpectedly wiped/rebuilt"

        self.log.info("Phase 1: a normal restart does NOT wipe/rebuild")
        off = self.debug_offset(node)
        self.restart_node(0, extra_args=self.extra_args[0])
        self.wait_index_synced(node)
        assert "wiping and rebuilding" not in self.debug_since(node, off), \
            "normal restart (version current) unexpectedly wiped/rebuilt"
        assert_equal(node.gettxoutsetinfo("muhash"), base)   # stats unchanged
        assert_equal(node.getbestblockhash(), base_tip)      # tip unchanged

        self.log.info("Phase 2: stale on-disk DB_VERSION => wipe + rebuild")
        self.stop_node(0)
        self.make_stale_db_version(node)
        off = self.debug_offset(node) if node.debug_log_path.exists() else 0
        self.start_node(0, extra_args=self.extra_args[0])
        self.wait_index_synced(node)
        log_tail = self.debug_since(node, off)
        assert (f"on-disk index version {STALE_VERSION} does not match expected "
                f"{CURRENT_INDEX_VERSION}") in log_tail, \
            "version-mismatch gate did not fire on a stale DB\n" + log_tail[-2000:]
        assert "wiping and rebuilding the index with current semantics" in log_tail, \
            "wipe/rebuild was not logged on version mismatch"
        # The rebuilt index reproduces the EXACT same stats (only the version byte
        # was tampered with; the chain is unchanged), proving a correct rebuild.
        rebuilt = node.gettxoutsetinfo("muhash")
        assert_equal(rebuilt, base)
        # Stats-only: the wipe must not touch consensus state.
        assert_equal(node.getbestblockhash(), base_tip)
        assert_equal(node.getblockcount(), base_height)

        self.log.info("Phase 3: after rebuild the version is current => no wipe")
        off = self.debug_offset(node)
        self.restart_node(0, extra_args=self.extra_args[0])
        self.wait_index_synced(node)
        assert "wiping and rebuilding" not in self.debug_since(node, off), \
            "restart after rebuild unexpectedly wiped again (version not restamped)"
        assert_equal(node.gettxoutsetinfo("muhash"), base)

        self.phase4_reorg_across_bounty(node, block_hashes, base)

    def phase4_reorg_across_bounty(self, node, block_hashes, base):
        # block_hashes[i] is the block at height i+1 (clean chain, genesis == 0).
        def hash_at(height):
            return block_hashes[height - 1]

        bounty_heights = []
        for h in range(BOUNTY_ACTIVATION_REGTEST, self.chain_len):  # leave >=1 above
            parent_hex = hash_at(h - 1) if h - 1 >= 1 else node.getblockhash(0)
            if _bounty_value_from_parent_hash(parent_hex) < VOID_BOUNTY_THRESHOLD:
                bounty_heights.append(h)

        if not bounty_heights:
            self.log.info("Phase 4: SKIPPED - no Void Collapse Bounty block "
                          f"materialized in {self.chain_len} blocks (~1/500); the "
                          "version-gate wipe/rebuild path above is fully covered.")
            return

        # Highest bounty with room above it -> smallest reorg to exercise
        # ReverseBlock() across a bounty block.
        hb = bounty_heights[-1]
        self.log.info(f"Phase 4: reorg across bounty block at height {hb} "
                      f"(found bounties at {bounty_heights})")

        # Independent oracle: the coinbase at a bounty height mints 200 VOID.
        cb = self.coinbase_amount(node, hb)
        assert_equal(cb, BOUNTY_REWARD)

        tip = node.getbestblockhash()
        pre = node.gettxoutsetinfo("muhash")
        assert_equal(pre, base)
        parent_of_hb = node.getblockhash(hb - 1)

        # Invalidate the bounty block: the active tip drops to hb-1. The index does
        # not rewind yet (no competing block has connected), but the node must stay
        # alive.
        node.invalidateblock(hash_at(hb))
        assert_equal(node.getbestblockhash(), parent_of_hb)
        assert_equal(node.getblockcount(), hb - 1)

        # Mine a short competing branch on hb-1. The first new block connecting with
        # prev == hb-1 (!= the index's best block at chain_len) forces the
        # coinstatsindex to REWIND across the now-disconnected bounty block via
        # CustomRewind -> ReverseBlock, whose consistency Assert()s check the
        # bounty-aware subsidy. On a fresh v2 DB these hold; if they fired the node
        # would abort right here and the mining RPC would fail.
        new_len = 3
        self.generatetoaddress(node, new_len, P2SH_ADDR2, sync_fun=self.no_op)
        assert_equal(node.getblockcount(), hb - 1 + new_len)  # node alive, reorged
        self.wait_index_at(node, hb - 1 + new_len)            # index followed, no abort

        # Reconsider the bounty block: the original (longer) chain reactivates, the
        # index rewinds the competing branch and reconnects across the bounty, and
        # the stats must round-trip to the exact pre-reorg muhash.
        node.reconsiderblock(hash_at(hb))
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getblockcount(), self.chain_len)
        self.wait_index_at(node, self.chain_len)
        assert_equal(node.gettxoutsetinfo("muhash"), pre)
        self.log.info("Phase 4: reorg across a bounty block completed with NO abort")


if __name__ == "__main__":
    CoinStatsIndexVersionTest(__file__).main()
