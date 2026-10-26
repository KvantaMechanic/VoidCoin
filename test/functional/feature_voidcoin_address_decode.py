#!/usr/bin/env python3
# Copyright (c) 2026 The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""VC-09 / fix #4: key_io.cpp address-decode routing for VoidCoin P2QR.

Exercises DecodeDestination() through the validateaddress RPC (pure RPC, no
mining) and asserts the runtime behaviour of the "vqt-misroute" fix in
src/key_io.cpp. On regtest the three relevant human-readable prefixes are:

    Bech32HRP              = "bcrt"    (segwit-style; subsumes the two below)
    Bech32QRHRP            = "bcrtqr"  (native P2QR receive address)
    Bech32QRTTimelockHRP   = "bcrtqt"  (P2QR time-lock / vault -> ENABLED)

The P2QR time-lock ("bcrtqt1...") output type has been rebuilt and RE-ENABLED
as a working, spendable output type. Its address now carries a 42-byte payload
(32-byte program || 10-byte lock descriptor: version(1) || lock_type(1) ||
lock_value(uint64 LE)) and decodes as VALID. This test asserts:
  (1) a genuine time-lock address (both an absolute-"height" lock and an
      absolute-median-time-past "time" lock), minted via the wallet RPC
      getnewtimelockaddress, decodes to isvalid=true with
      isvoidcoinp2qrtimelock=true, timelock_version==1, and lock_type/lock_value
      matching the request, and round-trips to the same canonical address;
  (2) a normal native P2QR address (getnewvoidcoinp2qraddress -> "bcrtqr1...")
      still decodes to isvalid=true with isvoidcoinp2qr=true (and is NOT flagged
      as a time-lock);
  (3) an ordinary, non-colliding Base58Check address still decodes correctly
      (isvalid=true) -- i.e. the fix's added `&& !DecodeBase58Check(...)` guard
      did NOT start swallowing legitimate Base58 addresses into the time-lock/
      bech32 branch. This is MORE important now that vqt is enabled: the guard
      must still keep a valid "VQT1..." Base58 string out of the time-lock
      branch; and
  (4) the `isvoidcoinp2qrtimelock` describe-field is correctly DISCRIMINATED --
      it appears ONLY for a genuine time-lock address and is absent for a native
      P2QR address and for a Base58 P2SH address.

Documented limitation (goal 3, adversarial collision) -- see decode_check_3().
"""
from test_framework.test_framework import VoidCoinTestFramework
from test_framework.util import (
    assert_equal,
)

REGTEST_TIMELOCK_HRP = "bcrtqt"   # Bech32QRTTimelockHRP on regtest (enabled)
REGTEST_P2QR_HRP = "bcrtqr"       # Bech32QRHRP on regtest (native P2QR)

# lock_type integer codes as reported by validateaddress (lock_type_name gives
# the human-readable form). See VOIDCOIN_P2QR_TIMELOCK_TYPE_* in
# src/script/voidcoin_p2qr.h.
LOCK_TYPE_INT = {"height": 0, "time": 1}


class VoidCoinAddressDecodeTest(VoidCoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        # Address decoding is independent of VCIP-3; no activation knobs needed.
        # The harness default -rpcdoccheck=1 is left ON: validateaddress and
        # getaddressinfo now enumerate the P2QR/mining/time-lock describe-fields
        # (isvoidcoinp2qr, p2qr_program, native_scriptPubKey, mining_address,
        # mining_*, isvoidcoinp2qrtimelock, timelock_version, lock_type,
        # lock_type_name, lock_value) in their RPCResult schemas, so inspecting
        # a native P2QR ("bcrtqr1...") OR a now-valid time-lock ("bcrtqt1...")
        # address under the strict doc-check no longer raises. Running with the
        # check ON here also guards that RPC-doc-schema fix against regression.
        self.extra_args = [[]]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def init_wallet(self, *, node):
        # VoidCoin refuses legacy/bech32 addresses, so the framework's default
        # importprivkey(deterministic legacy coinbase key) path is unusable.
        # Create a plain descriptor wallet instead; keys come from P2QR RPCs.
        self.nodes[node].createwallet(wallet_name=self.default_wallet_name,
                                      descriptors=self.options.descriptors,
                                      load_on_startup=True)

    def run_test(self):
        self.node = self.nodes[0]
        self.decode_check_1_genuine_timelock_valid()
        self.decode_check_2_native_p2qr_valid()
        self.decode_check_3_base58_not_misrouted()
        self.decode_check_4_timelock_field_discriminated()

    # ------------------------------------------------------------------ (1)
    def decode_check_1_genuine_timelock_valid(self):
        node = self.node
        self.log.info("check 1: genuine bcrtqt1 time-lock addresses (height + "
                      "time) now decode VALID with the describe-fields set")

        # (lock_type, lock_value) pairs -- one absolute-height lock and one
        # absolute median-time-past ("time") lock.
        for lock_type, lock_value in (("height", 500), ("time", 1893456000)):
            # Mint a real, correctly-formatted time-lock address via the wallet
            # RPC (the on-chain-truth encoder), rather than hand-building the
            # 42-byte descriptor payload.
            created = node.getnewtimelockaddress(lock_type, lock_value)
            tl_addr = created["address"]
            self.log.info("  minted %s time-lock address: %s", lock_type, tl_addr)
            assert tl_addr.startswith(REGTEST_TIMELOCK_HRP + "1"), tl_addr
            # The RPC echoes back the descriptor it committed.
            assert_equal(created["timelock_version"], 1)
            assert_equal(created["lock_type"], lock_type)   # string form
            assert_equal(created["lock_value"], lock_value)

            res = node.validateaddress(tl_addr)
            # ENABLED -> the address decodes and is valid (no fail-closed error).
            assert_equal(res["isvalid"], True)
            assert "error" not in res, res
            # It is recognised specifically as a P2QR time-lock, version 1.
            assert_equal(res["isvoidcoinp2qrtimelock"], True)
            assert_equal(res["timelock_version"], 1)
            # lock_type (integer code) + lock_type_name (human form) + lock_value
            # all round-trip the request.
            assert_equal(res["lock_type"], LOCK_TYPE_INT[lock_type])
            assert_equal(res["lock_type_name"], lock_type)
            assert_equal(res["lock_value"], lock_value)
            # The canonical re-encoding round-trips to the exact same address.
            assert_equal(res["address"], tl_addr)
            # It is neither a script nor a witness output, and carries a 32-byte
            # P2QR program (ML-DSA commitment).
            assert_equal(res["isscript"], False)
            assert_equal(res["iswitness"], False)
            assert_equal(len(res["p2qr_program"]), 64)  # 32 bytes hex
            # A time-lock is NOT a native (non-time-locked) P2QR address.
            assert_equal(res.get("isvoidcoinp2qr", False), False)

    # ------------------------------------------------------------------ (2)
    def decode_check_2_native_p2qr_valid(self):
        node = self.node
        self.log.info("check 2: native P2QR (getnewvoidcoinp2qraddress) decodes "
                      "valid with isvoidcoinp2qr=true")

        p2qr = node.getnewvoidcoinp2qraddress()
        self.log.info("  native P2QR address: %s", p2qr)
        assert p2qr.startswith(REGTEST_P2QR_HRP + "1"), p2qr

        res = node.validateaddress(p2qr)
        assert_equal(res["isvalid"], True)
        assert_equal(res["isvoidcoinp2qr"], True)
        # Round-trips to the same canonical address.
        assert_equal(res["address"], p2qr)
        # It is neither a script nor a witness output, and carries a 32-byte
        # P2QR program (ML-DSA commitment).
        assert_equal(res["isscript"], False)
        assert_equal(res["iswitness"], False)
        assert_equal(len(res["p2qr_program"]), 64)  # 32 bytes hex
        # It must NOT be flagged as a timelock.
        assert_equal(res.get("isvoidcoinp2qrtimelock", False), False)

    # ------------------------------------------------------------------ (3)
    def decode_check_3_base58_not_misrouted(self):
        node = self.node
        self.log.info("check 3: an ordinary Base58Check address still decodes "
                      "correctly (guard did not break Base58)")

        # The P2QR mining compatibility address is a genuine Base58Check P2SH
        # string. It decodes through the Base58 branch of DecodeDestination, so
        # it is exactly the class of address the fix's `!DecodeBase58Check(...)`
        # guard must NOT divert into the disabled/bech32 branch.
        mining = node.getnewvoidcoinp2qrminingaddress()["address"]
        self.log.info("  base58 P2SH mining address: %s", mining)
        # Regtest Base58 addresses never begin with the "bcrt" HRP.
        assert not mining.lower().startswith("bcrt"), mining

        res = node.validateaddress(mining)
        assert_equal(res["isvalid"], True)     # decoded, not misrouted/refused
        assert_equal(res["isscript"], True)    # P2SH
        assert "error" not in res, res
        # A valid Base58 address is not a native P2QR nor a timelock.
        assert_equal(res.get("isvoidcoinp2qr", False), False)
        assert_equal(res.get("isvoidcoinp2qrtimelock", False), False)

        # DOCUMENTED LIMITATION (goal 3, adversarial collision):
        # The fix's `&& !DecodeBase58Check(str)` guard only changes routing when
        # the timelock HRP is NOT a prefix of the segwit HRP. On regtest the
        # segwit HRP "bcrt" is a strict prefix of the timelock HRP "bcrtqt", so
        # ANY string that could trip the vqt check ("bcrtqt1...") already matches
        # the "bcrt" segwit-HRP prefix and enters the bech32 branch regardless of
        # the guard. Additionally, regtest Base58 addresses start with m/n/2 and
        # can NEVER begin with "bcrt", so a real Base58-vs-vqt collision is not
        # constructible on regtest. The guard is load-bearing only on networks
        # where the segwit HRP is not a prefix of the vqt HRP (mainnet:
        # "void"/"vqr" vs "vqt"). What IS verifiable on regtest -- and asserted
        # above -- is the guard's non-regression: a valid Base58 address still
        # decodes to isvalid=true rather than being swallowed by the fix.

    # ------------------------------------------------------------------ (4)
    def decode_check_4_timelock_field_discriminated(self):
        node = self.node
        self.log.info("check 4: isvoidcoinp2qrtimelock is discriminated -- it "
                      "appears ONLY for a real time-lock address")

        # Across a native P2QR, a Base58 P2SH, and a genuine time-lock address,
        # validateaddress must set isvoidcoinp2qrtimelock ONLY for the time-lock:
        # the describe visitor emits that field solely for the time-lock
        # destination, so it must be absent (not merely false) for the other two.
        native = node.getnewvoidcoinp2qraddress()
        mining = node.getnewvoidcoinp2qrminingaddress()["address"]
        timelock = node.getnewtimelockaddress("height", 99)["address"]

        # The genuine time-lock: valid, and the field is present and true.
        res_tl = node.validateaddress(timelock)
        assert_equal(res_tl["isvalid"], True)
        assert_equal(res_tl["isvoidcoinp2qrtimelock"], True)

        # The native P2QR: valid, but the time-lock field must NOT appear.
        res_native = node.validateaddress(native)
        assert_equal(res_native["isvalid"], True)
        assert "isvoidcoinp2qrtimelock" not in res_native, res_native

        # The Base58 P2SH mining address: valid, and the time-lock field must
        # NOT appear (a Base58 output is never a P2QR time-lock).
        res_mining = node.validateaddress(mining)
        assert_equal(res_mining["isvalid"], True)
        assert "isvoidcoinp2qrtimelock" not in res_mining, res_mining

        # All three are valid now (the time-lock is no longer refused); the field
        # is what discriminates the time-lock, not an isvalid=false refusal.
        assert_equal(res_tl["isvalid"], True)
        assert_equal(res_native["isvalid"], True)
        assert_equal(res_mining["isvalid"], True)


if __name__ == "__main__":
    VoidCoinAddressDecodeTest(__file__).main()
