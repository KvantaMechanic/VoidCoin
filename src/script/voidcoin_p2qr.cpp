// Copyright (c) 2026 The VoidCoin Core developers
// Copyright (c) 2026 Kvanta5 Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// SPDX-License-Identifier: MIT
//
// VoidCoin Pay-to-Quantum-Resistant (P2QR) script recognition and encoding.
// Derived from the Kvanta5-Core P2QR implementation, used under the MIT
// License as distributed at the time of the fork, and modified by VoidCoin;
// specified in VCIP-2 (/VCIP-2.md).
// Built on Bitcoin Core (MIT). Design lineage: BIP-360 (P2QR output design,
// Hunter Beast); ML-DSA-87 / NIST FIPS 204 via the pq-crystals/CRYSTALS-
// Dilithium reference implementation (src/crypto/pq/mldsa87/upstream/, not
// relicensed). The wire format is defined solely by VCIP-2 and by the bytes
// present on the VoidCoin chain.
//
//Liam's false Copyright claims end here. 
//
//All Original P2QR implementations are Copyright (c) 2026 The Kvanta5 Organization. 
//Whatever other ridiculous nonsense Liam did before he abandoned the chain is Copyright (c) 2026 Liam/Void/Whatever
//
//A note from KvantaMechanic: This is a good example for why people shouldn't be "vibe coding" blockchains. 
//Liam claims Kvanta5's P2QR implementation is derived from Hunter Beast's Pay-to-Merkle-Root (P2MR).
//He doesn't understand what he's claiming, at all. 
//Kvanta5's P2QR implements a native Pay-to-Quantum-Resistant (P2QR) output type using opcode 0x50 (Bitcoin's former OP_RESERVED), with ML-DSA-87 signature verification.


#include <script/voidcoin_p2qr.h>

#include <hash.h>

#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>

static void VoidCoinSetP2QRError(std::string* error, const std::string& msg)
{
    if (error) *error = msg;
}


bool VoidCoinIsCanonicalP2QRPush(opcodetype opcode, const std::vector<unsigned char>& data)
{
    const size_t size = data.size();

    /*
     * VoidCoin P2QR canonical scriptSig push rules.
     *
     * This intentionally does NOT require OP_1..OP_16 for numeric values,
     * because VoidCoin wallet signing currently encodes m/n/index values as
     * byte-vector pushes.
     */

    if (size == 0) {
        return opcode == OP_0;
    }

    if (size <= 75) {
        return opcode == static_cast<opcodetype>(size);
    }

    if (size <= 0xff) {
        return opcode == OP_PUSHDATA1;
    }

    if (size <= 0xffff) {
        return opcode == OP_PUSHDATA2;
    }

    return opcode == OP_PUSHDATA4;
}

bool VoidCoinReadCanonicalP2QRPushes(
    const CScript& script,
    std::vector<std::vector<unsigned char>>& pushes_out,
    std::string* error,
    size_t max_pushes)
{
    pushes_out.clear();

    if (script.empty()) {
        VoidCoinSetP2QRError(error, "p2qr-script-empty");
        return false;
    }

    if (!script.IsPushOnly()) {
        VoidCoinSetP2QRError(error, "p2qr-script-not-push-only");
        return false;
    }

    CScript::const_iterator pc = script.begin();

    while (pc < script.end()) {
        opcodetype opcode;
        std::vector<unsigned char> data;

        if (!script.GetOp(pc, opcode, data)) {
            VoidCoinSetP2QRError(error, "p2qr-script-invalid-push-opcode");
            return false;
        }

        if (opcode > OP_PUSHDATA4) {
            VoidCoinSetP2QRError(error, "p2qr-script-non-push-opcode");
            return false;
        }

        if (!VoidCoinIsCanonicalP2QRPush(opcode, data)) {
            VoidCoinSetP2QRError(error, "p2qr-script-non-canonical-push");
            return false;
        }

        pushes_out.push_back(std::move(data));

        if (max_pushes != 0 && pushes_out.size() > max_pushes) {
            VoidCoinSetP2QRError(error, "p2qr-script-too-many-pushes");
            return false;
        }
    }

    if (pushes_out.empty()) {
        VoidCoinSetP2QRError(error, "p2qr-script-no-pushes");
        return false;
    }

    return true;
}


static bool VoidCoinReadMinimalUInt16NonZero(const std::vector<unsigned char>& v, uint16_t& out)
{
    if (v.empty()) return false;
    if (v.size() > 2) return false;

    if (v.size() == 1) {
        if (v[0] == 0x00) return false;
        out = v[0];
        return true;
    }

    // 2-byte little-endian. Values <= 255 must use 1 byte.
    if (v[1] == 0x00) return false;

    out = static_cast<uint16_t>(v[0]) |
          (static_cast<uint16_t>(v[1]) << 8);

    if (out <= 0xff) return false;

    return true;
}

static bool VoidCoinReadMinimalUInt16AllowZero(const std::vector<unsigned char>& v, uint16_t& out)
{
    if (v.empty()) return false;
    if (v.size() > 2) return false;

    if (v.size() == 1) {
        out = v[0];
        return true;
    }

    // 2-byte little-endian. Values <= 255 must use 1 byte.
    if (v[1] == 0x00) return false;

    out = static_cast<uint16_t>(v[0]) |
          (static_cast<uint16_t>(v[1]) << 8);

    if (out <= 0xff) return false;

    return true;
}

static uint256 VoidCoinUint256FromP2QRProgramPush(const std::vector<unsigned char>& push)
{
    uint256 program;
    std::copy(push.begin(), push.end(), program.begin());
    return program;
}

CScript VoidCoinMakeP2QRScriptPubKey(const uint256& program)
{
    return CScript() << OP_RESERVED << std::vector<unsigned char>(program.begin(), program.end());
}

uint256 VoidCoinP2QRSingleProgram(const std::vector<unsigned char>& pubkey)
{
    // Preserve existing VoidCoin single-sig P2QR consensus behavior:
    // program = Hash(pubkey)
    return Hash(pubkey);
}

bool VoidCoinIsSupportedP2QRTimeLock(const VoidCoinP2QRTimeLock& lock)
{
    if (lock.version != VOIDCOIN_P2QR_TIMELOCK_VERSION) {
        return false;
    }
    return lock.lock_type == VOIDCOIN_P2QR_TIMELOCK_TYPE_HEIGHT ||
           lock.lock_type == VOIDCOIN_P2QR_TIMELOCK_TYPE_MTP;
}

std::vector<unsigned char> VoidCoinEncodeP2QRTimeLockDescriptor(const VoidCoinP2QRTimeLock& lock)
{
    std::vector<unsigned char> d;
    d.reserve(VOIDCOIN_P2QR_TIMELOCK_DESCRIPTOR_SIZE);
    d.push_back(lock.version);
    d.push_back(lock.lock_type);
    for (int i = 0; i < 8; ++i) {
        d.push_back(static_cast<unsigned char>((lock.lock_value >> (8 * i)) & 0xFF));
    }
    return d;
}

bool VoidCoinDecodeP2QRTimeLockDescriptor(
    const std::vector<unsigned char>& descriptor,
    VoidCoinP2QRTimeLock& out,
    std::string* error)
{
    if (descriptor.size() != VOIDCOIN_P2QR_TIMELOCK_DESCRIPTOR_SIZE) {
        VoidCoinSetP2QRError(error, "p2qr-timelock-bad-descriptor-size");
        return false;
    }

    out.version = descriptor[0];
    out.lock_type = descriptor[1];

    uint64_t value = 0;
    for (int i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(descriptor[2 + i]) << (8 * i);
    }
    out.lock_value = value;
    return true;
}

CScript VoidCoinMakeP2QRTimeLockScriptPubKey(const uint256& program, const VoidCoinP2QRTimeLock& lock)
{
    return CScript()
        << OP_RESERVED
        << std::vector<unsigned char>(program.begin(), program.end())
        << VoidCoinEncodeP2QRTimeLockDescriptor(lock);
}

bool VoidCoinIsCanonicalP2QRMultisigPolicy(
    uint16_t required,
    const std::vector<uint256>& signer_programs,
    std::string* error)
{
    const uint16_t total = static_cast<uint16_t>(signer_programs.size());

    if (required == 0) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-required-zero");
        return false;
    }

    if (total == 0) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-total-zero");
        return false;
    }

    if (required > total) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-required-greater-than-total");
        return false;
    }

    if (total > VOIDCOIN_P2QR_MULTISIG_MAX_KEYS) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-too-many-keys");
        return false;
    }

    if (required > VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-too-many-signatures");
        return false;
    }

    for (size_t i = 1; i < signer_programs.size(); ++i) {
        if (!(signer_programs[i - 1] < signer_programs[i])) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-signer-programs-not-strictly-sorted");
            return false;
        }
    }

    return true;
}

bool VoidCoinIsCanonicalP2QRMultisigPolicy(
    uint16_t required,
    const std::vector<std::vector<unsigned char>>& pubkeys,
    std::string* error)
{
    if (required == 0 || pubkeys.empty() || required > pubkeys.size()) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-invalid-threshold");
        return false;
    }

    if (pubkeys.size() > VOIDCOIN_P2QR_MULTISIG_MAX_KEYS) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-too-many-keys");
        return false;
    }

    if (required > VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-too-many-signatures");
        return false;
    }

    for (const auto& pubkey : pubkeys) {
        if (pubkey.size() != VOIDCOIN_P2QR_PUBKEY_SIZE) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-bad-pubkey-size");
            return false;
        }
    }

    for (size_t i = 1; i < pubkeys.size(); ++i) {
        if (!(pubkeys[i - 1] < pubkeys[i])) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-pubkeys-not-strictly-sorted");
            return false;
        }
    }

    return true;
}


uint256 VoidCoinP2QRMultisigProgram(
    uint16_t required,
    const std::vector<uint256>& signer_programs)
{
    HashWriter ss{};

    const std::string domain{"VOID:P2QR:MSIG:ADDR:v1"};

    ss << domain;
    ss << required;
    ss << static_cast<uint16_t>(signer_programs.size());

    for (const uint256& signer_program : signer_programs) {
        ss << signer_program;
    }

    return ss.GetSHA256();
}

uint256 VoidCoinP2QRMultisigProgram(
    uint16_t required,
    const std::vector<std::vector<unsigned char>>& pubkeys)
{
    HashWriter ss{};

    /*
     * Legacy/live-chain pubkey-policy multisig commitment.
     *
     * DO NOT change this domain once historical blocks exist.
     * This must match the version that created old vault outputs already
     * present on-chain, including the spend in block 13153.
     */
    const std::string domain{"VOID:P2QR:MSIG:v1"};

    ss << domain;
    ss << required;
    ss << static_cast<uint16_t>(pubkeys.size());

    for (const std::vector<unsigned char>& pubkey : pubkeys) {
        ss << pubkey;
    }

    return ss.GetSHA256();
}


bool VoidCoinParseP2QRMultisigSpend(
    const std::vector<std::vector<unsigned char>>& stack,
    VoidCoinP2QRMultisigSpend& out,
    std::string* error)
{
    out = VoidCoinP2QRMultisigSpend{};

    /*
     * Permanent dual-format P2QR multisig parser.
     *
     * Legacy/live-chain pubkey-policy stack:
     *
     *   <signature[0]> ... <signature[m-1]>
     *   <signer_index[0]> ... <signer_index[m-1]>
     *   <pubkey[0]> ... <pubkey[n-1]>
     *   <m>
     *   <n>
     *
     * New signer-address/program-policy stack:
     *
     *   <signature[0]> ... <signature[m-1]>
     *   <signer_index[0]> ... <signer_index[m-1]>
     *   <signing_pubkey[0]> ... <signing_pubkey[m-1]>
     *   <signer_program[0]> ... <signer_program[n-1]>
     *   <m>
     *   <n>
     *
     * The last two pushes are always m and n, so we can decode threshold first,
     * then disambiguate by total stack size.
     */
    if (stack.size() < 5) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-stack-too-small");
        return false;
    }

    uint16_t total = 0;
    uint16_t required = 0;

    if (!VoidCoinReadMinimalUInt16NonZero(stack[stack.size() - 1], total)) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-bad-total-encoding");
        return false;
    }

    if (!VoidCoinReadMinimalUInt16NonZero(stack[stack.size() - 2], required)) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-bad-required-encoding");
        return false;
    }

    if (required == 0 || total == 0 || required > total) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-invalid-threshold");
        return false;
    }

    if (total > VOIDCOIN_P2QR_MULTISIG_MAX_KEYS) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-too-many-keys");
        return false;
    }

    if (required > VOIDCOIN_P2QR_MULTISIG_MAX_SIGNATURES) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-too-many-signatures");
        return false;
    }

    const size_t legacy_expected_stack_size =
        static_cast<size_t>(required) + // signatures
        static_cast<size_t>(required) + // signer indexes
        static_cast<size_t>(total) +    // pubkeys
        2;                              // m, n

    const size_t signer_program_expected_stack_size =
        static_cast<size_t>(required) + // signatures
        static_cast<size_t>(required) + // signer indexes
        static_cast<size_t>(required) + // signing pubkeys
        static_cast<size_t>(total) +    // signer programs
        2;                              // m, n

    const bool is_legacy_pubkey_policy = stack.size() == legacy_expected_stack_size;
    const bool is_signer_program_policy = stack.size() == signer_program_expected_stack_size;

    if (!is_legacy_pubkey_policy && !is_signer_program_policy) {
        VoidCoinSetP2QRError(error, "p2qr-multisig-extra-or-missing-stack-items");
        return false;
    }

    const size_t sig_begin = 0;
    const size_t sig_end = static_cast<size_t>(required);

    const size_t idx_begin = sig_end;
    const size_t idx_end = idx_begin + static_cast<size_t>(required);

    out.required = required;
    out.total = total;

    out.signatures.reserve(required);
    out.signer_indexes.reserve(required);

    for (size_t i = sig_begin; i < sig_end; ++i) {
        if (stack[i].size() != VOIDCOIN_P2QR_SIGNATURE_SIZE) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-bad-signature-size");
            return false;
        }

        out.signatures.push_back(stack[i]);
    }

    uint16_t previous_index = 0;

    for (size_t i = idx_begin; i < idx_end; ++i) {
        uint16_t signer_index = 0;

        if (!VoidCoinReadMinimalUInt16AllowZero(stack[i], signer_index)) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-bad-signer-index-encoding");
            return false;
        }

        if (signer_index >= total) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-signer-index-out-of-range");
            return false;
        }

        const size_t approval_pos = i - idx_begin;
        if (approval_pos > 0 && signer_index <= previous_index) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-signer-indexes-not-strictly-sorted");
            return false;
        }

        previous_index = signer_index;
        out.signer_indexes.push_back(signer_index);
    }

    if (is_legacy_pubkey_policy) {
        /*
         * Legacy/live-chain format:
         *
         *   <sig[m]> <signer_index[m]> <pubkey[n]> <m> <n>
         *
         * This must validate historical chain data, including old vault spends.
         */
        const size_t pubkey_begin = idx_end;
        const size_t pubkey_end = pubkey_begin + static_cast<size_t>(total);

        out.pubkeys.reserve(total);

        for (size_t i = pubkey_begin; i < pubkey_end; ++i) {
            if (stack[i].size() != VOIDCOIN_P2QR_PUBKEY_SIZE) {
                VoidCoinSetP2QRError(error, "p2qr-multisig-bad-pubkey-size");
                return false;
            }

            out.pubkeys.push_back(stack[i]);
        }

        for (size_t i = 1; i < out.pubkeys.size(); ++i) {
            if (!(out.pubkeys[i - 1] < out.pubkeys[i])) {
                VoidCoinSetP2QRError(error, "p2qr-multisig-pubkeys-not-strictly-sorted");
                return false;
            }
        }

        return true;
    }

    /*
     * New signer-address/program-policy format:
     *
     *   <sig[m]> <signer_index[m]> <signing_pubkey[m]> <signer_program[n]> <m> <n>
     */
    const size_t signing_pubkey_begin = idx_end;
    const size_t signing_pubkey_end = signing_pubkey_begin + static_cast<size_t>(required);

    const size_t signer_program_begin = signing_pubkey_end;
    const size_t signer_program_end = signer_program_begin + static_cast<size_t>(total);

    out.signing_pubkeys.reserve(required);
    out.signer_programs.reserve(total);

    for (size_t i = signing_pubkey_begin; i < signing_pubkey_end; ++i) {
        if (stack[i].size() != VOIDCOIN_P2QR_PUBKEY_SIZE) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-bad-signing-pubkey-size");
            return false;
        }

        out.signing_pubkeys.push_back(stack[i]);
    }

    for (size_t i = signer_program_begin; i < signer_program_end; ++i) {
        if (stack[i].size() != VOIDCOIN_P2QR_PROGRAM_SIZE) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-bad-signer-program-size");
            return false;
        }

        out.signer_programs.push_back(VoidCoinUint256FromP2QRProgramPush(stack[i]));
    }

    if (!VoidCoinIsCanonicalP2QRMultisigPolicy(required, out.signer_programs, error)) {
        return false;
    }

    /*
     * Each revealed signing pubkey must derive to the signer program at its
     * claimed signer index.
     */
    for (size_t i = 0; i < out.signing_pubkeys.size(); ++i) {
        const uint16_t signer_index = out.signer_indexes[i];
        const uint256 derived_program = VoidCoinP2QRSingleProgram(out.signing_pubkeys[i]);

        if (derived_program != out.signer_programs[signer_index]) {
            VoidCoinSetP2QRError(error, "p2qr-multisig-signing-pubkey-does-not-match-signer-program");
            return false;
        }
    }

    return true;
}
