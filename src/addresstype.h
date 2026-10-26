// Copyright (c) 2023 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef VOIDCOIN_ADDRESSTYPE_H
#define VOIDCOIN_ADDRESSTYPE_H

#include <attributes.h>
#include <pubkey.h>
#include <script/script.h>
#include <uint256.h>
#include <util/check.h>
#include <util/hash_type.h>

#include <algorithm>
#include <cstdint>
#include <variant>
#include <vector>

class CNoDestination
{
private:
    CScript m_script;

public:
    CNoDestination() = default;
    explicit CNoDestination(const CScript& script) : m_script(script) {}

    const CScript& GetScript() const LIFETIMEBOUND { return m_script; }

    friend bool operator==(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() == b.GetScript(); }
    friend bool operator<(const CNoDestination& a, const CNoDestination& b) { return a.GetScript() < b.GetScript(); }
};

struct PubKeyDestination {
private:
    CPubKey m_pubkey;

public:
    explicit PubKeyDestination(const CPubKey& pubkey) : m_pubkey(pubkey) {}

    const CPubKey& GetPubKey() const LIFETIMEBOUND { return m_pubkey; }

    friend bool operator==(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() == b.GetPubKey(); }
    friend bool operator<(const PubKeyDestination& a, const PubKeyDestination& b) { return a.GetPubKey() < b.GetPubKey(); }
};

struct PKHash : public BaseHash<uint160>
{
    PKHash() : BaseHash() {}
    explicit PKHash(const uint160& hash) : BaseHash(hash) {}
    explicit PKHash(const CPubKey& pubkey);
    explicit PKHash(const CKeyID& pubkey_id);
};
CKeyID ToKeyID(const PKHash& key_hash);

struct WitnessV0KeyHash;

struct ScriptHash : public BaseHash<uint160>
{
    ScriptHash() : BaseHash() {}
    // These don't do what you'd expect.
    // Use ScriptHash(GetScriptForDestination(...)) instead.
    explicit ScriptHash(const WitnessV0KeyHash& hash) = delete;
    explicit ScriptHash(const PKHash& hash) = delete;

    explicit ScriptHash(const uint160& hash) : BaseHash(hash) {}
    explicit ScriptHash(const CScript& script);
    explicit ScriptHash(const CScriptID& script);
};
CScriptID ToScriptID(const ScriptHash& script_hash);

struct WitnessV0ScriptHash : public BaseHash<uint256>
{
    WitnessV0ScriptHash() : BaseHash() {}
    explicit WitnessV0ScriptHash(const uint256& hash) : BaseHash(hash) {}
    explicit WitnessV0ScriptHash(const CScript& script);
};

struct WitnessV0KeyHash : public BaseHash<uint160>
{
    WitnessV0KeyHash() : BaseHash() {}
    explicit WitnessV0KeyHash(const uint160& hash) : BaseHash(hash) {}
    explicit WitnessV0KeyHash(const CPubKey& pubkey);
    explicit WitnessV0KeyHash(const PKHash& pubkey_hash);
};
CKeyID ToKeyID(const WitnessV0KeyHash& key_hash);

struct WitnessV1Taproot : public XOnlyPubKey
{
    WitnessV1Taproot() : XOnlyPubKey() {}
    explicit WitnessV1Taproot(const XOnlyPubKey& xpk) : XOnlyPubKey(xpk) {}
};

struct VoidCoinP2QRDestination : public BaseHash<uint256>
{
    VoidCoinP2QRDestination() : BaseHash() {}
    explicit VoidCoinP2QRDestination(const uint256& hash) : BaseHash(hash) {}
};

//! VCIP-3 versioned P2QR time-lock destination (vqt1... addresses).
//! Encodes the SAME 32-byte P2QR policy commitment used by native P2QR (a single
//! ML-DSA-87 key or an M-of-N multisig) plus a 10-byte lock descriptor:
//!   version(1) || lock_type(1) || lock_value(uint64 little-endian, 8)
//! The retired int32 lockHeight (and its VC-08 sign-wrap bug) is replaced by an
//! unsigned uint64 lock_value. The output scriptPubKey is:
//!   OP_RESERVED <program[32]> <lock_descriptor[10]>
struct VoidCoinP2QRTimeLockDestination
{
    uint256 program;     //!< 32-byte P2QR policy commitment (same as native P2QR)
    uint8_t version;     //!< lock descriptor version (0x01 is the only defined value)
    uint8_t lock_type;   //!< 0x00 absolute height, 0x01 absolute median-time-past
    uint64_t lock_value; //!< absolute block height, or MTP in unix seconds

    VoidCoinP2QRTimeLockDestination()
        : program(), version(1), lock_type(0), lock_value(0) {}
    VoidCoinP2QRTimeLockDestination(const uint256& prog, uint8_t ver, uint8_t type, uint64_t value)
        : program(prog), version(ver), lock_type(type), lock_value(value) {}

    bool operator==(const VoidCoinP2QRTimeLockDestination& o) const {
        return program == o.program && version == o.version &&
               lock_type == o.lock_type && lock_value == o.lock_value;
    }
    bool operator<(const VoidCoinP2QRTimeLockDestination& o) const {
        if (program != o.program) return program < o.program;
        if (version != o.version) return version < o.version;
        if (lock_type != o.lock_type) return lock_type < o.lock_type;
        return lock_value < o.lock_value;
    }
};

//! CTxDestination subtype to encode any future Witness version
struct WitnessUnknown
{
private:
    unsigned int m_version;
    std::vector<unsigned char> m_program;

public:
    WitnessUnknown(unsigned int version, const std::vector<unsigned char>& program) : m_version(version), m_program(program) {}
    WitnessUnknown(int version, const std::vector<unsigned char>& program) : m_version(static_cast<unsigned int>(version)), m_program(program) {}

    unsigned int GetWitnessVersion() const { return m_version; }
    const std::vector<unsigned char>& GetWitnessProgram() const LIFETIMEBOUND { return m_program; }

    friend bool operator==(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() != w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() == w2.GetWitnessProgram();
    }

    friend bool operator<(const WitnessUnknown& w1, const WitnessUnknown& w2) {
        if (w1.GetWitnessVersion() < w2.GetWitnessVersion()) return true;
        if (w1.GetWitnessVersion() > w2.GetWitnessVersion()) return false;
        return w1.GetWitnessProgram() < w2.GetWitnessProgram();
    }
};

struct PayToAnchor : public WitnessUnknown
{
    PayToAnchor() : WitnessUnknown(1, {0x4e, 0x73}) {
        Assume(CScript::IsPayToAnchor(1, {0x4e, 0x73}));
    };
};

/**
 * A txout script categorized into standard templates.
 *  * CNoDestination: Optionally a script, no corresponding address.
 *  * PubKeyDestination: TxoutType::PUBKEY (P2PK), no corresponding address
 *  * PKHash: TxoutType::PUBKEYHASH destination (P2PKH address)
 *  * ScriptHash: TxoutType::SCRIPTHASH destination (P2SH address)
 *  * WitnessV0ScriptHash: TxoutType::WITNESS_V0_SCRIPTHASH destination (P2WSH address)
 *  * WitnessV0KeyHash: TxoutType::WITNESS_V0_KEYHASH destination (P2WPKH address)
 *  * WitnessV1Taproot: TxoutType::WITNESS_V1_TAPROOT destination (P2TR address)
 *  * VoidCoinP2QRDestination: TxoutType::VOIDCOIN_P2QR destination (native VoidCoin quantum-resistant address)
 *  * PayToAnchor: TxoutType::ANCHOR destination (P2A address)
 *  * WitnessUnknown: TxoutType::WITNESS_UNKNOWN destination (P2W??? address)
 *  A CTxDestination is the internal data type encoded in a voidcoin address
 */
using CTxDestination = std::variant<CNoDestination, PubKeyDestination, PKHash, ScriptHash, WitnessV0ScriptHash, WitnessV0KeyHash, WitnessV1Taproot, VoidCoinP2QRDestination, VoidCoinP2QRTimeLockDestination, PayToAnchor, WitnessUnknown>;

/** Check whether a CTxDestination corresponds to one with an address. */
bool IsValidDestination(const CTxDestination& dest);

/**
 * Parse a scriptPubKey for the destination.
 *
 * For standard scripts that have addresses (and P2PK as an exception), a corresponding CTxDestination
 * is assigned to addressRet.
 * For all other scripts. addressRet is assigned as a CNoDestination containing the scriptPubKey.
 *
 * Returns true for standard destinations with addresses - P2PKH, P2SH, P2WPKH, P2WSH, P2TR and P2W??? scripts.
 * Returns false for non-standard destinations and those without addresses - P2PK, bare multisig, null data, and nonstandard scripts.
 */
bool ExtractDestination(const CScript& scriptPubKey, CTxDestination& addressRet);

/**
 * Generate a VoidCoin scriptPubKey for the given CTxDestination. Returns a P2PKH
 * script for a CKeyID destination, a P2SH script for a CScriptID, and an empty
 * script for CNoDestination.
 */
CScript GetScriptForDestination(const CTxDestination& dest);

#endif // VOIDCOIN_ADDRESSTYPE_H
