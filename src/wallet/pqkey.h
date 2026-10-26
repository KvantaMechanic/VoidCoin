#ifndef VOIDCOIN_WALLET_PQKEY_H
#define VOIDCOIN_WALLET_PQKEY_H

#include <addresstype.h>
#include <crypto/pq/mldsa87/mldsa87.h>
#include <serialize.h>
#include <span.h>
#include <uint256.h>

#include <cstdint>
#include <vector>

class P2QRKeyRecord
{
public:
    std::vector<unsigned char> seed;
    std::vector<unsigned char> pubkey;
    int64_t creation_time{0};

    P2QRKeyRecord() = default;
    // VC-10: the resident cleartext seed of an *unencrypted* wallet lives in this
    // record for the wallet's lifetime. Zeroize it on scope exit so it does not
    // survive in freed/pageable heap after the record (or any transient copy of
    // it) is destroyed. Declaring the destructor suppresses implicit moves, so a
    // copy of the 32-byte seed is cheap and acceptable here.
    ~P2QRKeyRecord();
    P2QRKeyRecord(const P2QRKeyRecord&) = default;
    P2QRKeyRecord& operator=(const P2QRKeyRecord&) = default;

    SERIALIZE_METHODS(P2QRKeyRecord, obj)
    {
        READWRITE(obj.seed, obj.pubkey, obj.creation_time);
    }
};

/**
 * On-disk / in-memory representation of a wallet-encrypted P2QR key.
 *
 * The 32-byte ML-DSA-87 seed is the only secret; it is stored as
 * EncryptSecret(master_key, seed, key_hash) in `crypted_seed`. The public key
 * and creation time are kept in the clear so that ownership detection
 * (IsMine / GetScriptPubKeys / multisig signer derivation) keeps working while
 * the wallet is locked, exactly as the public half of an ECDSA ckey does.
 */
class CryptedP2QRKeyRecord
{
public:
    std::vector<unsigned char> pubkey;
    int64_t creation_time{0};
    std::vector<unsigned char> crypted_seed;

    SERIALIZE_METHODS(CryptedP2QRKeyRecord, obj)
    {
        READWRITE(obj.pubkey, obj.creation_time, obj.crypted_seed);
    }
};

class VoidCoinP2QRMultisigRecord
{
public:
    uint16_t required{0};

    /*
     * Vault multisig policy is committed to signer P2QR programs/addresses,
     * not full signer pubkeys. Pubkeys are only revealed by signers at spend
     * time and must derive back to these signer programs.
     */
    std::vector<uint256> signer_programs;

    SERIALIZE_METHODS(VoidCoinP2QRMultisigRecord, obj)
    {
        READWRITE(obj.required, obj.signer_programs);
    }
};

class CPQPubKey
{
private:
    std::vector<unsigned char> m_pubkey;

public:
    CPQPubKey() = default;
    explicit CPQPubKey(std::vector<unsigned char> pubkey);

    bool IsValid() const;
    Span<const unsigned char> Bytes() const;
    const std::vector<unsigned char>& Raw() const;

    uint256 GetHash() const;
    VoidCoinP2QRDestination GetDestination() const;
};

class CPQKey
{
private:
    std::vector<unsigned char> m_seed;
    std::vector<unsigned char> m_pubkey;
    std::vector<unsigned char> m_seckey;

public:
    CPQKey() = default;
    // VC-10: zeroize the 32-byte seed and the expanded 4896-byte secret key when
    // a CPQKey handed out by GetKey()/GetKeyByPubKey()/the ExportSeed path goes
    // out of scope, so signing material does not linger in freed/pageable heap.
    // Declaring the destructor suppresses implicit moves; copies are cheap and
    // rare for this type.
    ~CPQKey();
    CPQKey(const CPQKey&) = default;
    CPQKey& operator=(const CPQKey&) = default;

    bool MakeNewKey();
    bool SetSeed(Span<const unsigned char> seed);
    bool SetSeedBytes(const std::vector<unsigned char>& seed);
    bool IsValid() const;
    bool HasSeed() const;

    CPQPubKey GetPubKey() const;
    const std::vector<unsigned char>& GetSeedBytes() const;
    const std::vector<unsigned char>& GetPubKeyBytes() const;
    const std::vector<unsigned char>& GetSecretKeyBytes() const;

    uint256 GetHash() const;
    VoidCoinP2QRDestination GetDestination() const;

    bool Sign(Span<const unsigned char> msg, std::vector<unsigned char>& sig_out) const;
    bool SelfTest() const;
};

#endif // VOIDCOIN_WALLET_PQKEY_H
