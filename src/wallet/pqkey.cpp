#include <wallet/pqkey.h>

#include <hash.h>
#include <random.h>
#include <support/cleanse.h>

// VC-10: cleanse the resident cleartext seed of an unencrypted-wallet record on
// destruction so it does not survive in freed/pageable heap.
P2QRKeyRecord::~P2QRKeyRecord()
{
    if (!seed.empty()) memory_cleanse(seed.data(), seed.size());
}

// VC-10: cleanse the transient seed and expanded secret key held by a CPQKey on
// destruction (the GetKey()/ExportSeed signing paths).
CPQKey::~CPQKey()
{
    if (!m_seed.empty()) memory_cleanse(m_seed.data(), m_seed.size());
    if (!m_seckey.empty()) memory_cleanse(m_seckey.data(), m_seckey.size());
}

CPQPubKey::CPQPubKey(std::vector<unsigned char> pubkey)
    : m_pubkey(std::move(pubkey))
{
}

bool CPQPubKey::IsValid() const
{
    return m_pubkey.size() == MLDSA87_PUBLIC_KEY_SIZE;
}

Span<const unsigned char> CPQPubKey::Bytes() const
{
    return Span<const unsigned char>(m_pubkey.data(), m_pubkey.size());
}

const std::vector<unsigned char>& CPQPubKey::Raw() const
{
    return m_pubkey;
}

uint256 CPQPubKey::GetHash() const
{
    return Hash(m_pubkey);
}

VoidCoinP2QRDestination CPQPubKey::GetDestination() const
{
    return VoidCoinP2QRDestination(GetHash());
}

bool CPQKey::MakeNewKey()
{
    m_seed.resize(MLDSA87_SEED_SIZE);
    GetStrongRandBytes(m_seed);

    if (!MLDSA87GenerateKeypairFromSeed(
            Span<const unsigned char>(m_seed.data(), m_seed.size()),
            m_pubkey,
            m_seckey)) {
        // VC-10: zeroize secret material on the failure path, not just .clear().
        if (!m_seed.empty()) memory_cleanse(m_seed.data(), m_seed.size());
        if (!m_seckey.empty()) memory_cleanse(m_seckey.data(), m_seckey.size());
        m_seed.clear();
        m_pubkey.clear();
        m_seckey.clear();
        return false;
    }

    return SelfTest();
}

bool CPQKey::SetSeed(Span<const unsigned char> seed)
{
    if (seed.size() != MLDSA87_SEED_SIZE) return false;

    m_seed.assign(seed.begin(), seed.end());

    if (!MLDSA87GenerateKeypairFromSeed(seed, m_pubkey, m_seckey)) {
        // VC-10: zeroize secret material on the failure path, not just .clear().
        if (!m_seed.empty()) memory_cleanse(m_seed.data(), m_seed.size());
        if (!m_seckey.empty()) memory_cleanse(m_seckey.data(), m_seckey.size());
        m_seed.clear();
        m_pubkey.clear();
        m_seckey.clear();
        return false;
    }

    return SelfTest();
}

bool CPQKey::SetSeedBytes(const std::vector<unsigned char>& seed)
{
    return SetSeed(Span<const unsigned char>(seed.data(), seed.size()));
}

bool CPQKey::IsValid() const
{
    return m_seed.size() == MLDSA87_SEED_SIZE &&
           m_pubkey.size() == MLDSA87_PUBLIC_KEY_SIZE &&
           m_seckey.size() == MLDSA87_SECRET_KEY_SIZE;
}

bool CPQKey::HasSeed() const
{
    return m_seed.size() == MLDSA87_SEED_SIZE;
}

CPQPubKey CPQKey::GetPubKey() const
{
    return CPQPubKey(m_pubkey);
}

const std::vector<unsigned char>& CPQKey::GetSeedBytes() const
{
    return m_seed;
}

const std::vector<unsigned char>& CPQKey::GetPubKeyBytes() const
{
    return m_pubkey;
}

const std::vector<unsigned char>& CPQKey::GetSecretKeyBytes() const
{
    return m_seckey;
}

uint256 CPQKey::GetHash() const
{
    return Hash(m_pubkey);
}

VoidCoinP2QRDestination CPQKey::GetDestination() const
{
    return VoidCoinP2QRDestination(GetHash());
}

bool CPQKey::Sign(Span<const unsigned char> msg, std::vector<unsigned char>& sig_out) const
{
    if (!IsValid()) return false;

    return MLDSA87Sign(
        Span<const unsigned char>(m_seckey.data(), m_seckey.size()),
        msg,
        sig_out
    );
}

bool CPQKey::SelfTest() const
{
    if (!IsValid()) return false;

    const uint256 test_msg = Hash(std::string{"VOID-P2QR-MLDSA87-seed-self-test"});

    std::vector<unsigned char> sig;
    if (!MLDSA87Sign(
            Span<const unsigned char>(m_seckey.data(), m_seckey.size()),
            Span<const unsigned char>(test_msg.begin(), test_msg.size()),
            sig)) {
        return false;
    }

    return MLDSA87Verify(
        Span<const unsigned char>(m_pubkey.data(), m_pubkey.size()),
        Span<const unsigned char>(test_msg.begin(), test_msg.size()),
        Span<const unsigned char>(sig.data(), sig.size())
    );
}
