// Copyright (c) 2026 The Kvanta5 Core Developers
// Copyright (c) 2026 The VoidCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#include <crypto/pq/mldsa87/mldsa87.h>




extern "C" {
#include <crypto/pq/mldsa87/upstream/ref/api.h>
}

// Compile-time tripwires: the wallet-facing size constants MUST match the
// vendored pq-crystals Dilithium5 (ML-DSA-87) parameter set. If a future
// upstream bump changes any of these, the build fails here rather than silently
// truncating a key or signature.
static_assert(MLDSA87_PUBLIC_KEY_SIZE == pqcrystals_dilithium5_PUBLICKEYBYTES);
static_assert(MLDSA87_SECRET_KEY_SIZE == pqcrystals_dilithium5_SECRETKEYBYTES);
static_assert(MLDSA87_SIGNATURE_SIZE == pqcrystals_dilithium5_BYTES);

// VC-17: the seedless upstream keygen (pqcrystals_dilithium5_ref_keypair, which
// draws its master seed from the vendored randombytes and discards it) is
// intentionally NOT wrapped here. All wallet keys are derived deterministically
// via MLDSA87GenerateKeypairFromSeed() below so they remain seed-recoverable.

bool MLDSA87Sign(Span<const unsigned char> seckey,
                 Span<const unsigned char> msg,
                 std::vector<unsigned char>& sig_out)
{
    if (seckey.size() != MLDSA87_SECRET_KEY_SIZE) return false;

    sig_out.resize(MLDSA87_SIGNATURE_SIZE);
    size_t sig_len = sig_out.size();

    const unsigned char* ctx = nullptr;
    const size_t ctx_len = 0;

    const int ret = pqcrystals_dilithium5_ref_signature(
        sig_out.data(),
        &sig_len,
        msg.data(),
        msg.size(),
        ctx,
        ctx_len,
        seckey.data());

    if (ret != 0 || sig_len != MLDSA87_SIGNATURE_SIZE) {
        sig_out.clear();
        return false;
    }

    return true;
}

bool MLDSA87Verify(Span<const unsigned char> pubkey,
                   Span<const unsigned char> msg,
                   Span<const unsigned char> sig)
{
    if (pubkey.size() != MLDSA87_PUBLIC_KEY_SIZE) return false;
    if (sig.size() != MLDSA87_SIGNATURE_SIZE) return false;

    const unsigned char* ctx = nullptr;
    const size_t ctx_len = 0;

    return pqcrystals_dilithium5_ref_verify(
        sig.data(),
        sig.size(),
        msg.data(),
        msg.size(),
        ctx,
        ctx_len,
        pubkey.data()) == 0;
}

bool MLDSA87GenerateKeypairFromSeed(Span<const unsigned char> seed, std::vector<unsigned char>& pubkey, std::vector<unsigned char>& seckey)
{
    if (seed.size() != MLDSA87_SEED_SIZE) {
        return false;
    }

    pubkey.resize(MLDSA87_PUBLIC_KEY_SIZE);
    seckey.resize(MLDSA87_SECRET_KEY_SIZE);

    const int ret = crypto_sign_keypair_from_seed(pubkey.data(), seckey.data(), seed.data());
    if (ret != 0) {
        pubkey.clear();
        seckey.clear();
        return false;
    }

    return true;
}
