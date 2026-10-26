// Copyright (c) 2026 The Kvanta5 Core Developers
// Copyright (c) 2026 The VoidCoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.



#ifndef VOIDCOIN_CRYPTO_PQ_MLDSA87_H
#define VOIDCOIN_CRYPTO_PQ_MLDSA87_H

#include <span.h>

#include <cstddef>
#include <vector>

static constexpr size_t MLDSA87_PUBLIC_KEY_SIZE = 2592;
static constexpr size_t MLDSA87_SECRET_KEY_SIZE = 4896;
static constexpr size_t MLDSA87_SIGNATURE_SIZE = 4627;
static constexpr size_t MLDSA87_SEED_SIZE = 32;

// Deterministic, seed-recoverable keygen — the ONLY supported keygen entry
// point. The seedless upstream keypair generator is deliberately not exposed
// (audit VC-17): it would draw and discard a fresh random seed, yielding a
// non-recoverable key that could be mistaken for the wallet keygen path.
bool MLDSA87GenerateKeypairFromSeed(Span<const unsigned char> seed, std::vector<unsigned char>& pubkey, std::vector<unsigned char>& seckey);

bool MLDSA87Sign(
    Span<const unsigned char> seckey,
    Span<const unsigned char> msg,
    std::vector<unsigned char>& sig_out);

bool MLDSA87Verify(
    Span<const unsigned char> pubkey,
    Span<const unsigned char> msg,
    Span<const unsigned char> sig);

#endif // VOIDCOIN_CRYPTO_PQ_MLDSA87_H
