// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VOIDCOIN_TEST_FUZZ_UTIL_MEMPOOL_H
#define VOIDCOIN_TEST_FUZZ_UTIL_MEMPOOL_H

#include <kernel/mempool_entry.h>
#include <validation.h>

class CTransaction;
class CTxMemPool;
class FuzzedDataProvider;

class DummyChainState final : public Chainstate
{
public:
    void SetMempool(CTxMemPool* mempool)
    {
        m_mempool = mempool;
    }
};

[[nodiscard]] CTxMemPoolEntry ConsumeTxMemPoolEntry(FuzzedDataProvider& fuzzed_data_provider, const CTransaction& tx) noexcept;

#endif // VOIDCOIN_TEST_FUZZ_UTIL_MEMPOOL_H
