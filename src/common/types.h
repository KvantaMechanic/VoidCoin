// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! @file common/types.h is a home for simple enum and struct type definitions
//! that can be used internally by functions in the libvoidcoin_common library,
//! but also used externally by node, wallet, and GUI code.
//!
//! This file is intended to define only simple types that do not have external
//! dependencies. More complicated types should be defined in dedicated header
//! files.

#ifndef VOIDCOIN_COMMON_TYPES_H
#define VOIDCOIN_COMMON_TYPES_H

namespace common {
enum class PSBTError {
    MISSING_INPUTS,
    SIGHASH_MISMATCH,
    EXTERNAL_SIGNER_NOT_FOUND,
    EXTERNAL_SIGNER_FAILED,
    UNSUPPORTED,
    // VoidCoin: a native P2QR (ML-DSA-87) input cannot be represented in a
    // BIP-174 PSBT (the post-quantum signature/pubkey are far larger than its
    // standard fields, and there is no VoidCoin PSBT extension). Reported instead
    // of the generic UNSUPPORTED so the error points at the working spend paths.
    VOIDCOIN_P2QR_UNSUPPORTED,
};
} // namespace common

#endif // VOIDCOIN_COMMON_TYPES_H
