// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VOIDCOIN_QT_TRANSACTIONDESC_H
#define VOIDCOIN_QT_TRANSACTIONDESC_H

#include <qt/voidcoinunits.h>

#include <QObject>
#include <QString>

class TransactionRecord;

namespace interfaces {
class Node;
class Wallet;
struct WalletTx;
struct WalletTxStatus;
}

/** Provide a human-readable extended HTML description of a transaction.
 */
class TransactionDesc: public QObject
{
    Q_OBJECT

public:
    static QString toHTML(interfaces::Node& node, interfaces::Wallet& wallet, TransactionRecord* rec, VoidCoinUnit unit);

private:
    TransactionDesc() = default;

    static QString FormatTxStatus(const interfaces::WalletTxStatus& status, bool inMempool);
};

#endif // VOIDCOIN_QT_TRANSACTIONDESC_H
