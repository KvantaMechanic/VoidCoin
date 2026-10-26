// Copyright (c) 2015-2026 The Bitcoin Core developers
// Copyright (c) 2026 The VoidCoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VOIDCOIN_QT_BITCOINADDRESSVALIDATOR_H
#define VOIDCOIN_QT_BITCOINADDRESSVALIDATOR_H

#include <QValidator>

/** Base58 entry widget validator, checks for valid characters and
 * removes some whitespace.
 */
class VoidCoinAddressEntryValidator : public QValidator
{
    Q_OBJECT

public:
    explicit VoidCoinAddressEntryValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

/** VoidCoin address widget validator, checks for a valid voidcoin address.
 */
class VoidCoinAddressCheckValidator : public QValidator
{
    Q_OBJECT

public:
    explicit VoidCoinAddressCheckValidator(QObject *parent);

    State validate(QString &input, int &pos) const override;
};

#endif // VOIDCOIN_QT_BITCOINADDRESSVALIDATOR_H
