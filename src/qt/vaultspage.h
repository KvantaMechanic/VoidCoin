// Copyright (c) 2026 Kvanta5 Core Developers.
// Copyright (c) 2026 Kvanta5 Organization.
// All rights reserved.
//
// Kvanta5 Vault Component.
// Proprietary source-available code for review and security inspection only.
//
// No copying, modification, forking, redistribution, publication,
// sublicensing, reimplementation, derivative works, or commercial use is
// permitted without prior express written permission from the Kvanta5 Core
// Developers or an authorized representative of the Kvanta5 Organization.
//
// This file is NOT licensed under the MIT License.
// A one time use is granted by KvantaMechanic to the individual reviving the dead Void chain, so that any Void holder who may have coins locked in a vault can recover them. 
// This one time use is limited to this version (v2.0.3) of the VoidCoin software. 

#ifndef VOIDCOIN_QT_VAULTSPAGE_H
#define VOIDCOIN_QT_VAULTSPAGE_H

#include <QWidget>
#include <QVector>

class QLabel;
class QPushButton;
class QTableWidget;
class PlatformStyle;
#include <qt/walletmodel.h>

class VaultsPage : public QWidget
{
    Q_OBJECT

public:
    explicit VaultsPage(const PlatformStyle* platform_style, QWidget* parent = nullptr);

    void setModel(WalletModel* model);

private Q_SLOTS:
    void createVault();
    void createVaultPayment();
    void approveVaultPayment();
    void importExportVault();
    void broadcastVaultPayment();
    void refreshVaults();
    void showSelectedVaultDetails();

private:
    void updateWalletLabel();
    void populateVaultTable();

    const PlatformStyle* m_platform_style{nullptr};
    WalletModel* m_wallet_model{nullptr};

    QLabel* m_wallet_label{nullptr};
    QLabel* m_summary_label{nullptr};

    QTableWidget* m_vaults_table{nullptr};

    QPushButton* m_create_vault_button{nullptr};
    QPushButton* m_create_payment_button{nullptr};
    QPushButton* m_approve_button{nullptr};
    QPushButton* m_import_export_button{nullptr};
    QPushButton* m_refresh_button{nullptr};

    QVector<WalletModel::VaultInfo> m_vaults;
};

#endif // VOIDCOIN_QT_VAULTSPAGE_H
