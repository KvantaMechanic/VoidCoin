# Copyright (c) 2023-present The VoidCoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

function(generate_setup_nsi)
  set(abs_top_srcdir ${PROJECT_SOURCE_DIR})
  set(abs_top_builddir ${PROJECT_BINARY_DIR})
  set(CLIENT_URL ${PROJECT_HOMEPAGE_URL})
  set(CLIENT_TARNAME "voidcoin")
  set(VOIDCOIN_GUI_NAME "voidcoin-qt")
  set(VOIDCOIN_DAEMON_NAME "voidcoind")
  set(VOIDCOIN_CLI_NAME "voidcoin-cli")
  set(VOIDCOIN_TX_NAME "voidcoin-tx")
  set(VOIDCOIN_WALLET_TOOL_NAME "voidcoin-wallet")
  set(VOIDCOIN_TEST_NAME "test_voidcoin")
  set(EXEEXT ${CMAKE_EXECUTABLE_SUFFIX})
  configure_file(${PROJECT_SOURCE_DIR}/share/setup.nsi.in ${PROJECT_BINARY_DIR}/voidcoin-win64-setup.nsi USE_SOURCE_PERMISSIONS @ONLY)
endfunction()
