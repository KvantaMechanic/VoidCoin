# Libraries

| Name                     | Description |
|--------------------------|-------------|
| *libvoidcoin_cli*         | RPC client functionality used by *voidcoin-cli* executable |
| *libvoidcoin_common*      | Home for common functionality shared by different executables and libraries. Similar to *libvoidcoin_util*, but higher-level (see [Dependencies](#dependencies)). |
| *libvoidcoin_consensus*   | Consensus functionality used by *libvoidcoin_node* and *libvoidcoin_wallet*. |
| *libvoidcoin_crypto*      | Hardware-optimized functions for data encryption, hashing, message authentication, and key derivation. |
| *libvoidcoin_kernel*      | Consensus engine and support library used for validation by *libvoidcoin_node*. |
| *libvoidcoinqt*           | GUI functionality used by *voidcoin-qt* and *voidcoin-gui* executables. |
| *libvoidcoin_ipc*         | IPC functionality used by *voidcoin-node*, *voidcoin-wallet*, *voidcoin-gui* executables to communicate when [`-DWITH_MULTIPROCESS=ON`](multiprocess.md) is used. |
| *libvoidcoin_node*        | P2P and RPC server functionality used by *voidcoind* and *voidcoin-qt* executables. |
| *libvoidcoin_util*        | Home for common functionality shared by different executables and libraries. Similar to *libvoidcoin_common*, but lower-level (see [Dependencies](#dependencies)). |
| *libvoidcoin_wallet*      | Wallet functionality used by *voidcoind* and *voidcoin-wallet* executables. |
| *libvoidcoin_wallet_tool* | Lower-level wallet functionality used by *voidcoin-wallet* executable. |
| *libvoidcoin_zmq*         | [ZeroMQ](../zmq.md) functionality used by *voidcoind* and *voidcoin-qt* executables. |

## Conventions

- Most libraries are internal libraries and have APIs which are completely unstable! There are few or no restrictions on backwards compatibility or rules about external dependencies. An exception is *libvoidcoin_kernel*, which, at some future point, will have a documented external interface.

- Generally each library should have a corresponding source directory and namespace. Source code organization is a work in progress, so it is true that some namespaces are applied inconsistently, and if you look at [`add_library(voidcoin_* ...)`](../../src/CMakeLists.txt) lists you can see that many libraries pull in files from outside their source directory. But when working with libraries, it is good to follow a consistent pattern like:

  - *libvoidcoin_node* code lives in `src/node/` in the `node::` namespace
  - *libvoidcoin_wallet* code lives in `src/wallet/` in the `wallet::` namespace
  - *libvoidcoin_ipc* code lives in `src/ipc/` in the `ipc::` namespace
  - *libvoidcoin_util* code lives in `src/util/` in the `util::` namespace
  - *libvoidcoin_consensus* code lives in `src/consensus/` in the `Consensus::` namespace

## Dependencies

- Libraries should minimize what other libraries they depend on, and only reference symbols following the arrows shown in the dependency graph below:

<table><tr><td>

```mermaid

%%{ init : { "flowchart" : { "curve" : "basis" }}}%%

graph TD;

voidcoin-cli[voidcoin-cli]-->libvoidcoin_cli;

voidcoind[voidcoind]-->libvoidcoin_node;
voidcoind[voidcoind]-->libvoidcoin_wallet;

voidcoin-qt[voidcoin-qt]-->libvoidcoin_node;
voidcoin-qt[voidcoin-qt]-->libvoidcoinqt;
voidcoin-qt[voidcoin-qt]-->libvoidcoin_wallet;

voidcoin-wallet[voidcoin-wallet]-->libvoidcoin_wallet;
voidcoin-wallet[voidcoin-wallet]-->libvoidcoin_wallet_tool;

libvoidcoin_cli-->libvoidcoin_util;
libvoidcoin_cli-->libvoidcoin_common;

libvoidcoin_consensus-->libvoidcoin_crypto;

libvoidcoin_common-->libvoidcoin_consensus;
libvoidcoin_common-->libvoidcoin_crypto;
libvoidcoin_common-->libvoidcoin_util;

libvoidcoin_kernel-->libvoidcoin_consensus;
libvoidcoin_kernel-->libvoidcoin_crypto;
libvoidcoin_kernel-->libvoidcoin_util;

libvoidcoin_node-->libvoidcoin_consensus;
libvoidcoin_node-->libvoidcoin_crypto;
libvoidcoin_node-->libvoidcoin_kernel;
libvoidcoin_node-->libvoidcoin_common;
libvoidcoin_node-->libvoidcoin_util;

libvoidcoinqt-->libvoidcoin_common;
libvoidcoinqt-->libvoidcoin_util;

libvoidcoin_util-->libvoidcoin_crypto;

libvoidcoin_wallet-->libvoidcoin_common;
libvoidcoin_wallet-->libvoidcoin_crypto;
libvoidcoin_wallet-->libvoidcoin_util;

libvoidcoin_wallet_tool-->libvoidcoin_wallet;
libvoidcoin_wallet_tool-->libvoidcoin_util;

classDef bold stroke-width:2px, font-weight:bold, font-size: smaller;
class voidcoin-qt,voidcoind,voidcoin-cli,voidcoin-wallet bold
```
</td></tr><tr><td>

**Dependency graph**. Arrows show linker symbol dependencies. *Crypto* lib depends on nothing. *Util* lib is depended on by everything. *Kernel* lib depends only on consensus, crypto, and util.

</td></tr></table>

- The graph shows what _linker symbols_ (functions and variables) from each library other libraries can call and reference directly, but it is not a call graph. For example, there is no arrow connecting *libvoidcoin_wallet* and *libvoidcoin_node* libraries, because these libraries are intended to be modular and not depend on each other's internal implementation details. But wallet code is still able to call node code indirectly through the `interfaces::Chain` abstract class in [`interfaces/chain.h`](../../src/interfaces/chain.h) and node code calls wallet code through the `interfaces::ChainClient` and `interfaces::Chain::Notifications` abstract classes in the same file. In general, defining abstract classes in [`src/interfaces/`](../../src/interfaces/) can be a convenient way of avoiding unwanted direct dependencies or circular dependencies between libraries.

- *libvoidcoin_crypto* should be a standalone dependency that any library can depend on, and it should not depend on any other libraries itself.

- *libvoidcoin_consensus* should only depend on *libvoidcoin_crypto*, and all other libraries besides *libvoidcoin_crypto* should be allowed to depend on it.

- *libvoidcoin_util* should be a standalone dependency that any library can depend on, and it should not depend on other libraries except *libvoidcoin_crypto*. It provides basic utilities that fill in gaps in the C++ standard library and provide lightweight abstractions over platform-specific features. Since the util library is distributed with the kernel and is usable by kernel applications, it shouldn't contain functions that external code shouldn't call, like higher level code targeted at the node or wallet. (*libvoidcoin_common* is a better place for higher level code, or code that is meant to be used by internal applications only.)

- *libvoidcoin_common* is a home for miscellaneous shared code used by different VoidCoin Core applications. It should not depend on anything other than *libvoidcoin_util*, *libvoidcoin_consensus*, and *libvoidcoin_crypto*.

- *libvoidcoin_kernel* should only depend on *libvoidcoin_util*, *libvoidcoin_consensus*, and *libvoidcoin_crypto*.

- The only thing that should depend on *libvoidcoin_kernel* internally should be *libvoidcoin_node*. GUI and wallet libraries *libvoidcoinqt* and *libvoidcoin_wallet* in particular should not depend on *libvoidcoin_kernel* and the unneeded functionality it would pull in, like block validation. To the extent that GUI and wallet code need scripting and signing functionality, they should be able to get it from *libvoidcoin_consensus*, *libvoidcoin_common*, *libvoidcoin_crypto*, and *libvoidcoin_util*, instead of *libvoidcoin_kernel*.

- GUI, node, and wallet code internal implementations should all be independent of each other, and the *libvoidcoinqt*, *libvoidcoin_node*, *libvoidcoin_wallet* libraries should never reference each other's symbols. They should only call each other through [`src/interfaces/`](../../src/interfaces/) abstract interfaces.

## Work in progress

- Validation code is moving from *libvoidcoin_node* to *libvoidcoin_kernel* as part of [The libvoidcoinkernel Project #27587](https://github.com/voidcoin/voidcoin/issues/27587)
