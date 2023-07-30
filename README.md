# Bitcoin wallet libraries

![Build](https://github.com/BP-WG/bp-wallet/workflows/Build/badge.svg)
![Tests](https://github.com/BP-WG/bp-wallet/workflows/Tests/badge.svg)
![Lints](https://github.com/BP-WG/bp-wallet/workflows/Lints/badge.svg)
[![codecov](https://codecov.io/gh/BP-WG/bp-wallet/branch/master/graph/badge.svg)](https://codecov.io/gh/BP-WG/bp-wallet)

[![crates.io](https://img.shields.io/crates/v/bp-wallet)](https://crates.io/crates/bp-wallet)
[![Docs](https://docs.rs/bp-wallet/badge.svg)](https://docs.rs/bp-wallet)
[![Apache-2 licensed](https://img.shields.io/crates/l/bp-wallet)](./LICENSE)

Modern, minimalistic & standard-compliant cold wallet libraries: an alternative
to `rust-bitcoin` and BDK libraries from [LNP/BP Standards Association][Assoc].

The main goals of the library are:
- **fast stabilization of APIs**: the library will be targeting v1.0 version
  within the first year of its development; which should enable downstream
  crates using the library also to stabilize and not spend too much effort
  on changing the integration each time the new version of `bp-wallet` is 
  released;
- **no use of private keys**: the library analyzes wallet state using 
  descriptors and allows to produce unsigned PSBTs, as well as publish and 
  analyze (partially) signed PSBTs - but doesn't provide a signer or a way to 
  work with any private key material (seeds, mnemonics, xprivs, private keys);
  PSBT files must be signed with some external signers or hardware wallets;
- **standard-compliance**: the library tries to provide full compliance with
  existing bitcoin standards defined in BIPs and do not use any legacy 
  approaches or "blockchain-not-bitcoin" practices (like the ones provided by 
  BLIPs);
- **separation of bitcoin consensus and standards**: the consensus-related
  code is not a part of this library; all data structures and business logic
  which may have consensus meaning and is required for a wallet is separated
  into an independent [`bp-primitives`] library (a part of [`bp-core`] library),
  which is planned to be more extensively audited and ossified alongside 
  bitcoin protocol (while this library will continue to evolve with better
  APIs and to match new wallet standards);
- **extensive use of descriptors**: library focuses on defining all parts of 
  a wallet using descriptors; additionally to script pubkey descriptors it also
  supports xpub descriptors, derivation descriptors, applied to script pubkey 
  descriptor as a whole, and input descriptors for RBFs. You can read more on
  specific descriptor types in the [section below](#descriptors);
- **script templates**: the library allows to provide an arbitrary script as
  a part of a descriptor, which allows support for BOLT lightning channel
  transaction and makes it possible to ensure stability in the long run;
  you can read more about script templates vs miniscript below;
- **opinionated high-level wallet abstractions**: the library provide a set
  of high-level wallet data structures abstracting away blockchain-level
  details; helping in writing less boilerplate business logic;
- **APIs usable in all rust projects and in FFI**: the library doesn't use
  async rust, complex callbacks, threads etc., which allows to keep the API
  simple, usable from any rust app (like ones using reactive patterns instead of
  async); at the same time all the data structures of the library are 
  `Send + Sync`, meaning that they can be used in any multi-thread or async 
  environment;
- **abstracted blockchain data providers**: the library abstracts blockchain
  indexer APIs (Electrum, Esplora, Bitcoin Core etc.) and also provides their
  implementation using this library structures.

## FAQs

### Why not use `rust-bitcoin`?

The library doesn't rely on `rust-bitcoin` crate. The reasons for that are:
- **to keep the functionality set small and wallet-specific**: `rust-bitcoin` 
  provides "all in one" solution, covering many parts of bitcoin ecosystem, like
  bitcoin peer-to-peer protocol, not really used by a wallet;
- **to keep API stable**: `rust-bitcoin` with each release significantly breaks
  APIs, being in constant refactoring since early 2022 - a process likely to 
  last for few years more; update of wallet libraries after each major change is
  painful and takes a lot of developers time and effort, as well as introduces
  API breaking changes downstream preventing all dependent libraries from 
  stabilization;
- **separation of private key material**: in Rust it is impossible to achieve
  constant-time production of secret key material, as well as prevent the
  compiler from copying it all over the machine memory (`zeroise` and other
  approaches doesn't prevent that). Thus, providing secret keys alongside
  other APIs may lead to non-secure design of the wallet and should be avoided;
- **separation of consensus code from standards**: `rust-bitcoin` provides next
  to each other consensus-related structures and higher level wallet 
  abstractions, which contradicts to the design decision we are making in this
  library;
- **to introduce strong semantic typing**: for instance, `rust-bitcoin` doesn't 
  differentiate different forms of scripts (pubkey, sig, witness etc.), while
  in this library we are using semantic type approach, providing type-safe
  variants for each semantically-distinct entity even if it shares the same
  representation with others.

As one may see from the list, `rust-bitcoin` design and maintenance approach
contradicts to the major aims of this project - in fact, this project was 
created by [Maxim Orlovsky][orlovsky] (who was the most active contributor to 
`rust-bitcoin` since Q1 2019 till Q2 2022) in order to address these issues
using different set of trade-offs, providing an alternative to `rust-bitcoin` 
to those who needs it.

### Why not use miniscript?

Miniscript is great for many purposes, but it can't be used for many cases,
including representation of BOLT-3 lightning channel transaction outputs,
re-use of public key in different branches of pre-taproot scripts [1][ms-1]. 
Miniscript is also still unstable, having recent changes to the semantic due 
to discovered bugs [2][ms-2] [3][ms-3]; meaning that the descriptors created
with miniscript before may not be able to deterministically reproduce the 
structure of some wallet UTXOs in a future. Finally, the existing Rust 
miniscript implementation [`rust-miniscript`] inherits all `rust-bitcoin`
tradeoffs, and is much more unstable in terms of APIs and semantic. Thus, it was
decided to use this library to provide an alternative to miniscript with
introduction of [script tempaltes][#script-templates] convertable to and from 
miniscript representation - but with some externally-provided tools instead 
of adding miniscript as a direct dependency here.

### Why not BDK?

BDK is great, but it relies on `rust-bitcoin` and `rust-miniscript` and can't
be used outside of that ecosystem, inheriting all tradeoffs described above.
Since we try to address those trade-offs, we had to create a BDK alternative.

### How this project is related to `descriptor-wallet`?

[Descriptor wallet][descriptor-wallet] was an earlier project by the same 
authors trying to address `rust-bitcoin` issues by building on top of it. With
the recent v0.30 `rust-bitcoin` release it became clear that the effort of 
adoption to API-breaking changes is much higher than creating a new independent 
project from scratch, while at the same time the new project may address 
`rust-bitcoin` issues in much more efficient and elegant way. Thus, it was 
decided to discontinue `descriptor-wallet` and start the new `bp-wallet` project
instead.


## Design

### Script templates

### Descriptors


## Contributing

Contribution guidelines can be found in [CONTRIBUTING](CONTRIBUTING.md)


## More information

### MSRV

This library requires minimum rust compiler version (MSRV) 1.60.0.

### Policy on altcoins

Altcoins and "blockchains" other than Bitcoin blockchain/Bitcoin protocols are
not supported and not planned to be supported; pull requests targeting them will
be declined.

### Licensing

The libraries are distributed on the terms of Apache 2.0 opensource license.
See [LICENCE](LICENSE) file for the license details.

[Assoc]: https://lnp-bp.org
[bp-primitives]: https://crates.io/crates/bp-primitives
[bp-core]: https://github.com/BP-WG/bp-core
[orlovsky]: https://github.com/dr-orlovsky
[descriptor-wallet]: https://github.com/BP-WG/descriptor-wallet
