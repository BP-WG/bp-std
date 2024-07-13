// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2024 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::borrow::Borrow;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use amplify::{confinement, hex, ByteArray, Bytes20, Bytes32, Bytes4, Wrapper};
use bc::secp256k1::{Keypair, PublicKey, SecretKey, SECP256K1};
use bc::{secp256k1, CompressedPk, InvalidPubkey, LegacyPk, XOnlyPk};
use bitcoin_hashes::{hash160, sha512, Hash, HashEngine, Hmac, HmacEngine};

use crate::{
    base58, DerivationIndex, DerivationParseError, DerivationPath, DerivationSeg, HardenedIndex,
    Idx, IdxBase, IndexParseError, Keychain, NormalIndex, SegParseError, Terminal,
};

pub const XPRIV_MAINNET_MAGIC: [u8; 4] = [0x04u8, 0x88, 0xAD, 0xE4];
pub const XPRIV_TESTNET_MAGIC: [u8; 4] = [0x04u8, 0x35, 0x83, 0x94];

pub const XPUB_MAINNET_MAGIC: [u8; 4] = [0x04u8, 0x88, 0xB2, 0x1E];
pub const XPUB_TESTNET_MAGIC: [u8; 4] = [0x04u8, 0x35, 0x87, 0xCF];

#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum XkeyDecodeError {
    /// wrong length of extended pubkey data ({0}).
    WrongExtendedKeyLength(usize),

    /// provided key is not a standard BIP-32 extended pubkey
    UnknownKeyType([u8; 4]),

    /// extended pubkey contains {0}
    #[from]
    #[from(bc::secp256k1::Error)]
    InvalidPubkey(InvalidPubkey<33>),

    /// xpriv contains invalid byte for the secret key type ({0:#04x}) which must be set to zero.
    InvalidType(u8),

    /// xpriv contains invalid data with secret key value overflowing over field order.
    InvalidSecretKey,
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
pub enum XkeyParseError {
    /// wrong Base58 encoding of extended pubkey data - {0}
    #[display(doc_comments)]
    #[from]
    Base58(base58::Error),

    #[display(inner)]
    #[from]
    Decode(XkeyDecodeError),

    #[display(inner)]
    #[from]
    DerivationPath(DerivationParseError),

    /// invalid master key fingerprint - {0}
    #[from]
    InvalidMasterFp(hex::Error),

    /// invalid terminal derivation format.
    InvalidTerminal,

    /// invalid keychain segment - {0}
    #[from]
    InvalidKeychain(SegParseError),

    /// invalid index value in terminal derivation segment.
    #[from]
    InvalidIndex(IndexParseError),

    /// no xpub key origin information.
    NoOrigin,

    /// no extended public key.
    NoXpub,

    /// xpub network and origin mismatch.
    NetworkMismatch,

    /// xpub depth and origin mismatch.
    DepthMismatch,

    /// xpub parent not matches the provided origin information.
    ParentMismatch,
}

impl From<OriginParseError> for XkeyParseError {
    fn from(err: OriginParseError) -> Self {
        match err {
            OriginParseError::DerivationPath(e) => XkeyParseError::DerivationPath(e),
            OriginParseError::InvalidMasterFp(e) => XkeyParseError::InvalidMasterFp(e),
        }
    }
}

/// BIP32 chain code used for hierarchical derivation
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, RangeOps)]
pub struct ChainCode(Bytes32);

impl AsRef<[u8]> for ChainCode {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<[u8; 32]> for ChainCode {
    fn from(value: [u8; 32]) -> Self { Self(value.into()) }
}

impl From<ChainCode> for [u8; 32] {
    fn from(value: ChainCode) -> Self { value.0.into_inner() }
}

/// Deterministic part of the extended public key.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct XpubCore {
    /// Public key
    pub public_key: CompressedPk,
    /// BIP32 chain code used for hierarchical derivation
    pub chain_code: ChainCode,
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display, From)]
#[wrapper(RangeOps, Hex, FromStr)]
#[display(LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct XpubFp(
    #[from]
    #[from([u8; 4])]
    Bytes4,
);

impl AsRef<[u8]> for XpubFp {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<XpubFp> for [u8; 4] {
    fn from(value: XpubFp) -> Self { value.0.into_inner() }
}

impl XpubFp {
    pub const fn master() -> Self { Self(Bytes4::zero()) }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, Display, From)]
#[wrapper(RangeOps, Hex, FromStr)]
#[display(LowerHex)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct XpubId(
    #[from]
    #[from([u8; 20])]
    Bytes20,
);

impl AsRef<[u8]> for XpubId {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl From<XpubId> for [u8; 20] {
    fn from(value: XpubId) -> Self { value.0.into_inner() }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct XkeyMeta {
    pub depth: u8,
    pub parent_fp: XpubFp,
    pub child_number: DerivationIndex,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Xpub {
    testnet: bool,
    meta: XkeyMeta,
    core: XpubCore,
}

impl Xpub {
    pub fn decode(data: impl Borrow<[u8]>) -> Result<Xpub, XkeyDecodeError> {
        let data = data.borrow();

        if data.len() != 78 {
            return Err(XkeyDecodeError::WrongExtendedKeyLength(data.len()));
        }

        let testnet = match &data[0..4] {
            magic if magic == XPUB_MAINNET_MAGIC => false,
            magic if magic == XPUB_TESTNET_MAGIC => true,
            unknown => {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(unknown);
                return Err(XkeyDecodeError::UnknownKeyType(magic));
            }
        };
        let depth = data[4];

        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&data[5..9]);

        let mut child_number = [0u8; 4];
        child_number.copy_from_slice(&data[9..13]);
        let child_number = u32::from_be_bytes(child_number);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        let public_key = CompressedPk::from_bytes(&data[45..78])?;

        Ok(Xpub {
            testnet,
            meta: XkeyMeta {
                depth,
                parent_fp: parent_fp.into(),
                child_number: child_number.into(),
            },
            core: XpubCore {
                public_key,
                chain_code: chain_code.into(),
            },
        })
    }

    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.testnet {
            false => XPUB_MAINNET_MAGIC,
            true => XPUB_TESTNET_MAGIC,
        });
        ret[4] = self.meta.depth;
        ret[5..9].copy_from_slice(self.meta.parent_fp.as_ref());
        ret[9..13].copy_from_slice(&self.meta.child_number.index().to_be_bytes());
        ret[13..45].copy_from_slice(self.core.chain_code.as_ref());
        ret[45..78].copy_from_slice(&self.core.public_key.serialize());
        ret
    }

    #[must_use]
    pub fn is_testnet(&self) -> bool { self.testnet }

    pub fn depth(&self) -> u8 { self.meta.depth }

    pub fn child_number(&self) -> DerivationIndex { self.meta.child_number }

    pub fn parent_fp(&self) -> XpubFp { self.meta.parent_fp }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XpubId {
        let hash = hash160::Hash::hash(&self.core.public_key.serialize());
        XpubId::from_byte_array(*hash.as_byte_array())
    }

    pub fn fingerprint(&self) -> XpubFp {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.identifier()[..4]);
        XpubFp::from_byte_array(bytes)
    }

    /// Constructs ECDSA public key valid in legacy context (compressed by default).
    pub fn to_legacy_pk(&self) -> LegacyPk { LegacyPk::compressed(*self.core.public_key) }

    /// Constructs ECDSA public key.
    pub fn to_compr_pk(&self) -> CompressedPk { self.core.public_key }

    /// Constructs BIP340 public key matching internal public key representation.
    pub fn to_xonly_pk(&self) -> XOnlyPk { XOnlyPk::from(self.core.public_key) }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing `AsRef<ChildNumber>`, such as
    /// `DerivationPath`, for instance.
    pub fn derive_pub(&self, path: impl AsRef<[NormalIndex]>) -> Self {
        let mut pk = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(*cnum)
        }
        pk
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(&self, child_no: NormalIndex) -> (secp256k1::Scalar, ChainCode) {
        let mut hmac_engine: HmacEngine<sha512::Hash> =
            HmacEngine::new(self.core.chain_code.as_ref());
        hmac_engine.input(&self.core.public_key.serialize());
        hmac_engine.input(&child_no.to_be_bytes());

        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])
            .expect("negligible probability")
            .into();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hmac_result[32..]);
        let chain_code = ChainCode::from_byte_array(bytes);
        (private_key, chain_code)
    }

    /// Public->Public child key derivation
    pub fn ckd_pub(&self, child_no: NormalIndex) -> Xpub {
        let (scalar, chain_code) = self.ckd_pub_tweak(child_no);
        let tweaked =
            self.core.public_key.add_exp_tweak(SECP256K1, &scalar).expect("negligible probability");

        let meta = XkeyMeta {
            depth: self.meta.depth + 1,
            parent_fp: self.fingerprint(),
            child_number: child_no.into(),
        };
        let core = XpubCore {
            public_key: tweaked.into(),
            chain_code,
        };
        Xpub {
            testnet: self.testnet,
            meta,
            core,
        }
    }
}

impl Display for Xpub {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(f, &self.encode())
    }
}

impl FromStr for Xpub {
    type Err = XkeyParseError;

    fn from_str(inp: &str) -> Result<Xpub, XkeyParseError> {
        let data = base58::decode_check(inp)?;
        Ok(Xpub::decode(data)?)
    }
}

/// Deterministic part of the extended public key.
#[derive(Copy, Clone, Eq, PartialEq)]
pub struct XprivCore {
    /// Secret key
    pub private_key: SecretKey,
    /// BIP32 chain code used for hierarchical derivation
    pub chain_code: ChainCode,
}

#[derive(Copy, Clone, Eq, PartialEq)]
pub struct Xpriv {
    testnet: bool,
    meta: XkeyMeta,
    core: XprivCore,
}

impl Xpriv {
    // TODO: Use dedicated `Seed` type
    pub fn new_master(testnet: bool, seed: &[u8]) -> Xpriv {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&hmac_result[32..]);

        Xpriv {
            testnet,
            meta: XkeyMeta {
                depth: 0,
                parent_fp: XpubFp::master(),
                child_number: DerivationIndex::ZERO,
            },
            core: XprivCore {
                private_key: SecretKey::from_slice(&hmac_result[..32])
                    .expect("negligible probability"),
                chain_code: chain_code.into(),
            },
        }
    }

    pub fn decode(data: impl Borrow<[u8]>) -> Result<Xpriv, XkeyDecodeError> {
        let data = data.borrow();

        if data.len() != 78 {
            return Err(XkeyDecodeError::WrongExtendedKeyLength(data.len()));
        }

        let testnet = match &data[0..4] {
            magic if magic == XPRIV_MAINNET_MAGIC => false,
            magic if magic == XPRIV_TESTNET_MAGIC => true,
            unknown => {
                let mut magic = [0u8; 4];
                magic.copy_from_slice(unknown);
                return Err(XkeyDecodeError::UnknownKeyType(magic));
            }
        };
        let depth = data[4];

        let mut parent_fp = [0u8; 4];
        parent_fp.copy_from_slice(&data[5..9]);

        let mut child_number = [0u8; 4];
        child_number.copy_from_slice(&data[9..13]);
        let child_number = u32::from_be_bytes(child_number);

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&data[13..45]);

        if data[45] != 0x00 {
            return Err(XkeyDecodeError::InvalidType(data[45]));
        }
        let private_key =
            SecretKey::from_slice(&data[46..78]).map_err(|_| XkeyDecodeError::InvalidSecretKey)?;

        Ok(Xpriv {
            testnet,
            meta: XkeyMeta {
                depth,
                parent_fp: parent_fp.into(),
                child_number: child_number.into(),
            },
            core: XprivCore {
                private_key,
                chain_code: chain_code.into(),
            },
        })
    }

    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.testnet {
            false => XPRIV_MAINNET_MAGIC,
            true => XPRIV_TESTNET_MAGIC,
        });
        ret[4] = self.meta.depth;
        ret[5..9].copy_from_slice(self.meta.parent_fp.as_ref());
        ret[9..13].copy_from_slice(&self.meta.child_number.index().to_be_bytes());
        ret[13..45].copy_from_slice(self.core.chain_code.as_ref());
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.core.private_key.secret_bytes());
        ret
    }

    #[must_use]
    pub fn is_testnet(&self) -> bool { self.testnet }

    pub fn depth(&self) -> u8 { self.meta.depth }

    pub fn child_number(&self) -> DerivationIndex { self.meta.child_number }

    pub fn parent_fp(&self) -> XpubFp { self.meta.parent_fp }

    pub fn fingerprint(self) -> XpubFp { self.to_xpub().fingerprint() }

    pub fn identifier(self) -> XpubId { self.to_xpub().identifier() }

    pub fn to_xpub(self) -> Xpub {
        Xpub {
            testnet: self.testnet,
            meta: self.meta,
            core: XpubCore {
                public_key: self.core.private_key.public_key(SECP256K1).into(),
                chain_code: self.core.chain_code,
            },
        }
    }

    pub fn to_compr_pk(self) -> CompressedPk {
        self.to_private_ecdsa().public_key(SECP256K1).into()
    }

    pub fn to_xonly_pk(self) -> XOnlyPk {
        self.to_private_ecdsa().x_only_public_key(SECP256K1).0.into()
    }

    pub fn to_private_ecdsa(self) -> SecretKey { self.core.private_key }

    pub fn to_keypair_bip340(self) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &self.core.private_key[..])
            .expect("BIP32 internal private key representation is broken")
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<I: Into<DerivationIndex> + Copy>(&self, path: impl AsRef<[I]>) -> Xpriv {
        let mut xpriv: Xpriv = *self;
        for idx in path.as_ref() {
            xpriv = xpriv.ckd_priv((*idx).into());
        }
        xpriv
    }

    /// Private->Private child key derivation
    pub fn ckd_priv(&self, idx: impl Into<DerivationIndex>) -> Xpriv {
        let idx = idx.into();

        let mut hmac_engine: HmacEngine<sha512::Hash> =
            HmacEngine::new(self.core.chain_code.as_slice());
        match idx {
            DerivationIndex::Normal(_) => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &PublicKey::from_secret_key(SECP256K1, &self.core.private_key).serialize(),
                );
            }
            DerivationIndex::Hardened(_) => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.core.private_key[..]);
            }
        }

        hmac_engine.input(&idx.index().to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk =
            SecretKey::from_slice(&hmac_result[..32]).expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.core.private_key.into()).expect("statistically impossible to hit");

        let mut chain_code = [0u8; 32];
        chain_code.copy_from_slice(&hmac_result[32..]);

        Xpriv {
            testnet: self.testnet,
            meta: XkeyMeta {
                depth: self.meta.depth + 1,
                parent_fp: self.fingerprint(),
                child_number: idx,
            },
            core: XprivCore {
                private_key: tweaked,
                chain_code: chain_code.into(),
            },
        }
    }
}

impl Display for Xpriv {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(f, &self.encode())
    }
}

impl FromStr for Xpriv {
    type Err = XkeyParseError;

    fn from_str(inp: &str) -> Result<Xpriv, XkeyParseError> {
        let data = base58::decode_check(inp)?;
        Ok(Xpriv::decode(data)?)
    }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{master_fp}{derivation}", alt = "{master_fp}{derivation:#}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct XkeyOrigin {
    master_fp: XpubFp,
    derivation: DerivationPath<HardenedIndex>,
}

impl XkeyOrigin {
    pub fn new(master_fp: XpubFp, derivation: DerivationPath<HardenedIndex>) -> Self {
        XkeyOrigin {
            master_fp,
            derivation,
        }
    }

    pub const fn master_fp(&self) -> XpubFp { self.master_fp }

    pub fn derivation(&self) -> &[HardenedIndex] { self.derivation.as_ref() }

    pub fn as_derivation(&self) -> &DerivationPath<HardenedIndex> { &self.derivation }

    pub fn to_derivation(&self) -> DerivationPath {
        self.derivation.iter().copied().map(DerivationIndex::from).collect()
    }

    pub fn child_derivation<'a>(&'a self, child: &'a KeyOrigin) -> Option<&[DerivationIndex]> {
        if self.master_fp() == child.master_fp() {
            let d = child.derivation();
            let shared = d.shared_prefix(self.derivation());
            if shared > 0 {
                return Some(&d[shared..]);
            }
        }
        None
    }

    pub fn is_subset_of(&self, other: &KeyOrigin) -> bool {
        self.master_fp == other.master_fp
            && self.derivation.shared_prefix(other.derivation()) == self.derivation.len()
    }
}

impl FromStr for XkeyOrigin {
    type Err = OriginParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (master_fp, path) = match s.split_once('/') {
            None => (XpubFp::default(), ""),
            Some(("00000000", p)) | Some(("m", p)) => (XpubFp::default(), p),
            Some((fp, p)) => (XpubFp::from_str(fp)?, p),
        };
        Ok(XkeyOrigin {
            master_fp,
            derivation: DerivationPath::from_str(path)?,
        })
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum OriginParseError {
    /// invalid derivation path - {0}
    #[from]
    DerivationPath(DerivationParseError),

    /// invalid master key fingerprint - {0}
    #[from]
    InvalidMasterFp(hex::Error),
}

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug, Display)]
#[display("{master_fp}{derivation}", alt = "{master_fp}{derivation:#}")]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct KeyOrigin {
    #[getter(as_copy)]
    master_fp: XpubFp,
    derivation: DerivationPath,
}

impl FromStr for KeyOrigin {
    type Err = XkeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (master_fp, path) = match s.split_once('/') {
            None => (XpubFp::default(), ""),
            Some(("00000000", p)) | Some(("m", p)) => (XpubFp::default(), p),
            Some((fp, p)) => (XpubFp::from_str(fp)?, p),
        };
        Ok(KeyOrigin {
            master_fp,
            derivation: DerivationPath::from_str(path)?,
        })
    }
}

impl KeyOrigin {
    pub fn new(master_fp: XpubFp, derivation: DerivationPath) -> Self {
        KeyOrigin {
            master_fp,
            derivation,
        }
    }

    pub fn with(xpub_origin: XkeyOrigin, terminal: Terminal) -> Self {
        let mut derivation = DerivationPath::new();
        derivation.extend(xpub_origin.to_derivation());
        derivation.push(terminal.keychain.into());
        derivation.push(DerivationIndex::Normal(terminal.index));
        KeyOrigin {
            master_fp: xpub_origin.master_fp(),
            derivation,
        }
    }
}

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug)]
pub struct XpubAccount {
    origin: XkeyOrigin,
    xpub: Xpub,
}

impl XpubAccount {
    pub fn new(xpub: Xpub, origin: XkeyOrigin) -> Self { XpubAccount { xpub, origin } }

    #[inline]
    pub const fn master_fp(&self) -> XpubFp { self.origin.master_fp }

    #[inline]
    pub fn account_fp(&self) -> XpubFp { self.xpub.fingerprint() }

    #[inline]
    pub fn account_id(&self) -> XpubId { self.xpub.identifier() }

    #[inline]
    pub fn derivation(&self) -> &[HardenedIndex] { self.origin.derivation.as_ref() }

    #[inline]
    pub const fn as_derivation(&self) -> &DerivationPath<HardenedIndex> { &self.origin.derivation }

    #[inline]
    pub fn to_derivation(&self) -> DerivationPath { self.origin.to_derivation() }
}

impl Display for XpubAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        Display::fmt(&self.origin, f)?;
        f.write_str("]")?;
        write!(f, "{}/", self.xpub)
    }
}

impl FromStr for XpubAccount {
    type Err = XkeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('[') {
            return Err(XkeyParseError::NoOrigin);
        }
        let (origin, xpub) =
            s.trim_start_matches('[').split_once(']').ok_or(XkeyParseError::NoOrigin)?;
        let origin = XkeyOrigin::from_str(origin)?;
        let xpub = Xpub::from_str(xpub)?;

        if origin.derivation.len() != xpub.meta.depth as usize {
            return Err(XkeyParseError::DepthMismatch);
        }
        if !origin.derivation.is_empty() {
            let network = if xpub.testnet { HardenedIndex::ONE } else { HardenedIndex::ZERO };
            if origin.derivation.get(1) != Some(&network) {
                return Err(XkeyParseError::NetworkMismatch);
            }
            if origin.derivation.last().copied().map(DerivationIndex::Hardened)
                != Some(xpub.meta.child_number)
            {
                return Err(XkeyParseError::ParentMismatch);
            }
        }

        Ok(XpubAccount { origin, xpub })
    }
}

#[derive(Getters, Eq, PartialEq)]
pub struct XprivAccount {
    origin: XkeyOrigin,
    xpriv: Xpriv,
}

impl XprivAccount {
    pub fn new(xpriv: Xpriv, origin: XkeyOrigin) -> Self { XprivAccount { xpriv, origin } }

    pub fn to_xpub_account(&self) -> XpubAccount {
        XpubAccount {
            origin: self.origin.clone(),
            xpub: self.xpriv.to_xpub(),
        }
    }

    #[inline]
    pub const fn master_fp(&self) -> XpubFp { self.origin.master_fp }

    #[inline]
    pub fn account_fp(&self) -> XpubFp { self.xpriv.fingerprint() }

    #[inline]
    pub fn account_id(&self) -> XpubId { self.xpriv.identifier() }

    #[inline]
    pub fn derivation(&self) -> &[HardenedIndex] { self.origin.derivation.as_ref() }

    #[inline]
    pub const fn as_derivation(&self) -> &DerivationPath<HardenedIndex> { &self.origin.derivation }

    #[inline]
    pub fn to_derivation(&self) -> DerivationPath { self.origin.to_derivation() }
}

impl Display for XprivAccount {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str("[")?;
        Display::fmt(&self.origin, f)?;
        f.write_str("]")?;
        write!(f, "{}/", self.xpriv)
    }
}

impl FromStr for XprivAccount {
    type Err = XkeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('[') {
            return Err(XkeyParseError::NoOrigin);
        }
        let (origin, xpriv) =
            s.trim_start_matches('[').split_once(']').ok_or(XkeyParseError::NoOrigin)?;
        let origin = XkeyOrigin::from_str(origin)?;
        let xpriv = Xpriv::from_str(xpriv)?;

        if origin.derivation.len() != xpriv.meta.depth as usize {
            return Err(XkeyParseError::DepthMismatch);
        }
        if !origin.derivation.is_empty() {
            let network = if xpriv.testnet { HardenedIndex::ONE } else { HardenedIndex::ZERO };
            if origin.derivation.get(1) != Some(&network) {
                return Err(XkeyParseError::NetworkMismatch);
            }
            if origin.derivation.last().copied().map(DerivationIndex::Hardened)
                != Some(xpriv.meta.child_number)
            {
                return Err(XkeyParseError::ParentMismatch);
            }
        }

        Ok(XprivAccount { origin, xpriv })
    }
}

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug)]
pub struct XpubDerivable {
    spec: XpubAccount,
    variant: Option<NormalIndex>,
    pub(crate) keychains: DerivationSeg<Keychain>,
}

impl From<XpubAccount> for XpubDerivable {
    fn from(spec: XpubAccount) -> Self {
        XpubDerivable {
            spec,
            variant: None,
            keychains: DerivationSeg::from([Keychain::INNER, Keychain::OUTER]),
        }
    }
}

impl XpubDerivable {
    pub fn new_standard(xpub: Xpub, origin: XkeyOrigin) -> Self {
        XpubDerivable {
            spec: XpubAccount::new(xpub, origin),
            variant: None,
            keychains: DerivationSeg::from([Keychain::INNER, Keychain::OUTER]),
        }
    }

    pub fn new_custom(xpub: Xpub, origin: XkeyOrigin, keychains: &'static [Keychain]) -> Self {
        XpubDerivable {
            spec: XpubAccount::new(xpub, origin),
            variant: None,
            keychains: DerivationSeg::from(keychains),
        }
    }

    pub fn try_custom(
        xpub: Xpub,
        origin: XkeyOrigin,
        keychains: impl IntoIterator<Item = Keychain>,
    ) -> Result<Self, confinement::Error> {
        Ok(XpubDerivable {
            spec: XpubAccount::new(xpub, origin),
            variant: None,
            keychains: DerivationSeg::with(keychains)?,
        })
    }

    pub fn xpub(&self) -> Xpub { self.spec.xpub }

    pub fn origin(&self) -> &XkeyOrigin { &self.spec.origin }
}

impl Display for XpubDerivable {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.spec, f)?;
        if let Some(variant) = self.variant {
            write!(f, "{variant}/")?;
        }
        Display::fmt(&self.keychains, f)?;
        f.write_str("/*")
    }
}

impl FromStr for XpubDerivable {
    type Err = XkeyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('[') {
            return Err(XkeyParseError::NoOrigin);
        }
        let (origin, remains) =
            s.trim_start_matches('[').split_once(']').ok_or(XkeyParseError::NoOrigin)?;

        let origin = XkeyOrigin::from_str(origin)?;
        let mut segs = remains.split('/');
        let Some(xpub) = segs.next() else {
            return Err(XkeyParseError::NoXpub);
        };
        let xpub = Xpub::from_str(xpub)?;

        let (variant, keychains) = match (segs.next(), segs.next(), segs.next(), segs.next()) {
            (Some(var), Some(keychains), Some("*"), None) => {
                (Some(var.parse()?), keychains.parse()?)
            }
            (Some(keychains), Some("*"), None, None) => (None, keychains.parse()?),
            _ => return Err(XkeyParseError::InvalidTerminal),
        };

        Ok(XpubDerivable {
            spec: XpubAccount::new(xpub, origin),
            variant,
            keychains,
        })
    }
}

#[cfg(feature = "serde")]
mod _serde {
    use serde_crate::{de, Deserialize, Deserializer, Serialize, Serializer};

    use super::*;

    impl Serialize for Xpub {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            if serializer.is_human_readable() {
                serializer.serialize_str(&self.to_string())
            } else {
                serializer.serialize_bytes(&self.encode())
            }
        }
    }

    impl<'de> Deserialize<'de> for Xpub {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            if deserializer.is_human_readable() {
                let s = String::deserialize(deserializer)?;
                Xpub::from_str(&s).map_err(|err| {
                    de::Error::custom(format!("invalid xpub string representation; {err}"))
                })
            } else {
                let v = Vec::<u8>::deserialize(deserializer)?;
                Xpub::decode(v)
                    .map_err(|err| de::Error::custom(format!("invalid xpub bytes; {err}")))
            }
        }
    }

    impl Serialize for XpubAccount {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for XpubAccount {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let s = String::deserialize(deserializer)?;
            XpubAccount::from_str(&s).map_err(|err| {
                de::Error::custom(format!(
                    "invalid xpub specification string representation; {err}"
                ))
            })
        }
    }

    impl Serialize for XpubDerivable {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer {
            serializer.serialize_str(&self.to_string())
        }
    }

    impl<'de> Deserialize<'de> for XpubDerivable {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de> {
            let s = String::deserialize(deserializer)?;
            XpubDerivable::from_str(&s).map_err(|err| {
                de::Error::custom(format!("invalid xpub derivation string representation; {err}"))
            })
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_xpub_derivable_from_str_with_hardened_index() {
        let s = "[643a7adc/86h/1h/0h]tpubDCNiWHaiSkgnQjuhsg9kjwaUzaxQjUcmhagvYzqQ3TYJTgFGJstVaqnu4yhtFktBhCVFmBNLQ5sN53qKzZbMksm3XEyGJsEhQPfVZdWmTE2/<0;1>/*";
        let xpub = XpubDerivable::from_str(s).unwrap();
        assert_eq!(s, xpub.to_string());
    }

    #[test]
    fn test_xpub_derivable_from_str_with_normal_index() {
        let s = "[643a7adc/86'/1'/0']tpubDCNiWHaiSkgnQjuhsg9kjwaUzaxQjUcmhagvYzqQ3TYJTgFGJstVaqnu4yhtFktBhCVFmBNLQ5sN53qKzZbMksm3XEyGJsEhQPfVZdWmTE2/<0;1>/*";
        let xpub = XpubDerivable::from_str(s).unwrap();
        assert_eq!(s, format!("{xpub:#}"));
    }

    #[test]
    fn test_xpub_derivable_from_str_with_normal_index_rgb_keychain() {
        let s = "[643a7adc/86'/1'/0']tpubDCNiWHaiSkgnQjuhsg9kjwaUzaxQjUcmhagvYzqQ3TYJTgFGJstVaqnu4yhtFktBhCVFmBNLQ5sN53qKzZbMksm3XEyGJsEhQPfVZdWmTE2/<0;1;9;10>/*";
        let xpub = XpubDerivable::from_str(s).unwrap();
        assert_eq!(s, format!("{xpub:#}"));
    }
}
