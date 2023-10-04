// Modern, minimalistic & standard-compliant cold wallet library.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2020-2023 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2020-2023 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2020-2023 Dr Maxim Orlovsky. All rights reserved.
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

use std::fmt::{self, Display, Formatter};
use std::io::{self, Cursor, Read, Write};

use amplify::{confinement, Bytes, IoError, RawArray, Wrapper};
use base64::Engine;
use bp::secp256k1::ecdsa;
use bp::{
    secp256k1, ComprPubkey, ConsensusDataError, ConsensusDecode, ConsensusDecodeError,
    ConsensusEncode, DerivationIndex, DerivationPath, HardenedIndex, Idx, KeyOrigin, LegacyPubkey,
    LockTime, RedeemScript, Sats, ScriptBytes, ScriptPubkey, SeqNo, SigScript, Tx, TxOut, TxVer,
    Txid, UncomprPubkey, VarInt, Vout, Witness, WitnessScript, Xpub, XpubDecodeError, XpubFp,
    XpubOrigin,
};

use crate::keys::KeyValue;
use crate::{
    GlobalKey, Input, InputKey, KeyData, KeyMap, KeyPair, KeyType, LegacySig, LockHeight,
    LockTimestamp, Map, ModifiableFlags, NonStandardSighashType, Output, OutputKey, PropKey, Psbt,
    PsbtUnsupportedVer, PsbtVer, SighashType, ValueData,
};

impl Display for Psbt {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let engine = base64::engine::GeneralPurpose::new(
            &base64::alphabet::STANDARD,
            base64::engine::GeneralPurposeConfig::new(),
        );
        let mut ver = match f.width().unwrap_or(0) {
            0 => PsbtVer::V0,
            2 => PsbtVer::V2,
            _ => return Err(fmt::Error),
        };
        if f.alternate() {
            ver = PsbtVer::V2;
        }
        f.write_str(&engine.encode(self.serialize(ver)))
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(inner)]
pub enum DecodeError {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[from]
    #[from(ConsensusDataError)]
    #[from(PsbtUnsupportedVer)]
    #[from(XpubDecodeError)]
    #[from(NonStandardSighashType)]
    #[from(confinement::Error)]
    Psbt(PsbtError),
}

impl From<ConsensusDecodeError> for DecodeError {
    fn from(e: ConsensusDecodeError) -> Self {
        match e {
            ConsensusDecodeError::Io(e) => DecodeError::Io(e),
            ConsensusDecodeError::Data(data) => data.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PsbtError {
    /// unexpected end of data.
    UnexpectedEod,

    /// PSBT data are followed by some excessive bytes.
    DataNotConsumed,

    /// invalid magic bytes {0}.
    InvalidMagic(Bytes<5>),

    /// key {0:#02x} must not be present in PSBT {1}.
    UnexpectedKey(u8, PsbtVer),

    /// key {0:#02x} is deprecated not be present in PSBT {1}.
    DeprecatedKey(u8, PsbtVer),

    /// key {0:#02x} required for PSBT {1} is not present.
    RequiredKeyAbsent(u8, PsbtVer),

    /// repeated key {0:#02x}.
    RepeatedKey(u8),

    /// repeated proprietary key {0}.
    RepeatedPropKey(PropKey),

    /// repeated unknown key {0:#02x}.
    RepeatedUnknownKey(u8),

    /// key {0:#02x} must not contain additional key data.
    NonEmptyKeyData(u8, KeyData),

    #[from]
    #[display(inner)]
    UnsupportedVersion(PsbtUnsupportedVer),

    /// invalid lock height value {0}.
    InvalidLockHeight(u32),

    /// invalid lock timestamp {0}.
    InvalidLockTimestamp(u32),

    /// invalid compressed pubkey data.
    InvalidComprPubkey(Bytes<33>),

    /// invalid compressed pubkey data.
    InvalidUncomprPubkey(Bytes<65>),

    /// empty signature data.
    EmptySig,

    /// invalid signature data.
    InvalidSig(secp256k1::Error),

    #[from]
    #[display(inner)]
    InvalidSighash(NonStandardSighashType),

    #[from]
    #[display(inner)]
    InvalidXub(XpubDecodeError),

    /// one of xpubs has an unhardened derivation index
    XpubUnhardenedOrigin,

    /// unrecognized public key encoding starting with flag {0:#02x}.
    UnrecognizedKeyFormat(u8),

    #[from]
    #[display(inner)]
    Consensus(ConsensusDataError),

    #[from]
    #[display(inner)]
    Confinement(confinement::Error),
}

impl From<DecodeError> for PsbtError {
    fn from(err: DecodeError) -> Self {
        match err {
            DecodeError::Psbt(e) => e,
            DecodeError::Io(_) => PsbtError::UnexpectedEod,
        }
    }
}

pub trait Encode {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError>;
}

impl<'a, T: Encode> Encode for &'a T {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> { (*self).encode(writer) }
}

pub trait Decode
where Self: Sized
{
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError>;
    fn deserialize(bytes: impl AsRef<[u8]>) -> Result<Self, PsbtError> {
        let bytes = bytes.as_ref();
        let mut cursor = Cursor::new(bytes);
        let me = Self::decode(&mut cursor)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(PsbtError::DataNotConsumed);
        }
        Ok(me)
    }
}

impl Psbt {
    const MAGIC: [u8; 5] = *b"psbt\xFF";
    pub(crate) const SEPARATOR: [u8; 1] = [0x0];

    pub fn encode(&self, ver: PsbtVer, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = Self::MAGIC.len();
        writer.write_all(&Self::MAGIC)?;

        counter += self.encode_global(ver, writer)? + Self::SEPARATOR.len();
        writer.write_all(&Self::SEPARATOR)?;

        for input in &self.inputs {
            counter += input.encode(ver, writer)?;
        }

        for output in &self.outputs {
            counter += output.encode(ver, writer)?;
        }

        Ok(counter)
    }
    pub fn encode_vec(&self, ver: PsbtVer, writer: &mut Vec<u8>) -> usize {
        self.encode(ver, writer).expect("in-memory encoding can't error")
    }
    pub fn serialize(&self, ver: PsbtVer) -> Vec<u8> {
        let mut vec = Vec::new();
        self.encode_vec(ver, &mut vec);
        vec
    }

    fn encode_global(&self, ver: PsbtVer, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        for (xpub, source) in &self.xpubs {
            counter += KeyPair::new(GlobalKey::Xpub, xpub, source).encode(writer)?;
        }

        match ver {
            PsbtVer::V0 => {
                counter += KeyPair::new(GlobalKey::UnsignedTx, &(), &self.to_unsigned_tx())
                    .encode(writer)?;
            }
            PsbtVer::V2 => {
                counter +=
                    KeyPair::new(GlobalKey::TxVersion, &(), &self.tx_version).encode(writer)?;

                counter += KeyPair::new(GlobalKey::FallbackLocktime, &(), &self.fallback_locktime)
                    .encode(writer)?;

                counter +=
                    KeyPair::new(GlobalKey::InputCount, &(), &VarInt::with(self.inputs.len()))
                        .encode(writer)?;

                counter +=
                    KeyPair::new(GlobalKey::OutputCount, &(), &VarInt::with(self.outputs.len()))
                        .encode(writer)?;

                counter += KeyPair::new(GlobalKey::TxModifiable, &(), &self.tx_modifiable)
                    .encode(writer)?;
            }
        }

        counter += KeyPair::new(GlobalKey::Version, &(), &ver).encode(writer)?;

        Ok(counter)
    }

    pub fn decode(&self, reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut magic = Self::MAGIC;
        reader.read_exact(&mut magic)?;
        if magic != Self::MAGIC {
            return Err(PsbtError::InvalidMagic(magic.into()).into());
        }

        let map = Map::<GlobalKey>::parse(reader)?;
        let version = map
            .singular
            .get(&GlobalKey::Version)
            .ok_or(PsbtError::RequiredKeyAbsent(GlobalKey::Version.to_u8(), PsbtVer::V0))
            .and_then(PsbtVer::deserialize)?;
        let mut psbt = Psbt::create();
        psbt.populate(map, version)?;

        for input in &mut psbt.inputs {
            let map = Map::<InputKey>::parse(reader)?;
            input.populate(map, version)?;
        }

        for output in &mut psbt.outputs {
            let map = Map::<OutputKey>::parse(reader)?;
            output.populate(map, version)?;
        }

        Ok(psbt)
    }
    pub fn deserialize(&self, data: impl AsRef<[u8]>) -> Result<Self, PsbtError> {
        let data = data.as_ref();
        let mut cursor = Cursor::new(data);
        let psbt = self.decode(&mut cursor)?;
        if cursor.position() != data.len() as u64 {
            return Err(PsbtError::DataNotConsumed);
        }
        Ok(psbt)
    }
}

impl Input {
    fn encode(&self, ver: PsbtVer, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        counter += KeyPair::new(InputKey::WitnessUtxo, &(), &self.witness_utxo).encode(writer)?;

        for (key, sig) in &self.partial_sigs {
            counter += KeyPair::new(InputKey::PartialSig, key, sig).encode(writer)?;
        }

        counter += KeyPair::new(InputKey::SighashType, &(), &self.sighash_type).encode(writer)?;

        counter += KeyPair::new(InputKey::RedeemScript, &(), &self.redeem_script).encode(writer)?;

        counter +=
            KeyPair::new(InputKey::WitnessScript, &(), &self.witness_script).encode(writer)?;

        for (key, origin) in &self.bip32_derivation {
            counter += KeyPair::new(InputKey::Bip32Derivation, key, origin).encode(writer)?;
        }

        counter +=
            KeyPair::new(InputKey::FinalScriptSig, &(), &self.final_script_sig).encode(writer)?;

        counter += KeyPair::new(InputKey::FinalWitness, &(), &self.final_witness).encode(writer)?;

        if ver < PsbtVer::V2 {
            counter += KeyPair::new(InputKey::PreviousTxid, &(), &self.previous_outpoint.txid)
                .encode(writer)?;

            counter += KeyPair::new(InputKey::OutputIndex, &(), &self.previous_outpoint.vout)
                .encode(writer)?;

            counter +=
                KeyPair::new(InputKey::Sequence, &(), &self.sequence_number).encode(writer)?;

            counter += KeyPair::new(InputKey::RequiredTimeLock, &(), &self.required_time_lock)
                .encode(writer)?;

            counter += KeyPair::new(InputKey::RequiredHeighLock, &(), &self.required_height_lock)
                .encode(writer)?;
        }

        counter += Psbt::SEPARATOR.len();
        writer.write_all(&Psbt::SEPARATOR)?;

        Ok(counter)
    }
}

impl Output {
    fn encode(&self, ver: PsbtVer, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        counter +=
            KeyPair::new(OutputKey::RedeemScript, &(), &self.redeem_script).encode(writer)?;

        counter +=
            KeyPair::new(OutputKey::WitnessScript, &(), &self.witness_script).encode(writer)?;

        for (key, origin) in &self.bip32_derivation {
            counter += KeyPair::new(OutputKey::Bip32Derivation, key, origin).encode(writer)?;
        }

        if ver < PsbtVer::V2 {
            counter += KeyPair::new(OutputKey::Amount, &(), &self.amount).encode(writer)?;

            counter += KeyPair::new(OutputKey::Script, &(), &self.script).encode(writer)?;
        }

        counter += Psbt::SEPARATOR.len();
        writer.write_all(&Psbt::SEPARATOR)?;

        Ok(counter)
    }
}

impl Encode for GlobalKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_u8().encode(writer)
    }
}

impl Decode for GlobalKey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        u8::decode(reader).map(Self::from_u8)
    }
}

impl Encode for InputKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_u8().encode(writer)
    }
}

impl Decode for InputKey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        u8::decode(reader).map(Self::from_u8)
    }
}

impl Encode for OutputKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_u8().encode(writer)
    }
}

impl Decode for OutputKey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        u8::decode(reader).map(Self::from_u8)
    }
}

impl<T: KeyType, K: Encode, V: Encode> Encode for KeyPair<T, K, V> {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 0;

        counter += self.key_len().encode(writer)?;
        counter += self.key_type.encode(writer)?;
        counter += self.key_data.encode(writer)?;

        counter += self.value_len().encode(writer)?;
        counter += self.value_data.encode(writer)?;

        Ok(counter)
    }
}

impl<T: KeyType> Decode for KeyValue<T> {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let key_len = VarInt::decode(reader)?;
        if key_len == 0u64 {
            return Ok(KeyValue::Separator);
        }

        let key_type = T::decode(reader)?;
        let mut key_data = vec![0u8; key_len.to_usize() - 1];
        reader.read_exact(key_data.as_mut_slice())?;

        let value_len = VarInt::decode(reader)?;
        let mut value_data = vec![0u8; value_len.to_usize()];
        reader.read_exact(value_data.as_mut_slice())?;

        Ok(KeyValue::Pair(KeyPair {
            key_type,
            key_data: KeyData::try_from(key_data)?,
            value_data: ValueData::try_from(value_data)?,
        }))
    }
}

impl Encode for PropKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = self.identifier.len();
        let len = VarInt::with(counter);
        counter += len.encode(writer)?;

        writer.write_all(self.identifier.as_bytes())?;
        counter += VarInt::new(self.subtype).encode(writer)?;
        counter += self.data.len();
        writer.write_all(&self.data)?;

        Ok(counter)
    }
}

impl Decode for PropKey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let len = VarInt::decode(reader)?;
        let mut identifier = vec![0u8; len.to_usize()];
        reader.read_exact(&mut identifier)?;
        let identifier = String::from_utf8_lossy(&identifier).to_string();

        let subtype = VarInt::decode(reader)?.to_u64();

        let mut data = Vec::<u8>::new();
        reader.read_to_end(&mut data)?;

        Ok(PropKey {
            identifier,
            subtype,
            data,
        })
    }
}

impl Encode for ModifiableFlags {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_standard_u8().encode(writer)
    }
}

impl Decode for ModifiableFlags {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let val = u8::decode(reader)?;
        Ok(Self::from_standard_u8(val))
    }
}

impl Encode for PsbtVer {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_standard_u32().encode(writer)
    }
}

impl Decode for PsbtVer {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let ver = u32::decode(reader)?;
        PsbtVer::try_from_standard_u32(ver).map_err(DecodeError::from)
    }
}

impl Encode for Xpub {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.encode())?;
        Ok(78)
    }
}

impl Decode for Xpub {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 78];
        reader.read_exact(&mut buf)?;
        Xpub::decode(buf).map_err(DecodeError::from)
    }
}

impl Encode for XpubOrigin {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(self.master_fp().as_ref())?;
        for index in self.derivation() {
            index.index().encode(writer)?;
        }
        Ok(4 + self.derivation().len() * 4)
    }
}

impl Decode for XpubOrigin {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let master_fp = XpubFp::from_raw_array(buf);
        let mut derivation = DerivationPath::<HardenedIndex>::new();
        while let Ok(index) = u32::decode(reader) {
            derivation.push(
                HardenedIndex::try_from_index(index)
                    .map_err(|_| PsbtError::XpubUnhardenedOrigin)?,
            );
        }
        Ok(XpubOrigin::new(master_fp, derivation))
    }
}

impl Encode for ComprPubkey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(33)
    }
}

impl Decode for ComprPubkey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 33];
        reader.read_exact(&mut buf)?;
        ComprPubkey::from_byte_array(buf)
            .map_err(|_| PsbtError::InvalidComprPubkey(buf.into()).into())
    }
}

impl Encode for UncomprPubkey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(65)
    }
}

impl Decode for UncomprPubkey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 65];
        reader.read_exact(&mut buf)?;
        UncomprPubkey::from_byte_array(buf)
            .map_err(|_| PsbtError::InvalidUncomprPubkey(buf.into()).into())
    }
}

impl Encode for LegacyPubkey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        if self.compressed {
            ComprPubkey::from(self.pubkey).encode(writer)
        } else {
            UncomprPubkey::from(self.pubkey).encode(writer)
        }
    }
}

impl Decode for LegacyPubkey {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let flag = u8::decode(reader)?;
        match flag {
            02 | 03 => ComprPubkey::decode(reader).map(Self::from),
            04 => UncomprPubkey::decode(reader).map(Self::from),
            other => Err(PsbtError::UnrecognizedKeyFormat(other).into()),
        }
    }
}

impl Encode for KeyOrigin {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(self.master_fp().as_ref())?;
        for index in self.derivation() {
            index.index().encode(writer)?;
        }
        Ok(4 + self.derivation().len() * 4)
    }
}

impl Decode for KeyOrigin {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf)?;
        let master_fp = XpubFp::from_raw_array(buf);
        let mut derivation = DerivationPath::new();
        while let Ok(index) = u32::decode(reader) {
            derivation.push(DerivationIndex::from_index(index));
        }
        Ok(KeyOrigin::new(master_fp, derivation))
    }
}

impl Encode for LegacySig {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let sig = self.sig.serialize_der();
        writer.write_all(sig.as_ref())?;
        self.sighash_type.into_u8().encode(writer)?;
        Ok(sig.len() + 1)
    }
}

impl Decode for LegacySig {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let mut buf = Vec::with_capacity(78);
        reader.read_to_end(&mut buf)?;
        let (sighash, sig) = buf.split_last().ok_or(PsbtError::EmptySig)?;
        let sig = ecdsa::Signature::from_der(&sig).map_err(PsbtError::InvalidSig)?;
        let sighash_type = SighashType::from_psbt_u8(*sighash)?;
        Ok(LegacySig { sig, sighash_type })
    }
}

impl Encode for SighashType {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.into_u32().encode(writer)
    }
}

impl Decode for SighashType {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        u32::decode(reader).map(Self::from_consensus)
    }
}

macro_rules! psbt_code_using_consensus {
    ($ty:ty) => {
        psbt_encode_from_consensus!($ty);
        psbt_decode_from_consensus!($ty);
    };
}

macro_rules! psbt_encode_from_consensus {
    ($ty:ty) => {
        impl Encode for $ty {
            fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
                self.consensus_encode(writer)
            }
        }
    };
}

macro_rules! psbt_decode_from_consensus {
    ($ty:ty) => {
        impl Decode for $ty {
            fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
                Self::consensus_decode(reader).map_err(DecodeError::from)
            }
        }
    };
}

psbt_code_using_consensus!(Tx);
psbt_code_using_consensus!(TxVer);
psbt_code_using_consensus!(TxOut);
psbt_code_using_consensus!(Txid);
psbt_code_using_consensus!(Vout);
psbt_code_using_consensus!(SeqNo);
psbt_code_using_consensus!(LockTime);

impl Encode for LockTimestamp {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().encode(writer)
    }
}

impl Decode for LockTimestamp {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let val = u32::decode(reader)?;
        Self::try_from_consensus_u32(val).map_err(|e| PsbtError::InvalidLockTimestamp(e.0).into())
    }
}

impl Encode for LockHeight {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().encode(writer)
    }
}

impl Decode for LockHeight {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        let val = u32::decode(reader)?;
        Self::try_from_consensus_u32(val).map_err(|e| PsbtError::InvalidLockHeight(e.0).into())
    }
}

psbt_code_using_consensus!(ScriptBytes);
psbt_code_using_consensus!(SigScript);
psbt_code_using_consensus!(ScriptPubkey);
psbt_code_using_consensus!(Witness);

impl Encode for WitnessScript {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().encode(writer)
    }
}

impl Decode for WitnessScript {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        ScriptBytes::decode(reader).map(Self::from_inner)
    }
}

impl Encode for RedeemScript {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_script_bytes().encode(writer)
    }
}

impl Decode for RedeemScript {
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError> {
        ScriptBytes::decode(reader).map(Self::from_inner)
    }
}

psbt_code_using_consensus!(Sats);
psbt_code_using_consensus!(u8);
psbt_code_using_consensus!(u32);
psbt_code_using_consensus!(VarInt);

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        Ok(match self {
            Some(data) => data.encode(writer)?,
            None => 0,
        })
    }
}

impl Encode for () {
    fn encode(&self, _writer: &mut impl Write) -> Result<usize, IoError> { Ok(0) }
}

impl Decode for () {
    fn decode(_reader: &mut impl Read) -> Result<Self, DecodeError> { Ok(()) }
}
