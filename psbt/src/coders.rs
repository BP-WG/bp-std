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

use amplify::{IoError, Wrapper};
use base64::Engine;
use bp::{
    ComprPubkey, ConsensusEncode, Idx, KeyOrigin, LegacyPubkey, LockTime, RedeemScript, Sats,
    ScriptBytes, ScriptPubkey, SeqNo, SigScript, Tx, TxOut, TxVer, Txid, UncomprPubkey, VarInt,
    Vout, Witness, WitnessScript, Xpub, XpubOrigin,
};

use crate::{
    EcdsaSig, GlobalKey, Input, InputKey, KeyPair, KeyType, LockHeight, LockTimestamp,
    ModifiableFlags, Output, OutputKey, Psbt, PsbtVer, SighashType,
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

#[derive(Clone, Debug, Display, Error, From)]
#[display(inner)]
pub enum DecodeError {
    #[from]
    #[from(io::Error)]
    Io(IoError),

    #[from]
    Psbt(PsbtError),
}

#[derive(Clone, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum PsbtError {
    /// PSBT data are followed by some excessive bytes
    DataNotConsumed,
}

pub trait Encode {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError>;
}

pub trait Decode
where Self: Sized
{
    fn decode(reader: &mut impl Read) -> Result<Self, DecodeError>;
    fn deserialize(bytes: impl AsRef<[u8]>) -> Result<Self, PsbtError> {
        let mut cursor = Cursor::new(bytes.as_ref());
        let me = Self::decode(&mut cursor).map_err(|err| match err {
            DecodeError::Psbt(e) => e,
            DecodeError::Io(_) => unreachable!(),
        })?;
        if cursor.position() as usize != bytes.as_ref().len() {
            return Err(PsbtError::DataNotConsumed);
        }
        Ok(me)
    }
}

impl Psbt {
    pub fn encode(&self, ver: PsbtVer, writer: &mut impl Write) -> Result<usize, IoError> {
        let mut counter = 5;
        writer.write_all(b"psbt\xFF")?;

        counter += self.encode_global(ver, writer)? + 1;
        writer.write_all(&[0x0])?;

        for input in &self.inputs {
            counter += input.encode(ver, writer)?;
        }
        counter += 1;
        writer.write_all(&[0x0])?;

        for output in &self.outputs {
            counter += output.encode(ver, writer)?;
        }
        counter += 1;
        writer.write_all(&[0x0])?;

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

        Ok(counter)
    }
}

impl Encode for GlobalKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        (*self as u8).encode(writer)
    }
}

impl Encode for InputKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        (*self as u8).encode(writer)
    }
}

impl Encode for OutputKey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        (*self as u8).encode(writer)
    }
}

impl<'a, T: KeyType, K: Encode, V: Encode> Encode for KeyPair<'a, T, K, V> {
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

impl Encode for ModifiableFlags {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_standard_u8().encode(writer)
    }
}

impl Encode for PsbtVer {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_standard_u32().encode(writer)
    }
}

impl Encode for Xpub {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.encode())?;
        Ok(78)
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

impl Encode for ComprPubkey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(33)
    }
}

impl Encode for UncomprPubkey {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(&self.to_byte_array())?;
        Ok(65)
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

impl Encode for KeyOrigin {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        writer.write_all(self.master_fp().as_ref())?;
        for index in self.derivation() {
            index.index().encode(writer)?;
        }
        Ok(4 + self.derivation().len() * 4)
    }
}

impl Encode for EcdsaSig {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        let sig = self.sig.serialize_der();
        writer.write_all(sig.as_ref())?;
        self.sighash_type.into_u8().encode(writer)?;
        Ok(sig.len() + 1)
    }
}

impl Encode for SighashType {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.into_u32().encode(writer)
    }
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

psbt_encode_from_consensus!(Tx);
psbt_encode_from_consensus!(TxVer);
psbt_encode_from_consensus!(TxOut);
psbt_encode_from_consensus!(Txid);
psbt_encode_from_consensus!(Vout);
psbt_encode_from_consensus!(SeqNo);
psbt_encode_from_consensus!(LockTime);

impl Encode for LockTimestamp {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().encode(writer)
    }
}

impl Encode for LockHeight {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.to_consensus_u32().encode(writer)
    }
}

psbt_encode_from_consensus!(ScriptBytes);
psbt_encode_from_consensus!(SigScript);
psbt_encode_from_consensus!(ScriptPubkey);
psbt_encode_from_consensus!(Witness);

impl Encode for WitnessScript {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_inner().encode(writer)
    }
}

impl Encode for RedeemScript {
    fn encode(&self, writer: &mut impl Write) -> Result<usize, IoError> {
        self.as_inner().encode(writer)
    }
}

psbt_encode_from_consensus!(Sats);
psbt_encode_from_consensus!(u8);
psbt_encode_from_consensus!(u32);
psbt_encode_from_consensus!(VarInt);

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
