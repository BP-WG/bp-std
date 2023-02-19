#[cfg(feature = "wallet")]
/// Errors working with anchors.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    /// Errors embedding LNPBP-4 commitment into PSBT
    #[from]
    EmbedCommit(PsbtCommitError),

    /// Errors constructing LNPBP-4 commitment
    #[from]
    Lnpbp4(lnpbp4::Error),
}

impl Anchor<lnpbp4::MerkleBlock> {
    /// Returns id of the anchor (commitment hash).
    #[inline]
    pub fn anchor_id(&self) -> AnchorId { self.consensus_commit() }

    /// Convenience constructor for anchor, which also does embedding of LNPBP4
    /// commitment into PSBT.
    #[cfg(feature = "wallet")]
    pub fn commit(
        psbt: &mut Psbt,
    ) -> Result<Anchor<lnpbp4::MerkleBlock>, Error> {
        let anchor = psbt.embed_commit(&PsbtEmbeddedMessage)?;
        Ok(Anchor {
            txid: anchor.txid,
            lnpbp4_proof: lnpbp4::MerkleBlock::from(anchor.lnpbp4_proof),
            dbc_proof: anchor.dbc_proof,
        })
    }
}

#[cfg(feature = "wallet")]
impl EmbedCommitProof<PsbtEmbeddedMessage, Psbt, Lnpbp6>
for Anchor<lnpbp4::MerkleTree>
{
    fn restore_original_container(
        &self,
        psbt: &Psbt,
    ) -> Result<Psbt, PsbtVerifyError> {
        match self.dbc_proof {
            Proof::OpretFirst => Ok(psbt.clone()),
            Proof::TapretFirst(ref proof) => {
                let mut psbt = psbt.clone();
                for output in &mut psbt.outputs {
                    if output.is_tapret_host() {
                        *output = EmbedCommitProof::<_, psbt::Output, Lnpbp6>::restore_original_container(proof, output)?;
                        return Ok(psbt);
                    }
                }
                Err(PsbtVerifyError::Commit(
                    PsbtCommitError::CommitmentImpossible,
                ))
            }
        }
    }
}

#[cfg(feature = "wallet")]
impl EmbedCommitVerify<PsbtEmbeddedMessage, Lnpbp6> for Psbt {
    type Proof = Anchor<lnpbp4::MerkleTree>;
    type CommitError = PsbtCommitError;
    type VerifyError = PsbtVerifyError;

    fn embed_commit(
        &mut self,
        _: &PsbtEmbeddedMessage,
    ) -> Result<Self::Proof, Self::CommitError> {
        let lnpbp4_tree =
            |output: &mut psbt::Output| -> Result<_, PsbtCommitError> {
                let messages = output.lnpbp4_message_map()?;
                let min_depth = output
                    .lnpbp4_min_tree_depth()?
                    .unwrap_or(ANCHOR_MIN_LNPBP4_DEPTH);
                let multi_source = lnpbp4::MultiSource {
                    min_depth,
                    messages,
                };
                Ok(lnpbp4::MerkleTree::try_commit(&multi_source)?)
            };

        let (dbc_proof, lnpbp4_proof) = if let Some(output) =
            self.outputs.iter_mut().find(|o| o.is_tapret_host())
        {
            let tree = lnpbp4_tree(output)?;
            let commitment = tree.consensus_commit();
            let proof = output.embed_commit(&commitment)?;
            output.set_tapret_commitment(commitment.into_array(), &proof)?;
            output.set_lnpbp4_entropy(tree.entropy())?;
            (Proof::TapretFirst(proof), tree)
        } else if let Some(output) =
            self.outputs.iter_mut().find(|o| o.is_opret_host())
        {
            let tree = lnpbp4_tree(output)?;
            let commitment = tree.consensus_commit();
            output.script = Script::new_op_return(commitment.as_slice()).into();
            output.set_opret_commitment(commitment.into_array())?;
            output.set_lnpbp4_entropy(tree.entropy())?;
            (Proof::OpretFirst, tree)
        } else {
            return Err(PsbtCommitError::CommitmentImpossible);
        };

        Ok(Anchor {
            txid: self.to_txid(),
            lnpbp4_proof,
            dbc_proof,
        })
    }
}


/// Empty type indicating that the message has to be taken from PSBT proprietary
/// keys
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct PsbtEmbeddedMessage;

impl CommitEncode for PsbtEmbeddedMessage {
    fn commit_encode<E: Write>(&self, _: E) -> usize { 0 }
}
