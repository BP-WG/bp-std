use crate::util::Bytes;

/// Bare script is a bitcoin script which may be present in a pre-segwit
/// contexts, i.e. in bare, P2PK & P2PKH `scriptPubkeys`, pre-segwit
/// `redeemScript` and in only pre-BIP16 `sigScript` (pre-segwit `sigScripts`
/// spending P2SH outputs do not contain this script type and use
/// [`Bip16SigScript`] instead).
///
/// The structure doesn't put any assumptions regarding consensus script
/// limitations, including (but not limiting to) validity of public keys or
/// signatures present in the script, correctness of the script business logic,
/// minimal and maximal length of the script etc.
///
/// Bare script is any sequence of bytes and may be parsed into pre-taproot
/// op codes using some softfork context. However, the parsing may fail, and
/// the failed parsing must not indicate that the transaction is invalid; as
/// well as the ability to parse a bare script into opcodes does not indicate
/// validity of the transaction.
#[derive(Wrapper, WrapperMut, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Default, Debug, From)]
#[wrapper(RangeOps, BorrowSlice, Hex)]
#[wrapper_mut(RangeMut, BorrowSliceMut)]
pub struct BareScript(#[from] #[from(&[u8])] #[from(Vec<u8>)]Bytes);

/// Redeem script is a script which is deserialized from the last data push
/// in BIP-16 compliant transactions.
pub struct RedeemScript(BareScript);

pub struct Bip16SigScript {
    pub sigs: Vec<Box<[u8]>>,
    pub redeemScript: RedeemScript
}

pub struct TapScript(Bytes);

pub enum ScriptPubkey {
    Bare(BareScript),
    Witness {
        version: WitnessVer,
        program: WitnessProg,
    },
}

/// A content of the script from `witness` structure; en equivalent of
/// `redeemScript` for witness-based transaction inputs. However, unlike
/// [`RedeemScript`], [`WitnessScript`] produce SHA256-based hashes of
/// [`WScriptHash`] type - and it is prohibited to contain uncompressed keys.
///
/// Witness script can be nested within the redeem script in legacy
/// P2WSH-in-P2SH schemes; for this purpose use [`RedeemScript::from`] method.
pub struct WitnessScript(BareScript);

pub enum LeafScript {
    TapScript(TapScript),
    Future {
        version: FutureLeafVer,
        script: Box<[u8]>,
    },
}

pub enum SigScript {
    Bare(BareScript),
    Bip16(Bip16Script),

    SegwitEmpty,
}
