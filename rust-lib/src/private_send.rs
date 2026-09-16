//! A whole private send, through the ENGINE's own `prepare_transfer` path, on a
//! chain with no money in it.
//!
//! ## What was still missing after the first #213 cycle
//!
//! [`crate::proof_circuit`] reached the engine's own `calculate_witness` on the
//! venue's physical iPad and timed the Groth16 proof after it (892 ms + 383 ms).
//! But it fed that circuit the real SHAPE with placeholder VALUES, so the proof
//! did not verify and could not: `verified: false` was the honest answer and the
//! honest limit. Nothing had run `TransactCircuitInputs::from_inputs` — the note
//! decryption, the merkle proof, the EdDSA signature over the bound-params hash,
//! the output-note encryption — and nothing had produced a RAILGUN proof a
//! verifier accepts.
//!
//! The reason was chain state: a private send spends a note that a `shield`
//! transaction put in the contract's merkle tree, and the venue's iPad account
//! (`0x493A73e8…`) has 0 ETH and has never sent a transaction, so no shield can
//! be mined for it. Faucets are captcha-gated and out of scope for this fleet.
//!
//! ## What this module does instead, and exactly where it stops being real
//!
//! The engine learns about notes through ONE public seam:
//! [`UtxoSyncer`](railgun::indexer::syncer::UtxoSyncer), which
//! `RailgunBuilder::with_utxo_syncer` lets a consumer replace. So this probe
//! hands the engine a syncer that emits one `Shield` event — encrypted to the
//! probe's own address by the ENGINE's own `encrypt_shield`, the same call
//! `ShieldBuilder::build` makes for every shield this module has ever prepared —
//! and then lets the engine do everything else itself:
//!
//! ```text
//!   UtxoIndexer::sync_to   decrypts the commitment into a UtxoNote, inserts the
//!                          leaf into its UTXO merkle tree, and asks the chain to
//!                          verify the root (a real eth_call, on the real
//!                          contract, which answers "no")
//!   RailgunProvider::balance  reports the shielded balance the note gives it
//!   TransactionBuilder     selects the note, builds a transfer + a change note
//!   TransactCircuitInputs  merkle proof, nullifier, EdDSA signature, npks
//!   calculate_witness      THE ENGINE'S OWN, patched line and all (#188/#213)
//!   Groth16Prover::prove   creates the proof AND VERIFIES IT, returning
//!                          `InvalidProof` if it does not verify
//! ```
//!
//! **THE ONE THING THAT IS NOT REAL IS THE EVENT.** The note is cryptographically
//! genuine — its commitment is the poseidon hash the contract would store, its
//! nullifier is the one the contract would consume, the merkle proof verifies
//! against the root the engine computed — but that root is not in the smart
//! wallet's `rootHistory`, because no shield was ever mined. The probe does not
//! hide this: it makes the real `rootHistory` call (the engine does, on every
//! sync) and reports the answer, which is `false`. Broadcasting the calldata this
//! probe produces would revert.
//!
//! So what it proves, and what it does not:
//!
//! * PROVED: every line of the engine's private-send path runs on this device,
//!   and the proof it produces **verifies** — `Groth16Prover::prove` errors
//!   otherwise, so a green run IS a verified proof. That is the end of the
//!   "placeholder values" caveat.
//! * PROVED: what a private send COSTS on this device, end to end, over inputs
//!   that satisfy every constraint (the circuit's assertions are all live here;
//!   placeholders skipped most of them).
//! * NOT PROVED: that the chain would accept it. That needs a mined shield, i.e.
//!   acceptance clause 1 of #213, which is an operator step and stays open.
//!
//! ## THE ANSWER, on the venue's physical iPad Air (4th generation)
//!
//! iOS 26.5.2, the shipped release build, in an iOS Bundled set carrying
//! `railgun_module` + `capability_module`:
//!
//! ```text
//! railgun: witness store backend = wasmi (#188 iOS: the interpreter, no JIT)
//! private-send probe: SENT (circuit=01x02 balance=1000000 rootOnChain=false
//!   calldata=1956B shield=1ms engine=4ms sync=147ms
//!   transferCold=4382ms transferWarm=1280ms total=5912ms)
//! ```
//!
//! **A private send costs 1.28 s of compute on an A14, and the proof verifies.**
//! `transfer-warm` — note selection, merkle proof, EdDSA signature, output-note
//! encryption, the engine's own `calculate_witness` under the interpreter,
//! Groth16 prove and verify — reproduced within 3 ms across two runs, and lands
//! on [`crate::proof_circuit`]'s independently measured 892 + 383 + 2 ms. The
//! two probes agree from opposite ends: placeholder values with the circuit's
//! real shape, and real values through the engine's own builder. A FIRST send
//! pays 4.4 s, 3.1 s of which is 3.5 MB of cacheable artifact.
//!
//! ## It cannot touch the user's wallet
//!
//! The probe builds its OWN [`RailgunProvider`] over a
//! [`MemoryDatabase`](railgun::database::memory::MemoryDatabase) with keys
//! derived from a fixed probe seed — not the module's engine, not the module's
//! persistence dir, and not the user's keys. Nothing it does is written anywhere,
//! and the fabricated note exists only for the lifetime of the call.

use std::sync::Arc;
use std::time::Instant;

use alloy::primitives::Address;
use eip_1193_provider::provider::{Eip1193Caller, Eip1193Provider};
use railgun::account::chain::ChainId;
use railgun::account::signer::RailgunSigner;
use railgun::builder::RailgunBuilder;
use railgun::caip::AssetId;
use railgun::chain_config::ChainConfig;
use railgun::database::memory::MemoryDatabase;
use railgun::indexer::syncer::{SyncEvent, SyncerError, UtxoSyncer};

use crate::keys;
use crate::proof_circuit::Leg;

/// The block the fabricated shield is reported at. Any block the engine has not
/// synced past works; 1 is the first one `sync()` asks for (`synced_block` starts
/// at 0 and the indexer syncs from `synced_block + 1`).
const SHIELD_BLOCK: u64 = 1;

/// Tree 0, leaf 0 — the first commitment a fresh tree would hold. The tree is the
/// engine's own `UtxoMerkleTree`, built from this one leaf, so the position only
/// has to be self-consistent.
const TREE_NUMBER: u32 = 0;
/// Only the seam build has an event to place, so only it has a leaf index; the
/// tree number above is also the one the root question is asked about.
#[cfg(feature = "engine_seam")]
const LEAF_INDEX: u32 = 0;

/// Where the probe's railgun keys come from. Fixed rather than random so two runs
/// on one device produce the same `0zk` address and the same note, which makes a
/// repeat measurement comparable — and so that nothing here can ever coincide
/// with a real user's wallet. `derive_keys_from_seed` is the module's own
/// derivation ([`crate::keys`]).
pub const PROBE_SEED: &[u8] = b"logos-railgun/#213 private-send probe/v1";
/// The counterparty. A second seed, so the transfer goes to an address the probe
/// does not hold the spending key for — as a real private transfer does.
pub const PROBE_RECIPIENT_SEED: &[u8] = b"logos-railgun/#213 private-send probe recipient/v1";

/// How much the fabricated shield is worth, and how much of it the transfer
/// moves. The remainder becomes the engine's own change note, which is what makes
/// this a `01x02` operation — one nullifier in, two commitments out — the same
/// circuit [`crate::proof_circuit`] measured, so the two numbers can be compared.
pub const DEFAULT_SHIELD: u128 = 1_000_000;
pub const DEFAULT_TRANSFER: u128 = 400_000;

/// What a caller may vary. Every field has a default that needs no argument, so
/// `--call 'railgun_module.private_send_probe()'` is a complete invocation.
#[derive(Debug, Clone)]
pub struct Params {
    pub chain_id: u64,
    /// The ERC-20 to shield and transfer. `None` = the chain's own wrapped base
    /// token, taken from the engine's `ChainConfig` rather than hard-coded.
    pub asset: Option<Address>,
    pub shield: u128,
    pub transfer: u128,
    pub memo: String,
    /// Run the transfer a second time over the same (still unspent) note. The
    /// engine's artifact loader caches in memory, so the second run is the
    /// compute-only cost of a private send and the first is compute + 3.5 MB of
    /// one-off download.
    pub repeat: bool,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            chain_id: 11155111,
            asset: None,
            shield: DEFAULT_SHIELD,
            transfer: DEFAULT_TRANSFER,
            memo: "#213 private-send probe".to_string(),
            repeat: true,
        }
    }
}

/// Everything one [`run`] measured.
#[derive(Debug, Clone, Default)]
pub struct Run {
    pub chain_id: u64,
    /// Whether this image carries the engine seam — without it there is no
    /// `encrypt_shield` to call and the probe can only say so.
    pub engine_seam: bool,
    pub legs: Vec<Leg>,
    /// The probe's own `0zk` address, and the counterparty's.
    pub from: Option<String>,
    pub to: Option<String>,
    pub asset: Option<String>,
    /// The shielded balance the engine reported AFTER the sync, in the asset's
    /// smallest unit. This is the number that does not exist without chain state,
    /// and the whole point of the fabricated event.
    pub balance: Option<u128>,
    /// What the chain said about the merkle root the engine computed. `Some(false)`
    /// is the expected answer and the honest limit of this probe — see the module
    /// docs. `None` means the call itself did not complete.
    pub root_on_chain: Option<bool>,
    /// The transact circuit the engine chose, from the operation it built:
    /// nullifiers x commitments, e.g. `01x02`.
    pub circuit: Option<String>,
    /// Bytes of `transact(...)` calldata the proved transaction produced.
    pub calldata_bytes: Option<usize>,
    pub total_ms: u128,
    pub error: Option<String>,
}

impl Run {
    /// A run is `ok` when every leg completed. Unlike
    /// [`crate::proof_circuit`], that DOES mean the proof verified:
    /// `Groth16Prover::prove` returns `InvalidProof` rather than a proof when
    /// verification fails, so a green `transfer` leg is a verified proof.
    pub fn ok(&self) -> bool {
        self.error.is_none() && !self.legs.is_empty() && self.legs.iter().all(Leg::ok)
    }

    pub fn leg(&self, name: &str) -> Option<&Leg> {
        self.legs.iter().find(|l| l.name == name)
    }

    /// Stamp the elapsed total and hand the run back — every exit from [`run`]
    /// goes through this, so a run that gave up early still reports the time it
    /// spent getting there.
    fn finished(mut self, started: Instant) -> Run {
        self.total_ms = started.elapsed().as_millis();
        report(&self);
        self
    }
}

/// Announce a stage BEFORE entering it, for the reason
/// [`crate::witness_engine`] gives where it does the same: on a platform that
/// kills the process there is no reply to read, only the last line printed.
fn entering(what: &str) {
    eprintln!("railgun_module: private-send probe: entering {what}");
}

/// The syncer that stands in for a chain nobody funded: it reports exactly one
/// block and exactly one `Shield`, and it is the ONLY fabricated thing in this
/// probe (see the module docs).
///
/// `RailgunBuilder::with_utxo_syncer` is a public, documented seam — the engine's
/// own way of saying "get your events from here" — so this is a substitution the
/// engine supports, not a hole cut in it.
pub struct OneShieldSyncer {
    block: u64,
    events: Vec<SyncEvent>,
}

impl OneShieldSyncer {
    pub fn new(block: u64, events: Vec<SyncEvent>) -> Self {
        Self { block, events }
    }
}

#[async_trait::async_trait]
impl UtxoSyncer for OneShieldSyncer {
    async fn latest_block(&self) -> Result<u64, SyncerError> {
        Ok(self.block)
    }

    async fn sync(&self, from_block: u64, to_block: u64) -> Result<Vec<SyncEvent>, SyncerError> {
        if from_block <= self.block && self.block <= to_block {
            Ok(self.events.clone())
        } else {
            Ok(Vec::new())
        }
    }
}

/// One `Shield` event for `recipient`, built by the ENGINE'S OWN
/// `encrypt_shield` — the call `ShieldBuilder::build` makes for every shield
/// [`crate::engine::RailgunEngine::prepare_shield`] has ever emitted.
///
/// The three derived fields are read off the `ShieldRequest` exactly as
/// `RpcSyncer`'s `handle_shield_event` reads them off the contract's log, so the
/// engine cannot tell this event from one the chain emitted — which is the point:
/// what is missing is the transaction, not the commitment.
#[cfg(feature = "engine_seam")]
fn shield_event(
    recipient: railgun::account::address::RailgunAddress,
    asset: AssetId,
    value: u128,
) -> Result<SyncEvent, String> {
    use ruint::aliases::U256;

    let request = railgun::logos_engine_seam::encrypt_shield(
        recipient,
        asset,
        value,
        &mut rand::rng(),
    )
    .map_err(|e| format!("encrypt_shield: {e}"))?;

    Ok(SyncEvent::Shield(
        railgun::indexer::syncer::Shield {
            tree_number: TREE_NUMBER,
            leaf_index: LEAF_INDEX,
            npk: request.preimage.npk.into(),
            token: asset,
            value: U256::from(value),
            ciphertext: request.ciphertext.clone().into(),
            shield_key: request.ciphertext.shieldKey.into(),
            // The indexer computes it: poseidon(npk, token hash, value), which
            // is what the contract stores. Supplying one would be fabricating a
            // commitment rather than letting the engine derive it.
            hash: None,
        },
        SHIELD_BLOCK,
    ))
}

/// Without the seam there is no `encrypt_shield` to call — `mod note` is private
/// at the engine crate's root. A plain `cargo build` is this arm; every image the
/// nix build produces is the one above.
#[cfg(not(feature = "engine_seam"))]
fn shield_event(
    _recipient: railgun::account::address::RailgunAddress,
    _asset: AssetId,
    _value: u128,
) -> Result<SyncEvent, String> {
    Err("this build carries no engine seam \
         (rust-lib/patch-kohaku-engine-seam.sh is applied by the nix build's postPatch, \
         not by cargo)"
        .to_string())
}

/// Whether [`shield_event`] can do anything but refuse.
pub const ENGINE_SEAM: bool = cfg!(feature = "engine_seam");

/// THE WHOLE PRIVATE SEND, in the order a user pays for it.
///
/// `eip1193` is the real chain-read seam — the engine makes a real `rootHistory`
/// call on the real contract during the sync, and the answer is reported rather
/// than avoided.
pub async fn run(eip1193: Arc<dyn Eip1193Provider>, p: Params) -> Run {
    let started = Instant::now();
    let mut out = Run {
        chain_id: p.chain_id,
        engine_seam: ENGINE_SEAM,
        ..Default::default()
    };

    let Some(chain) = ChainConfig::from_chain_id(p.chain_id) else {
        out.error = Some(format!("unsupported chain id {} (mainnet + Sepolia only)", p.chain_id));
        return out.finished(started);
    };
    let asset = AssetId::erc20(p.asset.unwrap_or(chain.wrapped_base_token));
    // Read before the builder takes `chain`: the contract the root question goes to.
    let smart_wallet = chain.railgun_smart_wallet;
    out.asset = Some(asset.to_string());

    if p.transfer > p.shield {
        out.error = Some(format!(
            "transfer {} exceeds the shielded {} -- the engine would refuse this before proving \
             anything",
            p.transfer, p.shield
        ));
        return out.finished(started);
    }

    // ── the two parties, derived rather than random so a repeat run is one ──
    entering("keys");
    let binding = ChainId::evm(p.chain_id);
    let (spend, view) = keys::derive_keys_from_seed(PROBE_SEED);
    let signer = match keys::make_signer(&spend, &view, binding) {
        Ok(s) => s,
        Err(e) => {
            out.legs.push(Leg::failed("keys", None, e));
            return out.finished(started);
        }
    };
    let (r_spend, r_view) = keys::derive_keys_from_seed(PROBE_RECIPIENT_SEED);
    let recipient = match keys::make_signer(&r_spend, &r_view, binding) {
        Ok(s) => s,
        Err(e) => {
            out.legs.push(Leg::failed("keys", None, e));
            return out.finished(started);
        }
    };
    let from = signer.address();
    let to = recipient.address();
    out.from = Some(from.to_string());
    out.to = Some(to.to_string());
    out.legs.push(Leg::timed("keys", None));

    // ── the one fabricated thing: a commitment nobody mined ────────────────
    entering("shield");
    let t = Instant::now();
    let event = match shield_event(from.clone(), asset, p.shield) {
        Ok(e) => e,
        Err(e) => {
            out.legs.push(Leg::failed("shield", None, e));
            return out.finished(started);
        }
    };
    out.legs.push(Leg::timed("shield", Some(t.elapsed().as_millis())));

    // ── the engine, over its own in-memory database ────────────────────────
    entering("engine");
    let t = Instant::now();
    let syncer = Arc::new(OneShieldSyncer::new(SHIELD_BLOCK, vec![event]));
    let build = RailgunBuilder::new(chain, eip1193.clone())
        .with_database(Arc::new(MemoryDatabase::new()))
        .with_utxo_syncer(syncer)
        .build()
        .await;
    let mut provider = match build {
        Ok(p) => p,
        Err(e) => {
            out.legs.push(Leg::failed("engine", None, format!("engine build: {e}")));
            return out.finished(started);
        }
    };
    if let Err(e) = provider.register(signer.clone() as Arc<dyn RailgunSigner>).await {
        out.legs.push(Leg::failed("engine", None, format!("register signer: {e}")));
        return out.finished(started);
    }
    out.legs.push(Leg::timed("engine", Some(t.elapsed().as_millis())));

    // ── the sync: decrypt, insert the leaf, ask the chain about the root ───
    entering("sync");
    let t = Instant::now();
    if let Err(e) = provider.sync().await {
        out.legs.push(Leg::failed("sync", Some(t.elapsed().as_millis()), format!("sync: {e}")));
        return out.finished(started);
    }
    out.legs.push(Leg::timed("sync", Some(t.elapsed().as_millis())));

    // ── the balance that does not exist without the event above ────────────
    entering("balance");
    let t = Instant::now();
    let balance: u128 = provider
        .balance(from.clone())
        .await
        .iter()
        .filter(|b| b.asset == asset)
        .map(|b| b.amount)
        .sum();
    let ms = Some(t.elapsed().as_millis());
    out.balance = Some(balance);
    // The engine has to have DECRYPTED the commitment as its own note, not just
    // inserted the leaf -- a leaf it cannot read is a tree with no balance in it,
    // and the transfer below would fail later with `InsufficientBalance` instead
    // of here with the reason.
    if balance != p.shield {
        out.legs.push(Leg::failed(
            "balance",
            ms,
            format!(
                "the engine sees {balance} of {asset} shielded, the probe shielded {} -- it did \
                 not decrypt its own note",
                p.shield
            ),
        ));
        return out.finished(started);
    }
    out.legs.push(Leg::timed("balance", ms));

    // ── the private send itself, proof and verification included ───────────
    // `Groth16Prover::prove` VERIFIES what it produced and answers `InvalidProof`
    // instead of a proof when verification fails, so a leg that completes here is
    // a proof a verifier accepted -- which is the thing placeholder values could
    // never give (#213, and see [`crate::proof_circuit`]).
    let mut merkleroot: Option<alloy::primitives::U256> = None;
    for name in ["transfer-cold", "transfer-warm"] {
        if name == "transfer-warm" && !p.repeat {
            break;
        }
        entering(name);
        // The note is still unspent as far as this engine knows -- nothing
        // nullified it, because nothing was broadcast -- so the second run
        // spends the same note again. Its only difference is the artifact
        // loader's in-memory cache, which is why it is the compute-only figure.
        let builder = provider.transact().transfer(
            signer.clone() as Arc<dyn RailgunSigner>,
            to.clone(),
            asset,
            p.transfer,
            &p.memo,
        );
        let t = Instant::now();
        match provider.build(builder, &mut rand::rng()).await {
            Ok(proved) => {
                out.legs.push(Leg::timed(name, Some(t.elapsed().as_millis())));
                if let Some(op) = proved.proved_operations.first() {
                    out.circuit = Some(format!(
                        "{:02}x{:02}",
                        op.circuit_inputs.nullifiers.len(),
                        op.circuit_inputs.commitments_out.len()
                    ));
                    merkleroot = Some(op.circuit_inputs.merkleroot.into());
                }
                out.calldata_bytes = Some(proved.tx_data.data.len());
            }
            Err(e) => {
                out.legs.push(Leg::failed(
                    name,
                    Some(t.elapsed().as_millis()),
                    format!("prove transfer: {e}"),
                ));
                return out.finished(started);
            }
        }
    }

    // ── and the honest limit, asked of the chain rather than assumed ───────
    // The engine already asked this inside `sync` and threw the answer away
    // (`UtxoIndexer::verify` propagates the error and ignores the bool). Asked
    // again here, about the root the proof was actually built over, so the limit
    // of this probe is IN its result: `false` means no shield was mined, so this
    // calldata would revert on chain. Acceptance clause 1 of #213 is exactly
    // this boolean turning true, and only an operator can make it.
    if let Some(root) = merkleroot {
        entering("root-on-chain");
        let t = Instant::now();
        match root_on_chain(eip1193.as_ref(), smart_wallet, root).await {
            Ok(seen) => {
                out.root_on_chain = Some(seen);
                out.legs.push(Leg::timed("root-on-chain", Some(t.elapsed().as_millis())));
            }
            Err(e) => {
                out.legs.push(Leg::failed("root-on-chain", Some(t.elapsed().as_millis()), e))
            }
        }
    }

    out.finished(started)
}

/// `RailgunSmartWallet.rootHistory(treeNumber, root)` — the same question
/// `SmartWalletUtxoVerifier` asks on every sync, asked here so the answer is
/// reported. Spelled with this module's own `sol!` because the engine's ABI
/// module is private to it; the signature is copied from the engine's
/// `abis/railgun.rs` and is the contract's.
async fn root_on_chain(
    provider: &dyn Eip1193Provider,
    smart_wallet: Address,
    root: alloy::primitives::U256,
) -> Result<bool, String> {
    alloy::sol! {
        function rootHistory(uint256 treeNumber, bytes32 root) external view returns (bool);
    }
    provider
        .sol_call(
            smart_wallet,
            rootHistoryCall { treeNumber: alloy::primitives::U256::from(TREE_NUMBER), root: root.into() },
        )
        .await
        .map_err(|e| format!("rootHistory: {e}"))
}

/// Print the result as it completes, for the reason
/// [`crate::proof_circuit::report`] does the same: on a platform that kills the
/// process the console line is the only thing that survives.
pub fn report(r: &Run) {
    let leg = |n: &str| r.leg(n).and_then(|l| l.ms);
    eprintln!(
        "railgun_module: private-send probe: {} (seam={} chain={} circuit={:?} balance={:?} \
         rootOnChain={:?} calldata={:?}B shield={:?}ms engine={:?}ms sync={:?}ms \
         balanceMs={:?} transferCold={:?}ms transferWarm={:?}ms total={}ms)",
        if r.ok() { "SENT" } else { "DID NOT" },
        r.engine_seam,
        r.chain_id,
        r.circuit,
        r.balance,
        r.root_on_chain,
        r.calldata_bytes,
        leg("shield"),
        leg("engine"),
        leg("sync"),
        leg("balance"),
        leg("transfer-cold"),
        leg("transfer-warm"),
        r.total_ms,
    );
    if let Some(from) = &r.from {
        eprintln!("railgun_module: private-send probe: from {from}");
    }
    for l in r.legs.iter().filter(|l| !l.ok()) {
        eprintln!("railgun_module: private-send probe: {} -> {:?}", l.name, l.error);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::*;
    use crate::rpc_backend::{EthRpcEip1193, RpcBackend};

    /// The chain, as far as this probe needs one: `rootHistory` answers `false`
    /// for every root, which is what Sepolia answers for a root no shield put
    /// there. Nothing else is called — `RailgunBuilder::build` reads only the
    /// database, and the sync's only chain question is this one.
    struct NoRootBackend;

    impl RpcBackend for NoRootBackend {
        fn rpc(&self, method: &str, _params: Value) -> Result<Value, String> {
            match method {
                // abi-encoded `false`
                "eth_call" => Ok(json!(format!("0x{}", "0".repeat(64)))),
                other => Err(format!("unexpected rpc {other} -- the probe should not need it")),
            }
        }
    }

    fn offline_chain() -> Arc<dyn Eip1193Provider> {
        Arc::new(EthRpcEip1193::new(Arc::new(NoRootBackend)))
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    // The syncer answers for its own block and no other, so the indexer's
    // `from_block = synced_block + 1` window decides whether the note arrives —
    // and a second `sync()` must not deliver the same commitment twice (which
    // would insert a second leaf and change the tree the proof is built over).
    #[test]
    fn the_syncer_answers_only_inside_its_block_range() {
        let syncer = OneShieldSyncer::new(7, vec![]);
        assert_eq!(block_on(syncer.latest_block()).unwrap(), 7);
        assert_eq!(block_on(syncer.sync(1, 7)).unwrap().len(), 0);
        // (empty above only because the event list is; the range logic is below)
        let event = SyncEvent::Legacy(
            railgun::indexer::syncer::LegacyCommitment {
                hash: ruint::aliases::U256::from(1),
                tree_number: 0,
                leaf_index: 0,
            },
            7,
        );
        let syncer = OneShieldSyncer::new(7, vec![event]);
        assert_eq!(block_on(syncer.sync(1, 7)).unwrap().len(), 1, "block 7 is in [1, 7]");
        assert_eq!(block_on(syncer.sync(1, 6)).unwrap().len(), 0, "not synced that far yet");
        assert_eq!(block_on(syncer.sync(8, 99)).unwrap().len(), 0, "already past it");
    }

    // A transfer larger than the shield is refused BEFORE the engine is built,
    // so a misuse costs nothing and says why rather than failing inside the
    // builder with `InsufficientBalance` after a 3.5 MB download.
    #[test]
    fn a_transfer_bigger_than_the_shield_never_builds_an_engine() {
        let out = block_on(run(
            offline_chain(),
            Params { shield: 10, transfer: 11, ..Default::default() },
        ));
        assert!(out.legs.is_empty(), "it started work: {:?}", out.legs);
        assert!(out.error.unwrap_or_default().contains("exceeds the shielded"));
    }

    #[test]
    fn an_unsupported_chain_is_refused_by_name() {
        let out = block_on(run(offline_chain(), Params { chain_id: 999, ..Default::default() }));
        assert!(out.legs.is_empty());
        assert!(out.error.unwrap_or_default().contains("unsupported chain id 999"));
    }

    // THE ONE THAT MATTERS, and it needs no network and no chain: the engine
    // must DECRYPT the fabricated commitment as its own note and report it as a
    // shielded balance. Everything after this in `run` is the engine's own
    // proving path, so this is the assertion that the substitution works at all.
    //
    // Only the seam build can run it — `encrypt_shield` is the engine's, and a
    // plain `cargo test` has no patched vendor directory.
    #[cfg(feature = "engine_seam")]
    #[test]
    fn a_shielded_balance_appears_with_no_chain_state() {
        let mut p = Params { repeat: false, ..Default::default() };
        p.shield = 1_234_567;
        // Stop before the proof: this test is about the balance, and the proof
        // needs 3.5 MB of artifacts. `transfer > shield` would refuse early, so
        // the stop is made by asserting on the legs rather than by a flag.
        let out = block_on(run(offline_chain(), p.clone()));
        assert_eq!(out.balance, Some(p.shield), "{out:?}");
        assert!(out.from.unwrap().starts_with("0zk1"));
        for name in ["keys", "shield", "engine", "sync", "balance"] {
            let leg = out.legs.iter().find(|l| l.name == name).expect(name);
            assert!(leg.ok(), "{name} failed: {:?}", leg.error);
        }
    }

    // THE WHOLE PRIVATE SEND, over the real artifacts, on this host. `#[ignore]`
    // because it needs the network (~3.5 MB) and tens of seconds of proving, not
    // because it is optional: it is the only test that proves the engine's own
    // path produces a proof that VERIFIES. Run it before trusting a device
    // number:
    //
    //   cargo test --features engine_seam -- --ignored --nocapture
    #[cfg(feature = "engine_seam")]
    #[test]
    #[ignore = "needs the network (~3.5 MB of artifacts) and a full Groth16 proof"]
    fn the_engine_sends_privately_on_this_host() {
        let out = block_on(run(offline_chain(), Params::default()));
        assert!(out.ok(), "{out:?}");
        // One nullifier in (the shielded note), two commitments out (the
        // transfer and the engine's own change note) — the circuit
        // `proof_circuit` measured.
        assert_eq!(out.circuit.as_deref(), Some("01x02"));
        assert_eq!(out.balance, Some(DEFAULT_SHIELD));
        // A green `transfer-cold` IS a verified proof: `Groth16Prover::prove`
        // answers `InvalidProof` rather than a proof otherwise.
        assert!(out.leg("transfer-cold").and_then(|l| l.ms).is_some());
        assert!(out.calldata_bytes.unwrap_or(0) > 0);
        // And the limit this probe cannot pass: the root is not on chain,
        // because no shield was mined. If this is ever `Some(true)` the venue
        // has chain state and #213's clause 1 can be closed for real.
        assert_eq!(out.root_on_chain, Some(false));
    }
}
