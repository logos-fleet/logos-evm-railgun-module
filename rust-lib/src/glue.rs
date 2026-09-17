//! Logos module glue for `railgun_module` (rust-first authoring).
//!
//! Wires the contract trait to the Logos runtime: the engine's chain reads are
//! served by `modules().eth_rpc_module` (declared in metadata.json
//! `dependencies`) through the [`EthRpcBackend`] → [`EthRpcEip1193`] adapter.
//!
//! ## Concurrency
//! `concurrency: "single"` for now. The railgun engine (`RailgunProvider`) is a
//! single `&mut`-driven object and is **not `Send + Sync`** — its `dyn
//! RailgunSigner` field isn't, so it can't satisfy multi-dispatch's `Send + Sync`
//! bound. So we hold it directly behind `&mut self`. The cost: a long proof
//! blocks the module's dispatch. `concurrency: "multi"` is a follow-up that needs
//! a one-line upstream patch (`RailgunSigner: Send + Sync`, satisfied by the
//! concrete `PrivateKeySigner`) carried in our engine fork.
//!
//! ## Async bridge
//! The engine is `async`; each (sync) glue method drives it on a per-call
//! current-thread tokio runtime via `block_on`, on the module's dispatch thread
//! (which carries the Qt event loop the engine's outbound `modules()` IPC needs).
//!
//! ## Signing is a request, not a call
//! The relayer's EOA signature comes from `keystore_module`, which no longer
//! signs on demand: a signature is approved by a human and collected later. So
//! `relayed_send` does not return a `userOpHash` any more. It prepares the
//! operation, asks for approval, parks the job and returns `{ ok, pending,
//! requestId }`; `relayed_send_status` drives it forward and broadcasts once the
//! human has decided. Nothing here parks a dispatch thread on a person — the
//! keystore answers in microseconds and the decision arrives later. See
//! [`crate::relay`] for the two passes that split the signing step.
//!
//! ⚠️ Unaudited upstream engine — Sepolia-first; the railgun keys never leave
//! this module (see [`crate::keys`]).

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use alloy::primitives::{Address, B256};
use eip_1193_provider::provider::Eip1193Provider;
use serde::Deserialize;
use serde_json::{json, Value};
use userop_kit::signable_user_operation::SignableUserOperation;

use crate::engine::RailgunEngine;
use crate::live_send;
use crate::private_send;
use crate::proof_circuit;
use crate::relay;
use crate::rpc_backend::{EthRpcEip1193, RpcBackend};
use crate::sync::{self, Plan};
use crate::web_dependency::{self, Dependency, Leg};
use crate::witness_circuit;
use crate::witness_engine;

pub trait RailgunModule: 'static {
    /// One-time load: `{ "chainId": u64, "spendingKey": hex, "viewingKey": hex,
    /// "poi": bool }`. Imports the railgun keys (held in-module), builds the
    /// engine for the chain, and returns `{ ok, address }` (the `0zk` address).
    fn init(&mut self, params_json: String) -> String;
    /// Like [`Self::init`] but derives the railgun keys from a `seed` (a
    /// deterministic EOA signature from keystore) rather than explicit keys:
    /// `{ "chainId": u64, "seed": hex, "poi": bool }` → `{ ok, address }`. The
    /// derived spending/viewing keys are produced and held in-module.
    fn init_from_seed(&mut self, params_json: String) -> String;
    /// The public `0zk1…` RAILGUN address (`{ ok, address }`).
    fn get_zk_address(&mut self) -> String;
    /// Sync UTXO/TXID (and POI, if enabled) state to the latest block.
    ///
    /// ONE CALL, AS LONG AS IT TAKES — 221 s on a physical iPad Air 4 (#235),
    /// with nothing to report and nothing to interrupt. Use it where there is
    /// no user: [`Self::sync_step`] is the same work, in bounded pieces.
    fn sync(&mut self) -> String;
    /// ADVANCE THE SYNC, A BOUNDED PIECE AT A TIME, AND SAY WHERE IT GOT TO.
    /// `{ "blocks"?: u64, "budgetMs"?: u64 }` →
    /// `{ ok, done, startBlock, syncedBlock, targetBlock, blocksTotal,
    /// blocksDone, blocksRemaining, percent, windows, elapsedMs, etaMs,
    /// stepMs }`.
    ///
    /// The accumulator sync is the whole cost of a private send — 221 s of the
    /// 239 s one took on a handset, against 3.6 s for witness + Groth16 +
    /// verify — and [`Self::sync`] does it in one opaque call that cannot be
    /// shown, cannot be interrupted and outlasts any caller's timeout. This
    /// does the same work in windows: each call syncs at most `blocks`
    /// (default 25 000) and returns after `budgetMs` (default 20 000) whether
    /// or not it finished, so **no call takes minutes** and the caller has a
    /// real percentage and an ETA between them rather than a spinner.
    ///
    /// **Call it until `done` is true.** The target is pinned when the first
    /// step makes the plan, so the percentage cannot go backwards as the chain
    /// advances; a send needs the tree to hold its own shield, and the blocks
    /// after that are the next sync's business.
    ///
    /// **THE CANCEL PATH IS: STOP CALLING IT.** There is nothing to roll back.
    /// A sync only reads the chain, `UtxoIndexer::sync_to` persists
    /// `synced_block` before each window returns, and a later step (or a later
    /// launch — the record is on disk) resumes from there. A **shield that is
    /// already mined is untouched**: it is on chain, the note is owned by this
    /// wallet's `0zk` address, and the next sync of any length finds and
    /// decrypts it. Cancelling after the shield leaves a shielded balance and
    /// no transfer, which is a state the wallet can show and spend from.
    /// [`Self::sync_cancel`] exists to say so in one call and to drop the
    /// pinned target; it is not an undo.
    fn sync_step(&mut self, params_json: String) -> String;
    /// WHERE THE SYNC IS, without doing any of it.
    /// `{ ok, running, done, startBlock, syncedBlock, targetBlock, percent, … }`
    /// — the same fields [`Self::sync_step`] answers with.
    ///
    /// With a plan in progress it reports that plan. With none it reads the
    /// engine's persisted `synced_block` and asks the chain for its head, which
    /// is what a wallet wants before it offers to send: "this device is 2 200
    /// blocks behind" is the difference between a send that is instant and one
    /// that is not. Costs one `eth_blockNumber` and no chain walk.
    fn sync_status(&mut self) -> String;
    /// GIVE UP ON THE SYNC IN PROGRESS. `{ ok, cancelled, keptToBlock, … }`.
    ///
    /// Drops the pinned target so the next [`Self::sync_step`] makes a fresh
    /// plan against the current head. **It undoes nothing**, because there is
    /// nothing a sync did that should be undone: every window that completed is
    /// persisted and correct, and a mined shield is the chain's, not this
    /// module's. `keptToBlock` is how far the cancelled sync had got, and a
    /// later step starts there.
    fn sync_cancel(&mut self) -> String;
    /// Shielded balance per asset (`{ ok, balances: [BalanceEntry] }`).
    fn get_shielded_balance(&mut self) -> String;
    /// SHIELD (deposit public → private): `{ "asset": "0x…", "amount": "decimal" }`
    /// → `{ ok, txs: [TxData] }` for the caller to approve+sign+send. No proof.
    fn prepare_shield(&mut self, params_json: String) -> String;
    /// Private TRANSFER (0zk → 0zk): `{ "to": "0zk…", "asset", "amount", "memo"? }`
    /// → `{ ok, tx: TxData }` (Groth16-proven). No fee.
    fn prepare_transfer(&mut self, params_json: String) -> String;
    /// UNSHIELD (private → public 0x): `{ "to": "0x…", "asset", "amount" }`
    /// → `{ ok, tx: TxData }` (Groth16-proven; engine adds the unshield fee).
    fn prepare_unshield(&mut self, params_json: String) -> String;
    /// REQUEST a relayed private send (ERC-4337 — hides the sender):
    /// `{ "to": "0zk…"|"0x…", "asset", "amount", "memo"?, "owner": "0x…",
    /// "bundlerUrl": "https://…" }` → `{ ok, pending: true, requestId }`.
    /// Routes 0zk→transfer / 0x→unshield, wraps it in a 7702 UserOp paid from the
    /// shielded pool, then asks `keystore_module` for a human to approve
    /// `owner`'s signature over the operation's digests (the EOA key never
    /// leaves keystore). Returns AS SOON AS the request is lodged — the
    /// operation is not signed and nothing has been broadcast yet. Drive it with
    /// [`Self::relayed_send_status`]. Needs a live bundler + chain (no offline
    /// path).
    fn relayed_send(&mut self, params_json: String) -> String;
    /// Drive a parked relayed send forward. `{ ok, state, userOpHash?, reason? }`
    /// where `state` is `awaiting_approval` while the human has not decided,
    /// `declined` once they refused (or the request expired or was cancelled),
    /// and `done` once the approved operation has been submitted to the bundler
    /// **through eth_rpc** (`raw_rpc_url`, proxied — the bundler never sees the
    /// user's IP). Safe to call repeatedly; poll it.
    fn relayed_send_status(&mut self, request_id: String) -> String;
    /// Give up on a parked relayed send: withdraws the request so it stops
    /// occupying the approver's queue. `{ ok }`. A request nobody withdraws is
    /// swept by the keystore, but only after a minute.
    fn relayed_send_cancel(&mut self, request_id: String) -> String;
    /// CAN THIS DEVICE PROVE AT ALL?
    /// `{ ok, requested, backend, reached, answer?, error?, alternatives: [...] }`.
    /// Every transfer/unshield proof needs a witness, and the witness comes out
    /// of the circuit's `.wasm` run under `wasmer`'s cranelift JIT — which iOS
    /// refuses to let execute (#188). This asks that question directly, in four
    /// stages (`engine` → `compile` → `instantiate` → `call`), over a wasm
    /// module carried inside this crate: no chain, no keys, no artifact
    /// download, no shielded balance. `ok: true` only when emitted code ran and
    /// answered correctly; `reached` says where it stopped otherwise.
    /// `alternatives` carries the same four stages over every OTHER wasm
    /// backend in the image (the `wasmi` interpreter), so a device that refuses
    /// the JIT also says what would work instead. Safe to call before `init`.
    /// See [`crate::witness_engine`].
    fn witness_engine_probe(&mut self) -> String;
    /// AND HOW LONG DOES A REAL WITNESS TAKE?
    /// `{ "circuit"?: "01x02", "backends"?: ["wasmi", ...] }` →
    /// `{ ok, circuit, artifactUrl, downloadMs, wasmBytes, sanityCheck,
    /// probes: [{ requested, backend, reached, compileMs, instantiateMs,
    /// witnessMs, witnessLen, witnessNonzero, signals, error }] }`.
    ///
    /// [`Self::witness_engine_probe`] answers whether a backend MAY run here;
    /// this answers what it costs, over the circuit the engine really proves
    /// with — the same `.wasm` `calculate_witness` downloads, through the same
    /// `ark_circom::WitnessCalculator`, on each backend in the image. It
    /// matters because the backend a physical iOS device permits is an
    /// INTERPRETER, and an interpreter that takes minutes is a different
    /// product decision from one that takes seconds.
    ///
    /// Needs the network (it fetches ~900 KB of artifact) and no chain, keys or
    /// shielded balance: the inputs are the circuit's real SHAPE filled with
    /// placeholders, checked against the circuit's own `getInputSignalSize`,
    /// with circom's sanity check off. So it times witness generation honestly
    /// and proves nothing about a proof VERIFYING. `backends` defaults to every
    /// backend in the image, engine-default last — name `["wasmi"]` alone on a
    /// device where the JIT kills the process and the reply survives.
    /// See [`crate::witness_circuit`].
    fn witness_circuit_probe(&mut self, params_json: String) -> String;
    /// AND A WITNESS IS NOT A PROOF — WHAT DOES THE PROOF COST?
    /// `{ "circuit"?: "01x02" }` →
    /// `{ ok, circuit, backend, engineSeam, witnessSource, witnessLen,
    /// numInstanceVariables, numWitnessVariables, numConstraints, verified,
    /// totalMs, legs: [{ name, ms, bytes, ok, error }], error }`.
    ///
    /// [`Self::witness_circuit_probe`] timed the witness (817 ms on an iPad Air
    /// 4). `Groth16Prover::prove_transact` then downloads a ~3 MB proving key
    /// and ~140 KB of constraint matrices and runs arkworks Groth16 over that
    /// witness, and RAILGUN's published "1-2 minutes on mobile" is about THAT
    /// half. This measures it, leg by leg, over the engine's own artifacts and
    /// through the same arkworks calls `Groth16Prover::prove` makes (#213).
    ///
    /// It also calls the ENGINE'S OWN `calculate_witness` — the function #188's
    /// build-time patch rewrote and which, until this probe, nothing had ever
    /// reached on a device (the engine crate's `mod circuit` is private; a
    /// sibling build-time patch opens a `pub use` seam). The call prints the
    /// patched line naming the backend it chose, which is the direct evidence
    /// that the engine's own path takes the interpreter on physical iOS.
    ///
    /// Needs the network (~3.5 MB) and no chain, keys or shielded balance: the
    /// inputs are the circuit's real SHAPE filled with placeholders, so
    /// `verified` is expected to be `false` and is reported rather than hidden
    /// — the milliseconds are a property of the circuit, the verdict is a
    /// property of the values. See [`crate::proof_circuit`].
    fn proof_circuit_probe(&mut self, params_json: String) -> String;
    /// A WHOLE PRIVATE SEND, THROUGH THE ENGINE'S OWN PATH, ON A CHAIN WITH NO
    /// MONEY IN IT.
    /// `{ ok, engineSeam, chainId, asset, from, to, balance, circuit,
    /// rootOnChain, calldataBytes, totalMs, legs: [{ name, ms, ok, error? }] }`.
    ///
    /// `proof_circuit_probe` proved the engine's own `calculate_witness` runs on
    /// a device, but over the circuit's real SHAPE with placeholder VALUES — so
    /// its proof could not verify. This runs the REAL thing: the engine decrypts
    /// a shielded note, selects it, builds the merkle proof, signs the
    /// bound-params hash, generates the witness and proves AND VERIFIES with
    /// `Groth16Prover` — `ok` is therefore a proof a verifier accepted.
    ///
    /// The one thing it fabricates is the chain event that would have put the
    /// note there, handed to the engine through its own public
    /// `RailgunBuilder::with_utxo_syncer` seam, because the venue's account has
    /// no testnet funds and faucets are captcha-gated. `rootOnChain` reports
    /// that limit rather than hiding it: it is `false` until a real shield is
    /// mined. Needs the network (~3.5 MB of artifacts) and `eth_rpc_module`; no
    /// keys, no keystore, and nothing of the user's — the probe derives its own
    /// from a fixed seed and keeps its state in memory. See
    /// [`crate::private_send`].
    fn private_send_probe(&mut self, params_json: String) -> String;
    /// AND THE SAME SEND WITH NOTHING SUBSTITUTED — ON CHAIN, MINED, AND
    /// ACCEPTED BY THE CONTRACT.
    /// `{ "asset"?, "shield"?, "transfer"?, "memo"?, "broadcast"?, "confirmMs"? }`
    /// → `{ ok, chainId, node, forked, witnessBackend, eoa, ethWei, tokenUnits,
    /// needsFunding?, asset, wrappedWei, wrapTx, from, to, approveTx, shieldTx,
    /// shieldBlock, syncFromBlock, syncToBlock, balance, transferred, circuit,
    /// rootOnChain, syncedTree, syncedRoot, syncedRootOnChain, calldataBytes,
    /// transferTx, transferBlock, totalMs, legs: [{ name, ms, ok, error? }] }`.
    ///
    /// `node` / `forked` say WHOSE chain answered, because a fork of Sepolia
    /// prints byte-identical lines to the public chain. `witnessBackend` is the
    /// backend the engine's own `calculate_witness` used — `wasmi` on a physical
    /// iOS device (#188), the platform default everywhere else — and it is here
    /// because the engine announces it on stderr, where a caller reading this
    /// object never sees it (#213 clause 2).
    ///
    /// [`Self::private_send_probe`] fabricates exactly one thing — the `Shield`
    /// event — and says so with `rootOnChain: false`. This fabricates nothing:
    /// it shields real ERC-20 with a real transaction, waits for a block, syncs
    /// the REAL Sepolia tree, proves over the root the CONTRACT holds, and
    /// broadcasts the proved `transact(...)` so the contract itself verifies the
    /// proof this device produced. `rootOnChain: true` is #213's acceptance
    /// clause 1.
    ///
    /// It signs with an EOA OF ITS OWN whose key is derived from a seed printed
    /// in `live_send.rs` — public by construction, because the user's account
    /// cannot sign for an agent (keystore needs a human and a password) and a
    /// probe must never hold anything worth taking. Sepolia only, refused before
    /// any chain read otherwise. Until an operator funds that address every run
    /// reports what to send in `needsFunding` — and what to send is **Sepolia
    /// ETH and nothing else**: with no ERC-20 in hand the probe mints its own by
    /// wrapping some of its ETH into the chain's wrapped base token (`wrap`
    /// leg), which RAILGUN shields like any other ERC-20.
    ///
    /// An unfunded run then SURVEYS rather than stopping: it still builds the
    /// engine, walks the real accumulator to the live tip and checks the root it
    /// arrives at against the contract (`syncedRootOnChain`) — every leg money
    /// is not needed for, including the one that dominates a private send's wall
    /// clock. `ok` stays false and the summary says `SURVEY-ONLY-UNFUNDED`,
    /// because a survey is not a send.
    ///
    /// `syncedRootOnChain` is the verdict the ENGINE asks for at the end of
    /// every sync and then discards (kohaku's `UtxoIndexer::verify` keeps the
    /// RPC error and drops the `bool`): `true` means the accumulator this device
    /// rebuilt from chain events is the one the RAILGUN contract holds. Unlike
    /// `rootOnChain` it needs no shielded balance.
    /// See [`crate::live_send`].
    fn live_send_probe(&mut self, params_json: String) -> String;
    /// CAN THIS MODULE REACH ITS `web` DEPENDENCY?
    /// `{ ok, target, dispatchThread, loadThread, dispatchLeftTheLoadThread,
    /// callerKind, callerIdentity, callerIsThisModule,
    /// legs: [{ method, ms, ok, reply?, error? }] }`.
    ///
    /// On a phone `keystore_module` is a `web` (wasm) variant — a page in the
    /// Shell's container — and this module is native, Bare and in-process.
    /// ADR 0010 lets a Bundled member depend on the image's web half, which is
    /// what puts this module in the mobile catalog at all, and it rests on the
    /// host's claim that a consumer reaches a Web module exactly as it reaches
    /// a subprocess one. This asks that claim on the device: three ordinary
    /// crossings to the dependency, timed, with the name the page believes
    /// called it, and the thread the dispatch ran on beside the one the image
    /// was loaded on. No chain, no keys, no engine — safe to call before
    /// `init`. See [`crate::web_dependency`].
    fn web_dependency_probe(&mut self) -> String;

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct RailgunModuleImpl {
    persist_dir: Option<PathBuf>,
    engine: Option<RailgunEngine>,
    /// The stepped sync in progress, if any — see [`RailgunModule::sync_step`].
    /// `None` between syncs, which is also what a cancel leaves behind.
    sync_plan: Option<Plan>,
    /// Relayed sends awaiting a human, keyed by the keystore approval handle
    /// (the `requestId` the caller polls).
    jobs: HashMap<String, PendingRelay>,
}

/// A prepared UserOperation parked on a human decision. Held whole rather than
/// re-prepared on approval: re-preparing would iterate against the bundler
/// again and could produce a DIFFERENT operation from the one that was
/// approved.
struct PendingRelay {
    /// Authorises collecting the result. Returned by `request_approval` exactly
    /// once, so it is never re-derivable — losing it loses the signatures.
    receipt: String,
    chain_id: u64,
    bundler_url: String,
    signable: SignableUserOperation,
    /// Exactly the digests the human was asked to approve.
    digests: Vec<B256>,
    owner: Address,
}

// ── eth_rpc-backed RpcBackend (the chain-read seam the engine adapter uses) ──

/// Backs the engine's `Eip1193Provider` by forwarding raw JSON-RPC to
/// `modules().eth_rpc_module.raw_rpc(chainId, method, params)` and unwrapping the
/// `{ ok, result }` envelope.
struct EthRpcBackend {
    chain_id: i64,
}

impl RpcBackend for EthRpcBackend {
    fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let resp = modules()
            .eth_rpc_module
            .raw_rpc(self.chain_id, method, &params.to_string())
            .map_err(|e| e.to_string())?;
        let v: Value = serde_json::from_str(&resp).map_err(|e| e.to_string())?;
        if v.get("ok").and_then(Value::as_bool) == Some(false) {
            return Err(v.get("error").and_then(Value::as_str).unwrap_or("eth_rpc failed").to_string());
        }
        v.get("result").cloned().ok_or_else(|| "eth_rpc: missing result".to_string())
    }
}

// ── helpers ──────────────────────────────────────────────────────────────────

/// How long one [`RailgunModule::sync_step`] keeps going before it reports,
/// when the caller names no budget.
///
/// 20 s: comfortably inside every default call timeout this module is reached
/// through (`ShellCallDriver` waits 60 s, `logoscore` 30 s), and long enough
/// that a caller driving a two-minute sync makes six calls rather than sixty.
const DEFAULT_STEP_BUDGET_MS: u64 = 20_000;

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

/// A PROGRESS REPLY: the plan's own fields ([`Plan::to_json`]) with this call's
/// `verdict` object merged over them. `sync_step`, `sync_status` and
/// `sync_cancel` all answer the same shape, so there is one place it is built.
fn plan_reply(plan: &Plan, verdict: Value) -> String {
    let mut out = plan.to_json();
    if let Some(fields) = verdict.as_object() {
        for (field, value) in fields {
            out[field] = value.clone();
        }
    }
    out.to_string()
}

/// A probe's `params_json`, where every field is optional. A `--call` with no
/// argument arrives as the empty string or as `null`, and both mean "the
/// defaults" rather than a parse error.
fn optional_params<T: Default + serde::de::DeserializeOwned>(
    params_json: &str,
) -> Result<T, serde_json::Error> {
    let trimmed = params_json.trim();
    if trimmed.is_empty() || trimmed == "null" {
        return Ok(T::default());
    }
    serde_json::from_str(trimmed)
}

/// Parse a dependency's `{ ok, ... }` JSON reply. Anything but an explicit
/// `ok: true` is an Err: a reply this module cannot read is a failure, not a
/// success with missing fields.
fn ok_value(s: String) -> Result<Value, String> {
    let v: Value = serde_json::from_str(&s).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err(v.get("error").and_then(Value::as_str).unwrap_or("dependency error").to_string());
    }
    Ok(v)
}

/// Drive an async engine op on a per-call current-thread runtime (on this
/// dispatch thread, so the engine's outbound `modules()` IPC has the event loop).
fn block_on<F: Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build current-thread runtime")
        .block_on(f)
}

#[derive(Deserialize)]
struct InitParams {
    #[serde(rename = "chainId")]
    chain_id: u64,
    #[serde(rename = "spendingKey")]
    spending_key: String,
    #[serde(rename = "viewingKey")]
    viewing_key: String,
    #[serde(default)]
    poi: bool,
}

#[derive(Deserialize)]
struct InitFromSeedParams {
    #[serde(rename = "chainId")]
    chain_id: u64,
    /// An opaque seed (hex) — a deterministic EOA signature from keystore.
    seed: String,
    #[serde(default)]
    poi: bool,
}

// Amounts are decimal strings (u128 wei exceeds JSON's safe-integer range).
#[derive(Deserialize)]
struct ShieldParams {
    asset: String,
    amount: String,
}
#[derive(Deserialize)]
struct TransferParams {
    to: String,
    asset: String,
    amount: String,
    #[serde(default)]
    memo: String,
}
#[derive(Deserialize)]
struct UnshieldParams {
    to: String,
    asset: String,
    amount: String,
}
#[derive(Deserialize)]
struct RelayedSendParams {
    to: String,
    asset: String,
    amount: String,
    #[serde(default)]
    memo: String,
    owner: String,
    #[serde(rename = "bundlerUrl")]
    bundler_url: String,
}

fn parse_amount(s: &str) -> Result<u128, String> {
    s.parse::<u128>().map_err(|e| format!("bad amount {s:?}: {e}"))
}

impl RailgunModule for RailgunModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        self.persist_dir = Some(PathBuf::from(&ctx.instance_persistence_path));
    }

    fn init(&mut self, params_json: String) -> String {
        let p: InitParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(format!("bad init params: {e}")),
        };
        let dir = match &self.persist_dir {
            Some(d) => d.join(format!("chain-{}", p.chain_id)),
            None => return err("railgun_module not initialized (context not ready)"),
        };
        let backend = Arc::new(EthRpcBackend { chain_id: p.chain_id as i64 });

        match block_on(RailgunEngine::init(
            p.chain_id,
            backend,
            &p.spending_key,
            &p.viewing_key,
            &dir,
            p.poi,
        )) {
            Ok(engine) => {
                let addr = engine.zk_address();
                self.engine = Some(engine);
                json!({ "ok": true, "address": addr }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn init_from_seed(&mut self, params_json: String) -> String {
        let p: InitFromSeedParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(format!("bad init-from-seed params: {e}")),
        };
        let seed = match hex::decode(p.seed.trim_start_matches("0x")) {
            Ok(b) => b,
            Err(e) => return err(format!("bad seed hex: {e}")),
        };
        let dir = match &self.persist_dir {
            Some(d) => d.join(format!("chain-{}", p.chain_id)),
            None => return err("railgun_module not initialized (context not ready)"),
        };
        let backend = Arc::new(EthRpcBackend { chain_id: p.chain_id as i64 });
        match block_on(RailgunEngine::init_from_seed(p.chain_id, backend, &seed, &dir, p.poi)) {
            Ok(engine) => {
                let addr = engine.zk_address();
                self.engine = Some(engine);
                json!({ "ok": true, "address": addr }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn get_zk_address(&mut self) -> String {
        match &self.engine {
            Some(e) => json!({ "ok": true, "address": e.zk_address() }).to_string(),
            None => err("railgun_module not initialized (call init first)"),
        }
    }

    fn sync(&mut self) -> String {
        match self.engine.as_mut() {
            Some(e) => match block_on(e.sync()) {
                Ok(()) => json!({ "ok": true }).to_string(),
                Err(e) => err(e),
            },
            None => err("railgun_module not initialized (call init first)"),
        }
    }

    fn sync_step(&mut self, params_json: String) -> String {
        #[derive(Debug, Default, Deserialize)]
        #[serde(rename_all = "camelCase", default)]
        struct StepParams {
            blocks: Option<u64>,
            budget_ms: Option<u64>,
        }

        let p: StepParams = match optional_params(&params_json) {
            Ok(p) => p,
            Err(e) => return err(format!("bad params: {e}")),
        };
        let window = p.blocks.unwrap_or(sync::DEFAULT_WINDOW_BLOCKS);
        let budget_ms = u128::from(p.budget_ms.unwrap_or(DEFAULT_STEP_BUDGET_MS));

        // Both fields of `self`, taken apart so the plan can be held across the
        // engine's awaits.
        let Some(engine) = self.engine.as_mut() else {
            return err("railgun_module not initialized (call init first)");
        };
        let slot = &mut self.sync_plan;

        block_on(async move {
            if slot.is_none() {
                let synced = engine.synced_block().await;
                let target = match engine.latest_block().await {
                    Ok(t) => t,
                    Err(e) => return err(e),
                };
                // The subsquid half in one window; only the `eth_getLogs`
                // tail after it is stepped. Without this a cold sync is 469
                // windows and 195 s where one call is ~8 s -- measured on an
                // iPad Air 13-inch simulator, which is how it was found.
                let mut plan = Plan::new(synced, target);
                if let Some(frontier) = engine.subsquid_frontier().await {
                    plan = plan.with_fast_forward(frontier);
                }
                *slot = Some(plan);
            }
            let plan = slot.as_mut().expect("just filled");

            let step = Instant::now();
            // AS MANY WINDOWS AS THE BUDGET BUYS, and at least one: a step that
            // returned having done nothing would make a caller's loop spin.
            loop {
                let Some(end) = plan.next_window_end(window) else { break };
                let before = plan.synced_block;
                let (result, ms) = sync::timed(engine.sync_to(end)).await;
                if let Err(e) = result {
                    let step_ms = step.elapsed().as_millis();
                    return plan_reply(plan, json!({ "ok": false, "error": e, "stepMs": step_ms }));
                }
                // WHAT THE ENGINE REACHED, read back from its own record rather
                // than assumed to be the window end: the indexer clamps to its
                // syncer's latest block, so a chain that has not produced the
                // blocks we asked for gives less than we asked for.
                plan.record(engine.synced_block().await, ms);
                sync::report(plan);
                if plan.synced_block <= before {
                    // Nothing moved. Report it rather than looping on it — an
                    // engine that cannot pass this block will not pass it on the
                    // next turn either, and a spin is worse than a stall.
                    let step_ms = step.elapsed().as_millis();
                    return plan_reply(plan, json!({ "ok": true, "stalled": true, "stepMs": step_ms }));
                }
                if step.elapsed().as_millis() >= budget_ms {
                    break;
                }
            }

            let step_ms = step.elapsed().as_millis();
            plan_reply(plan, json!({ "ok": true, "stepMs": step_ms }))
        })
    }

    fn sync_status(&mut self) -> String {
        if let Some(plan) = self.sync_plan.as_ref() {
            return plan_reply(plan, json!({ "ok": true, "running": true }));
        }
        let Some(engine) = self.engine.as_mut() else {
            return err("railgun_module not initialized (call init first)");
        };
        block_on(async {
            let synced = engine.synced_block().await;
            let target = match engine.latest_block().await {
                Ok(t) => t,
                Err(e) => return err(e),
            };
            // A plan that was never started, so the caller sees the same shape
            // and the same fields whether one is running or not. No frontier
            // query here: `sync_status` costs one `eth_blockNumber` and nothing
            // else, which is what makes it safe to ask often.
            plan_reply(&Plan::new(synced, target), json!({ "ok": true, "running": false }))
        })
    }

    fn sync_cancel(&mut self) -> String {
        match self.sync_plan.take() {
            Some(plan) => plan_reply(
                &plan,
                json!({ "ok": true, "cancelled": true, "keptToBlock": plan.synced_block }),
            ),
            None => json!({ "ok": true, "cancelled": false }).to_string(),
        }
    }

    fn get_shielded_balance(&mut self) -> String {
        match self.engine.as_mut() {
            Some(e) => match block_on(e.shielded_balance_json()) {
                Ok(j) => json!({
                    "ok": true,
                    "balances": serde_json::from_str::<Value>(&j).unwrap_or(Value::Null)
                })
                .to_string(),
                Err(e) => err(e),
            },
            None => err("railgun_module not initialized (call init first)"),
        }
    }

    fn prepare_shield(&mut self, params_json: String) -> String {
        let p: ShieldParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(format!("bad shield params: {e}")),
        };
        let amount = match parse_amount(&p.amount) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match self.engine.as_ref() {
            Some(e) => match block_on(e.prepare_shield(&p.asset, amount)) {
                Ok(txs) => json!({
                    "ok": true,
                    "txs": serde_json::from_str::<Value>(&txs).unwrap_or(Value::Null)
                })
                .to_string(),
                Err(e) => err(e),
            },
            None => err("railgun_module not initialized (call init first)"),
        }
    }

    fn prepare_transfer(&mut self, params_json: String) -> String {
        let p: TransferParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(format!("bad transfer params: {e}")),
        };
        let amount = match parse_amount(&p.amount) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match self.engine.as_mut() {
            Some(e) => match block_on(e.prepare_transfer(&p.to, &p.asset, amount, &p.memo)) {
                Ok(tx) => json!({ "ok": true, "tx": serde_json::from_str::<Value>(&tx).unwrap_or(Value::Null) }).to_string(),
                Err(e) => err(e),
            },
            None => err("railgun_module not initialized (call init first)"),
        }
    }

    fn prepare_unshield(&mut self, params_json: String) -> String {
        let p: UnshieldParams = match serde_json::from_str(&params_json) {
            Ok(p) => p,
            Err(e) => return err(format!("bad unshield params: {e}")),
        };
        let amount = match parse_amount(&p.amount) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        match self.engine.as_mut() {
            Some(e) => match block_on(e.prepare_unshield(&p.to, &p.asset, amount)) {
                Ok(tx) => json!({ "ok": true, "tx": serde_json::from_str::<Value>(&tx).unwrap_or(Value::Null) }).to_string(),
                Err(e) => err(e),
            },
            None => err("railgun_module not initialized (call init first)"),
        }
    }

    fn relayed_send(&mut self, params_json: String) -> String {
        match self.request_relayed_send(params_json) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn relayed_send_status(&mut self, request_id: String) -> String {
        match self.drive_relayed_send(&request_id) {
            Ok(v) => v.to_string(),
            Err(e) => err(e),
        }
    }

    fn relayed_send_cancel(&mut self, request_id: String) -> String {
        match self.jobs.remove(&request_id) {
            Some(job) => {
                // Best effort: the job is dropped here either way, and an offer
                // the keystore never hears about is swept on its own.
                let _ = modules().keystore_module.cancel_approval(&request_id, &job.receipt);
                json!({ "ok": true }).to_string()
            }
            None => err("unknown request"),
        }
    }

    fn witness_engine_probe(&mut self) -> String {
        fn probe_json(p: &witness_engine::Probe) -> Value {
            json!({
                "ok": p.ok(),
                "requested": p.requested,
                "backend": p.backend,
                "reached": p.reached,
                "answer": p.answer,
                "error": p.error,
            })
        }
        let all = witness_engine::probe_all();
        // The engine's own backend is probed LAST and is the headline: `ok`
        // answers "can THIS device prove", not "can some backend here run
        // wasm". The rest are the way out, measured beside it.
        let Some((engine, alternatives)) = all.split_last() else {
            return err("no wasm backend is compiled into this module");
        };
        let mut reply = probe_json(engine);
        reply["alternatives"] = Value::Array(alternatives.iter().map(probe_json).collect());
        reply.to_string()
    }

    fn witness_circuit_probe(&mut self, params_json: String) -> String {
        #[derive(Deserialize, Default)]
        struct Params {
            #[serde(default)]
            circuit: Option<String>,
            #[serde(default)]
            backends: Option<Vec<String>>,
        }
        let params: Params = match optional_params(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let circuit = params
            .circuit
            .unwrap_or_else(|| witness_circuit::DEFAULT_CIRCUIT.to_string());

        // Named backends are resolved against what is actually IN this image,
        // so asking for one that is not (`wasmi` on Android, #202) is an error
        // naming the ones there are rather than a silently shorter run.
        let backends = match params.backends {
            None => witness_engine::PROBE_ORDER.to_vec(),
            Some(names) => match witness_engine::backends_named(&names) {
                Ok(picked) => picked,
                Err(e) => return err(e),
            },
        };

        let started = Instant::now();
        let (url, wasm) = match block_on(witness_circuit::fetch_wasm(&circuit)) {
            Ok(v) => v,
            Err(e) => return err(e),
        };
        let download_ms = started.elapsed().as_millis();
        let run = witness_circuit::run(&circuit, &backends, &wasm, url, download_ms);

        let probes: Vec<Value> = run
            .probes
            .iter()
            .map(|p| {
                json!({
                    "ok": p.ok(),
                    "requested": p.requested,
                    "backend": p.backend,
                    "reached": p.reached,
                    "compileMs": p.compile_ms,
                    "instantiateMs": p.instantiate_ms,
                    "witnessMs": p.witness_ms,
                    "witnessLen": p.witness_len,
                    "witnessNonzero": p.witness_nonzero,
                    "signals": p.signals.iter().map(|s| json!({
                        "name": s.name,
                        "expected": s.expected,
                        "declared": s.declared,
                        "ok": s.ok(),
                    })).collect::<Vec<Value>>(),
                    "error": p.error,
                })
            })
            .collect();

        json!({
            "ok": run.error.is_none() && !run.probes.is_empty()
                && run.probes.iter().all(witness_circuit::Probe::ok),
            "circuit": run.circuit,
            "artifactUrl": run.artifact_url,
            "downloadMs": run.download_ms,
            "wasmBytes": run.wasm_bytes,
            "sanityCheck": witness_circuit::SANITY_CHECK,
            "probes": probes,
            "error": run.error,
        })
        .to_string()
    }

    fn proof_circuit_probe(&mut self, params_json: String) -> String {
        #[derive(Deserialize, Default)]
        struct Params {
            #[serde(default)]
            circuit: Option<String>,
        }
        let params: Params = match optional_params(&params_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        let circuit = params
            .circuit
            .unwrap_or_else(|| witness_circuit::DEFAULT_CIRCUIT.to_string());

        let run = block_on(proof_circuit::run(&circuit));
        json!({
            "ok": run.ok(),
            "circuit": run.circuit,
            "backend": run.backend,
            "engineSeam": run.engine_seam,
            "witnessSource": run.witness_source,
            "witnessLen": run.witness_len,
            "numInstanceVariables": run.num_instance_variables,
            "numWitnessVariables": run.num_witness_variables,
            "numConstraints": run.num_constraints,
            "verified": run.verified,
            "totalMs": run.total_ms,
            "legs": run.legs.iter().map(|l| json!({
                "name": l.name,
                "ms": l.ms,
                "bytes": l.bytes,
                "ok": l.ok(),
                "error": l.error,
            })).collect::<Vec<Value>>(),
            "error": run.error,
        })
        .to_string()
    }

    fn private_send_probe(&mut self, params_json: String) -> String {
        /// Every field is optional and overrides the matching
        /// [`private_send::Params`] default.
        #[derive(Deserialize, Default)]
        struct Requested {
            #[serde(rename = "chainId", default)]
            chain_id: Option<u64>,
            #[serde(default)]
            asset: Option<String>,
            /// Decimal strings: u128 wei exceeds JSON's safe-integer range.
            #[serde(default)]
            shield: Option<String>,
            #[serde(default)]
            transfer: Option<String>,
            #[serde(default)]
            memo: Option<String>,
            #[serde(default)]
            repeat: Option<bool>,
        }
        let requested: Requested = match optional_params(&params_json) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let mut params = private_send::Params::default();
        if let Some(c) = requested.chain_id {
            params.chain_id = c;
        }
        if let Some(a) = &requested.asset {
            match Address::from_str(a) {
                Ok(a) => params.asset = Some(a),
                Err(e) => return err(format!("bad asset address {a:?}: {e}")),
            }
        }
        if let Some(v) = &requested.shield {
            match parse_amount(v) {
                Ok(v) => params.shield = v,
                Err(e) => return err(e),
            }
        }
        if let Some(v) = &requested.transfer {
            match parse_amount(v) {
                Ok(v) => params.transfer = v,
                Err(e) => return err(e),
            }
        }
        if let Some(m) = requested.memo {
            params.memo = m;
        }
        if let Some(r) = requested.repeat {
            params.repeat = r;
        }

        let backend = Arc::new(EthRpcBackend { chain_id: params.chain_id as i64 });
        let eip1193: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(backend));
        let run = block_on(private_send::run(eip1193, params));
        json!({
            "ok": run.ok(),
            "engineSeam": run.engine_seam,
            "chainId": run.chain_id,
            "asset": run.asset,
            "from": run.from,
            "to": run.to,
            // Decimal string for the same reason the params are.
            "balance": run.balance.map(|b| b.to_string()),
            "circuit": run.circuit,
            "rootOnChain": run.root_on_chain,
            "calldataBytes": run.calldata_bytes,
            "totalMs": run.total_ms,
            "legs": run.legs.iter().map(|l| json!({
                "name": l.name,
                "ms": l.ms,
                "ok": l.ok(),
                "error": l.error,
            })).collect::<Vec<Value>>(),
            "error": run.error,
        })
        .to_string()
    }

    fn live_send_probe(&mut self, params_json: String) -> String {
        /// Every field is optional and overrides the matching
        /// [`live_send::Params`] default. `chainId` is deliberately NOT here:
        /// the probe's key is public, so the chain is a property of the probe
        /// rather than a choice its caller makes.
        #[derive(Deserialize, Default)]
        struct Requested {
            #[serde(default)]
            asset: Option<String>,
            /// Decimal strings: a u128 amount exceeds JSON's safe-integer range.
            #[serde(default)]
            shield: Option<String>,
            #[serde(default)]
            transfer: Option<String>,
            #[serde(default)]
            memo: Option<String>,
            #[serde(default)]
            broadcast: Option<bool>,
            #[serde(rename = "confirmMs", default)]
            confirm_ms: Option<u64>,
        }
        let requested: Requested = match optional_params(&params_json) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        let mut params = live_send::Params::default();
        if let Some(a) = &requested.asset {
            match Address::from_str(a) {
                Ok(a) => params.asset = Some(a),
                Err(e) => return err(format!("bad asset address {a:?}: {e}")),
            }
        }
        if let Some(v) = &requested.shield {
            match parse_amount(v) {
                Ok(v) => params.shield = Some(v),
                Err(e) => return err(e),
            }
        }
        if let Some(v) = &requested.transfer {
            match parse_amount(v) {
                Ok(v) => params.transfer = Some(v),
                Err(e) => return err(e),
            }
        }
        if let Some(m) = requested.memo {
            params.memo = m;
        }
        if let Some(b) = requested.broadcast {
            params.broadcast = b;
        }
        if let Some(ms) = requested.confirm_ms {
            params.confirm_ms = ms;
        }

        let backend = Arc::new(EthRpcBackend { chain_id: params.chain_id as i64 });
        let run = block_on(live_send::run(backend, params));
        json!({
            "ok": run.ok(),
            "chainId": run.chain_id,
            // WHOSE chain answered, and whether it was a local fork. A fork of
            // Sepolia agrees with Sepolia about the chain id, the contracts,
            // the tree and `rootOnChain`, so without these two fields a run on
            // a desk is indistinguishable from a run on the public chain.
            "node": run.node,
            "forked": run.forked,
            // The backend the ENGINE proved on, which it announces only on
            // stderr — see `live_send::Run::witness_backend`.
            "witnessBackend": run.witness_backend(),
            "eoa": run.eoa,
            // Decimal strings for the same reason the params are.
            "ethWei": run.eth_wei.map(|v| v.to_string()),
            "tokenUnits": run.token_units.map(|v| v.to_string()),
            "needsFunding": run.needs_funding,
            "asset": run.asset,
            "wrappedWei": run.wrapped_wei.map(|v| v.to_string()),
            "wrapTx": run.wrap_tx,
            "from": run.from,
            "to": run.to,
            "approveTx": run.approve_tx,
            "shieldTx": run.shield_tx,
            "shieldBlock": run.shield_block,
            // Where the sync started and where it was going: the `sync` leg's
            // milliseconds mean nothing without them (#235).
            "syncFromBlock": run.sync_from_block,
            "syncToBlock": run.sync_to_block,
            "balance": run.balance.map(|v| v.to_string()),
            "transferred": run.transferred.map(|v| v.to_string()),
            "circuit": run.circuit,
            "rootOnChain": run.root_on_chain,
            // The root the ENGINE synced to and what the contract said about
            // it — the check upstream makes and discards. Needs no money, so an
            // unfunded survey carries it too.
            "syncedTree": run.synced_tree,
            "syncedRoot": run.synced_root,
            "syncedRootOnChain": run.synced_root_on_chain,
            "calldataBytes": run.calldata_bytes,
            "transferTx": run.transfer_tx,
            "transferBlock": run.transfer_block,
            "totalMs": run.total_ms,
            "legs": run.legs.iter().map(|l| json!({
                "name": l.name,
                "ms": l.ms,
                "ok": l.ok(),
                "error": l.error,
            })).collect::<Vec<Value>>(),
            "error": run.error,
        })
        .to_string()
    }

    fn web_dependency_probe(&mut self) -> String {
        let p = web_dependency::probe(&mut BusDependency::new(), LOAD_THREAD.get().cloned());
        json!({
            "ok": p.ok(),
            "target": p.target,
            "dispatchThread": p.dispatch_thread,
            "loadThread": p.load_thread,
            "dispatchLeftTheLoadThread": p.dispatch_left_the_load_thread(),
            "callerKind": p.saw_kind,
            "callerIdentity": p.saw_identity,
            "callerIsThisModule": p.identity_is_this_module(),
            "legs": p.legs.iter().map(|l: &Leg| json!({
                "method": l.method,
                "ms": l.ms,
                "ok": l.ok(),
                "reply": l.reply,
                "error": l.error,
            })).collect::<Vec<Value>>(),
        })
        .to_string()
    }
}

/// The dependency, reached over the module bus.
///
/// A raw `PluginProxy` rather than `modules().keystore_module`, and the two are
/// the same call: a LIDL-generated wrapper for a `String`-returning method IS
/// `proxy.call_json(method, [])` with the answer unwrapped. It is the proxy so
/// that the probe still asks its question against a `keystore_module` pin whose
/// generated contract predates `caller_identity` — which this crate's own
/// flake.lock is. [`crate::web_dependency`] has the rest of the reasoning.
struct BusDependency(logos_rust_sdk::PluginProxy);

impl BusDependency {
    fn new() -> Self {
        Self(logos_rust_sdk::LogosModuleSDK::new().plugin(web_dependency::TARGET))
    }

    /// One no-argument call. The reply is a `String` on the contract, so the
    /// transport hands back a JSON string; anything else is forwarded verbatim
    /// rather than discarded, so an unexpected shape is reported and not hidden.
    fn call(&self, method: &str) -> Result<String, String> {
        let value = self
            .0
            .call_json(method, &Value::Array(vec![]))
            .map_err(|e| e.to_string())?;
        Ok(match value.as_str() {
            Some(text) => text.to_string(),
            None => value.to_string(),
        })
    }
}

impl Dependency for BusDependency {
    fn caller_identity(&mut self) -> Result<String, String> {
        self.call("caller_identity")
    }
    fn list_accounts(&mut self) -> Result<String, String> {
        self.call("list_accounts")
    }
}

impl RailgunModuleImpl {
    /// Prepare the relayed send and lodge the approval request. Returns as soon
    /// as the keystore has the request — NOT when a human has answered it.
    fn request_relayed_send(&mut self, params_json: String) -> Result<Value, String> {
        let p: RelayedSendParams =
            serde_json::from_str(&params_json).map_err(|e| format!("bad relayed-send params: {e}"))?;
        let amount = parse_amount(&p.amount)?;
        let owner = Address::from_str(&p.owner).map_err(|e| format!("bad owner address: {e}"))?;
        let engine = self.engine.as_mut().ok_or("railgun_module not initialized (call init first)")?;
        let chain_id = engine.chain_id();

        // 1) Prepare the unsigned 7702 UserOperation (iterates against the bundler).
        let signable = block_on(engine.prepare_relayed_userop(
            &p.to,
            &p.asset,
            amount,
            &p.memo,
            &p.owner,
            &p.bundler_url,
        ))?;

        // 2) Take the digests it needs signed, and put THOSE in front of a human.
        //    `to` and `asset` can go in the purpose because the prepare above
        //    already parsed both as addresses; the memo cannot, it is arbitrary
        //    caller text and the keystore refuses text it cannot render safely.
        let digests = block_on(relay::capture_digests(&signable, owner, chain_id))?;
        let purpose = format!(
            "RAILGUN relayed private send: {amount} of {} to {}",
            p.asset.trim(),
            p.to.trim()
        );
        let intent = relay::relay_intent(&p.owner, &purpose, &digests)?;

        // 3) Ask. The keystore answers immediately with the handle to poll.
        let resp = ok_value(
            modules().keystore_module.request_approval(&intent).map_err(|e| e.to_string())?,
        )?;
        let handle = resp["handle"].as_str().ok_or("keystore: no handle")?.to_string();
        let receipt = resp["receipt"].as_str().ok_or("keystore: no receipt")?.to_string();

        self.jobs.insert(
            handle.clone(),
            PendingRelay {
                receipt,
                chain_id,
                bundler_url: p.bundler_url,
                signable,
                digests,
                owner,
            },
        );
        Ok(json!({ "ok": true, "pending": true, "requestId": handle }))
    }

    /// Drive a parked relayed send: poll the decision, and on approval put the
    /// signatures back into the operation and submit it. Safe to call
    /// repeatedly — `fetch_result` is idempotent until it is acknowledged.
    fn drive_relayed_send(&mut self, request_id: &str) -> Result<Value, String> {
        let receipt = self.jobs.get(request_id).ok_or("unknown request")?.receipt.clone();

        let st = ok_value(
            modules()
                .keystore_module
                .approval_status(request_id, &receipt)
                .map_err(|e| e.to_string())?,
        )?;
        match st["state"].as_str().unwrap_or("") {
            "offered" | "rendered" => return Ok(json!({ "ok": true, "state": "awaiting_approval" })),
            "settled" => {}
            other => return Err(format!("unexpected approval state {other:?}")),
        }
        if st["reason"].as_str() != Some("approved") {
            let reason = st["reason"].as_str().unwrap_or("settled").to_string();
            self.jobs.remove(request_id);
            return Ok(json!({ "ok": true, "state": "declined", "reason": reason }));
        }

        // Approved. Collect the signatures: `fetch_result` answers with them
        // under `signed`.
        let fetched = ok_value(
            modules().keystore_module.fetch_result(request_id, &receipt).map_err(|e| e.to_string())?,
        )?;
        let sigs: Vec<String> = fetched["signed"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();

        let job = self.jobs.remove(request_id).ok_or("unknown request")?;
        let signed = block_on(relay::apply_signatures(
            &job.signable,
            job.owner,
            job.chain_id,
            &job.digests,
            &sigs,
        ))?;

        // Submit to the bundler through eth_rpc (proxied) — params are the
        // `eth_sendUserOperation` tuple `[userOp, entryPoint]`.
        let params = serde_json::to_string(&(&signed.user_op, &signed.entry_point))
            .map_err(|e| format!("encode userop: {e}"))?;
        let resp = ok_value(
            modules()
                .eth_rpc_module
                .raw_rpc_url(job.chain_id as i64, &job.bundler_url, "eth_sendUserOperation", &params)
                .map_err(|e| format!("bundler submit: {e}"))?,
        )?;

        // The signatures are spent; let the keystore wipe its copy.
        let _ = modules().keystore_module.ack_result(request_id, &receipt);
        Ok(json!({
            "ok": true,
            "state": "done",
            "userOpHash": resp.get("result").cloned().unwrap_or(Value::Null),
        }))
    }
}

/// The thread this image was LOADED on, recorded once by the host's own load
/// call. The host loads an in-process module on the thread it delivers calls
/// on, and `BareModuleGlue` then dispatches on a worker of its own — so this
/// is the other end of the comparison `web_dependency_probe` reports, and the
/// only way to take it is from inside the load. See [`crate::web_dependency`].
static LOAD_THREAD: std::sync::OnceLock<String> = std::sync::OnceLock::new();

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    let _ = LOAD_THREAD.set(web_dependency::thread_id());
    install::<RailgunModuleImpl>();
}
