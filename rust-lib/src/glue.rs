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

use alloy::primitives::{Address, B256};
use serde::Deserialize;
use serde_json::{json, Value};
use userop_kit::signable_user_operation::SignableUserOperation;

use crate::engine::RailgunEngine;
use crate::relay;
use crate::rpc_backend::RpcBackend;

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
    fn sync(&mut self) -> String;
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

    fn on_context_ready(&mut self, _ctx: &RustModuleContext) {}
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

#[derive(Default)]
struct RailgunModuleImpl {
    persist_dir: Option<PathBuf>,
    engine: Option<RailgunEngine>,
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
    chain_id: i64,
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

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

/// Parse a dependency's `{ ok, ... }` JSON reply, surfacing `{ok:false}` as Err.
fn ok_value(s: String) -> Result<Value, String> {
    let v: Value = serde_json::from_str(&s).map_err(|e| e.to_string())?;
    if v.get("ok").and_then(Value::as_bool) == Some(false) {
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
            // Best effort: the job is dropped here either way, and an offer the
            // keystore never hears about is swept on its own.
            Some(job) => {
                let _ = modules().keystore_module.cancel_approval(&request_id, &job.receipt);
                json!({ "ok": true }).to_string()
            }
            None => err("unknown request"),
        }
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
        let chain_id = engine.chain_id() as i64;

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
        let digests = block_on(relay::capture_digests(&signable, owner, chain_id as u64))?;
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

        // Approved. Collect the signatures — `signed`, which is what
        // `fetch_result` answers.
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
            job.chain_id as u64,
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
                .raw_rpc_url(job.chain_id, &job.bundler_url, "eth_sendUserOperation", &params)
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

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<RailgunModuleImpl>();
}
