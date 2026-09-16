//! THE PRIVATE SEND THE CHAIN ITSELF WITNESSED — #213's remaining clause.
//!
//! ## What was still missing after the second #213 cycle
//!
//! [`crate::private_send`] runs the engine's WHOLE private-send path on a device
//! — note decryption, merkle proof, EdDSA signature, output-note encryption, the
//! engine's own `calculate_witness`, `Groth16Prover::prove` AND verify — and it
//! measured 1.28 s of compute on the venue's iPad Air 4. One thing in it is not
//! real: the chain event. It injects a single `Shield` through the engine's
//! public `RailgunBuilder::with_utxo_syncer` seam, so the note it spends is in
//! the ENGINE's tree and not in the CONTRACT's, and it says so rather than
//! hiding it — `rootOnChain: false`.
//!
//! This module removes that last substitution. Nothing here is fabricated:
//!
//! ```text
//!   funding   how much ETH and ERC-20 the probe's own EOA holds, read off chain
//!   engine    RailgunBuilder over the DEFAULT syncer (subsquid, then RPC) --
//!             i.e. the real Sepolia tree, not a syncer we wrote
//!   approve   ERC-20 approve(RailgunSmartWallet, amount), SIGNED AND BROADCAST
//!   shield    the ENGINE's own ShieldBuilder calldata, SIGNED AND BROADCAST,
//!             waited on until a block carries it
//!   sync      the engine syncs to tip and finds ITS OWN note in the contract's
//!             tree, beside every other shield anyone ever made on this chain
//!   balance   a shielded balance that a transaction put there
//!   transfer  TransactionBuilder -> circuit inputs -> calculate_witness ->
//!             Groth16Prover::prove and verify, over the CONTRACT's merkle root
//!   root      RailgunSmartWallet.rootHistory(tree, root) -- expected TRUE here,
//!             which is the boolean #213 clause 1 is about
//!   broadcast the proved `transact(...)` calldata, sent and mined: the chain
//!             VERIFIES the Groth16 proof this device produced, or reverts
//! ```
//!
//! ## Why it has its own EOA, and why that EOA's key is PUBLIC
//!
//! A shield is an ordinary transaction and needs an ordinary signature. The
//! venue's wallet account (`0x493A73e8…`) cannot give one to an agent:
//! `keystore_module` signs only through `request_approval` → a human
//! `approve(handle, bundle_id, password)`, which is Tier A AND takes the vault
//! password. That is the gate working as designed, and two #213 cycles stopped
//! there.
//!
//! So this probe holds its own key, derived from a seed spelled out in this file:
//!
//! ```text
//!   secp256k1 secret = keccak256(PROBE_EOA_SEED)
//! ```
//!
//! **Anyone reading this source can spend that account.** That is deliberate and
//! it is the whole safety argument: it is a measurement fixture, not a wallet, so
//! it must never be able to hold anything worth taking. Two guards keep it that
//! way — [`run`] refuses any chain but Sepolia before it reads anything, and it
//! never touches the module's engine, the user's keys or the module's
//! persistence. Fund it with testnet dust and nothing else.
//!
//! ## What an operator has to do, once
//!
//! Send Sepolia ETH for gas and the ERC-20 to shield to the address this probe
//! prints. Until then every run stops at the `funding` leg and reports the ask,
//! which is a complete handoff rather than a failure: the address is fixed, so
//! the funding is a one-time step and every later run is unattended.

use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::AccessList;
use alloy::primitives::{keccak256, Address, Bytes, Signature, TxKind, B256, U256};
use alloy::signers::k256::ecdsa::{RecoveryId, SigningKey};
use alloy::signers::utils::secret_key_to_address;
use alloy::sol_types::SolCall;
use eip_1193_provider::provider::{Eip1193Caller, Eip1193Provider};
use railgun::account::chain::ChainId;
use railgun::account::signer::RailgunSigner;
use railgun::builder::RailgunBuilder;
use railgun::caip::AssetId;
use railgun::chain_config::ChainConfig;
use railgun::database::memory::MemoryDatabase;
use serde_json::{json, Value};

use crate::keys;
use crate::private_send::{PROBE_RECIPIENT_SEED, PROBE_SEED};
use crate::proof_circuit::Leg;
use crate::rpc_backend::{EthRpcEip1193, RpcBackend};

alloy::sol! {
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function rootHistory(uint256 treeNumber, bytes32 root) external view returns (bool);
}

/// THE PROBE'S OWN EOA. Public by construction — see the module docs — and
/// therefore usable on Sepolia and nowhere else.
pub const PROBE_EOA_SEED: &[u8] = b"logos-railgun/#213 live-send probe EOA/v1";

/// The only chain this probe will run on. Not a default: a value.
pub const SEPOLIA: u64 = 11155111;

/// Sepolia USDC — the token this module's own fixtures already name
/// (`crate::engine`'s tests, `doctests/railgun-module-runtime.test.yaml`) and
/// the one the venue's account was funded with.
pub const SEPOLIA_USDC: &str = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";

/// How much of the ERC-20 one run shields, in the token's smallest unit
/// (0.1 USDC at 6 decimals). Proof cost does not depend on the value, so this is
/// as small as it can be while still splitting into a transfer and a change note.
pub const DEFAULT_SHIELD: u128 = 100_000;

/// Gas the probe wants to see before it starts spending: a shield is ~250 k gas
/// and a `transact` ~1.5 M, so at Sepolia's usual few gwei this is generous.
pub const MIN_GAS_WEI: u128 = 5_000_000_000_000_000; // 0.005 ETH

/// The tree the root question is asked about. RAILGUN opens a new tree every
/// 65 536 commitments; Sepolia is still on its first, and the proof carries the
/// tree it was built over, so this is read from the operation rather than assumed
/// wherever the engine will tell us.
const DEFAULT_TREE: u32 = 0;

/// The probe's secp256k1 key. Deterministic, and derivable by anybody.
pub fn probe_eoa_key() -> SigningKey {
    let material = keccak256(PROBE_EOA_SEED);
    SigningKey::from_slice(material.as_slice())
        .expect("a keccak digest is a valid secp256k1 scalar with overwhelming probability")
}

/// The address an operator funds.
pub fn probe_eoa_address() -> Address {
    secret_key_to_address(&probe_eoa_key())
}

/// What a caller may vary. Every field has a default that needs no argument.
#[derive(Debug, Clone)]
pub struct Params {
    pub chain_id: u64,
    /// The ERC-20 to shield and transfer. `None` = [`SEPOLIA_USDC`].
    pub asset: Option<Address>,
    pub shield: u128,
    /// `None` = half of whatever the engine reports as shielded, which keeps the
    /// operation at one nullifier and two commitments (`01x02`) whatever the
    /// shield fee took.
    pub transfer: Option<u128>,
    pub memo: String,
    /// Broadcast the proved `transact(...)` too, and wait for it. This is the
    /// difference between "a verifier accepted this proof" (which
    /// [`crate::private_send`] already showed) and "the RAILGUN contract on
    /// Sepolia accepted it", so it is on by default.
    pub broadcast: bool,
    /// Wall budget for ONE transaction to be mined.
    pub confirm_ms: u64,
}

impl Default for Params {
    fn default() -> Self {
        Self {
            chain_id: SEPOLIA,
            asset: None,
            shield: DEFAULT_SHIELD,
            transfer: None,
            memo: "#213 live-send probe".to_string(),
            broadcast: true,
            confirm_ms: 300_000,
        }
    }
}

/// Everything one [`run`] measured.
#[derive(Debug, Clone, Default)]
pub struct Run {
    pub chain_id: u64,
    pub legs: Vec<Leg>,
    /// The EOA that pays and shields. Always reported, even by a run that stops
    /// at `funding`, because it IS the handoff.
    pub eoa: Option<String>,
    pub eth_wei: Option<u128>,
    pub token_units: Option<u128>,
    /// What an operator has to do, in one sentence, when the answer is "fund it".
    pub needs_funding: Option<String>,
    pub asset: Option<String>,
    /// The probe's `0zk` address and the counterparty's.
    pub from: Option<String>,
    pub to: Option<String>,
    pub approve_tx: Option<String>,
    pub shield_tx: Option<String>,
    pub shield_block: Option<u64>,
    /// The shielded balance AFTER a real sync of the real tree.
    pub balance: Option<u128>,
    pub transferred: Option<u128>,
    pub circuit: Option<String>,
    pub calldata_bytes: Option<usize>,
    /// `RailgunSmartWallet.rootHistory` for the root the proof was built over.
    /// TRUE is the whole point of this module.
    pub root_on_chain: Option<bool>,
    pub transfer_tx: Option<String>,
    pub transfer_block: Option<u64>,
    pub total_ms: u128,
    pub error: Option<String>,
}

impl Run {
    /// Every leg completed. A green `transfer` leg is a proof a verifier
    /// accepted (`Groth16Prover::prove` answers `InvalidProof` otherwise); a
    /// green `broadcast` leg is a proof the RAILGUN CONTRACT accepted.
    pub fn ok(&self) -> bool {
        self.error.is_none() && !self.legs.is_empty() && self.legs.iter().all(Leg::ok)
    }

    pub fn leg(&self, name: &str) -> Option<&Leg> {
        self.legs.iter().find(|l| l.name == name)
    }

    fn finished(mut self, started: Instant) -> Run {
        self.total_ms = started.elapsed().as_millis();
        report(&self);
        self
    }
}

/// Announce a stage BEFORE entering it: on a platform that kills the process
/// there is no reply to read, only the last line printed.
fn entering(what: &str) {
    eprintln!("railgun_module: live-send probe: entering {what}");
}

// ── the EOA half: read a quantity, sign a transaction, wait for a block ──────

/// A JSON-RPC quantity (`0x…`) as a `u128`.
fn quantity(v: &Value) -> Result<u128, String> {
    let s = v.as_str().ok_or_else(|| format!("expected a hex quantity, got {v}"))?;
    u128::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| format!("bad quantity {s}: {e}"))
}

/// The probe's EOA, over the same `eth_rpc_module` seam the engine reads through
/// — so a transaction this probe sends goes out the way every other call does
/// (proxied, one chain configuration, no second transport).
struct Eoa<B: RpcBackend> {
    backend: Arc<B>,
    chain_id: u64,
    key: SigningKey,
    address: Address,
}

impl<B: RpcBackend> Eoa<B> {
    fn new(backend: Arc<B>, chain_id: u64) -> Self {
        let key = probe_eoa_key();
        let address = secret_key_to_address(&key);
        Self { backend, chain_id, key, address }
    }

    fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        self.backend.rpc(method, params)
    }

    fn eth_balance(&self) -> Result<u128, String> {
        quantity(&self.rpc("eth_getBalance", json!([self.address.to_string(), "latest"]))?)
    }

    /// `eth_estimateGas` with 30 % of headroom. A revert here is the honest place
    /// to learn that a transaction would fail, so the error is propagated rather
    /// than replaced with a fixed limit that would burn the gas to find out.
    fn gas_limit(&self, to: Address, value: U256, data: &Bytes) -> Result<u64, String> {
        let tx = json!({
            "from": self.address.to_string(),
            "to": to.to_string(),
            "value": format!("0x{value:x}"),
            "data": format!("0x{}", hex::encode(data)),
        });
        let est = quantity(&self.rpc("eth_estimateGas", json!([tx]))?)?;
        Ok((est.saturating_mul(13) / 10).min(u64::MAX as u128) as u64)
    }

    /// Sign and submit. Returns the transaction hash; the caller waits for it.
    fn send(&self, to: Address, value: U256, data: Bytes, gas_limit: u64) -> Result<String, String> {
        // "pending" rather than "latest": the shield follows the approve within
        // one block often enough that a latest-nonce would replace it.
        let nonce = quantity(&self.rpc(
            "eth_getTransactionCount",
            json!([self.address.to_string(), "pending"]),
        )?)? as u64;
        let base = quantity(&self.rpc("eth_gasPrice", json!([]))?)?;
        // A tip the node suggests, where it will suggest one; 1 gwei is Sepolia's
        // usual floor and an over-tip costs testnet dust.
        let tip = self
            .rpc("eth_maxPriorityFeePerGas", json!([]))
            .ok()
            .and_then(|v| quantity(&v).ok())
            .unwrap_or(1_000_000_000);
        let tx = TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit,
            // Room for two base-fee doublings, which is what a wallet does: the
            // probe pays the base fee of the block it lands in, not this.
            max_fee_per_gas: base.saturating_mul(2).saturating_add(tip),
            max_priority_fee_per_gas: tip,
            to: TxKind::Call(to),
            value,
            access_list: AccessList::default(),
            input: data,
        };
        let (_, _, raw) = sign_1559(&self.key, tx)?;
        let sent = self.rpc(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(&raw))]),
        )?;
        sent.as_str()
            .map(str::to_string)
            .ok_or_else(|| format!("eth_sendRawTransaction answered {sent}"))
    }

    /// Poll until a receipt appears. A receipt with `status: 0x0` is an ERROR:
    /// a mined revert is the failure mode this whole probe exists to catch.
    async fn wait(&self, tx: &str, budget: Duration) -> Result<u64, String> {
        let started = Instant::now();
        loop {
            let receipt = self.rpc("eth_getTransactionReceipt", json!([tx]))?;
            if !receipt.is_null() {
                let status = receipt.get("status").and_then(Value::as_str).unwrap_or("");
                let block = receipt
                    .get("blockNumber")
                    .map(quantity)
                    .transpose()?
                    .unwrap_or_default() as u64;
                if status == "0x1" {
                    return Ok(block);
                }
                return Err(format!("{tx} reverted on chain (status {status}, block {block})"));
            }
            if started.elapsed() >= budget {
                return Err(format!(
                    "{tx} was not mined within {} s",
                    budget.as_secs()
                ));
            }
            tokio::time::sleep(Duration::from_millis(2_000)).await;
        }
    }
}

/// Sign an EIP-1559 transaction. Split out of [`Eoa::send`] so a test can assert
/// the signature recovers to the probe's own address without a chain.
fn sign_1559(key: &SigningKey, tx: TxEip1559) -> Result<(B256, Signature, Vec<u8>), String> {
    let hash = tx.signature_hash();
    let (sig, recid): (_, RecoveryId) = key
        .sign_prehash_recoverable(hash.as_slice())
        .map_err(|e| format!("sign: {e}"))?;
    let bytes = sig.to_bytes();
    let signature = Signature::new(
        U256::from_be_slice(&bytes[..32]),
        U256::from_be_slice(&bytes[32..]),
        recid.is_y_odd(),
    );
    Ok((hash, signature, tx.into_signed(signature).encoded_2718()))
}

// ── the run ─────────────────────────────────────────────────────────────────

/// THE WHOLE THING, on the real chain.
pub async fn run<B: RpcBackend>(backend: Arc<B>, p: Params) -> Run {
    let started = Instant::now();
    let mut out = Run { chain_id: p.chain_id, ..Default::default() };

    // The key in this file is public, so the chain is a gate rather than a
    // parameter — and it is checked before anything is read.
    if p.chain_id != SEPOLIA {
        out.error = Some(format!(
            "this probe runs on Sepolia ({SEPOLIA}) only -- its EOA key is derived from a seed \
             printed in the source, so it must never hold anything but testnet dust (asked for \
             chain {})",
            p.chain_id
        ));
        return out.finished(started);
    }
    let Some(chain) = ChainConfig::from_chain_id(p.chain_id) else {
        out.error = Some(format!("unsupported chain id {}", p.chain_id));
        return out.finished(started);
    };
    let smart_wallet = chain.railgun_smart_wallet;
    let token = match p.asset {
        Some(a) => a,
        None => SEPOLIA_USDC.parse().expect("the fixture token address is a literal"),
    };
    let asset = AssetId::erc20(token);
    out.asset = Some(asset.to_string());

    let eip1193: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(backend.clone()));
    let eoa = Eoa::new(backend.clone(), p.chain_id);
    out.eoa = Some(eoa.address.to_string());

    // ── the two railgun parties ────────────────────────────────────────────
    entering("keys");
    let binding = ChainId::evm(p.chain_id);
    let party = |seed: &[u8]| {
        let (spend, view) = keys::derive_keys_from_seed(seed);
        keys::make_signer(&spend, &view, binding)
    };
    let parties = party(PROBE_SEED).and_then(|s| party(PROBE_RECIPIENT_SEED).map(|r| (s, r)));
    let (signer, recipient) = match parties {
        Ok(pair) => pair,
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

    // ── can this account pay for what follows? ─────────────────────────────
    entering("funding");
    let t = Instant::now();
    let funding: Result<(u128, u128), String> = async {
        let wei = eoa.eth_balance()?;
        let units: U256 = eip1193
            .sol_call(token, balanceOfCall { owner: eoa.address })
            .await
            .map_err(|e| format!("balanceOf: {e}"))?;
        Ok((wei, u128::try_from(units).unwrap_or(u128::MAX)))
    }
    .await;
    let (wei, units) = match funding {
        Ok(v) => v,
        Err(e) => {
            out.legs.push(Leg::failed("funding", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
    };
    out.eth_wei = Some(wei);
    out.token_units = Some(units);
    if wei < MIN_GAS_WEI || units < p.shield {
        let ask = format!(
            "fund {} on Sepolia: it holds {} wei of ETH and {} units of {}, and needs at least {} \
             wei for gas and {} units to shield. That address is FIXED (it is derived from a seed \
             in rust-lib/src/live_send.rs), so this is a one-time step -- every run after it is \
             unattended.",
            eoa.address, wei, units, token, MIN_GAS_WEI, p.shield
        );
        out.needs_funding = Some(ask.clone());
        out.legs.push(Leg::failed("funding", Some(t.elapsed().as_millis()), ask));
        return out.finished(started);
    }
    out.legs.push(Leg::timed("funding", Some(t.elapsed().as_millis())));

    // ── the engine, over the REAL syncer and the real tree ─────────────────
    entering("engine");
    let t = Instant::now();
    let build = RailgunBuilder::new(chain, eip1193.clone())
        .with_database(Arc::new(MemoryDatabase::new()))
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

    // ── approve, if the smart wallet may not already move the tokens ───────
    entering("approve");
    let t = Instant::now();
    let approved: Result<Option<String>, String> = async {
        let current: U256 = eip1193
            .sol_call(token, allowanceCall { owner: eoa.address, spender: smart_wallet })
            .await
            .map_err(|e| format!("allowance: {e}"))?;
        if current >= U256::from(p.shield) {
            return Ok(None);
        }
        let data: Bytes = approveCall { spender: smart_wallet, value: U256::from(p.shield) }
            .abi_encode()
            .into();
        let gas = eoa.gas_limit(token, U256::ZERO, &data)?;
        eoa.send(token, U256::ZERO, data, gas).map(Some)
    }
    .await;
    match approved {
        Ok(Some(tx)) => {
            out.approve_tx = Some(tx.clone());
            if let Err(e) = eoa.wait(&tx, Duration::from_millis(p.confirm_ms)).await {
                out.legs.push(Leg::failed("approve", Some(t.elapsed().as_millis()), e));
                return out.finished(started);
            }
            out.legs.push(Leg::timed("approve", Some(t.elapsed().as_millis())));
        }
        // An allowance that is already enough is not a leg that did nothing: it
        // is the second run of the day, and saying so keeps the timings readable.
        Ok(None) => out.legs.push(Leg::timed("approve", Some(t.elapsed().as_millis()))),
        Err(e) => {
            out.legs.push(Leg::failed("approve", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
    }

    // ── the shield: the ENGINE's calldata, this probe's signature ──────────
    entering("shield");
    let t = Instant::now();
    let shield = provider
        .shield()
        .shield(from.clone(), asset, p.shield)
        .build(&mut rand::rng())
        .map_err(|e| format!("build shield: {e}"))
        .and_then(|txs| {
            txs.into_iter().next().ok_or_else(|| "the engine built no shield transaction".to_string())
        })
        .and_then(|tx| {
            let gas = eoa.gas_limit(tx.to, tx.value, &tx.data)?;
            eoa.send(tx.to, tx.value, tx.data, gas)
        });
    let shield_tx = match shield {
        Ok(tx) => tx,
        Err(e) => {
            out.legs.push(Leg::failed("shield", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
    };
    out.shield_tx = Some(shield_tx.clone());
    match eoa.wait(&shield_tx, Duration::from_millis(p.confirm_ms)).await {
        Ok(block) => {
            out.shield_block = Some(block);
            out.legs.push(Leg::timed("shield", Some(t.elapsed().as_millis())));
        }
        Err(e) => {
            out.legs.push(Leg::failed("shield", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
    }

    // ── the sync: the whole of Sepolia's tree, our note among it ───────────
    entering("sync");
    let t = Instant::now();
    if let Err(e) = provider.sync().await {
        out.legs.push(Leg::failed("sync", Some(t.elapsed().as_millis()), format!("sync: {e}")));
        return out.finished(started);
    }
    out.legs.push(Leg::timed("sync", Some(t.elapsed().as_millis())));

    // ── a shielded balance a transaction put there ─────────────────────────
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
    if balance == 0 {
        out.legs.push(Leg::failed(
            "balance",
            ms,
            format!(
                "the shield was mined in block {:?} and the engine still sees 0 of {asset} \
                 shielded -- it synced past its own note or could not decrypt it",
                out.shield_block
            ),
        ));
        return out.finished(started);
    }
    out.legs.push(Leg::timed("balance", ms));

    // ── the private send itself ────────────────────────────────────────────
    // RAILGUN takes a shield fee, so the note is worth slightly less than what
    // was shielded; half of what the ENGINE reports keeps a change note and so
    // keeps the operation on the 01x02 circuit the other two probes measured.
    let value = p.transfer.unwrap_or(balance / 2).min(balance);
    out.transferred = Some(value);
    entering("transfer");
    let t = Instant::now();
    let builder = provider.transact().transfer(
        signer.clone() as Arc<dyn RailgunSigner>,
        to.clone(),
        asset,
        value,
        &p.memo,
    );
    let proved = match provider.build(builder, &mut rand::rng()).await {
        Ok(proved) => {
            out.legs.push(Leg::timed("transfer", Some(t.elapsed().as_millis())));
            proved
        }
        Err(e) => {
            out.legs.push(Leg::failed(
                "transfer",
                Some(t.elapsed().as_millis()),
                format!("prove transfer: {e}"),
            ));
            return out.finished(started);
        }
    };
    let mut tree = DEFAULT_TREE;
    let mut merkleroot: Option<U256> = None;
    if let Some(op) = proved.proved_operations.first() {
        out.circuit = Some(format!(
            "{:02}x{:02}",
            op.circuit_inputs.nullifiers.len(),
            op.circuit_inputs.commitments_out.len()
        ));
        merkleroot = Some(op.circuit_inputs.merkleroot.into());
        // The tree the proof was built over, read off the operation the engine
        // produced rather than assumed: RAILGUN opens a new tree every 65 536
        // commitments, and asking `rootHistory` about the wrong one answers a
        // confident `false`. `abis` is private to the engine, so the TYPE cannot
        // be named here -- the field can.
        tree = op.transaction.boundParams.treeNumber as u32;
    }
    out.calldata_bytes = Some(proved.tx_data.data.len());

    // ── and the boolean this whole module is about ─────────────────────────
    if let Some(root) = merkleroot {
        entering("root-on-chain");
        let t = Instant::now();
        let seen = eip1193
            .sol_call(smart_wallet, rootHistoryCall { treeNumber: U256::from(tree), root: root.into() })
            .await
            .map_err(|e| format!("rootHistory: {e}"));
        match seen {
            Ok(seen) => {
                out.root_on_chain = Some(seen);
                if seen {
                    out.legs.push(Leg::timed("root-on-chain", Some(t.elapsed().as_millis())));
                } else {
                    out.legs.push(Leg::failed(
                        "root-on-chain",
                        Some(t.elapsed().as_millis()),
                        format!(
                            "the contract does not know the root this proof was built over (tree \
                             {tree}) -- the engine's tree and the chain's have diverged, so this \
                             calldata would revert"
                        ),
                    ));
                    return out.finished(started);
                }
            }
            Err(e) => {
                out.legs.push(Leg::failed("root-on-chain", Some(t.elapsed().as_millis()), e));
                return out.finished(started);
            }
        }
    }

    // ── the chain's own verdict on a proof this device produced ────────────
    if p.broadcast {
        entering("broadcast");
        let t = Instant::now();
        let sent = eoa
            .gas_limit(proved.tx_data.to, proved.tx_data.value, &proved.tx_data.data)
            .and_then(|gas| {
                eoa.send(proved.tx_data.to, proved.tx_data.value, proved.tx_data.data.clone(), gas)
            });
        match sent {
            Ok(tx) => {
                out.transfer_tx = Some(tx.clone());
                match eoa.wait(&tx, Duration::from_millis(p.confirm_ms)).await {
                    Ok(block) => {
                        out.transfer_block = Some(block);
                        out.legs.push(Leg::timed("broadcast", Some(t.elapsed().as_millis())));
                    }
                    Err(e) => {
                        out.legs.push(Leg::failed("broadcast", Some(t.elapsed().as_millis()), e));
                        return out.finished(started);
                    }
                }
            }
            Err(e) => {
                out.legs.push(Leg::failed("broadcast", Some(t.elapsed().as_millis()), e));
                return out.finished(started);
            }
        }
    }

    out.finished(started)
}

/// Print the result as it completes: on a platform that kills the process the
/// console line is the only thing that survives.
pub fn report(r: &Run) {
    let leg = |n: &str| r.leg(n).and_then(|l| l.ms);
    eprintln!(
        "railgun_module: live-send probe: {} (chain={} eoa={:?} circuit={:?} shielded={:?} \
         transferred={:?} rootOnChain={:?} shieldTx={:?} transferTx={:?} calldata={:?}B \
         funding={:?}ms engine={:?}ms approve={:?}ms shield={:?}ms sync={:?}ms balance={:?}ms \
         transfer={:?}ms broadcast={:?}ms total={}ms)",
        if r.ok() { "SENT" } else { "DID NOT" },
        r.chain_id,
        r.eoa,
        r.circuit,
        r.balance,
        r.transferred,
        r.root_on_chain,
        r.shield_tx,
        r.transfer_tx,
        r.calldata_bytes,
        leg("funding"),
        leg("engine"),
        leg("approve"),
        leg("shield"),
        leg("sync"),
        leg("balance"),
        leg("transfer"),
        leg("broadcast"),
        r.total_ms,
    );
    if let Some(ask) = &r.needs_funding {
        eprintln!("railgun_module: live-send probe: NEEDS FUNDING -- {ask}");
    }
    for l in r.legs.iter().filter(|l| !l.ok()) {
        eprintln!("railgun_module: live-send probe: {} -> {:?}", l.name, l.error);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use super::*;

    /// A chain that answers whatever the test put in it, and refuses anything
    /// else BY NAME — so a test that reaches a leg it did not intend to reach
    /// fails saying which RPC it was.
    #[derive(Default)]
    struct Canned {
        answers: Mutex<HashMap<String, Value>>,
        seen: Mutex<Vec<String>>,
    }

    impl Canned {
        fn with(pairs: &[(&str, Value)]) -> Arc<Self> {
            let c = Self::default();
            {
                let mut a = c.answers.lock().unwrap();
                for (m, v) in pairs {
                    a.insert((*m).to_string(), v.clone());
                }
            }
            Arc::new(c)
        }

        fn asked(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl RpcBackend for Canned {
        fn rpc(&self, method: &str, _params: Value) -> Result<Value, String> {
            self.seen.lock().unwrap().push(method.to_string());
            self.answers
                .lock()
                .unwrap()
                .get(method)
                .cloned()
                .ok_or_else(|| format!("the probe asked for {method}, which this test did not set"))
        }
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    /// A 32-byte word, as an `eth_call` answers one.
    fn word(n: u128) -> Value {
        json!(format!("0x{n:064x}"))
    }

    // THE ADDRESS AN OPERATOR FUNDS. It is a constant of this file, so it is
    // asserted like one: a change to the seed, to the derivation or to the curve
    // library moves the account the testnet balance sits in, and that must never
    // happen quietly.
    #[test]
    fn the_probe_eoa_is_a_fixed_address_anybody_can_rederive() {
        assert_eq!(
            probe_eoa_address().to_string(),
            "0x23cc2752F664Bf465A3631253687712b222B1722",
            "if this fails, read the new address out of the message and update BOTH this test \
             and the funding note on the issue"
        );
    }

    // The key is printed in this file, so the chain is a gate rather than a
    // parameter. Refused BEFORE any read: `asked()` being empty is the
    // assertion that matters, because a probe that reads mainnet state first
    // has already told a mainnet node that this account is interesting.
    #[test]
    fn mainnet_is_refused_before_a_single_chain_call() {
        let chain = Canned::with(&[]);
        let out = block_on(run(chain.clone(), Params { chain_id: 1, ..Default::default() }));
        assert!(out.legs.is_empty(), "it started work: {:?}", out.legs);
        assert!(out.error.unwrap_or_default().contains("Sepolia"));
        assert!(chain.asked().is_empty(), "it touched the chain: {:?}", chain.asked());
    }

    // An unfunded run is a HANDOFF, not a crash: it must name the address, say
    // what to send, and stop before it builds an engine or signs anything.
    #[test]
    fn an_unfunded_eoa_reports_the_ask_and_builds_no_engine() {
        let chain = Canned::with(&[
            ("eth_getBalance", json!("0x0")),
            ("eth_call", word(0)), // balanceOf
        ]);
        let out = block_on(run(chain.clone(), Params::default()));
        assert!(!out.ok());
        assert_eq!(out.eoa, Some(probe_eoa_address().to_string()));
        let ask = out.needs_funding.expect("an unfunded run must say what it needs");
        assert!(ask.contains(&probe_eoa_address().to_string()), "{ask}");
        assert!(ask.contains(&MIN_GAS_WEI.to_string()), "{ask}");
        assert_eq!(
            out.legs.iter().map(|l| l.name).collect::<Vec<_>>(),
            vec!["keys", "funding"],
            "it went past the funding check"
        );
        assert!(!chain.asked().iter().any(|m| m == "eth_sendRawTransaction"));
    }

    // Gas but no token is still unfunded, and the ask carries both numbers —
    // the venue has already funded one of the two halves once.
    #[test]
    fn gas_without_the_token_is_still_a_funding_ask() {
        let chain = Canned::with(&[
            ("eth_getBalance", json!(format!("0x{:x}", MIN_GAS_WEI * 2))),
            ("eth_call", word(1)), // one unit, far short of a shield
        ]);
        let out = block_on(run(chain, Params::default()));
        let ask = out.needs_funding.expect("short of tokens is short");
        assert!(ask.contains(&DEFAULT_SHIELD.to_string()), "{ask}");
        assert_eq!(out.token_units, Some(1));
    }

    // The signature is the one thing here that no chain checks for us before it
    // costs gas: a transaction recovering to another address is simply rejected,
    // and one recovering to the WRONG address is an account we did not mean to
    // spend.
    #[test]
    fn a_signed_transaction_recovers_to_the_probes_own_address() {
        use alloy::signers::k256::ecdsa::VerifyingKey;

        let tx = TxEip1559 {
            chain_id: SEPOLIA,
            nonce: 7,
            gas_limit: 21_000,
            max_fee_per_gas: 3_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            to: TxKind::Call(Address::ZERO),
            value: U256::from(1),
            access_list: AccessList::default(),
            input: Bytes::new(),
        };
        let hash = tx.signature_hash();
        let (signed_hash, signature, raw) = sign_1559(&probe_eoa_key(), tx).expect("sign");
        assert_eq!(signed_hash, hash);
        let recid = RecoveryId::from_byte(u8::from(signature.v())).expect("parity");
        let sig = alloy::signers::k256::ecdsa::Signature::from_scalars(
            signature.r().to_be_bytes::<32>(),
            signature.s().to_be_bytes::<32>(),
        )
        .expect("scalars");
        let recovered =
            VerifyingKey::recover_from_prehash(hash.as_slice(), &sig, recid).expect("recover");
        assert_eq!(
            alloy::signers::utils::public_key_to_address(&recovered),
            probe_eoa_address()
        );
        // And it goes out as a typed transaction: the 0x02 envelope byte.
        assert_eq!(raw.first(), Some(&2u8));
    }

    // A MINED REVERT IS A FAILURE. The receipt is there, the RPC call
    // succeeded and every field is present — the only thing wrong is `status`,
    // which is exactly the shape of answer a probe reports as success by
    // accident.
    #[test]
    fn a_reverted_receipt_is_not_a_confirmation() {
        let chain = Canned::with(&[(
            "eth_getTransactionReceipt",
            json!({ "status": "0x0", "blockNumber": "0x2a" }),
        )]);
        let eoa = Eoa::new(chain, SEPOLIA);
        let err = block_on(eoa.wait("0xdead", Duration::from_millis(1))).unwrap_err();
        assert!(err.contains("reverted"), "{err}");
        assert!(err.contains("42"), "the block it reverted in is worth printing: {err}");
    }

    #[test]
    fn a_receipt_that_never_arrives_gives_up_saying_so() {
        let chain = Canned::with(&[("eth_getTransactionReceipt", Value::Null)]);
        let eoa = Eoa::new(chain, SEPOLIA);
        let err = block_on(eoa.wait("0xbeef", Duration::from_millis(1))).unwrap_err();
        assert!(err.contains("not mined"), "{err}");
    }

    // ── against the real chain, for the two `#[ignore]`d tests below ────────

    /// Sepolia over plain HTTP, for a host run. The module's own transport is
    /// `eth_rpc_module`, which exists only inside a Logos runtime; this is the
    /// same JSON-RPC by the same method names, so what these tests exercise is
    /// the probe and not the bridge.
    ///
    /// One thread per request, deliberately: [`RpcBackend::rpc`] is synchronous
    /// (the module bus is), `reqwest` is not, and a `block_on` inside the test's
    /// own runtime would panic. A test may pay a thread per chain read.
    struct RealSepolia {
        url: String,
    }

    impl RealSepolia {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                url: std::env::var("LOGOS_SEPOLIA_RPC")
                    .unwrap_or_else(|_| "https://ethereum-sepolia-rpc.publicnode.com".to_string()),
            })
        }
    }

    impl RpcBackend for RealSepolia {
        fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
            let (url, body) = (
                self.url.clone(),
                json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }),
            );
            std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| e.to_string())?
                    .block_on(async move {
                        let res: Value = reqwest::Client::new()
                            .post(&url)
                            .json(&body)
                            .send()
                            .await
                            .map_err(|e| e.to_string())?
                            .json()
                            .await
                            .map_err(|e| e.to_string())?;
                        if let Some(e) = res.get("error") {
                            return Err(e.to_string());
                        }
                        Ok(res.get("result").cloned().unwrap_or(Value::Null))
                    })
            })
            .join()
            .map_err(|_| "the rpc thread panicked".to_string())?
        }
    }

    // CAN THE ENGINE SYNC THE REAL TREE AT ALL? This needs no funds and no
    // proving, and it is the leg with nothing to fall back on: the shielded
    // balance of a real note is read out of a tree the engine builds from every
    // shield anyone has ever made on this chain. If the subsquid endpoint the
    // chain config names is gone, this is where it shows.
    //
    //   cargo test --features engine_seam -- --ignored --nocapture the_engine_syncs
    #[test]
    #[ignore = "needs the network and syncs the whole Sepolia UTXO tree"]
    fn the_engine_syncs_the_real_sepolia_tree() {
        let chain = ChainConfig::sepolia();
        let eip1193: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(RealSepolia::new()));
        let (spend, view) = keys::derive_keys_from_seed(PROBE_SEED);
        let signer = keys::make_signer(&spend, &view, ChainId::evm(SEPOLIA)).expect("keys");
        let started = Instant::now();
        let out = block_on(async {
            let mut provider = RailgunBuilder::new(chain, eip1193)
                .with_database(Arc::new(MemoryDatabase::new()))
                .build()
                .await
                .expect("engine");
            provider
                .register(signer.clone() as Arc<dyn RailgunSigner>)
                .await
                .expect("register");
            let built = started.elapsed().as_millis();
            let t = Instant::now();
            provider.sync().await.expect("sync");
            let synced = t.elapsed().as_millis();
            let balance: u128 = provider
                .balance(signer.address())
                .await
                .iter()
                .map(|b| b.amount)
                .sum();
            (built, synced, balance)
        });
        // Printed rather than asserted: the balance is 0 until an operator funds
        // the EOA and a run shields, and this test is about the SYNC completing.
        eprintln!(
            "live-send: real Sepolia sync: engine={}ms sync={}ms shielded={} (probe {})",
            out.0,
            out.1,
            out.2,
            signer.address()
        );
    }

    // WOULD A REAL NODE TAKE THIS TRANSACTION? The signature is the one part of
    // the send that nothing checks until it costs gas, and `sign_1559` above can
    // only prove it recovers to the right address with the same library that
    // produced it. So ask a node: a transaction from an EMPTY account is refused
    // for **funds**, and a transaction whose signature does not recover is
    // refused for the SENDER. Getting the first error is the evidence.
    //
    //   cargo test --features engine_seam -- --ignored --nocapture a_real_node
    #[test]
    #[ignore = "needs the network; asks a real Sepolia node to reject a signed transaction"]
    fn a_real_node_refuses_the_probes_transaction_for_funds_not_for_its_sender() {
        let eoa = Eoa::new(RealSepolia::new(), SEPOLIA);
        // Once the EOA is funded this would really send, so it does not run
        // there: the question is only interesting while the account is empty.
        let wei = eoa.eth_balance().expect("balance");
        if wei > 0 {
            eprintln!("live-send: {} holds {wei} wei -- skipped, this test spends", eoa.address);
            return;
        }
        // 1 wei to itself: correct in every respect except the balance behind it.
        let err = eoa
            .send(eoa.address, U256::from(1), Bytes::new(), 21_000)
            .expect_err("an empty account cannot pay for a transaction");
        eprintln!("live-send: a real Sepolia node answered: {err}");
        let said = err.to_lowercase();
        assert!(said.contains("funds") || said.contains("balance"), "{err}");
        assert!(
            !said.contains("sender") && !said.contains("signature"),
            "the node did not recover the sender from our signature: {err}"
        );
    }

    // THE WHOLE THING, ON CHAIN. `#[ignore]` because it spends testnet money and
    // waits on blocks — not because it is optional: it is #213's acceptance
    // clause 1, and a green run here is a shield mined, a proof the contract
    // verified, and `rootOnChain: true`.
    //
    //   cargo test --features engine_seam -- --ignored --nocapture the_whole_send
    #[test]
    #[ignore = "spends Sepolia testnet funds and waits for blocks"]
    fn the_whole_send_lands_on_chain() {
        let out = block_on(run(RealSepolia::new(), Params::default()));
        assert!(out.ok(), "{:?}", out.needs_funding.clone().unwrap_or(format!("{out:?}")));
        assert_eq!(out.circuit.as_deref(), Some("01x02"));
        // The boolean this module exists for.
        assert_eq!(out.root_on_chain, Some(true));
        // And the chain's own verdict on the proof: a mined `transact(...)`.
        assert!(out.transfer_block.is_some(), "the proved transfer was not mined: {out:?}");
    }
}
