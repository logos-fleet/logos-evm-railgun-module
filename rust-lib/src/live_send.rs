//! THE PRIVATE SEND THE CHAIN ITSELF WITNESSED — #213's last clause, CLOSED.
//!
//! On 2026-09-17, on the venue's physical iPad Air (4th generation), against
//! PUBLIC Sepolia (`reth/v2.4.1`, `forked: false`), this probe wrapped,
//! allowed, **shielded** (mined in block 11 723 148, `status 0x1`, 730 311 gas),
//! synced the real accumulator, proved through the engine's own
//! `calculate_witness` on the `wasmi` interpreter, and had the RAILGUN contract
//! **mine the proved `transact(...)`** in block 11 723 149 (`status 0x1`,
//! 1 002 375 gas). 53 411 ms end to end. The receipts are on the public chain
//! and in `docs/specs.md`.
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
//!   engine    RailgunBuilder over the DEFAULT syncer (subsquid, then RPC) --
//!             i.e. the real Sepolia tree, not a syncer we wrote
//!   sync      the engine syncs to tip, beside every other shield anyone ever
//!             made on this chain
//!   balance   what that tree already holds for this probe -- the input to the
//!             funding decision, which is why the free half goes FIRST
//!   funding   how much ETH and ERC-20 the probe's own EOA holds, read off chain
//!   wrap      `deposit()` on the chain's wrapped base token, so ETH alone is
//!             enough to fund a run -- skipped when an ERC-20 is already held,
//!             and whenever a note is being reused
//!   approve   ERC-20 approve(RailgunSmartWallet, amount), SIGNED AND BROADCAST
//!   shield    the ENGINE's own ShieldBuilder calldata, SIGNED AND BROADCAST,
//!             waited on until a block carries it
//!   resync    the blocks since, the shield's own among them
//!   note      a shielded balance that a transaction put there
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
//! ## What an operator has to do, once: SEND SEPOLIA ETH. That is the whole ask.
//!
//! The ask used to have two halves -- gas, and an ERC-20 to shield -- and the
//! second half was the expensive one: Sepolia ETH falls out of any faucet, while
//! an arbitrary test token has to be found, bridged or minted by hand. It never
//! had to be asked for. The chain config already names a token this probe can
//! MINT for itself (`wrapped_base_token`, i.e. WETH), `deposit()` is an ordinary
//! transaction this EOA can sign, and RAILGUN shields WETH like any other ERC-20
//! -- it is the token the engine's own native-shield path uses. So [`plan`]
//! wraps what it needs and an ERC-20 the EOA already holds is merely preferred.
//!
//! Until the ETH lands every run stops at the `funding` leg and reports the ask,
//! which is a complete handoff rather than a failure: the address is fixed, so
//! the funding is a one-time step and every later run is unattended. It landed:
//! the runs above are unattended runs off one operator transfer.
//!
//! AND THE SECOND RUN COSTS LESS THAN THE FIRST, because a mined shield does not
//! come back. Where the tree already holds one of this probe's notes there is
//! nothing to wrap, allow or shield: [`plan`] answers [`Plan::Spend`], the ask
//! shrinks to [`price_spend`] — what the proved `transact(...)` alone reserves —
//! and the run goes straight from the sync to the proof. That is what makes an
//! operator's single transfer survive a run that dies past its shield, which is
//! a real failure mode: #243 reproduced one, on a fork, with the shield mined
//! and the broadcast refused for funds.
//!
//! HOW MUCH is [`price_run`], read off the chain, rather than a constant. What
//! decides a run is not what its four transactions spend but what EIP-1559 makes
//! the LAST of them reserve, and that one is reached only after the shield has
//! been mined -- so an ask that is merely bigger than the gas bill strands a
//! note in the contract's tree. That is not a hypothesis: it is reproduced on a
//! fork in `docs/specs.md`, with the shield mined and the broadcast refused for
//! funds. [`can_still_transact`] asks the same question again immediately before
//! the shield, which is the last leg at which refusing costs nothing.
//!
//! ## And every leg can be RUN today, against a fork, with no operator at all
//!
//! `anvil --fork-url <sepolia>` serves the real Sepolia state — the same
//! `RailgunSmartWallet` bytecode at the same address, the same WETH, the whole
//! historical accumulator — from a node that will also credit an account on
//! request. Point the acceptance test's RPC at it (`LOGOS_SEPOLIA_RPC`),
//! `anvil_setBalance` this EOA, and `the_whole_send_lands_on_chain` shields,
//! mines, syncs, proves, checks `rootHistory` and broadcasts, end to end and
//! repeatably. docs/specs.md has the recipe and the measured run.
//!
//! That is not the same evidence as a public-chain run and it must not read like
//! one, so every [`Run`] carries [`Run::node`] (`web3_clientVersion`, verbatim)
//! and [`Run::forked`]: a fork and Sepolia agree about the chain id, the
//! contracts, the tree and `rootOnChain`, and the client version is the only
//! thing that tells them apart.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use alloy::consensus::{SignableTransaction, TxEip1559};
use alloy::eips::eip2718::Encodable2718;
use alloy::eips::eip2930::AccessList;
use alloy::primitives::{keccak256, Address, Bytes, Signature, TxKind, U256};
use alloy::signers::k256::ecdsa::{RecoveryId, SigningKey};
use alloy::signers::utils::secret_key_to_address;
use alloy::sol_types::SolCall;
use eip_1193_provider::provider::{Eip1193Caller, Eip1193Provider};
use railgun::account::address::RailgunAddress;
use railgun::account::chain::ChainId;
use railgun::account::signer::RailgunSigner;
use railgun::builder::RailgunBuilder;
use railgun::caip::AssetId;
use railgun::chain_config::ChainConfig;
use railgun::database::memory::MemoryDatabase;
use railgun::provider::RailgunProvider;
use serde_json::{json, Value};

use crate::keys;
use crate::private_send::{PROBE_RECIPIENT_SEED, PROBE_SEED};
use crate::proof_circuit::Leg;
use crate::rpc_backend::{EthRpcEip1193, RpcBackend};
use crate::sync::{self, Plan as SyncPlan, Tuning};

alloy::sol! {
    function balanceOf(address owner) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function rootHistory(uint256 treeNumber, bytes32 root) external view returns (bool);
    /// WETH9's `deposit()` -- how the probe MINTS the ERC-20 it shields, out of
    /// the ETH it was funded with. The chain config's `wrapped_base_token` is
    /// that contract (Sepolia: `0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14`,
    /// symbol `WETH`, 18 decimals), and RAILGUN shields it like any other
    /// ERC-20 -- it is the token the engine's own native-shield path uses.
    function deposit() external payable;
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

/// How much of the WRAPPED BASE TOKEN one run shields when the probe mints its
/// own (18 decimals, so `0.0001 ETH`). Proof cost does not depend on the value,
/// so this is as small as it can be and still survive RAILGUN's 25 bps shield
/// fee with a change note left over -- which is what keeps the operation on the
/// `01x02` circuit the other two probes measured.
pub const DEFAULT_WRAP_SHIELD: u128 = 100_000_000_000_000;

/// THE FLOOR under the operator ask, and nothing more than a floor: what a run
/// actually needs is [`price_run`], read off the chain it is pointed at. Kept
/// because a node that will not quote a fee still has to be asked for
/// something, and because every earlier #213 cycle's ask was this number.
pub const MIN_GAS_WEI: u128 = 5_000_000_000_000_000; // 0.005 ETH

// ── WHAT ONE WHOLE SEND COSTS, MEASURED ──────────────────────────────────────
//
// Not estimates: every figure below is a receipt this probe's own end-to-end
// runs produced, and they are in `docs/specs.md` with their block numbers. The
// estimate they replace was out by a factor of three on the leg that matters
// most (`MIN_GAS_WEI`'s own comment said "a shield is ~250 k gas").

/// `deposit()` on the wrapped base token -- `eth_estimateGas` against public
/// Sepolia, #213 cycle 4.
pub const GAS_WRAP: u128 = 45_418;
/// `approve(RailgunSmartWallet, …)` -- an ERC-20 allowance write.
pub const GAS_APPROVE: u128 = 46_000;
/// The engine's own `ShieldBuilder` calldata, MINED: 731 335 gas, block
/// 11 720 023 (#213 cycle 6, physical iPad).
pub const GAS_SHIELD: u128 = 731_335;
/// The proved `transact(...)`, MINED: 1 008 274 gas, block 11 720 024. The
/// largest single reservation a run makes, and the last one it makes.
pub const GAS_TRANSACT: u128 = 1_008_274;

/// [`Eoa::send`] sets `max_fee_per_gas` to twice the chain's own `eth_gasPrice`
/// -- plus a priority tip, which this leaves out. A node reserves against that
/// ceiling, not against the fee the transaction will actually pay.
///
/// Leaving the tip out is covered at the `funding` leg, where
/// [`FEE_DRIFT_MULTIPLE`] makes the ask hold 4x the quoted price per unit of
/// limit against a ceiling of 2x plus the tip. [`can_still_transact`] has no
/// such margin and so under-states each reservation by the tip over the limit.
const MAX_FEE_MULTIPLE: u128 = 2;

/// AND THE BASE FEE MOVES WHILE A RUN IS IN FLIGHT. Four transactions and a
/// sync are minutes apart on the public chain, and Sepolia's base fee routinely
/// doubles inside that window. An ask that is exactly right at the moment it is
/// printed is wrong by the time it is funded.
const FEE_DRIFT_MULTIPLE: u128 = 2;

/// The 30 % [`Eoa::gas_limit`] puts over an `eth_estimateGas`, written once so
/// the pricing and the sending cannot drift apart. The limit is what a node
/// checks a balance against, not the estimate under it.
fn with_headroom(gas: u128) -> u128 {
    gas.saturating_mul(13) / 10
}

/// WHAT A NODE MAKES AN ACCOUNT HOLD to accept one transaction: it refuses
/// `eth_sendRawTransaction` unless the balance covers
/// `gas_limit * max_fee_per_gas + value`, and both factors are larger than what
/// the transaction goes on to use -- see [`with_headroom`] and
/// [`MAX_FEE_MULTIPLE`]. The `value` is the caller's to add.
fn reservation(fee_wei_per_gas: u128, gas: u128) -> u128 {
    fee_wei_per_gas.saturating_mul(MAX_FEE_MULTIPLE).saturating_mul(with_headroom(gas))
}

/// WHAT THE PROBE'S EOA MUST HOLD FOR ONE WHOLE SEND, at a fee the chain has
/// just quoted -- the operator ask, as arithmetic rather than as a constant.
///
/// The binding constraint is not what the four transactions SPEND. It is what
/// the LAST of them RESERVES: a node refuses `eth_sendRawTransaction` unless the
/// account covers `gas_limit * max_fee_per_gas + value` at submission, and the
/// proved `transact(...)` is both the biggest of the four and the one reached
/// only after the shield has been mined. Fail there and the shield is already
/// in the contract's tree, worth exactly as much as the gas to move it -- which
/// is what the account no longer has.
///
/// So the ask is: what the wrap moves out, plus what the three legs before the
/// transact pay, plus what the transact has to be holding when it is signed --
/// all of it at a fee allowed to drift ([`FEE_DRIFT_MULTIPLE`]), and never less
/// than [`MIN_GAS_WEI`] plus the wrap.
pub fn price_run(fee_wei_per_gas: u128, wrap: u128) -> u128 {
    let drifted = fee_wei_per_gas.saturating_mul(FEE_DRIFT_MULTIPLE);
    let spent = drifted.saturating_mul(GAS_WRAP + GAS_APPROVE + GAS_SHIELD);
    let held_back = reservation(drifted, GAS_TRANSACT);
    wrap.saturating_add(spent)
        .saturating_add(held_back)
        .max(MIN_GAS_WEI.saturating_add(wrap))
}

/// WHAT THE PROBE'S EOA MUST HOLD WHEN THE TREE ALREADY HOLDS ITS NOTE: the
/// proved `transact(...)`'s reservation, and nothing before it.
///
/// A shield that has been mined has already bought the wrap, the approve and
/// the shield itself. If the run that mined it then failed -- for funds, for
/// the artifact host, for an app the platform backgrounded -- the note is still
/// in the contract's tree and is still this probe's to spend. Asking the
/// operator for a whole second run would be asking twice for three legs that
/// are already paid for, and would leave the first note stranded for good.
///
/// Same drift allowance as [`price_run`], for the same reason: the fee moves
/// between the moment the ask is printed and the moment it is funded.
pub fn price_spend(fee_wei_per_gas: u128) -> u128 {
    reservation(fee_wei_per_gas.saturating_mul(FEE_DRIFT_MULTIPLE), GAS_TRANSACT)
}

/// THE SMALLEST NOTE WORTH SENDING. The transfer is half of what the engine
/// reports, so a note of one unit splits into a transfer of nothing and is not
/// the `01x02` operation the rest of this issue measured. Two is the floor the
/// arithmetic imposes, not a policy.
pub const MIN_TRANSFERABLE: u128 = 2;

/// CAN THIS PURSE STILL PAY FOR THE `transact` AFTER THE SHIELD?
///
/// Asked immediately before the shield is broadcast, which is the last moment at
/// which nothing has been staked. [`price_run`] answers the same question at the
/// `funding` leg, but the two are minutes apart and the fee between them is the
/// chain's business, not this probe's -- so the question is asked twice and the
/// second answer is the one that decides.
///
/// Refusing here costs the gas of the wrap and the approve. Refusing one leg
/// later costs a shielded balance as well, and that is the expensive half of
/// #213 clause 1: a shield has to be re-mined and re-synced, the funds cannot.
pub fn can_still_transact(wei: u128, fee_wei_per_gas: u128) -> Result<(), String> {
    // Every refusal says the same two things -- what it is protecting and what
    // to do about it -- so only the reason in the middle is written twice.
    let refuse = |why: String| -> Result<(), String> {
        Err(format!(
            "stopping BEFORE the shield: {why} Top {} up and run again -- nothing has been \
             shielded, so nothing is stranded.",
            probe_eoa_address()
        ))
    };
    let shield_reservation = reservation(fee_wei_per_gas, GAS_SHIELD);
    if wei < shield_reservation {
        return refuse(format!(
            "at the chain's current {fee_wei_per_gas} wei/gas the shield alone reserves \
             {shield_reservation} wei and this EOA holds {wei}."
        ));
    }
    let after = wei.saturating_sub(fee_wei_per_gas.saturating_mul(GAS_SHIELD));
    let transact_reservation = reservation(fee_wei_per_gas, GAS_TRANSACT);
    if after < transact_reservation {
        return refuse(format!(
            "it would leave {after} wei and the proved transact(...) reserves \
             {transact_reservation} at the chain's current {fee_wei_per_gas} wei/gas. \
             Shielding now would put a note in the contract's tree that this EOA could not \
             then spend."
        ));
    }
    Ok(())
}

/// Client versions that mean "a chain running on this desk". A fork answers
/// every question Sepolia answers — same chain id, same contract bytecode, same
/// historical tree — so a run against one is real in every respect except that
/// its funds were conjured, and the report must not read like a public-chain
/// one. Matched on the client name, which is the part a node does not vary.
pub fn is_local_fork(client_version: &str) -> bool {
    let v = client_version.to_ascii_lowercase();
    ["anvil", "hardhat", "ganache", "ethereumjs", "foundry"].iter().any(|n| v.contains(n))
}

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
    /// The ERC-20 to shield and transfer. Naming one also says "shield THIS and
    /// nothing else": the probe will not wrap for a named asset, because the
    /// only ERC-20 it can mint is the chain's wrapped base token. `None` lets
    /// [`plan`] choose, and is what makes a run need nothing but ETH.
    pub asset: Option<Address>,
    /// How much to shield, in the chosen token's smallest unit. `None` =
    /// [`DEFAULT_SHIELD`] for an ERC-20 the EOA already holds and
    /// [`DEFAULT_WRAP_SHIELD`] for the 18-decimal wrapped base token, since one
    /// number cannot mean the same thing in both.
    ///
    /// Has NO effect on a run that reuses a note ([`Plan::Spend`]): there is
    /// nothing to shield. Deliberate -- the alternative is a caller who passes
    /// it after a failure paying for a second shield because of a number they
    /// meant as a default.
    pub shield: Option<u128>,
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
            shield: None,
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
    /// WHOSE CHAIN ANSWERED — `web3_clientVersion`, verbatim, read before
    /// anything is spent. A fork of Sepolia and Sepolia itself agree on the
    /// chain id, the contracts, the tree and `rootOnChain`, so this is the only
    /// field that tells the two apart. `None` where the node would not say.
    pub node: Option<String>,
    /// WHAT GAS COST WHEN THE `funding` LEG PRICED THIS RUN (`eth_gasPrice`).
    /// The ask is arithmetic over this number, so reporting it is what lets a
    /// reader tell a stale ask from a wrong one. `None` where the node would
    /// not quote a price.
    pub fee_wei_per_gas: Option<u128>,
    /// The node named itself a local development chain, so this run is against
    /// a FORK and not the public chain — see [`is_local_fork`].
    pub forked: bool,
    pub legs: Vec<Leg>,
    /// The EOA that pays and shields. Always reported, even by a run that stops
    /// at `funding`, because it IS the handoff.
    pub eoa: Option<String>,
    pub eth_wei: Option<u128>,
    pub token_units: Option<u128>,
    /// What an operator has to do, in one sentence, when the answer is "fund it".
    pub needs_funding: Option<String>,
    pub asset: Option<String>,
    /// Wei of the EOA's own ETH turned into the wrapped base token, and the
    /// transaction that did it. `None` = the EOA already held an ERC-20.
    pub wrapped_wei: Option<u128>,
    pub wrap_tx: Option<String>,
    /// The probe's `0zk` address and the counterparty's.
    pub from: Option<String>,
    pub to: Option<String>,
    pub approve_tx: Option<String>,
    pub shield_tx: Option<String>,
    pub shield_block: Option<u64>,
    /// How many blocks the `sync` leg actually walked, and from where. The
    /// `sync` leg's milliseconds mean nothing without them: a run whose
    /// subsquid tail is 2 200 blocks and a run whose tail is 100 are not
    /// comparable, and #235 was diagnosed by noticing that two runs 666 blocks
    /// apart differed by 70 s of sync.
    pub sync_from_block: Option<u64>,
    pub sync_to_block: Option<u64>,
    /// THE ENGINE'S OWN ROOT, AND THE CONTRACT'S VERDICT ON IT -- the check the
    /// engine makes at the end of every sync and then throws away, kept. See
    /// [`RootCheck`].
    ///
    /// Not the same claim as [`Run::root_on_chain`], which is about the root a
    /// PROOF was built over and therefore needs a shielded balance, a shield
    /// mined and money. This one needs none of them: it says the accumulator
    /// this device rebuilt out of chain events is, leaf for leaf, the one the
    /// RAILGUN contract holds -- which is the part of clause 1 an unfunded run
    /// can still answer.
    pub synced_tree: Option<u32>,
    pub synced_root: Option<String>,
    pub synced_root_on_chain: Option<bool>,
    /// The shielded balance AFTER a real sync of the real tree.
    pub balance: Option<u128>,
    /// THIS RUN SHIELDED NOTHING: the RAILGUN tree already held a note of this
    /// probe's, put there by an earlier run, and this one spent that instead.
    ///
    /// A mined shield is the expensive half of #213 clause 1 -- 731 335 gas and
    /// a wait for a block -- and it survives the run that made it. So a run
    /// that stopped after its shield (out of reservation at the broadcast, out
    /// of reach of the artifact host, backgrounded by a phone) leaves something
    /// the next run must SPEND rather than duplicate. `shieldTx` is `None` on
    /// such a run, and the ask that funds it is the transact's alone
    /// ([`price_spend`]).
    pub reused_note: bool,
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

    /// Record `name` as the leg `r` turned out to be, timed from `t`: a value
    /// passes through, an error becomes a RED leg and `None`. Callers stop on
    /// the `None`, so a leg is written exactly once and a failure is timed
    /// where it happened rather than being reported as an untimed one.
    fn record_leg<T>(&mut self, name: &'static str, t: Instant, r: Result<T, String>) -> Option<T> {
        let ms = Some(t.elapsed().as_millis());
        match r {
            Ok(v) => {
                self.legs.push(Leg::timed(name, ms));
                Some(v)
            }
            Err(e) => {
                self.legs.push(Leg::failed(name, ms, e));
                None
            }
        }
    }

    /// The wasm backend the ENGINE generates its witness on in THIS image —
    /// [`crate::proof_circuit::ENGINE_BACKEND`], which is character for
    /// character the cfg `patch-kohaku-witness-backend.sh` writes into the
    /// vendored `calculate_witness`.
    ///
    /// #213 clause 2 is evidenced by a line the VENDORED engine prints
    /// (`railgun: witness store backend = wasmi (#188 iOS: the interpreter, no
    /// JIT)`), which belongs to a different crate and never reaches a caller
    /// that reads the result as JSON. Naming it here puts the backend in the
    /// same line — and the same object — as `rootOnChain` and the timings.
    ///
    /// A method rather than a field because it is a property of the BUILD, not
    /// of the run: a run that stopped at `funding` knows it just as well.
    pub fn witness_backend(&self) -> &'static str {
        crate::proof_circuit::ENGINE_BACKEND.requested()
    }

    fn finished(mut self, started: Instant) -> Run {
        self.total_ms = started.elapsed().as_millis();
        report(&self);
        self
    }
}

// ── what to shield, and where it comes from ───────────────────────────

/// An ERC-20 and what the probe's EOA holds of it, in that token's own
/// smallest unit -- which is not the same unit twice, see [`DEFAULT_SHIELD`]
/// and [`DEFAULT_WRAP_SHIELD`].
#[derive(Debug, Clone, Copy)]
pub struct Holding {
    pub token: Address,
    pub units: u128,
}

/// Everything the funding decision looks at. A struct rather than four
/// arguments because [`plan`] is the one part of this probe that has to be
/// right without a chain to check it against.
#[derive(Debug, Clone)]
pub struct Purse {
    pub eoa: Address,
    pub wei: u128,
    /// The ERC-20 the run prefers, and how much of it the EOA holds.
    pub erc20: Holding,
    /// The chain's wrapped base token and the EOA's balance of it -- the one
    /// ERC-20 this probe can MINT, out of its own ETH. `None` when the caller
    /// named an asset: then there is nothing to mint and a short balance is an
    /// ask.
    pub wrapped: Option<Holding>,
    /// WHAT THE CHAIN SAYS GAS COSTS RIGHT NOW (`eth_gasPrice`), which is what
    /// turns the ask from a constant into a price ([`price_run`]). `None` where
    /// the node would not quote one: the ask then falls back to
    /// [`MIN_GAS_WEI`], which is what every #213 cycle before this one asked
    /// for. Evidence, like `node` -- never a reason to stop.
    pub fee_wei_per_gas: Option<u128>,
}

/// What the probe will send, and where the note it sends comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// SPEND WHAT IS ALREADY THERE. The RAILGUN tree holds a note of this
    /// probe's, so there is nothing to mint, allow or shield: the run goes
    /// straight from the sync to the proof.
    Spend { token: Address, units: u128 },
    /// Nothing spendable in the tree. `wrap` is the wei of the EOA's own ETH to
    /// turn into `token` first.
    Shield { token: Address, shield: u128, wrap: Option<u128> },
}

/// THE OPERATOR ASK, REDUCED TO ONE ASSET. Three #213 cycles stopped on funding,
/// and the ERC-20 half was the expensive half: Sepolia ETH falls out of any
/// faucet, while an arbitrary test token has to be found, bridged or minted by
/// hand. It never had to be asked for -- the chain config already names a token
/// the probe can mint for itself (`wrapped_base_token`, i.e. WETH), a `deposit()`
/// is an ordinary transaction this EOA can sign, and RAILGUN shields WETH like
/// any other ERC-20. So ETH alone is now enough, and an ERC-20 the EOA already
/// holds is still preferred when it is there.
///
/// `shielded` is what the RAILGUN tree already holds for this probe, in the
/// caller's own order of preference — see [`Plan::Spend`], which is the branch
/// that makes a funded run survive a failure past its shield.
///
/// Pure, and ordered so the answer is never surprising:
///
/// 0. a note already in the tree -> spend it; the ask is the transact alone;
/// 1. not enough ETH for the whole run -> ask, whatever else is held (see
///    `gas_only` below: the last leg's reservation is due whatever is shielded);
/// 2. enough of the preferred ERC-20 -> shield that, wrap nothing;
/// 3. a named asset that is short -> ask, naming it (nothing to mint);
/// 4. enough of the wrapped base token already -> shield that, wrap nothing;
/// 5. ETH to cover gas AND the shortfall -> wrap the shortfall;
/// 6. otherwise -> ask, in ETH.
pub fn plan(purse: &Purse, asked: Option<u128>, shielded: &[Holding]) -> Result<Plan, String> {
    // ── WHAT THE TREE ALREADY HOLDS, WHICH CHANGES THE QUESTION ──────────
    //
    // A shield that has been MINED is the expensive half of #213 clause 1, and
    // it does not come back: it is a leaf in the contract's accumulator, worth
    // exactly the gas to move it. A run that mined one and then stopped -- out
    // of reservation at the broadcast (#243's own reproduction), unable to
    // reach the artifact host, backgrounded by a phone mid-sync -- left that
    // leaf behind. Shielding again would spend 731 335 gas to create a second
    // one and abandon the first.
    //
    // So the tree is asked BEFORE the purse: with a note already there the run
    // has only the proved `transact(...)` left to pay for, and an ask priced
    // for a whole run would refuse a purse that can afford the rescue.
    if let Some(note) = shielded.iter().find(|h| h.units >= MIN_TRANSFERABLE) {
        let ask = match purse.fee_wei_per_gas {
            Some(fee) => price_spend(fee),
            None => MIN_GAS_WEI,
        };
        if purse.wei < ask {
            return Err(format!(
                "fund {} on Sepolia with at least {ask} wei of ETH{}: it holds {} wei, and the \
                 RAILGUN tree ALREADY holds {} units of {} shielded to this probe. An earlier run \
                 mined that shield, so this one needs only the gas to SPEND the note -- not to \
                 wrap, allow and shield a second one. Nothing already spent is lost.",
                purse.eoa,
                match purse.fee_wei_per_gas {
                    Some(fee) => format!(
                        " (priced at the chain's own {fee} wei/gas for the {GAS_TRANSACT} gas of \
                         the proved transact(...), with room for the fee to move)"
                    ),
                    None => " (this node would not quote a gas price, so this is the floor)"
                        .to_string(),
                },
                purse.wei,
                note.units,
                note.token,
            ));
        }
        return Ok(Plan::Spend { token: note.token, units: note.units });
    }

    // What a run would shield out of each source. One number cannot serve both:
    // the preferred ERC-20 is a 6-decimal stablecoin and the wrapped base token
    // is 18-decimal ETH.
    let want_erc20 = asked.unwrap_or(DEFAULT_SHIELD);
    let want_wrapped = asked.unwrap_or(DEFAULT_WRAP_SHIELD);
    // The wei a `wrap` leg would mint with, and so the one number an ask is:
    // gas, plus whatever the wrapped balance is short of a shield. Zero when
    // there is nothing to mint, which is what a named `asset` means.
    let shortfall = purse.wrapped.map_or(0, |w| want_wrapped.saturating_sub(w.units));
    // What the whole run costs at the fee the chain just quoted -- and the old
    // constant where it would not quote one.
    let priced = |wrap: u128| match purse.fee_wei_per_gas {
        Some(fee) => price_run(fee, wrap),
        None => MIN_GAS_WEI.saturating_add(wrap),
    };
    let full_ask = priced(shortfall);
    // The floor a run must clear even when it wraps nothing: the transact's
    // reservation does not get smaller because the ERC-20 was already there.
    let gas_only = priced(0);

    let ask = || {
        let (held, mint) = match purse.wrapped {
            Some(w) => (
                format!(
                    "{} units of {} and {} units of {}",
                    purse.erc20.units, purse.erc20.token, w.units, w.token
                ),
                format!(
                    " ETH is ALL it needs: it mints its own ERC-20 by wrapping {shortfall} wei of \
                     it into the chain's wrapped base token ({}) and shielding that.",
                    w.token
                ),
            ),
            None => (
                format!("{} units of {}", purse.erc20.units, purse.erc20.token),
                format!(
                    " This run named an asset ({}), and the only ERC-20 this probe can mint for \
                     itself is the chain's wrapped base token -- so send that token too, or leave \
                     `asset` unset.",
                    purse.erc20.token
                ),
            ),
        };
        format!(
            "fund {} on Sepolia with at least {full_ask} wei of ETH{}: it holds {} wei and \
             {held}.{mint} That address is FIXED (it is derived from a seed in \
             rust-lib/src/live_send.rs), so this is a one-time step -- every run after it is \
             unattended.",
            purse.eoa,
            // WHY THAT NUMBER. An ask nobody can check is an ask nobody can see
            // has gone stale, and the fee it was priced at is the thing that
            // moves -- see `price_run`.
            match purse.fee_wei_per_gas {
                Some(fee) => format!(
                    " (priced at the chain's own {fee} wei/gas for {} gas of shield and \
                     transact, with room for the fee to move)",
                    GAS_WRAP + GAS_APPROVE + GAS_SHIELD + GAS_TRANSACT
                ),
                None => " (this node would not quote a gas price, so this is the floor)"
                    .to_string(),
            },
            purse.wei
        )
    };

    if purse.wei < gas_only {
        return Err(ask());
    }
    if purse.erc20.units >= want_erc20 {
        return Ok(Plan::Shield { token: purse.erc20.token, shield: want_erc20, wrap: None });
    }
    let Some(wrapped) = purse.wrapped else {
        return Err(ask());
    };
    if wrapped.units >= want_wrapped {
        return Ok(Plan::Shield { token: wrapped.token, shield: want_wrapped, wrap: None });
    }
    if purse.wei >= full_ask {
        return Ok(Plan::Shield { token: wrapped.token, shield: want_wrapped, wrap: Some(shortfall) });
    }
    Err(ask())
}

/// WHAT THE LAST FREE QUESTION LEARNED: the fee, the balance and the verdict.
///
/// A struct rather than a `Result` because two of the three are worth reporting
/// whatever the answer was -- an ask that names neither the fee nor the balance
/// cannot be told from a wrong one.
#[derive(Debug, Clone, Default)]
pub struct ShieldGate {
    pub fee_wei_per_gas: Option<u128>,
    pub wei: Option<u128>,
    /// Why the shield must not go out. `None` also when the node would not
    /// answer: unreadable is not a refusal, exactly as it is not at the
    /// `funding` leg, because the price is EVIDENCE and the send is the
    /// measurement.
    pub refusal: Option<String>,
}

/// Ask it. Split out of [`run`] so a test can put a chain in front of it: the
/// call site is past the engine build, which no unit test can reach.
fn shield_gate<B: RpcBackend>(eoa: &Eoa<B>) -> ShieldGate {
    let fee_wei_per_gas = eoa.gas_price();
    let wei = eoa.eth_balance().ok();
    let refusal = match (fee_wei_per_gas, wei) {
        (Some(fee), Some(wei)) => can_still_transact(wei, fee).err(),
        _ => None,
    };
    ShieldGate { fee_wei_per_gas, wei, refusal }
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

    /// What the chain says gas costs. The same call [`Eoa::send`] prices every
    /// transaction from, asked here so the FUNDING decision is made on it too
    /// rather than on a constant -- see [`price_run`].
    fn gas_price(&self) -> Option<u128> {
        self.rpc("eth_gasPrice", json!([])).ok().and_then(|v| quantity(&v).ok())
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
        Ok(with_headroom(est).min(u64::MAX as u128) as u64)
    }

    /// Sign and submit. Returns the transaction hash; the caller waits for it.
    fn send(&self, to: Address, value: U256, data: Bytes, gas_limit: u64) -> Result<String, String> {
        // "pending" rather than "latest": the shield follows the approve within
        // one block often enough that a latest-nonce would replace it.
        let nonce = quantity(&self.rpc(
            "eth_getTransactionCount",
            json!([self.address.to_string(), "pending"]),
        )?)? as u64;
        let gas_price = quantity(&self.rpc("eth_gasPrice", json!([]))?)?;
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
            // Room for the base fee to double before this lands, which is what
            // a wallet does: the probe pays the base fee of the block it lands
            // in, not this ceiling.
            max_fee_per_gas: gas_price.saturating_mul(2).saturating_add(tip),
            max_priority_fee_per_gas: tip,
            to: TxKind::Call(to),
            value,
            access_list: AccessList::default(),
            input: data,
        };
        let (_, raw) = sign_1559(&self.key, tx)?;
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
fn sign_1559(key: &SigningKey, tx: TxEip1559) -> Result<(Signature, Vec<u8>), String> {
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
    Ok((signature, tx.into_signed(signature).encoded_2718()))
}

/// MINT THE PROBE'S OWN ERC-20: `deposit()` on the chain's wrapped base token,
/// paid for with `amount` wei of the EOA's own ETH. Split out of [`run`] so a
/// test can decode the signed transaction it produces without a chain -- the
/// destination, the value and the selector are the whole of this leg, and
/// getting any of the three wrong spends real gas to find out.
async fn wrap_native<B: RpcBackend>(
    eoa: &Eoa<B>,
    wrapped: Address,
    amount: u128,
    budget: Duration,
) -> Result<(String, u64), String> {
    let value = U256::from(amount);
    let data: Bytes = depositCall {}.abi_encode().into();
    let gas = eoa.gas_limit(wrapped, value, &data)?;
    let tx = eoa.send(wrapped, value, data, gas)?;
    let block = eoa.wait(&tx, budget).await?;
    Ok((tx, block))
}

// ── the engine's own root check, overheard ──────────────────────────────────

/// ONE `rootHistory(treeNumber, root)` THE ENGINE ASKED, AND WHAT IT WAS TOLD.
///
/// At the end of every `sync_to` the engine verifies each tree it has just
/// written against the deployed `RailgunSmartWallet` — and **drops the answer**:
/// `UtxoIndexer::verify` propagates an RPC *error* and discards the `bool`, so a
/// tree that does NOT match the contract syncs green (kohaku `96c835f`,
/// `crates/railgun/src/indexer/utxo_indexer.rs`). That boolean is exactly what
/// #213 clause 1 is about, so this probe keeps the verdict the engine throws
/// away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootCheck {
    pub tree: u32,
    pub root: U256,
    /// What `RailgunSmartWallet.rootHistory` answered about it.
    pub on_chain: bool,
}

/// A `bool` as an `eth_call` answers one: a 32-byte word, true when any bit of
/// it is set — which is how the ABI decoder reads it too.
fn word_is_true(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.trim_start_matches("0x").trim_start_matches('0').is_empty())
}

/// An [`RpcBackend`] that passes everything through and remembers the last
/// [`RootCheck`] the engine made against `smart_wallet`.
///
/// OVERHEARD RATHER THAN ASKED AGAIN. The root is a `pub(crate)` of the engine's
/// indexer and the provider holds the indexer privately, so a consumer cannot
/// read it — but the engine asks the CONTRACT about it over the provider this
/// module supplies, and that call is an ordinary `eth_call`. Listening costs no
/// round trip, needs no seam, and reports the root at the moment the engine
/// itself had it rather than one re-derived afterwards.
pub struct RootWatch<B: RpcBackend> {
    inner: Arc<B>,
    smart_wallet: Address,
    last: Mutex<Option<RootCheck>>,
}

impl<B: RpcBackend> RootWatch<B> {
    pub fn new(inner: Arc<B>, smart_wallet: Address) -> Self {
        Self { inner, smart_wallet, last: Mutex::new(None) }
    }

    /// The last root the engine checked. `None` when it checked none, which is
    /// what an empty tree looks like — upstream skips a tree with no leaves, and
    /// inventing a verdict for it would be worse than having none.
    pub fn last(&self) -> Option<RootCheck> {
        *self.last.lock().expect("the watch is never held across a panic")
    }

    /// `[{ "to": …, "data": … }, "latest"]`, as `EthRpcEip1193::eth_call` writes
    /// it, decoded back into the call the engine made. `None` for every other
    /// `eth_call` — a run makes many, and only this one is about a root.
    fn decode_root_history(&self, params: &Value) -> Option<(u32, U256)> {
        let call = params.get(0)?;
        let to = call.get("to")?.as_str()?.parse::<Address>().ok()?;
        if to != self.smart_wallet {
            return None;
        }
        let data = hex::decode(call.get("data")?.as_str()?.trim_start_matches("0x")).ok()?;
        let asked = rootHistoryCall::abi_decode(&data).ok()?;
        Some((u32::try_from(asked.treeNumber).ok()?, U256::from_be_bytes(asked.root.0)))
    }
}

impl<B: RpcBackend> RpcBackend for RootWatch<B> {
    fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let asked = if method == "eth_call" { self.decode_root_history(&params) } else { None };
        let answer = self.inner.rpc(method, params);
        if let (Some((tree, root)), Ok(v)) = (asked, &answer) {
            *self.last.lock().expect("the watch is never held across a panic") =
                Some(RootCheck { tree, root, on_chain: word_is_true(v) });
        }
        answer
    }
}

/// Keep the verdict the engine discarded, and fail on a `false`.
///
/// A `false` here means the tree this device rebuilt from chain events is not
/// the tree the contract holds, so every proof built over it would revert. The
/// engine syncs green through exactly that, which is why the check lives here.
fn record_root_check<B: RpcBackend>(out: &mut Run, watch: &RootWatch<B>) -> Result<(), String> {
    let Some(check) = watch.last() else { return Ok(()) };
    out.synced_tree = Some(check.tree);
    out.synced_root = Some(format!("0x{:064x}", check.root));
    out.synced_root_on_chain = Some(check.on_chain);
    if check.on_chain {
        return Ok(());
    }
    Err(format!(
        "the RAILGUN contract does not know the root this engine synced to (tree {}, root \
         0x{:064x}): the accumulator this device rebuilt is not the one the contract holds, and \
         any proof over it would revert. The engine's own sync asks this question and drops the \
         answer, which is why this probe keeps it.",
        check.tree, check.root
    ))
}

// ── the two halves both a send and a survey are made of ─────────────────────

/// The engine, over the REAL syncer and the real tree, with `signer` registered.
///
/// THE SYNCER IS TUNED, and this is the leg #235 is about. See [`crate::sync`]:
/// the engine's own `RpcSyncer` defaults walk whatever subsquid has not indexed
/// ten blocks at a time with a one-second sleep after each — 100 ms a block,
/// which was 221 of the 239 seconds this probe took on a physical iPad Air 4.
///
/// The database is the caller's rather than handed over and forgotten: the
/// engine persists `synced_block` into it and exposes no getter, so holding it
/// is what lets [`sync_windows`] step and report instead of making one opaque
/// call. `MemoryDatabase`, so a probe run leaves nothing behind — and so this
/// probe re-walks the tail every time, where a wallet built by [`crate::engine`]
/// over a `DiskDatabase` walks only the new blocks.
async fn build_engine(
    chain: &ChainConfig,
    eip1193: Arc<dyn Eip1193Provider>,
    db: Arc<MemoryDatabase>,
    signer: Arc<dyn RailgunSigner>,
) -> Result<RailgunProvider, String> {
    let mut provider = RailgunBuilder::new(chain.clone(), eip1193.clone())
        .with_database(db)
        .with_utxo_syncer(sync::utxo_syncer(chain, eip1193, &Tuning::default()))
        .build()
        .await
        .map_err(|e| format!("engine build: {e}"))?;
    provider
        .register(signer)
        .await
        .map_err(|e| format!("register signer: {e}"))?;
    Ok(provider)
}

/// The sync, IN WINDOWS, SAYING WHERE IT IS (#235).
///
/// One `provider.sync()` is the same work and reports nothing for as long as it
/// takes, which on a handset was 221 s of an unresponsive app. Each window
/// persists before it returns, so a run interrupted here loses none of it — and
/// so does a USER who walks away, which is the whole of the cancel path: stop
/// asking for the next one.
///
/// The [`SyncPlan`] comes back even when the sync failed, because where it got
/// to is the interesting half of a failure.
async fn sync_windows(
    provider: &mut RailgunProvider,
    eip1193: &Arc<dyn Eip1193Provider>,
    chain: &ChainConfig,
    db: &MemoryDatabase,
    zk_address: &str,
) -> (Option<SyncPlan>, Result<(), String>) {
    let head = match eip1193.get_block_number().await {
        Ok(b) => b,
        Err(e) => return (None, Err(format!("eth_blockNumber: {e}"))),
    };
    let mut plan = SyncPlan::new(sync::synced_block(db, Some(zk_address)).await, head);
    // The subsquid half in one window -- see `sync::subsquid_frontier`.
    if let Some(frontier) = sync::subsquid_frontier(chain).await {
        plan = plan.with_fast_forward(frontier);
    }
    while let Some(end) = plan.next_window_end(sync::DEFAULT_WINDOW_BLOCKS) {
        let before = plan.synced_block;
        let (result, ms) = sync::timed(provider.sync_to(end)).await;
        if let Err(e) = result {
            return (Some(plan), Err(format!("sync: {e}")));
        }
        plan.record(sync::synced_block(db, Some(zk_address)).await, ms);
        sync::report(&plan);
        if plan.synced_block <= before {
            // The engine will not pass this block, so neither will another turn
            // of this loop. Say where it stopped rather than spinning.
            let stalled =
                format!("sync stalled at block {} of {}", plan.synced_block, plan.target_block);
            return (Some(plan), Err(stalled));
        }
    }
    (Some(plan), Ok(()))
}

/// EVERY LEG MONEY IS NOT NEEDED FOR — what an unfunded run does instead of
/// stopping.
///
/// #213 clause 1 has been one testnet transfer away for several cycles, and the
/// issue asks that a cycle still produce a measurement while it waits. Nothing
/// in a sync costs anything: the engine is built over the real default syncer,
/// the real accumulator is walked to the live tip, the root it arrives at is
/// checked against the contract ([`record_root_check`]) and the shielded balance
/// is read. That is the leg which DOMINATES a private send's wall clock (#235:
/// 221 of 239 seconds before it was tuned) and the only one of them that has
/// never been measured against the public chain on a device — every figure so
/// far came from a local fork, whose tip does not move and whose node is on the
/// same desk.
///
/// IT IS NOT A SEND AND MUST NOT READ LIKE ONE. Nothing here signs anything;
/// when the `funding` leg that follows goes red, [`Run::ok`] stays false and
/// [`summary`] says `DID NOT` and prints `SURVEY-ONLY-UNFUNDED`.
///
/// AND IT IS THE HEAD OF EVERY RUN, not just an unfunded one's consolation. The
/// funding decision needs to know whether the tree ALREADY holds one of this
/// probe's notes ([`Plan::Spend`]), and only a sync can say — so the run syncs
/// before it prices itself, which it could not have afforded to do before #235
/// cut that leg from 221 s to seconds. What comes back is the synced engine
/// itself, so a send reuses it instead of building and walking a second one.
async fn survey<B: RpcBackend>(
    out: &mut Run,
    chain: &ChainConfig,
    eip1193: Arc<dyn Eip1193Provider>,
    watch: &RootWatch<B>,
    signer: Arc<dyn RailgunSigner>,
    from: RailgunAddress,
    candidates: &[Address],
) -> Option<Surveyed> {
    entering("engine");
    let t = Instant::now();
    let db = Arc::new(MemoryDatabase::new());
    let built = build_engine(chain, eip1193.clone(), db.clone(), signer).await;
    let mut provider = out.record_leg("engine", t, built)?;

    entering("sync");
    let t = Instant::now();
    let zk_address = from.to_string();
    let (plan, synced) =
        sync_windows(&mut provider, &eip1193, chain, db.as_ref(), &zk_address).await;
    if let Some(plan) = &plan {
        out.sync_from_block = Some(plan.start_block);
        out.sync_to_block = Some(plan.target_block);
    }
    out.record_leg("sync", t, synced)?;

    let t = Instant::now();
    let checked = record_root_check(out, watch);
    out.record_leg("synced-root", t, checked)?;

    entering("balance");
    let t = Instant::now();
    let held = provider.balance(from).await;
    // Every asset, not one: a survey has chosen no asset to shield, and a
    // balance the probe did not expect is worth seeing rather than filtering out.
    out.balance = Some(held.iter().map(|b| b.amount).sum());
    // And the same balances per candidate token, in the caller's order of
    // preference -- which is what [`plan`] reads to decide whether this run has
    // anything left to shield.
    let shielded = candidates
        .iter()
        .map(|&token| {
            let id = AssetId::erc20(token);
            Holding {
                token,
                units: held.iter().filter(|b| b.asset == id).map(|b| b.amount).sum(),
            }
        })
        .collect();
    out.legs.push(Leg::timed("balance", Some(t.elapsed().as_millis())));
    Some(Surveyed { provider, db, shielded })
}

/// The engine a [`survey`] built and walked, and what it found. Carried rather
/// than dropped so a send does not build a second engine and re-walk the same
/// accumulator behind it.
struct Surveyed {
    provider: RailgunProvider,
    db: Arc<MemoryDatabase>,
    /// What the tree holds of each candidate token, in the caller's order.
    shielded: Vec<Holding>,
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
    // The ERC-20 the run prefers, and the one it can mint. Naming an asset
    // turns the second off: `deposit()` exists on the wrapped base token and
    // nowhere else.
    let preferred = p
        .asset
        .unwrap_or_else(|| SEPOLIA_USDC.parse().expect("the fixture token address is a literal"));
    let mintable = p.asset.is_none().then_some(chain.wrapped_base_token);

    // THE ENGINE'S PROVIDER, LISTENED TO. Everything the engine reads goes
    // through here, including the `rootHistory` it asks about its own tree at
    // the end of every sync and then discards -- see `RootWatch`. The EOA keeps
    // the bare backend: its transactions are not the engine's reads.
    let watch = Arc::new(RootWatch::new(backend.clone(), smart_wallet));
    let eip1193: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(watch.clone()));
    let eoa = Eoa::new(backend.clone(), p.chain_id);
    out.eoa = Some(eoa.address.to_string());

    // Whose chain this is. Asked first and never fatal: a node that will not
    // name itself leaves `node: None` rather than stopping a run, because the
    // identity is EVIDENCE and the send is the measurement.
    out.node = backend
        .rpc("web3_clientVersion", json!([]))
        .ok()
        .and_then(|v| v.as_str().map(str::to_string));
    out.forked = out.node.as_deref().is_some_and(is_local_fork);

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
    // The engine takes the signer as a trait object, and either a send or a
    // survey hands it over -- coerced once here rather than at both call sites.
    let engine_signer: Arc<dyn RailgunSigner> = signer.clone();
    out.from = Some(from.to_string());
    out.to = Some(to.to_string());
    out.legs.push(Leg::timed("keys", None));

    // ── THE FREE HALF, WHICH EVERY RUN MAKES FIRST ─────────────────────────
    //
    // Engine, sync, the root the engine checks and discards, and the balance --
    // none of which costs anything, and one of which decides the question the
    // `funding` leg is about: a note this probe ALREADY owns is a run with
    // three legs fewer and a much smaller ask (see [`Plan::Spend`]). Before
    // #235 this could not have gone first -- the sync was 221 s on a handset.
    let candidates: Vec<Address> = [Some(preferred), mintable].into_iter().flatten().collect();
    let surveyed = survey(
        &mut out,
        &chain,
        eip1193.clone(),
        watch.as_ref(),
        engine_signer,
        from.clone(),
        &candidates,
    )
    .await;

    // ── can this account pay for what is LEFT to do? ───────────────────────
    entering("funding");
    let t = Instant::now();
    let held = |token: Address| {
        let eip1193 = eip1193.clone();
        async move {
            let units: U256 = eip1193
                .sol_call(token, balanceOfCall { owner: eoa.address })
                .await
                .map_err(|e| format!("balanceOf {token}: {e}"))?;
            Ok::<u128, String>(u128::try_from(units).unwrap_or(u128::MAX))
        }
    };
    let purse: Result<Purse, String> = async {
        let wei = eoa.eth_balance()?;
        let erc20 = Holding { token: preferred, units: held(preferred).await? };
        let wrapped = match mintable {
            Some(token) => Some(Holding { token, units: held(token).await? }),
            None => None,
        };
        Ok(Purse { eoa: eoa.address, wei, erc20, wrapped, fee_wei_per_gas: eoa.gas_price() })
    }
    .await;
    let purse = match purse {
        Ok(v) => v,
        Err(e) => {
            out.legs.push(Leg::failed("funding", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
    };
    out.eth_wei = Some(purse.wei);
    out.fee_wei_per_gas = purse.fee_wei_per_gas;
    let already = surveyed.as_ref().map_or(&[][..], |s| s.shielded.as_slice());
    let chosen = match plan(&purse, p.shield, already) {
        Ok(chosen) => chosen,
        Err(ask) => {
            out.token_units = Some(purse.erc20.units);
            out.needs_funding = Some(ask.clone());
            out.legs.push(Leg::failed("funding", Some(t.elapsed().as_millis()), ask));
            // The survey above already measured everything money is not needed
            // for, so there is nothing left to do but hand off.
            return out.finished(started);
        }
    };
    let (token, shield_units, chosen_wrap) = match chosen {
        Plan::Shield { token, shield, wrap } => (token, shield, wrap),
        Plan::Spend { token, units } => {
            // A NOTE AN EARLIER RUN MINED. Nothing to wrap, allow or shield:
            // the three legs it would take are already paid for, and shielding
            // again would abandon this leaf in the contract's tree.
            out.reused_note = true;
            out.balance = Some(units);
            (token, units, None)
        }
    };
    let asset = AssetId::erc20(token);
    out.asset = Some(asset.to_string());
    out.token_units = Some(if token == purse.erc20.token {
        purse.erc20.units
    } else {
        purse.wrapped.map_or(0, |w| w.units)
    });
    out.legs.push(Leg::timed("funding", Some(t.elapsed().as_millis())));

    // AN ASK IS PRINTED EITHER WAY, BUT A BROKEN SURVEY IS NOT A SEND. The
    // engine or the sync went red above, so the tree this run would prove
    // against is not the chain's -- and every leg after this one would be
    // measuring that instead of a private send.
    let Some(Surveyed { mut provider, db, .. }) = surveyed else {
        return out.finished(started);
    };

    // ── EVERYTHING A NOTE ALREADY IN THE TREE MAKES UNNECESSARY ────────────
    //
    // Wrap, allow, shield, and the walk to the block the shield landed in. A
    // run that mined a shield and then failed has paid for all four; doing them
    // again would cost another 731 335 gas and abandon the leaf it left.
    if !out.reused_note {
        // ── mint what is missing, out of the probe's own ETH ─────────────────
        if let Some(amount) = chosen_wrap {
            entering("wrap");
            let t = Instant::now();
            out.wrapped_wei = Some(amount);
            match wrap_native(&eoa, token, amount, Duration::from_millis(p.confirm_ms)).await {
                Ok((tx, _)) => {
                    out.wrap_tx = Some(tx);
                    out.legs.push(Leg::timed("wrap", Some(t.elapsed().as_millis())));
                }
                Err(e) => {
                    out.legs.push(Leg::failed("wrap", Some(t.elapsed().as_millis()), e));
                    return out.finished(started);
                }
            }
        }

        // ── approve, if the smart wallet may not already move the tokens ───────
        entering("approve");
        let t = Instant::now();
        let approved: Result<Option<String>, String> = async {
            let current: U256 = eip1193
                .sol_call(token, allowanceCall { owner: eoa.address, spender: smart_wallet })
                .await
                .map_err(|e| format!("allowance: {e}"))?;
            if current >= U256::from(shield_units) {
                return Ok(None);
            }
            let data: Bytes = approveCall { spender: smart_wallet, value: U256::from(shield_units) }
                .abi_encode()
                .into();
            let gas = eoa.gas_limit(token, U256::ZERO, &data)?;
            eoa.send(token, U256::ZERO, data, gas).map(Some)
        }
        .await;
        let allowance_set = match approved {
            Ok(Some(tx)) => {
                out.approve_tx = Some(tx.clone());
                eoa.wait(&tx, Duration::from_millis(p.confirm_ms)).await.map(|_| ())
            }
            // An allowance that is already enough is not a leg that did nothing: it
            // is the second run of the day, and saying so keeps the timings readable.
            Ok(None) => Ok(()),
            Err(e) => Err(e),
        };
        if let Err(e) = allowance_set {
            out.legs.push(Leg::failed("approve", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
        out.legs.push(Leg::timed("approve", Some(t.elapsed().as_millis())));

        // ── the shield: the ENGINE's calldata, this probe's signature ──────────
        //
        // FIRST, THE LAST FREE QUESTION. Everything up to here is recoverable: the
        // wrap left WETH the next run reuses and the approve left an allowance it
        // reuses. A shield is not -- it puts a note in the contract's tree, and a
        // note is worth the gas to move it, which is the gas this leg is about to
        // spend. So the run re-prices against the fee as it is NOW rather than as
        // it was at the `funding` leg, minutes and several blocks ago.
        entering("shield");
        let t = Instant::now();
        let gate = shield_gate(&eoa);
        out.fee_wei_per_gas = gate.fee_wei_per_gas.or(out.fee_wei_per_gas);
        out.eth_wei = gate.wei.or(out.eth_wei);
        if let Some(e) = gate.refusal {
            out.needs_funding = Some(e.clone());
            out.legs.push(Leg::failed("shield", Some(t.elapsed().as_millis()), e));
            return out.finished(started);
        }
        let shield = provider
            .shield()
            .shield(from.clone(), asset, shield_units)
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

        // ── the tail of the shield: walk to it, and see the note it left ───────
        //
        // The accumulator was already walked before the `funding` leg, so this is
        // the blocks since -- the shield's own among them. The same engine and the
        // same database, so it resumes rather than starting again.
        entering("resync");
        let t = Instant::now();
        // The account whose record says how far the sync has got -- this probe's own
        // `0zk`, the one `sync::synced_block` takes the minimum against.
        let zk_address = from.to_string();
        let (_, resynced) =
            sync_windows(&mut provider, &eip1193, &chain, db.as_ref(), &zk_address).await;
        if out.record_leg("resync", t, resynced).is_none() {
            return out.finished(started);
        }

        // ── a shielded balance a transaction put there ─────────────────────────
        entering("note");
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
                "note",
                ms,
                format!(
                    "the shield was mined in block {:?} and the engine still sees 0 of {asset} \
                     shielded -- it synced past its own note or could not decrypt it",
                    out.shield_block
                ),
            ));
            return out.finished(started);
        }
        out.legs.push(Leg::timed("note", ms));
    }

    // ── the private send itself ────────────────────────────────────────────
    // RAILGUN takes a shield fee, so the note is worth slightly less than what
    // was shielded; half of what the ENGINE reports keeps a change note and so
    // keeps the operation on the 01x02 circuit the other two probes measured.
    // Whatever the run is sending out of: the note the `funding` leg found in
    // the tree, or the one the `shield` leg above put there.
    let balance = out.balance.unwrap_or_default();
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
    // The root to ask the contract about, and the tree to ask it in: both read
    // off the operation the engine produced rather than assumed. RAILGUN opens a
    // new tree every 65 536 commitments, and asking `rootHistory` about the wrong
    // one answers a confident `false`. `abis` is private to the engine, so the
    // TYPE cannot be named here -- the fields can.
    let mut proved_root: Option<(u32, U256)> = None;
    if let Some(op) = proved.proved_operations.first() {
        out.circuit = Some(format!(
            "{:02}x{:02}",
            op.circuit_inputs.nullifiers.len(),
            op.circuit_inputs.commitments_out.len()
        ));
        proved_root = Some((
            op.transaction.boundParams.treeNumber as u32,
            op.circuit_inputs.merkleroot.into(),
        ));
    }
    out.calldata_bytes = Some(proved.tx_data.data.len());

    // ── and the boolean this whole module is about ─────────────────────────
    if let Some((tree, root)) = proved_root {
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
        let mined = match sent {
            Ok(tx) => {
                out.transfer_tx = Some(tx.clone());
                eoa.wait(&tx, Duration::from_millis(p.confirm_ms)).await
            }
            Err(e) => Err(e),
        };
        match mined {
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

    out.finished(started)
}

/// Print the result as it completes: on a platform that kills the process the
/// console line is the only thing that survives.
pub fn report(r: &Run) {
    eprintln!("{}", summary(r));
    if let Some(ask) = &r.needs_funding {
        eprintln!("railgun_module: live-send probe: NEEDS FUNDING -- {ask}");
    }
    for l in r.legs.iter().filter(|l| !l.ok()) {
        eprintln!("railgun_module: live-send probe: {} -> {:?}", l.name, l.error);
    }
}

/// The one line the whole run is judged by, as a value rather than as a side
/// effect — so a test can read it, and so a caller that has somewhere better to
/// put it than stderr can.
pub fn summary(r: &Run) -> String {
    let leg = |n: &str| r.leg(n).and_then(|l| l.ms);
    format!(
        "railgun_module: live-send probe: {} (chain={} node={:?}{}{}{} witnessBackend={:?} \
         eoa={:?} \
         circuit={:?} shielded={:?} transferred={:?} rootOnChain={:?} syncedRootOnChain={:?} \
         asset={:?} wrappedWei={:?} feeWeiPerGas={:?} \
         shieldTx={:?} transferTx={:?} calldata={:?}B funding={:?}ms wrap={:?}ms engine={:?}ms \
         approve={:?}ms shield={:?}ms sync={:?}ms/{:?}blocks resync={:?}ms balance={:?}ms \
         transfer={:?}ms broadcast={:?}ms total={}ms)",
        if r.ok() { "SENT" } else { "DID NOT" },
        r.chain_id,
        r.node,
        if r.forked { " FORK-NOT-PUBLIC-SEPOLIA" } else { "" },
        // A run that could not pay measured the chain and sent nothing. Said in
        // the line itself, because the timings below it look like a send's.
        if r.needs_funding.is_some() { " SURVEY-ONLY-UNFUNDED" } else { "" },
        // And a run that shielded NOTHING because the tree already held its
        // note: `shieldTx` is None and `shield` has no milliseconds, which on
        // its own reads like a leg that was skipped rather than one that was
        // already paid for.
        if r.reused_note { " REUSED-A-MINED-SHIELD" } else { "" },
        r.witness_backend(),
        r.eoa,
        r.circuit,
        r.balance,
        r.transferred,
        r.root_on_chain,
        r.synced_root_on_chain,
        r.asset,
        r.wrapped_wei,
        r.fee_wei_per_gas,
        r.shield_tx,
        r.transfer_tx,
        r.calldata_bytes,
        leg("funding"),
        leg("wrap"),
        leg("engine"),
        leg("approve"),
        leg("shield"),
        leg("sync"),
        r.sync_from_block.zip(r.sync_to_block).map(|(from, to)| to.saturating_sub(from)),
        leg("resync"),
        leg("balance").or_else(|| leg("note")),
        leg("transfer"),
        leg("broadcast"),
        r.total_ms,
    )
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
        seen: Mutex<Vec<(String, Value)>>,
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
            self.seen.lock().unwrap().iter().map(|(m, _)| m.clone()).collect()
        }

        /// The params of the first call to `method`.
        fn params(&self, method: &str) -> Option<Value> {
            self.seen.lock().unwrap().iter().find(|(m, _)| m == method).map(|(_, p)| p.clone())
        }
    }

    impl RpcBackend for Canned {
        fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
            self.seen.lock().unwrap().push((method.to_string(), params));
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

    /// Whom a node would bill for this transaction: recovered from the
    /// signature over the signing hash, exactly as a node does it. Alloy's own
    /// `recover_signer` needs a feature this crate does not ask for, and doing
    /// it by hand is what makes the answer independent of the code under test.
    fn sender(tx: &TxEip1559, signature: &Signature) -> Address {
        use alloy::signers::k256::ecdsa::VerifyingKey;

        let recid = RecoveryId::from_byte(u8::from(signature.v())).expect("parity");
        let sig = alloy::signers::k256::ecdsa::Signature::from_scalars(
            signature.r().to_be_bytes::<32>(),
            signature.s().to_be_bytes::<32>(),
        )
        .expect("scalars");
        let recovered =
            VerifyingKey::recover_from_prehash(tx.signature_hash().as_slice(), &sig, recid)
                .expect("recover");
        alloy::signers::utils::public_key_to_address(&recovered)
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

    // An unfunded run is a HANDOFF, not a crash: it must name the address and
    // say what to send. It must also SPEND NOTHING -- but "spend nothing" is not
    // "do nothing", and this is the difference (#213 clause 1). The chain reads
    // a survey makes are free, so the run carries on into every leg money is not
    // needed for and stops only before the first signature.
    #[test]
    fn an_unfunded_eoa_reports_the_ask_and_still_surveys_the_chain() {
        let chain = Canned::with(&[
            ("eth_getBalance", json!("0x0")),
            ("eth_call", word(0)), // balanceOf
        ]);
        let out = block_on(run(chain.clone(), Params::default()));
        assert!(!out.ok());
        assert_eq!(out.eoa, Some(probe_eoa_address().to_string()));
        let ask = out.needs_funding.clone().expect("an unfunded run must say what it needs");
        assert!(ask.contains(&probe_eoa_address().to_string()), "{ask}");
        assert!(
            ask.contains(&(MIN_GAS_WEI + DEFAULT_WRAP_SHIELD).to_string()),
            "the ask must be ONE number in ETH -- gas plus what it wraps: {ask}"
        );
        assert!(ask.contains("wrapping"), "and it must say ETH is all it needs: {ask}");
        // The `funding` leg is RED and stays red, so `ok()` is false and the
        // summary says DID NOT -- a survey must never read like a send.
        assert!(!out.leg("funding").expect("a funding leg").ok());
        assert!(
            out.legs.iter().any(|l| l.name == "engine"),
            "it stopped at the funding ask instead of surveying: {:?}",
            out.legs.iter().map(|l| l.name).collect::<Vec<_>>()
        );
        assert!(
            summary(&out).contains("SURVEY-ONLY-UNFUNDED"),
            "a survey has to be unmistakable in the one line it is judged by: {}",
            summary(&out)
        );
        // And the line nothing may cross without money.
        assert!(!chain.asked().iter().any(|m| m == "eth_sendRawTransaction"));
    }

    // WHICH NODE ANSWERED. A run against a FORK of Sepolia and a run against
    // public Sepolia produce byte-identical console lines otherwise — same chain
    // id, same contracts, same tree, same `rootOnChain: true` — and the two are
    // not the same evidence. #213 clause 1 is about a shield mined on the public
    // chain, so the report has to name its node rather than leave the
    // distinction in a human's memory: `anvil/v1.8.1` is a fork, `erigon/…` or
    // `Nethermind/…` is not.
    #[test]
    fn the_run_names_the_node_that_answered() {
        let chain = Canned::with(&[
            ("web3_clientVersion", json!("anvil/v1.8.1")),
            ("eth_getBalance", json!("0x0")),
            ("eth_call", word(0)),
        ]);
        let out = block_on(run(chain, Params::default()));
        assert_eq!(
            out.node.as_deref(),
            Some("anvil/v1.8.1"),
            "a run that stops at funding must still say whose chain it read"
        );
        assert!(
            out.forked,
            "an anvil client version is a local fork and the run must say so"
        );
    }

    // AND WHICH BACKEND PROVED. #213 clause 2 asks for the backend the engine's
    // OWN `calculate_witness` chose, and on a device that evidence is a line the
    // VENDORED engine prints — a different line, from a different crate, which a
    // machine-read result never sees. So the run's own summary names it too, and
    // one line then carries the backend beside `rootOnChain` and the timings.
    #[test]
    fn the_run_names_the_backend_the_engine_proves_with() {
        let chain = Canned::with(&[
            ("web3_clientVersion", json!("anvil/v1.8.1")),
            ("eth_getBalance", json!("0x0")),
            ("eth_call", word(0)),
        ]);
        let out = block_on(run(chain, Params::default()));
        assert_eq!(
            out.witness_backend(),
            crate::proof_circuit::ENGINE_BACKEND.requested(),
            "the run must name the backend THIS image's engine proves with"
        );
        assert!(
            summary(&out).contains(&format!("witnessBackend={:?}", out.witness_backend())),
            "the summary does not name the backend: {}",
            summary(&out)
        );
    }

    // And the name is read off the platform rather than typed: the interpreter
    // is the answer on a physical iOS device and nowhere else (#188).
    #[test]
    fn only_a_physical_ios_device_proves_on_the_interpreter() {
        let want = if cfg!(all(target_os = "ios", not(target_abi = "sim"))) {
            "wasmi"
        } else {
            "engine-default"
        };
        assert_eq!(Run::default().witness_backend(), want);
    }

    // A node that does not answer `web3_clientVersion` is NOT a failed run: the
    // identity is evidence, not a dependency, and a proxy may refuse the method.
    // The run reports `node: None` and carries on to the leg that matters.
    #[test]
    fn a_node_that_will_not_name_itself_does_not_stop_the_run() {
        let chain = Canned::with(&[
            ("eth_getBalance", json!("0x0")),
            ("eth_call", word(0)),
        ]);
        let out = block_on(run(chain, Params::default()));
        assert_eq!(out.node, None);
        assert!(!out.forked, "an unknown node is not a fork, it is unknown");
        assert!(out.needs_funding.is_some(), "it stopped before the funding leg: {out:?}");
    }

    // ── the root the engine checks and then forgets ────────────────────────

    /// The `eth_call` the engine makes to verify a tree, shaped exactly as
    /// `EthRpcEip1193::eth_call` writes it.
    fn root_history_call(to: Address, tree: u32, root: U256) -> Value {
        let data = rootHistoryCall { treeNumber: U256::from(tree), root: root.into() }.abi_encode();
        json!([{ "to": format!("{to:?}"), "data": format!("0x{}", hex::encode(data)) }, "latest"])
    }

    // THE VERDICT UPSTREAM THROWS AWAY. `UtxoIndexer::verify` asks the contract
    // whether it knows the root of every tree it has just synced -- and keeps
    // only the RPC error, dropping the `bool`. So an engine whose tree has
    // diverged from the contract's syncs GREEN, and every proof it then builds
    // reverts. The probe cannot make upstream keep the answer; it can overhear
    // it, because the question goes out over the provider this module supplies.
    #[test]
    fn the_engines_own_root_check_is_overheard() {
        let wallet = ChainConfig::sepolia().railgun_smart_wallet;
        let root = U256::from(0x1234_5678u64);
        let chain = Canned::with(&[("eth_call", word(1))]);
        let watch = RootWatch::new(chain, wallet);
        assert_eq!(watch.last(), None, "it invented a check nobody made");
        watch.rpc("eth_call", root_history_call(wallet, 3, root)).expect("answered");
        assert_eq!(watch.last(), Some(RootCheck { tree: 3, root, on_chain: true }));
    }

    // And it is the ROOT CHECK it keeps, not any `eth_call`: a run makes many
    // (balanceOf, allowance), and one of them landing in this field would report
    // a token balance as a merkle root.
    #[test]
    fn an_ordinary_eth_call_is_not_a_root_check() {
        let wallet = ChainConfig::sepolia().railgun_smart_wallet;
        let elsewhere: Address = SEPOLIA_USDC.parse().unwrap();
        let chain = Canned::with(&[("eth_call", word(1)), ("eth_blockNumber", word(9))]);
        let watch = RootWatch::new(chain, wallet);
        // Right contract, wrong call.
        let balance = json!([
            { "to": format!("{wallet:?}"), "data": format!("0x{}", hex::encode(
                balanceOfCall { owner: probe_eoa_address() }.abi_encode())) },
            "latest"
        ]);
        watch.rpc("eth_call", balance).expect("answered");
        assert_eq!(watch.last(), None, "a balanceOf was read as a root check");
        // Right call, wrong contract -- a root another deployment knows is not
        // evidence about this one.
        watch.rpc("eth_call", root_history_call(elsewhere, 0, U256::from(7))).expect("answered");
        assert_eq!(watch.last(), None, "another contract's root was read as ours");
        // And nothing that is not an `eth_call` at all.
        watch.rpc("eth_blockNumber", json!([])).expect("answered");
        assert_eq!(watch.last(), None);
    }

    // A ROOT THE CONTRACT DOES NOT KNOW IS A FAILED RUN. This is the whole
    // reason the verdict is kept: upstream's `verify()` returns `Ok(())` for
    // exactly this answer, so without this the sync leg goes green over a tree
    // that has diverged and the failure surfaces 200 s later as a reverted
    // `transact(...)` -- or, on an unfunded survey, not at all.
    #[test]
    fn a_root_the_contract_does_not_know_is_reported_and_fatal() {
        let wallet = ChainConfig::sepolia().railgun_smart_wallet;
        let root = U256::from(0xdeadbeefu64);
        let chain = Canned::with(&[("eth_call", word(0))]); // rootHistory -> false
        let watch = RootWatch::new(chain, wallet);
        watch.rpc("eth_call", root_history_call(wallet, 2, root)).expect("answered");

        let mut out = Run::default();
        let err = record_root_check(&mut out, &watch).expect_err("a false root must stop the run");
        assert!(err.contains("does not know the root"), "{err}");
        assert_eq!(out.synced_tree, Some(2), "the tree has to be named: the answer is per tree");
        assert_eq!(out.synced_root, Some(format!("0x{root:064x}")));
        assert_eq!(out.synced_root_on_chain, Some(false));
        assert!(
            summary(&out).contains("syncedRootOnChain=Some(false)"),
            "the one line a run is judged by must carry it: {}",
            summary(&out)
        );
    }

    // An engine that checked nothing is not an engine that failed: `verify()`
    // skips a tree with no leaves, and inventing a verdict for that would be a
    // worse answer than having none.
    #[test]
    fn an_engine_that_checked_no_root_is_not_a_failure() {
        let watch = RootWatch::new(Canned::with(&[]), ChainConfig::sepolia().railgun_smart_wallet);
        let mut out = Run::default();
        record_root_check(&mut out, &watch).expect("nothing checked is not a failure");
        assert_eq!(out.synced_root_on_chain, None);
    }

    // ── the funding decision, which is the whole of the operator ask ───────

    /// A purse on a chain that would not quote a gas price, so these tests are
    /// about the DECISION and not about the pricing -- which has its own tests
    /// below, and its own arithmetic to be wrong in.
    fn purse(wei: u128, erc20: u128, wrapped: Option<u128>) -> Purse {
        Purse {
            eoa: probe_eoa_address(),
            wei,
            erc20: Holding { token: SEPOLIA_USDC.parse().unwrap(), units: erc20 },
            wrapped: wrapped
                .map(|units| Holding { token: ChainConfig::sepolia().wrapped_base_token, units }),
            fee_wei_per_gas: None,
        }
    }

    /// The shield half of a plan, for the tests that are about the funding
    /// decision rather than about a note already in the tree.
    fn shielding(p: Plan) -> (Address, u128, Option<u128>) {
        match p {
            Plan::Shield { token, shield, wrap } => (token, shield, wrap),
            Plan::Spend { token, units } => {
                panic!("expected a shield plan, got a spend of {units} units of {token}")
            }
        }
    }

    // #213's THIRD BLOCKER, REMOVED. For three cycles the run stopped because
    // the EOA held no ERC-20, and an arbitrary test token is the half of the ask
    // an operator cannot satisfy from a faucet. It never had to be asked for:
    // the chain config names a token the probe can MINT out of its own ETH.
    #[test]
    fn eth_alone_is_enough_because_the_probe_mints_its_own_erc20() {
        let chosen = plan(&purse(MIN_GAS_WEI * 4, 0, Some(0)), None, &[])
            .expect("a well-funded-in-ETH account is not a funding ask any more");
        let (token, shield, wrap) = shielding(chosen);
        assert_eq!(token, ChainConfig::sepolia().wrapped_base_token);
        assert_eq!(shield, DEFAULT_WRAP_SHIELD);
        assert_eq!(wrap, Some(DEFAULT_WRAP_SHIELD), "it has to mint the whole amount");
    }

    // And an ERC-20 that is already there is still preferred, so the 20 USDC the
    // venue funded once are not stranded by this.
    #[test]
    fn an_erc20_the_eoa_already_holds_beats_wrapping() {
        let chosen =
            plan(&purse(MIN_GAS_WEI * 4, DEFAULT_SHIELD, Some(0)), None, &[]).expect("funded");
        let (token, _, wrap) = shielding(chosen);
        assert_eq!(token, SEPOLIA_USDC.parse::<Address>().unwrap());
        assert_eq!(wrap, None, "it wrapped ETH it did not need to");
    }

    // Wrapping only covers the SHORTFALL: a second run on the same EOA leaves
    // change behind, and spending ETH to re-mint it would be a slow leak.
    #[test]
    fn a_partial_wrapped_balance_is_topped_up_not_replaced() {
        let held = DEFAULT_WRAP_SHIELD / 4;
        let chosen = plan(&purse(MIN_GAS_WEI * 4, 0, Some(held)), None, &[]).expect("funded");
        assert_eq!(shielding(chosen).2, Some(DEFAULT_WRAP_SHIELD - held));
        let enough =
            plan(&purse(MIN_GAS_WEI * 4, 0, Some(DEFAULT_WRAP_SHIELD)), None, &[]).unwrap();
        assert_eq!(shielding(enough).2, None);
    }

    // Gas alone, with no room to wrap, is still an ask — and the number in it is
    // gas PLUS the wrap, because asking for exactly the gas would strand the run
    // one leg later.
    #[test]
    fn gas_with_no_room_to_wrap_is_a_funding_ask() {
        let err = plan(&purse(MIN_GAS_WEI, 0, Some(0)), None, &[]).expect_err("it cannot shield");
        assert!(err.contains(&(MIN_GAS_WEI + DEFAULT_WRAP_SHIELD).to_string()), "{err}");
    }

    // Nothing is minted for a NAMED asset: `deposit()` is on the wrapped base
    // token and nowhere else, so a caller who names a token has to bring it.
    #[test]
    fn a_named_asset_is_never_wrapped() {
        let err =
            plan(&purse(MIN_GAS_WEI * 4, 0, None), None, &[]).expect_err("it holds none of it");
        assert!(err.contains("named an asset"), "{err}");
        assert!(!err.contains("mints its own"), "{err}");
    }

    // No gas is an ask whatever else is held: nothing here can be signed without
    // it, so reporting a token balance as if it were progress would mislead.
    #[test]
    fn no_gas_is_an_ask_even_with_the_token_in_hand() {
        let err = plan(&purse(0, DEFAULT_SHIELD * 100, Some(DEFAULT_WRAP_SHIELD)), None, &[])
            .expect_err("it cannot pay for a transaction");
        assert!(err.contains(&MIN_GAS_WEI.to_string()), "{err}");
    }

    // ── A NOTE THE TREE ALREADY HOLDS, which changes the question ─────────

    // THE EXPENSIVE HALF OF CLAUSE 1 IS A MINED SHIELD, AND A RUN CAN LOSE IT.
    //
    // #243 stopped the probe STRANDING a note -- it will not shield when what
    // would be left cannot pay for the proved `transact(...)`. It did nothing
    // for a note that is already there, and there are several ways to get one:
    // a run whose `transfer` leg could not reach the artifact host, a phone
    // that backgrounded the app mid-sync, a `broadcast` that was refused for
    // funds (which is exactly the failure #243 reproduced, on a fork, WITH the
    // shield already mined). In every one of them the operator's transfer has
    // bought a note in the contract's tree.
    //
    // Before this, the next run shielded a SECOND note -- another 731 335 gas,
    // another whole funding ask -- and left the first one unspendable for good.
    #[test]
    fn a_note_already_in_the_tree_is_spent_instead_of_shielded_again() {
        let fee = 1_025_000_000_u128;
        let weth = ChainConfig::sepolia().wrapped_base_token;
        // What is left after a run that mined its shield and then stopped: it
        // wrapped, allowed and shielded, so the ETH is nearly gone and the WETH
        // with it. Not enough for another whole run, by construction.
        let left = price_spend(fee);
        let broke = Purse { fee_wei_per_gas: Some(fee), ..purse(left, 0, Some(0)) };
        assert!(
            left < price_run(fee, DEFAULT_WRAP_SHIELD),
            "this test is meaningless unless the purse is short of a whole run"
        );
        plan(&broke, None, &[]).expect_err("with an empty tree this purse cannot start a run");

        // But the tree holds what the last run put there.
        let note = [Holding { token: weth, units: DEFAULT_WRAP_SHIELD }];
        assert_eq!(
            plan(&broke, None, &note).expect("a note in the tree is a run this purse CAN finish"),
            Plan::Spend { token: weth, units: DEFAULT_WRAP_SHIELD },
            "it shielded a second note instead of spending the one already in the tree"
        );
    }

    // And the ask, when there IS a note, is the transact alone -- the three legs
    // before it have already been paid for, by the run that mined the shield.
    // An operator topping up after a failure must not be asked twice for them.
    #[test]
    fn the_ask_after_a_mined_shield_is_only_what_the_transact_reserves() {
        let fee = 1_025_000_000_u128;
        let weth = ChainConfig::sepolia().wrapped_base_token;
        let note = [Holding { token: weth, units: DEFAULT_WRAP_SHIELD }];
        let empty = Purse { fee_wei_per_gas: Some(fee), ..purse(0, 0, Some(0)) };
        let ask = plan(&empty, None, &note).expect_err("an empty EOA cannot pay for the transact");
        // Spelled out rather than read back from `price_spend`: the transact's
        // reservation is `max_fee_per_gas` (twice the quoted fee) over a limit
        // 30 % above its measured gas, at a fee allowed to double under it.
        let expected = 2 * fee * 2 * (GAS_TRANSACT * 13 / 10);
        assert!(ask.contains(&expected.to_string()), "the ask is not the transact's own: {ask}");
        assert!(
            expected < price_run(fee, DEFAULT_WRAP_SHIELD),
            "a rescue that costs more than a fresh run is not a rescue"
        );
        assert!(
            ask.contains("ALREADY holds"),
            "an operator must be told the money already spent is not lost: {ask}"
        );
    }

    // A note too small to split is not a note this probe can send: the transfer
    // is half of it, and half of one unit is nothing to prove over. Shield.
    #[test]
    fn a_note_too_small_to_split_is_shielded_over_rather_than_spent() {
        let weth = ChainConfig::sepolia().wrapped_base_token;
        // ONE unit, spelled out: half of it is nothing, so there is no transfer
        // to prove and no change note to keep the operation on `01x02`. Written
        // as the number rather than as `MIN_TRANSFERABLE - 1`, which would move
        // with the constant and assert nothing about where the floor is.
        let dust = [Holding { token: weth, units: 1 }];
        let chosen = plan(&purse(MIN_GAS_WEI * 4, 0, Some(0)), None, &dust)
            .expect("a funded purse is not an ask");
        assert_eq!(
            shielding(chosen).2,
            Some(DEFAULT_WRAP_SHIELD),
            "it tried to send a note of one unit"
        );
    }

    // The caller's order is the preference: the run reads the engine's balance
    // for the token it would otherwise shield FIRST, so a stale note in some
    // other asset cannot divert a run that was asked for a named one.
    #[test]
    fn the_first_spendable_note_the_caller_offers_is_the_one_taken() {
        let fee = 1_025_000_000_u128;
        let weth = ChainConfig::sepolia().wrapped_base_token;
        let usdc: Address = SEPOLIA_USDC.parse().unwrap();
        let funded = Purse { fee_wei_per_gas: Some(fee), ..purse(price_run(fee, 0) * 4, 0, Some(0)) };
        let notes = [
            Holding { token: usdc, units: 1 },
            Holding { token: weth, units: DEFAULT_WRAP_SHIELD },
        ];
        assert_eq!(
            plan(&funded, None, &notes).expect("funded"),
            Plan::Spend { token: weth, units: DEFAULT_WRAP_SHIELD },
            "it took a note it cannot split over one it can"
        );
    }

    // AND THE ONE LINE HAS TO SAY SO. On a reuse run `shieldTx` is null and the
    // `shield` leg has no milliseconds, which on their own read like a leg that
    // was skipped rather than one an earlier run already paid for.
    #[test]
    fn a_run_that_reused_a_note_says_so_in_the_line_it_is_judged_by() {
        assert!(
            !summary(&Run::default()).contains("REUSED"),
            "a run that shielded for itself must not claim to have reused anything"
        );
        let reused = Run { reused_note: true, ..Default::default() };
        assert!(
            summary(&reused).contains("REUSED-A-MINED-SHIELD"),
            "a run that shielded nothing does not say why: {}",
            summary(&reused)
        );
    }

    // ── WHAT THE ASK IS WORTH, which is not what a constant says ──────────

    // THE ASK HAS TO SURVIVE ITS OWN RUN, and a constant cannot promise that.
    //
    // `MIN_GAS_WEI` was written against an estimate -- its own comment says "a
    // shield is ~250 k gas" -- and the shield this probe has actually mined cost
    // **731 335** (the receipts are in `docs/specs.md`, #213 cycle 6). Worse,
    // the number a node checks a balance against is not what a transaction
    // SPENDS but what EIP-1559 makes it RESERVE: `gas_limit * max_fee_per_gas`,
    // and [`Eoa::send`] sets that ceiling at twice the chain's own `eth_gasPrice`
    // over a limit 30 % above the estimate ([`Eoa::gas_limit`]).
    //
    // So the binding moment is the proved `transact(...)` -- the LAST leg,
    // reached only after the shield has been mined. A purse that clears every
    // earlier leg and fails there leaves a shielded note this EOA cannot spend:
    // the operator's one funding transfer, spent on a balance nobody can move.
    // A fork never showed this, because `anvil_setBalance` handed the probe
    // 10 ETH.
    #[test]
    fn the_ask_survives_its_own_run_and_the_constant_it_replaces_does_not() {
        // Sepolia's base fee while this was written, read off the chain
        // (`eth_gasPrice` -> 0x3d24d3d7) rather than chosen.
        let fee = 1_025_000_000_u128;
        // What is left at the moment `can_still_transact` is asked -- i.e. just
        // before the shield, with the wrap moved into WETH and the two
        // recoverable legs paid for. The shield itself is what the gate is
        // deciding about, so it is NOT deducted here.
        let left = |start: u128| start - DEFAULT_WRAP_SHIELD - fee * (GAS_WRAP + GAS_APPROVE);

        let asked = price_run(fee, DEFAULT_WRAP_SHIELD);
        can_still_transact(left(asked), fee).expect("an ask that cannot finish its own run");
        // And at a fee that has doubled under it, which is a routine hour on
        // Sepolia -- the whole point of pricing rather than asserting.
        can_still_transact(left(asked), fee * 2)
            .expect("the ask carries no room for the fee to move");

        // The constant does not. Stated as the arithmetic, not as an opinion:
        // if this ever passes, the pricing above is dead weight and should go.
        assert!(
            can_still_transact(left(MIN_GAS_WEI), fee * 2).is_err(),
            "MIN_GAS_WEI survives a doubled fee after all -- then do not price the run"
        );
    }

    // AND THE QUESTION IS ASKED AGAIN WHERE STOPPING IS STILL FREE. A fee priced
    // at the `funding` leg can have moved by the time the shield is signed: the
    // legs between them are minutes apart on the public chain. The shield is the
    // last moment at which nothing has been staked, so that is where the run
    // re-prices. Refusing there costs the gas of the two legs before it;
    // refusing at the `transact` costs a shielded balance as well.
    #[test]
    fn a_fee_that_moved_stops_the_run_before_the_shield_not_after() {
        let fee = 1_025_000_000_u128;
        let funded = price_run(fee, DEFAULT_WRAP_SHIELD);
        let left = funded - DEFAULT_WRAP_SHIELD - fee * (GAS_WRAP + GAS_APPROVE);
        let refused =
            can_still_transact(left, fee * 10).expect_err("a tenfold fee is affordable?");
        assert!(
            refused.contains("BEFORE the shield"),
            "the refusal has to name what it is protecting: {refused}"
        );
        assert!(
            refused.contains(&probe_eoa_address().to_string()),
            "and the address to top up: {refused}"
        );
    }

    // THE RUN PRICES ITS OWN ASK OFF THE CHAIN IT IS POINTED AT. An operator
    // reading this issue funds ONE number; it has to be the number this run
    // needs on the chain as it is now, and it has to say what fee that was, so a
    // stale ask is visible as a stale ask rather than as a mysterious failure.
    #[test]
    fn the_ask_is_priced_at_the_fee_the_chain_quoted() {
        let fee = 3_000_000_000_u128;
        let chain = Canned::with(&[
            ("eth_getBalance", json!("0x0")),
            ("eth_call", word(0)),
            ("eth_gasPrice", json!(format!("0x{fee:x}"))),
        ]);
        let out = block_on(run(chain.clone(), Params::default()));
        assert_eq!(out.fee_wei_per_gas, Some(fee), "the funding leg must read the fee");
        let ask = out.needs_funding.clone().expect("an unfunded run must say what it needs");
        // Spelled out here rather than read back from `price_run`, so this
        // asserts the ask IS that number instead of asserting that two calls to
        // the same function agree: the wrap, the three legs before the transact
        // at a fee allowed to double, and the transact's own reservation at
        // twice that over a limit 30 % above its measured gas.
        let expected = DEFAULT_WRAP_SHIELD
            + 2 * fee * (GAS_WRAP + GAS_APPROVE + GAS_SHIELD)
            + 2 * fee * 2 * (GAS_TRANSACT * 13 / 10);
        assert_eq!(price_run(fee, DEFAULT_WRAP_SHIELD), expected);
        assert!(
            ask.contains(&expected.to_string()),
            "the ask must be this run's own price at that fee ({expected}): {ask}"
        );
        assert!(
            expected > MIN_GAS_WEI + DEFAULT_WRAP_SHIELD,
            "at {fee} wei/gas the priced ask is no bigger than the constant it replaced"
        );
        assert!(ask.contains(&fee.to_string()), "and it must name the fee it used: {ask}");
        // Still nothing signed.
        assert!(!chain.asked().iter().any(|m| m == "eth_sendRawTransaction"));
    }

    // A NODE THAT WILL NOT QUOTE A FEE DOES NOT STOP THE RUN. The price is
    // evidence, like `web3_clientVersion` -- an unreadable one falls back to the
    // constant, which is what every earlier cycle asked for, rather than
    // refusing to say anything at all.
    #[test]
    fn a_node_that_will_not_price_gas_falls_back_to_the_constant() {
        let chain = Canned::with(&[("eth_getBalance", json!("0x0")), ("eth_call", word(0))]);
        let out = block_on(run(chain, Params::default()));
        assert_eq!(out.fee_wei_per_gas, None);
        let ask = out.needs_funding.expect("an ask");
        assert!(ask.contains(&(MIN_GAS_WEI + DEFAULT_WRAP_SHIELD).to_string()), "{ask}");
    }

    // AND THE GATE AS IT IS ACTUALLY WIRED, over a chain. `can_still_transact`
    // is the arithmetic; this is the leg -- it has to READ the fee and the
    // balance off the chain at that moment, and it has to refuse without
    // sending anything.
    #[test]
    fn the_shield_gate_reads_the_chain_and_refuses_without_spending() {
        // Ten gwei: Sepolia does this, and a purse funded at one gwei does not
        // survive it.
        let fee = 10_000_000_000_u128;
        let chain = Canned::with(&[
            ("eth_gasPrice", json!(format!("0x{fee:x}"))),
            ("eth_getBalance", json!(format!("0x{MIN_GAS_WEI:x}"))),
        ]);
        let gate = shield_gate(&Eoa::new(chain.clone(), SEPOLIA));
        assert_eq!(gate.fee_wei_per_gas, Some(fee), "the gate must read the fee, not assume it");
        assert_eq!(gate.wei, Some(MIN_GAS_WEI));
        let refusal = gate.refusal.expect("ten gwei over this balance is not affordable");
        assert!(refusal.contains("BEFORE the shield"), "{refusal}");
        assert!(
            !chain.asked().iter().any(|m| m == "eth_sendRawTransaction"),
            "it refused AFTER signing something: {:?}",
            chain.asked()
        );
    }

    // A NODE THAT WILL NOT PRICE THE SHIELD DOES NOT BLOCK IT. The gate is a
    // safeguard, not a dependency: a chain that answers nothing must leave the
    // run exactly as it was before this was added, or a #213 run that used to
    // complete now stops for a reason that is not about money.
    #[test]
    fn a_node_that_will_not_price_the_shield_does_not_block_it() {
        let chain = Canned::with(&[("eth_getBalance", json!("0x0"))]);
        let gate = shield_gate(&Eoa::new(chain, SEPOLIA));
        assert_eq!(gate.wei, Some(0));
        assert!(gate.refusal.is_none(), "an unreadable fee must never be a refusal");
    }

    // THE WRAP ITSELF. Destination, value and selector are the whole leg and all
    // three are invisible until gas has been spent, so they are read back out of
    // the SIGNED transaction rather than out of the arguments that made it.
    #[test]
    fn the_wrap_is_a_deposit_on_the_chains_wrapped_base_token() {
        use alloy::consensus::TxEnvelope;
        use alloy::eips::eip2718::Decodable2718;

        let wrapped = ChainConfig::sepolia().wrapped_base_token;
        let chain = Canned::with(&[
            ("eth_getTransactionCount", json!("0x3")),
            ("eth_gasPrice", json!("0x3b9aca00")),
            ("eth_estimateGas", json!("0xb16a")),
            ("eth_sendRawTransaction", json!("0xwrapped")),
            ("eth_getTransactionReceipt", json!({ "status": "0x1", "blockNumber": "0x7b" })),
        ]);
        let eoa = Eoa::new(chain.clone(), SEPOLIA);
        let (tx, block) =
            block_on(wrap_native(&eoa, wrapped, DEFAULT_WRAP_SHIELD, Duration::from_millis(1)))
                .expect("wrap");
        assert_eq!((tx.as_str(), block), ("0xwrapped", 123));

        let raw = chain.params("eth_sendRawTransaction").expect("it never sent anything");
        let raw = raw[0].as_str().expect("a raw transaction is a hex string");
        let bytes = hex::decode(raw.trim_start_matches("0x")).expect("hex");
        let envelope = TxEnvelope::decode_2718(&mut bytes.as_slice()).expect("a 2718 envelope");
        let signed = envelope.as_eip1559().expect("EIP-1559");
        assert_eq!(signed.tx().to, TxKind::Call(wrapped), "it wrapped at the wrong contract");
        assert_eq!(signed.tx().value, U256::from(DEFAULT_WRAP_SHIELD), "wrong value");
        // `deposit()` — WETH9's payable mint. A wrong selector would pay ETH into
        // the contract's fallback, which on WETH9 happens to be deposit() anyway;
        // on anything else it is a donation.
        assert_eq!(hex::encode(&signed.tx().input), "d0e30db0");
        assert_eq!(
            sender(signed.tx(), signed.signature()),
            probe_eoa_address(),
            "the wrap has to come from the account an operator funded"
        );
    }

    // The signature is the one thing here that no chain checks for us before it
    // costs gas: a transaction recovering to another address is simply rejected,
    // and one recovering to the WRONG address is an account we did not mean to
    // spend.
    #[test]
    fn a_signed_transaction_recovers_to_the_probes_own_address() {
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
        let (signature, raw) = sign_1559(&probe_eoa_key(), tx.clone()).expect("sign");
        assert_eq!(sender(&tx, &signature), probe_eoa_address());
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

    /// Sync the real Sepolia tree once under `tuning`, and say what it cost.
    /// Returns `(engine_ms, sync_ms, from_block, to_block, shielded)`.
    fn sync_real_sepolia_once(tuning: Tuning) -> (u128, u128, u64, u64, u128) {
        let chain = ChainConfig::sepolia();
        let eip1193: Arc<dyn Eip1193Provider> = Arc::new(EthRpcEip1193::new(RealSepolia::new()));
        let (spend, view) = keys::derive_keys_from_seed(PROBE_SEED);
        let signer = keys::make_signer(&spend, &view, ChainId::evm(SEPOLIA)).expect("keys");
        let started = Instant::now();
        block_on(async {
            let db = Arc::new(MemoryDatabase::new());
            let mut provider = RailgunBuilder::new(chain.clone(), eip1193.clone())
                .with_database(db.clone())
                .with_utxo_syncer(sync::utxo_syncer(&chain, eip1193.clone(), &tuning))
                .build()
                .await
                .expect("engine");
            provider
                .register(signer.clone() as Arc<dyn RailgunSigner>)
                .await
                .expect("register");
            let built = started.elapsed().as_millis();
            let address = signer.address().to_string();
            let from = sync::synced_block(db.as_ref(), Some(&address)).await;
            let t = Instant::now();
            provider.sync().await.expect("sync");
            let synced = t.elapsed().as_millis();
            let to = sync::synced_block(db.as_ref(), Some(&address)).await;
            let balance: u128 =
                provider.balance(signer.address()).await.iter().map(|b| b.amount).sum();
            (built, synced, from, to, balance)
        })
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
        let (built, synced, from, to, balance) = sync_real_sepolia_once(Tuning::default());
        // Printed rather than asserted: the balance is 0 until an operator funds
        // the EOA and a run shields, and this test is about the SYNC completing.
        eprintln!(
            "live-send: real Sepolia sync: engine={built}ms sync={synced}ms \
             blocks={from}..{to} ({} blocks) shielded={balance}",
            to.saturating_sub(from)
        );
        assert!(to > from, "it synced nothing");
    }

    // AND WHAT IT COST BEFORE #235, ON THE SAME CHAIN, IN THE SAME SESSION.
    //
    // The engine's own `RpcSyncer` defaults -- 10 blocks per `eth_getLogs` with
    // a 1 000 ms sleep after each -- are the 221 s a private send spent syncing
    // on a physical iPad Air 4. This runs the identical cold sync twice, untuned
    // then tuned, minutes apart on the same chain, so the two numbers are
    // comparable in a way two runs on two days are not.
    //
    // WHAT IT SAVES IS 100 ms PER BLOCK OF **TAIL** -- the blocks after the last
    // RAILGUN transaction subsquid has indexed, which is what `SubsquidSyncer`
    // reports as its latest block. Everything before that comes out of subsquid
    // in 20 000-item pages and is the same either way, so the ABSOLUTE saving is
    // whatever the tail happens to be when you run this: measured 2026-09-17
    // against `ethereum-sepolia-rpc.publicnode.com`, a ~210-block tail,
    //
    //   before=31273ms  after=8192ms
    //
    // and on the day of the iPad run the tail was ~2 200 blocks, which is the
    // 221 s. The assertion is therefore only that the tuning never costs MORE:
    // a run on a chain whose tail is empty saves nothing and must not go red for
    // it. The ratio is the printed number, and
    // `sync::tests::the_tail_is_not_walked_ten_blocks_at_a_time` is the
    // deterministic form of the same claim (220 requests against 3).
    //
    // `#[ignore]` for the network AND for the wall clock: the untuned half takes
    // as long as the tail is deep, which is the point being made.
    //
    //   cargo test --features engine_seam -- --ignored --nocapture the_tuning_is_worth
    #[test]
    #[ignore = "needs the network; the untuned half takes as long as the tail is deep"]
    fn the_tuning_is_worth_what_it_claims_on_the_real_chain() {
        let untuned = Tuning { rpc_batch_blocks: 10, rpc_batch_delay_ms: 1_000 };
        let (_, before_ms, _, before_to, _) = sync_real_sepolia_once(untuned);
        let (_, after_ms, _, after_to, _) = sync_real_sepolia_once(Tuning::default());
        eprintln!(
            "live-send: cold sync of the real Sepolia tree to block {before_to} / {after_to}: \
             engine defaults ({}/{} ms) = {before_ms}ms, #235 ({}/{} ms) = {after_ms}ms",
            untuned.rpc_batch_blocks,
            untuned.rpc_batch_delay_ms,
            Tuning::default().rpc_batch_blocks,
            Tuning::default().rpc_batch_delay_ms,
        );
        assert!(after_ms <= before_ms, "before={before_ms}ms after={after_ms}ms");
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

    // THE HALF OF CLAUSE 1 THAT NEEDS NO MONEY, ON THE PUBLIC CHAIN.
    //
    // #213 clause 1 wants a shield mined on public Sepolia, and that is one
    // operator transfer away. Everything else the clause protects can be
    // measured without a penny: the engine builds over the DEFAULT syncer,
    // walks the real public accumulator to the LIVE tip -- which, unlike a
    // fork's, moves while the walk is going on -- and arrives at a root the
    // deployed RAILGUN contract confirms it knows. What a funded run would add
    // is a note of the probe's own in that tree.
    //
    // Asserted rather than printed, because each of the three is a real claim:
    // the run must not spend, the survey must complete, and the root must be
    // one the contract knows.
    //
    //   cargo test --features engine_seam -- --ignored --nocapture an_unfunded_run
    #[test]
    #[ignore = "needs the network and syncs the real Sepolia UTXO tree"]
    fn an_unfunded_run_still_surveys_the_public_chain() {
        let out = block_on(run(RealSepolia::new(), Params::default()));
        eprintln!("{}", summary(&out));
        assert!(out.needs_funding.is_some(), "the probe EOA is funded -- run the_whole_send");
        assert!(!out.ok(), "a survey must never report itself as a send");
        for leg in ["engine", "sync", "synced-root", "balance"] {
            let l = out.leg(leg).unwrap_or_else(|| panic!("no {leg} leg: {:?}", out.legs));
            assert!(l.ok(), "{leg}: {:?}", l.error);
        }
        assert_eq!(
            out.synced_root_on_chain,
            Some(true),
            "the contract does not know the root this device synced to: {:?}",
            out.synced_root
        );
    }

    // A RUN THAT MINED A SHIELD AND THEN FAILED MUST NOT COST A SECOND ONE.
    //
    // #243 stopped the probe stranding a note. This is the other half: a note
    // that IS already there. The first run below mines a shield and sends;
    // the second is then handed only what the proved `transact(...)` reserves
    // -- less than a fresh run needs, by construction -- and has to finish out
    // of the change note the first one left in the contract's tree.
    //
    // Driven on a fork because it needs to take the EOA's balance away between
    // the two runs, which is `anvil_setBalance`; every leg either side of that
    // is the real one, against real RAILGUN bytecode and the real accumulator.
    //
    //   anvil --fork-url <sepolia> --port 8753 --chain-id 11155111 --silent &
    //   LOGOS_SEPOLIA_RPC=http://127.0.0.1:8753 \
    //     cargo test --features engine_seam -- --ignored --nocapture a_run_after_a_mined_shield
    #[test]
    #[ignore = "needs a FORK of Sepolia (anvil): it sets the EOA's balance between two runs"]
    fn a_run_after_a_mined_shield_spends_the_note_instead_of_shielding_again() {
        let chain = RealSepolia::new();
        let quoted = || {
            quantity(&chain.rpc("eth_gasPrice", json!([])).expect("a node that quotes gas"))
                .expect("a gas price")
        };
        let fund = |wei: u128| {
            chain
                .rpc(
                    "anvil_setBalance",
                    json!([probe_eoa_address().to_string(), format!("0x{wei:x}")]),
                )
                .expect("anvil_setBalance -- point LOGOS_SEPOLIA_RPC at a fork");
        };

        fund(price_run(quoted(), DEFAULT_WRAP_SHIELD));
        let first = block_on(run(chain.clone(), Params::default()));
        eprintln!("{}", summary(&first));
        assert!(first.ok(), "the first run has to mine a shield: {:?}", first.needs_funding);
        assert!(first.shield_tx.is_some(), "the first run shielded nothing");
        assert!(!first.reused_note, "the first run had nothing to reuse");

        // Everything it had left, taken away. What remains is the note in the
        // tree and exactly the gas to move it -- which is the position an
        // operator is in after topping up a run that died past its shield.
        fund(price_spend(quoted()));
        let second = block_on(run(chain.clone(), Params::default()));
        eprintln!("{}", summary(&second));
        assert!(
            second.ok(),
            "a note in the tree plus the transact's own reservation is a run that finishes: {:?}",
            second.needs_funding.clone().unwrap_or(format!("{second:?}"))
        );
        assert!(
            second.reused_note,
            "it shielded a SECOND note instead of spending the one already in the tree"
        );
        assert_eq!(second.shield_tx, None, "a reused note costs no shield transaction");
        assert_eq!(second.wrap_tx, None, "and nothing to wrap");
        assert_eq!(second.root_on_chain, Some(true));
        assert!(second.transfer_block.is_some(), "the proved transfer was not mined: {second:?}");
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
